#include "pktgen.h"

#include <pcap.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_random.h>
#include <rte_udp.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>

#include <chrono>
#include <iomanip>
#include <iostream>
#include <memory>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "clock.h"
#include "flows.h"
#include "log.h"
#include "random.h"

// Source/destination MACs
const struct rte_ether_addr src_mac = {{0xb4, 0x96, 0x91, 0xa4, 0x02, 0xe9}};
const struct rte_ether_addr dst_mac = {{0xb4, 0x96, 0x91, 0xa4, 0x04, 0x21}};

volatile bool quit;
struct config_t config;

static void signal_handler(int signum) {
  (void)signum;
  quit = true;
}

static const struct rte_eth_conf port_conf_default = {};

// Per worker configuration
struct worker_config_t {
  bool ready;

  struct rte_mempool *pool;
  const uint16_t queue_id;

  const bytes_t pkt_size;
  const std::vector<uint32_t> flow_idx_seq;

  const runtime_config_t *runtime;

  worker_config_t(struct rte_mempool *_pool, uint16_t _queue_id, bytes_t _pkt_size, const std::vector<uint32_t> &_flow_idx_seq,
                  const runtime_config_t *_runtime)
      : ready(false), pool(_pool), queue_id(_queue_id), pkt_size(_pkt_size), flow_idx_seq(_flow_idx_seq), runtime(_runtime) {}
};

// Initializes a given port using global settings.
static inline int port_init(uint16_t port, unsigned num_rx_queues, unsigned num_tx_queues, struct rte_mempool **mbuf_pools) {
  struct rte_eth_conf port_conf = port_conf_default;
  const uint16_t rx_rings = num_rx_queues, tx_rings = num_tx_queues;
  uint16_t nb_rxd = DESC_RING_SIZE;
  uint16_t nb_txd = DESC_RING_SIZE;
  int retval;
  uint16_t q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf txconf;

  if (!rte_eth_dev_is_valid_port(port))
    return -1;

  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n", port, strerror(-retval));
  }

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM;

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;

  // Enable RX in promiscuous mode, just in case
  rte_eth_promiscuous_enable(port);
  if (rte_eth_promiscuous_get(port) != 1) {
    return retval;
  }

  /* Configure the Ethernet device. */
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0)
    return retval;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0)
    return retval;

  /* Allocate and set up 1 RX queue per RX worker port. */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pools[q]);
    if (retval < 0)
      return retval;
  }

  txconf          = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  /* Allocate and set up 1 TX queue per TX worker port. */
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0)
      return retval;
  }

  // Reset all stats.
  retval = rte_eth_stats_reset(port);
  if (retval != 0)
    return retval;

  retval = rte_eth_xstats_reset(port);
  if (retval != 0)
    return retval;

  /* Start the port. */
  retval = rte_eth_dev_start(port);
  if (retval < 0)
    return retval;

  return 0;
}

struct rte_mempool *create_mbuf_pool(unsigned lcore_id) {
  const unsigned mbuf_entries = RTE_MAX(MBUF_CACHE_SIZE + BURST_SIZE + NUM_SAMPLE_PACKETS, MIN_NUM_MBUFS);

  /* Creates a new mempool in memory to hold the mbufs. */
  char MBUF_POOL_NAME[20];
  sprintf(MBUF_POOL_NAME, "MBUF_POOL_%u", lcore_id);

  unsigned socket_id = rte_lcore_to_socket_id(lcore_id);

  struct rte_mempool *mbuf_pool =
      rte_pktmbuf_pool_create(MBUF_POOL_NAME, mbuf_entries, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);

  if (mbuf_pool == NULL) {
    rte_exit(EXIT_FAILURE, "Failed to create mbuf pool\n");
  }

  return mbuf_pool;
}

void wait_to_start() {
  uint64_t last_cnt = config.runtime.update_cnt;
  while (!quit) {
    if (config.runtime.running && (config.runtime.rate_per_core > 0)) {
      break;
    }
    while ((config.runtime.update_cnt == last_cnt) && !quit) {
      sleep_ms(100);
    }
    last_cnt = config.runtime.update_cnt;
  }
}

static void generate_template_packet(byte_t *pkt, uint16_t size) {
  bytes_t current_pkt_size = 0;
  byte_t *current_pkt_ptr  = pkt;

  struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)pkt;
  current_pkt_size += sizeof(rte_ether_hdr);
  current_pkt_ptr += sizeof(rte_ether_hdr);

  ether_hdr->src_addr   = src_mac;
  ether_hdr->dst_addr   = dst_mac;
  ether_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
  current_pkt_size += sizeof(rte_ipv4_hdr);
  current_pkt_ptr += sizeof(rte_ipv4_hdr);

  ip_hdr->version_ihl     = RTE_IPV4_VHL_DEF;
  ip_hdr->type_of_service = 0;
  ip_hdr->total_length    = rte_cpu_to_be_16(size - sizeof(rte_ether_hdr));
  ip_hdr->packet_id       = 0;
  ip_hdr->fragment_offset = 0;
  ip_hdr->time_to_live    = 64;
  ip_hdr->next_proto_id   = IPPROTO_UDP;
  ip_hdr->hdr_checksum    = 0; // Parameter
  ip_hdr->src_addr        = 0; // Parameter
  ip_hdr->dst_addr        = 0; // Parameter

  // Initialize the UDP header
  struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
  current_pkt_size += sizeof(rte_udp_hdr);
  current_pkt_ptr += sizeof(rte_udp_hdr);

  udp_hdr->src_port    = 0; // Parameter
  udp_hdr->dst_port    = 0; // Parameter
  udp_hdr->dgram_cksum = 0;
  udp_hdr->dgram_len   = rte_cpu_to_be_16(size - (sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr)));

  if (config.kvs_mode) {
    udp_hdr->dst_port = rte_cpu_to_be_16(KVSTORE_PORT);

    struct kvs_hdr_t *kvs_hdr = (struct kvs_hdr_t *)(udp_hdr + 1);
    current_pkt_size += sizeof(kvs_hdr_t);
    current_pkt_ptr += sizeof(kvs_hdr_t);

    kvs_hdr->op = KVS_OP_PUT;
    memset(kvs_hdr->key, 0, KEY_SIZE_BYTES);
    memset(kvs_hdr->value, 0, MAX_VALUE_SIZE_BYTES);
    kvs_hdr->status      = KVS_STATUS_MISS;
    kvs_hdr->client_port = 0;
  }

  constexpr uint16_t max_pkt_size_no_crc = MAX_PKT_SIZE - RTE_ETHER_CRC_LEN;

  byte_t *payload      = current_pkt_ptr;
  bytes_t payload_size = max_pkt_size_no_crc - current_pkt_size;
  memset(payload, 0xff, payload_size);
}

static void modify_packet(byte_t *pkt, const flow_t &flow, enum kvs_op kvs_op) {
  struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)pkt;
  struct rte_ipv4_hdr *ip_hdr     = (struct rte_ipv4_hdr *)(ether_hdr + 1);
  struct rte_udp_hdr *udp_hdr     = (struct rte_udp_hdr *)(ip_hdr + 1);

  if (config.mark_warmup_packets && config.warmup_active) {
    ip_hdr->next_proto_id = WARMUP_PROTO_ID;
  } else {
    ip_hdr->next_proto_id = IPPROTO_UDP;
  }

  if (config.kvs_mode) {
    ip_hdr->src_addr  = flow.src_ip;
    udp_hdr->src_port = flow.src_port;
    udp_hdr->dst_port = rte_cpu_to_be_16(KVSTORE_PORT);

    struct kvs_hdr_t *kvs_hdr = (struct kvs_hdr_t *)(udp_hdr + 1);
    kvs_hdr->op               = kvs_op;
    memcpy(kvs_hdr->key, flow.kvs_key, KEY_SIZE_BYTES);
    memcpy(kvs_hdr->value, flow.kvs_value, MAX_VALUE_SIZE_BYTES);
  } else {
    ip_hdr->src_addr  = flow.src_ip;
    udp_hdr->src_port = flow.src_port;
    ip_hdr->dst_addr  = flow.dst_ip;
    udp_hdr->dst_port = flow.dst_port;
  }
}

static void dump_flows_to_file() {
  bytes_t pkt_size_without_crc = config.pkt_size - 4;

  byte_t template_packet[MAX_PKT_SIZE];
  generate_template_packet(template_packet, pkt_size_without_crc);

  struct pcap_pkthdr header = {
      .ts = {.tv_sec = 0, .tv_usec = 0}, .caplen = (bpf_u_int32)pkt_size_without_crc, .len = (bpf_u_int32)pkt_size_without_crc};

  pcap_t *p         = NULL;
  pcap_dumper_t *pd = NULL;

  p = pcap_open_dead(DLT_EN10MB, 65535);
  assert(p);

  if ((pd = pcap_dump_open(p, DEFAULT_FLOWS_FILE)) == NULL) {
    fprintf(stderr, "Error opening savefile \"%s\" for writing: %s\n", DEFAULT_FLOWS_FILE, pcap_geterr(p));
    exit(7);
  }

  const std::vector<flow_t> &flows = get_generated_flows();
  for (const flow_t &flow : flows) {
    modify_packet(template_packet, flow, KVS_OP_GET);
    pcap_dump((u_char *)pd, &header, template_packet);
  }

  pcap_dump_close(pd);
  pcap_close(p);
}

// Given a desired throughput and (expected) packet size, computes the number of
// TSC ticks per packet burst.
static inline uint64_t compute_ticks_per_burst(rate_gbps_t rate, bits_t pkt_size) {
  // Traffic-gen is disabled
  if (rate == 0) {
    return 0;
  }

  pkt_size += (20 + RTE_ETHER_CRC_LEN) * 8; // CRC and inter-packet gap.
  double packets_per_us = (rate * 1000 / pkt_size);
  uint64_t ticks_per_us = clock_scale();

  // (ticks/us * packets/burst) / (packets/us)
  return (ticks_per_us * BURST_SIZE) / packets_per_us;
}

static int tx_worker_main(void *arg) {
  worker_config_t *worker_config = (worker_config_t *)arg;

  const std::vector<flow_t> &flows                             = get_generated_flows();
  const bytes_t pkt_size_without_crc                           = worker_config->pkt_size - RTE_ETHER_CRC_LEN;
  const size_t num_total_flows                                 = flows.size();
  const std::vector<std::vector<enum kvs_op>> kvs_ops_per_flow = generate_kvs_ops_per_flow();
  const size_t total_kvs_ops_per_flow                          = kvs_ops_per_flow[0].size();
  const size_t flow_idx_seq_size                               = worker_config->flow_idx_seq.size();

  struct rte_mbuf **mbufs = (struct rte_mbuf **)rte_malloc("mbufs", sizeof(rte_mbuf *) * NUM_SAMPLE_PACKETS, 0);
  if (mbufs == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot allocate mbufs\n");
  }

  byte_t template_packet[MAX_PKT_SIZE];
  generate_template_packet(template_packet, pkt_size_without_crc);

  // Prefill buffers with template packet.
  for (uint32_t i = 0; i < NUM_SAMPLE_PACKETS; i++) {
    mbufs[i] = rte_pktmbuf_alloc(worker_config->pool);

    if (unlikely(mbufs[i] == nullptr)) {
      rte_exit(EXIT_FAILURE, "Failed to create mbuf\n");
    }

    rte_pktmbuf_append(mbufs[i], pkt_size_without_crc);
    rte_memcpy(rte_pktmbuf_mtod(mbufs[i], void *), template_packet, pkt_size_without_crc);
  }

  // Triger clock scale calculation beforehand, as it pauses the execution for 1 second.
  clock_scale();

  worker_config->ready = true;
  wait_to_start();

  uint64_t last_update_cnt = 0;

  // Rate-limiting
  ticks_t ticks_per_burst = compute_ticks_per_burst(worker_config->runtime->rate_per_core, (worker_config->pkt_size * 8));

  // Rate control
  ticks_t period_end_tick   = 0;
  ticks_t first_tick        = now();
  ticks_t period_start_tick = first_tick;

  ticks_t elapsed_ticks      = 0;
  uint32_t mbuf_burst_offset = 0;

  bytes_t total_pkt_size    = 0;
  uint64_t num_total_tx     = 0;
  uint64_t flow_idx_counter = 0;

  ticks_t flow_ticks            = worker_config->runtime->flow_ttl * clock_scale() / 1000;
  ticks_t flow_ticks_offset_inc = flow_ticks / num_total_flows;

  std::vector<ticks_t> flows_timers(num_total_flows);
  std::vector<size_t> chosen_kvs_op_idxs(num_total_flows, 0);

  // Spreading out the churn, to avoid bursty churn.
  for (uint32_t i = 0; i < num_total_flows; i++) {
    flows_timers[i] = first_tick + i * flow_ticks_offset_inc;
  }

  uint16_t queue_id = worker_config->queue_id;

  // Run until the application is killed
  while (likely(!quit)) {
    // Check if the configuration was updated. We probably need to recompute some stuff before running again.
    if (unlikely(worker_config->runtime->update_cnt > last_update_cnt)) {
      elapsed_ticks += now() - first_tick;
      wait_to_start();

      last_update_cnt       = worker_config->runtime->update_cnt;
      ticks_per_burst       = compute_ticks_per_burst(worker_config->runtime->rate_per_core, worker_config->pkt_size * 8);
      flow_ticks            = worker_config->runtime->flow_ttl * clock_scale() / 1000;
      flow_ticks_offset_inc = flow_ticks / num_total_flows;
      first_tick            = now();

      for (uint32_t i = 0; i < num_total_flows; i++) {
        // Spreading out the churn, to avoid bursty churn.
        flows_timers[i] = first_tick + i * flow_ticks_offset_inc;
      }
    }

    period_end_tick = (period_start_tick + ticks_per_burst);

    rte_mbuf **mbuf_burst = mbufs + mbuf_burst_offset;
    mbuf_burst_offset     = (mbuf_burst_offset + BURST_SIZE) % NUM_SAMPLE_PACKETS;

    // Generate a burst of packets
    for (int i = 0; i < BURST_SIZE; i++) {
      rte_mbuf *mbuf = mbuf_burst[i % NUM_SAMPLE_PACKETS];
      total_pkt_size += mbuf->pkt_len;
      byte_t *pkt = rte_pktmbuf_mtod(mbuf, byte_t *);

      const uint32_t flow_idx = worker_config->flow_idx_seq[(flow_idx_counter + i) % flow_idx_seq_size];
      ticks_t &flow_timer     = flows_timers[flow_idx];

      size_t &chosen_kvs_op_idx = chosen_kvs_op_idxs[flow_idx];
      enum kvs_op chosen_kvs_op = kvs_ops_per_flow[flow_idx][chosen_kvs_op_idx];
      chosen_kvs_op_idx         = (chosen_kvs_op_idx + 1) % total_kvs_ops_per_flow;

      // Inducing churn by randomizing flows during run.
      if (flow_ticks > 0 && period_start_tick >= flow_timer) {
        flow_timer += flow_ticks;
        randomize_flow(flow_idx);
      }

      const flow_t &flow = flows[flow_idx];
      modify_packet(pkt, flow, chosen_kvs_op);

      // HACK(sadok): Increase refcnt to avoid freeing.
      mbuf->refcnt = MIN_NUM_MBUFS;
    }

    num_total_tx += rte_eth_tx_burst(config.tx.port, queue_id, mbuf_burst, BURST_SIZE);
    flow_idx_counter = (flow_idx_counter + BURST_SIZE) % flow_idx_seq_size;

    while ((period_start_tick = now()) < period_end_tick) {
      // prevent the compiler from removing this loop
      __asm__ __volatile__("");
    }
  }

  rte_free(mbufs);

  return 0;
}

static void wait_port_up(uint16_t port_id) {
  struct rte_eth_link link;
  link.link_status = RTE_ETH_LINK_DOWN;

  LOG("Waiting for port %u...", port_id);

  while (link.link_status == RTE_ETH_LINK_DOWN) {
    int retval = rte_eth_link_get(port_id, &link);
    if (retval != 0) {
      rte_exit(EXIT_FAILURE, "Error getting port status (port %u) info: %s\n", port_id, strerror(-retval));
    }
    sleep_ms(100);
  }
}

static void test() {
  time_s_t duration = 5;
  rate_mbps_t rate  = 100 * 1000;
  churn_fpm_t churn = 0;

  LOG("Sending at %.2lf Mbps with churn %lu fpm...", rate, churn);
  cmd_rate(rate / 1e3);
  cmd_churn(churn);

  cmd_stats_reset();

  cmd_start();
  sleep_s(duration);
  cmd_stop();

  stats_t stats = get_stats();

  float loss = (float)(stats.tx_pkts - stats.rx_pkts) / stats.tx_pkts;

  bits_t tx_bits = (config.pkt_size + 20) * 8 * stats.tx_pkts;

  rate_mpps_t mpps = stats.tx_pkts / (duration * 1e6);
  rate_gbps_t gbps = tx_bits / (duration * 1e9);

  LOG("");
  LOG("~~~~~~ Pktgen ~~~~~~");
  LOG("  TX:   %" PRIu64 "", stats.tx_pkts);
  LOG("  RX:   %" PRIu64 "", stats.rx_pkts);
  LOG("  Loss: %.2lf", 100 * loss);
  LOG("  Mpps: %.2lf", mpps);
  LOG("  Gbps: %.2lf", gbps);
}

int main(int argc, char *argv[]) {
  quit = false;

  signal(SIGINT, signal_handler);
  signal(SIGQUIT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* Initialize the Environment Abstraction Layer (EAL). */
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  }
  argc -= ret;
  argv += ret;

  // Parse command-line arguments
  config_init(argc, argv);
  config_print();

  struct rte_mempool **mbufs_pools = (struct rte_mempool **)rte_malloc("mbufs pools", sizeof(rte_mempool *) * config.tx.num_cores, 0);

  for (unsigned i = 0; i < config.tx.num_cores; i++) {
    unsigned lcore_id = config.tx.cores[i];
    mbufs_pools[i]    = create_mbuf_pool(lcore_id);
  }

  if (port_init(config.tx.port, config.tx.num_cores, config.tx.num_cores, mbufs_pools)) {
    rte_exit(EXIT_FAILURE, "Cannot init tx port %" PRIu16 "\n", 0);
  }

  if (config.rx.port != config.tx.port) {
    if (port_init(config.rx.port, 1, 1, mbufs_pools)) {
      rte_exit(EXIT_FAILURE, "Cannot init rx port %" PRIu16 "\n", 0);
    }
  }

  generate_flows();
  const std::vector<std::vector<uint32_t>> flow_idx_seq_per_worker = generate_flow_idx_sequence_per_worker();

  if (config.dump_flows_to_file) {
    dump_flows_to_file();
  }

  std::vector<std::unique_ptr<worker_config_t>> workers_configs(config.tx.num_cores);

  for (uint16_t i = 0; i < config.tx.num_cores; i++) {
    const std::vector<uint32_t> &flow_idx_seq = flow_idx_seq_per_worker.at(i);
    const uint16_t lcore_id                   = config.tx.cores[i];
    const uint16_t queue_id                   = i;

    workers_configs[i] = std::make_unique<worker_config_t>(mbufs_pools[i], queue_id, config.pkt_size, flow_idx_seq, &config.runtime);
    rte_eal_remote_launch(tx_worker_main, static_cast<void *>(workers_configs[i].get()), lcore_id);
  }

  // We no longer need the arrays. This doesn't free the mbufs themselves though, we still need them.
  rte_free(mbufs_pools);

  LOG("Waiting for workers...");

  for (std::unique_ptr<worker_config_t> &worker_config : workers_configs) {
    while (!worker_config->ready) {
      sleep_ms(100);
    }
  }

  wait_port_up(config.rx.port);
  wait_port_up(config.tx.port);

  if (config.test_and_exit) {
    test();
  } else {
    cmdline_start();
  }

  quit = true;
  LOG("Waiting for workers to finish...");

  // Wait for all processes to complete
  rte_eal_mp_wait_lcore();

  rte_eal_cleanup();

  return 0;
}