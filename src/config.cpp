#include <CLI/CLI.hpp>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "config.h"
#include "log.h"
#include "cmdline.h"

struct config_t config;

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define DEFAULT_PKT_SIZE MIN_PKT_SIZE
#define DEFAULT_TOTAL_FLOWS 10000
#define DEFAULT_ZIPF_PARAM 1.26
#define DEFAULT_KVS_GET_RATIO 0.0

void config_init(int argc, char **argv) {
  config.seed                = (uint64_t)time(NULL);
  config.test_and_exit       = false;
  config.num_flows           = DEFAULT_TOTAL_FLOWS;
  config.dist                = UNIFORM;
  config.zipf_param          = DEFAULT_ZIPF_PARAM;
  config.force_unique_flows  = false;
  config.pkt_size            = DEFAULT_PKT_SIZE;
  config.sync_cores          = false;
  config.dump_flows_to_file  = false;
  config.kvs_mode            = false;
  config.kvs_get_ratio       = DEFAULT_KVS_GET_RATIO;
  config.rx.port             = 0;
  config.tx.port             = 1;
  config.tx.num_cores        = 1;

  runtime_config.running       = false;
  runtime_config.update_cnt    = 0;
  runtime_config.rate_per_core = 0;
  runtime_config.flow_ttl      = 0;

  unsigned nb_devices = rte_eth_dev_count_avail();
  unsigned nb_cores   = rte_lcore_count();

  if (nb_devices < 2) {
    rte_exit(EXIT_FAILURE, "Insufficient number of available devices (%u detected, but we require at least 2).\n", nb_devices);
  }
  if (nb_cores < 2) {
    rte_exit(EXIT_FAILURE, "Insufficient number of cores (%u given, but we require at least 2).\n", nb_cores);
  }

  CLI::App app{"pktgen"};

  bytes_t pkt_size      = DEFAULT_PKT_SIZE;
  uint32_t tx_port      = config.tx.port;
  uint32_t rx_port      = config.rx.port;
  uint32_t num_tx_cores = config.tx.num_cores;
  std::string dist_str  = "uniform";

  app.add_flag("--test", config.test_and_exit, "Run test and exit");
  const CLI::Option *total_flows_opt =
      app.add_option("--total-flows", config.num_flows, "Total number of flows")->default_val(DEFAULT_TOTAL_FLOWS);

  const CLI::Option *pkt_size_opt = app.add_option("--pkt-size", pkt_size, "Packet size (bytes)")
                                        ->default_val(DEFAULT_PKT_SIZE)
                                        ->check(CLI::Range(MIN_PKT_SIZE, MAX_PKT_SIZE));

  app.add_option("--tx", tx_port, "TX port")->default_val(config.tx.port);
  app.add_option("--rx", rx_port, "RX port")->default_val(config.rx.port);
  app.add_option("--tx-cores", num_tx_cores, "Number of TX cores")->default_val(config.tx.num_cores)->check(CLI::PositiveNumber);
  app.add_flag("--unique-flows", config.force_unique_flows, "Flows are unique");
  app.add_option("--seed", config.seed, "Random seed");
  app.add_flag("--sync-cores", config.sync_cores, "Synchronize cores to replay the pcap in order across all cores");
  app.add_flag("--dump-flows-to-file", config.dump_flows_to_file, "Dump flows to pcap file");
  app.add_flag("--kvs-mode", config.kvs_mode, "Enable KVS mode");
  app.add_option("--kvs-get-ratio", config.kvs_get_ratio, "KVS get ratio")->default_val(DEFAULT_KVS_GET_RATIO)->check(CLI::Range(0.0, 1.0));
  app.add_option("--dist", dist_str, "Traffic distribution (uniform, zipf)")
      ->default_val("uniform")
      ->check(CLI::IsMember({"uniform", "zipf"}));
  app.add_option("--zipf-param", config.zipf_param, "Zipf parameter")->default_val(DEFAULT_ZIPF_PARAM)->check(CLI::NonNegativeNumber);
  app.add_option("--pcap", config.pcap_fname, "Pcap file to replay");

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError &e) {
    exit(app.exit(e));
  }

  config.pkt_size     = pkt_size;
  config.tx.port      = (uint16_t)tx_port;
  config.rx.port      = (uint16_t)rx_port;
  config.tx.num_cores = (uint16_t)num_tx_cores;
  config.dist         = (dist_str == "zipf") ? ZIPF : UNIFORM;

  if (tx_port >= nb_devices) {
    rte_exit(EXIT_FAILURE, "Invalid TX device: requested %u but only %u available.\n", tx_port, nb_devices);
  }
  if (rx_port >= nb_devices) {
    rte_exit(EXIT_FAILURE, "Invalid RX device: requested %u but only %u available.\n", rx_port, nb_devices);
  }
  if (num_tx_cores >= nb_cores) {
    rte_exit(EXIT_FAILURE, "Insufficient number of cores (main=1, tx=%u, available=%u).\n", num_tx_cores, nb_cores);
  }

  rte_srand(config.seed);

  if (config.kvs_mode) {
    if (pkt_size_opt->count() > 0) {
      WARNING("*************************************************************************");
      WARNING("Packet size is set to %" PRIu64 " bytes, but KVS mode requires a packet size of %" PRIu64 " bytes.", config.pkt_size,
              (uint64_t)KVS_PKT_SIZE_BYTES);
      WARNING("Overriding packet size to %" PRIu64 " bytes.", (uint64_t)KVS_PKT_SIZE_BYTES);
      WARNING("*************************************************************************");
    }
    config.pkt_size = MAX(KVS_PKT_SIZE_BYTES, MIN_PKT_SIZE);
  }

  if (!config.pcap_fname.empty() && total_flows_opt->count() > 0) {
    WARNING("*************************************************************************");
    WARNING("Total flows is set to %" PRIu32 ", but --pcap option is given. Ignoring the total flows option.", config.num_flows);
    WARNING("*************************************************************************");
  }

  unsigned idx = 0;
  unsigned lcore_id;
  RTE_LCORE_FOREACH_WORKER(lcore_id) { config.tx.cores[idx++] = lcore_id; }
}

void config_print() {
  const char *traffic_dist_str = (config.dist == UNIFORM) ? "uniform" : "zipf";

  LOG("\n----- Config -----");
  LOG("RX port:          %" PRIu16, config.rx.port);
  LOG("TX port:          %" PRIu16, config.tx.port);
  LOG("TX cores:         %" PRIu16, config.tx.num_cores);
  LOG("Random seed:      %" PRIu64, config.seed);
  LOG("Flows:            %" PRIu32, config.num_flows);
  LOG("Traffic dist:     %s", traffic_dist_str);
  LOG("Zipf param:       %lf", config.zipf_param);
  LOG("Unique flows:     %s", config.force_unique_flows ? "true" : "false");
  LOG("Packet size:      %" PRIu64 " bytes", config.pkt_size);
  LOG("Sync cores:       %s", config.sync_cores ? "true" : "false");
  LOG("Dump flows:       %s", config.dump_flows_to_file ? "true" : "false");
  LOG("KVS mode:         %s", config.kvs_mode ? "true" : "false");
  LOG("KVS get ratio:    %lf", config.kvs_get_ratio);
  LOG("------------------\n");
}
