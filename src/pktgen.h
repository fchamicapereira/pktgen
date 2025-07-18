#ifndef PKTGEN_SRC_PKTGEN_H_
#define PKTGEN_SRC_PKTGEN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_udp.h>
#include <stdbool.h>
#include <stdint.h>

#define BURST_SIZE 32
#define MBUF_CACHE_SIZE 512
#define MIN_NUM_MBUFS 8192
#define DESC_RING_SIZE 1024
#define NUM_SAMPLE_PACKETS (2 * DESC_RING_SIZE)
#define DEFAULT_FLOWS_FILE "flows.pcap"

#define MIN_FLOWS_NUM 2

// To induce churn, flows are changed from time to time, alternating between an
// old and a new value. Naturally, alternating between these flows so fast that
// the time between alternation becomes smaller than the expiration time
// completely nullifies the churn. To really make sure that flows are expired,
// we only perform flow swapping after at least EPOCH_TIME *
// MIN_CHURN_ACTION_TIME_MULTIPLIER time elapsed from the last swap.
#define MIN_CHURN_ACTION_TIME_MULTIPLIER 10

typedef uint64_t bits_t;
typedef uint64_t bytes_t;

typedef uint8_t bit_t;
typedef uint8_t byte_t;

#define PREAMBLE_SIZE_BYTES 8
#define IPG_SIZE_BYTES 12

#define MIN_PKT_SIZE ((bytes_t)64)   // With CRC
#define MAX_PKT_SIZE ((bytes_t)1518) // With CRC

#define MIN_CRC_BITS 1
#define MAX_CRC_BITS 32

#define WARMUP_PROTO_ID 0x92 // Reserved transport proto ID for warmup packets

typedef uint64_t time_s_t;
typedef uint64_t time_ms_t;
typedef uint64_t time_us_t;
typedef uint64_t time_ns_t;

#define NS_TO_S(T) (((double)(T)) / 1e9)

typedef uint32_t crc32_t;

#define KEY_SIZE_BYTES 4
#define MAX_VALUE_SIZE_BYTES 4
#define KVSTORE_PORT 670

enum kvs_op {
  KVS_OP_GET = 0,
  KVS_OP_PUT = 1,
  KVS_OP_DEL = 2,
};

enum kvs_status {
  KVS_STATUS_MISS = 0,
  KVS_STATUS_HIT  = 1,
};

typedef uint8_t kv_key_t[KEY_SIZE_BYTES];
typedef uint8_t kv_value_t[MAX_VALUE_SIZE_BYTES];

struct kvs_hdr_t {
  uint8_t op;
  kv_key_t key;
  kv_value_t value;
  uint8_t status;
  uint16_t client_port;
} __attribute__((__packed__));

#define KVS_PKT_SIZE_BYTES                                                                                                                 \
  (RTE_ETHER_CRC_LEN + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(struct kvs_hdr_t))

typedef uint64_t churn_fpm_t;
typedef uint64_t churn_fps_t;

typedef double rate_gbps_t;
typedef double rate_mbps_t;

typedef double rate_mpps_t;

struct runtime_config_t {
  bool running;
  uint64_t update_cnt;

  // Information for each TX worker
  rate_gbps_t rate_per_core;
  time_ns_t flow_ttl;
};

enum traffic_dist_t {
  UNIFORM = 0,
  ZIPF    = 1,
};

struct config_t {
  bool test_and_exit;
  bool dump_flows_to_file;

  uint64_t seed;
  uint32_t num_flows;
  enum traffic_dist_t dist;
  double zipf_param;
  bool force_unique_flows;
  bytes_t pkt_size;

  time_s_t warmup_duration;
  rate_mbps_t warmup_rate;
  bool warmup_active;
  bool mark_warmup_packets;
  bool kvs_mode;
  double kvs_get_ratio;

  rate_gbps_t rate;

  struct {
    uint16_t port;
    uint16_t num_cores;
    uint16_t cores[RTE_MAX_LCORE];
  } tx;

  struct {
    uint16_t port;
  } rx;

  struct runtime_config_t runtime;
};

extern struct config_t config;

void config_init(int argc, char **argv);
void config_print();
void config_print_usage(char **argv);

void cmdline_start();
void cmd_stats_display();
void cmd_stats_display_compact();
void cmd_stats_reset();
void cmd_flows_display();
void cmd_dist_display();
void cmd_start();
void cmd_stop();
void cmd_rate(rate_gbps_t rate);
void cmd_churn(churn_fpm_t churn);
void cmd_timer(time_s_t time);

struct stats_t {
  uint64_t rx_pkts;
  uint64_t rx_bytes;
  uint64_t tx_pkts;
  uint64_t tx_bytes;
};

struct stats_t get_stats();
crc32_t calculate_crc32(byte_t *data, int len);

#ifdef __cplusplus
}
#endif

#endif // PKTGEN_SRC_PKTGEN_H_