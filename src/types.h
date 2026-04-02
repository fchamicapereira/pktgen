#pragma once

#include <stdint.h>
#include <stdbool.h>

#define BURST_SIZE 32
#define MBUF_CACHE_SIZE 512
#define MIN_NUM_MBUFS 8192
#define DESC_RING_SIZE 1024
#define NUM_SAMPLE_PACKETS (2 * DESC_RING_SIZE)
#define DEFAULT_FLOWS_FILE "flows.pcap"

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

typedef uint64_t time_s_t;
typedef uint64_t time_ms_t;
typedef uint64_t time_us_t;
typedef uint64_t time_ns_t;

#define MIN_PKT_SIZE ((bytes_t)64)   // With CRC
#define MAX_PKT_SIZE ((bytes_t)1518) // With CRC

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

enum traffic_dist_t {
  UNIFORM = 0,
  ZIPF    = 1,
};
