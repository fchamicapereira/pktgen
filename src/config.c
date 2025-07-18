#include <getopt.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "pktgen.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define CMD_HELP "help"
#define CMD_TEST "test"
#define CMD_TOTAL_FLOWS "total-flows"
#define CMD_PKT_SIZE "pkt-size"
#define CMD_TX_PORT "tx"
#define CMD_RX_PORT "rx"
#define CMD_NUM_TX_CORES "tx-cores"
#define CMD_UNIQUE_FLOWS "unique-flows"
#define CMD_RANDOM_SEED "seed"
#define CMD_MARK_WARMUP_PKTS "mark-warmup-packets"
#define CMD_DUMP_FLOWS_TO_FILE "dump-flows-to-file"
#define CMD_KVS_MODE "kvs-mode"
#define CMD_KVS_GET_RATIO "kvs-get-ratio"
#define CMD_TRAFFIC_DISTRIBUTION "dist"
#define CMD_ZIPF_PARAM "zipf-param"

#define TRAFFIC_DISTRIBUTION_UNIFORM "uniform"
#define TRAFFIC_DISTRIBUTION_ZIPF "zipf"

#define DEFAULT_PKT_SIZE MIN_PKT_SIZE
#define DEFAULT_UNIQUE_FLOWS false
#define DEFAULT_TOTAL_FLOWS 10000
#define DEFAULT_WARMUP_DURATION 0 // No warmup
#define DEFAULT_WARMUP_RATE 1     // 1 Mbps
#define DEFAULT_MARK_WARMUP_PKTS false
#define DEFAULT_DUMP_FLOWS_TO_FILE false
#define DEFAULT_KVS_MODE false
#define DEFAULT_KVS_GET_RATIO 0.0
#define DEFAULT_TRAFFIC_DISTRIBUTION UNIFORM
#define DEFAULT_ZIPF_PARAM 1.26

enum {
  /* long options mapped to short options: first long only option value must
   * be >= 256, so that it does not conflict with short options.
   */
  CMD_HELP_NUM = 256,
  CMD_TEST_NUM,
  CMD_TOTAL_FLOWS_NUM,
  CMD_PKT_SIZE_NUM,
  CMD_TX_PORT_NUM,
  CMD_RX_PORT_NUM,
  CMD_NUM_TX_CORES_NUM,
  CMD_UNIQUE_FLOWS_NUM,
  CMD_RANDOM_SEED_NUM,
  CMD_MARK_WARMUP_PKTS_NUM,
  CMD_DUMP_FLOWS_TO_FILE_NUM,
  CMD_KVS_MODE_NUM,
  CMD_KVS_GET_RATIO_NUM,
  CMD_TRAFFIC_DISTRIBUTION_NUM,
  CMD_ZIPF_PARAM_NUM,
};

/* if we ever need short options, add to this string */
static const char short_options[] = "";

static const struct option long_options[] = {{CMD_HELP, no_argument, NULL, CMD_HELP_NUM},
                                             {CMD_TEST, no_argument, NULL, CMD_TEST_NUM},
                                             {CMD_TOTAL_FLOWS, required_argument, NULL, CMD_TOTAL_FLOWS_NUM},
                                             {CMD_PKT_SIZE, required_argument, NULL, CMD_PKT_SIZE_NUM},
                                             {CMD_TX_PORT, required_argument, NULL, CMD_TX_PORT_NUM},
                                             {CMD_RX_PORT, required_argument, NULL, CMD_RX_PORT_NUM},
                                             {CMD_NUM_TX_CORES, required_argument, NULL, CMD_NUM_TX_CORES_NUM},
                                             {CMD_UNIQUE_FLOWS, no_argument, NULL, CMD_UNIQUE_FLOWS_NUM},
                                             {CMD_RANDOM_SEED, required_argument, NULL, CMD_RANDOM_SEED_NUM},
                                             {CMD_MARK_WARMUP_PKTS, no_argument, NULL, CMD_MARK_WARMUP_PKTS_NUM},
                                             {CMD_DUMP_FLOWS_TO_FILE, no_argument, NULL, CMD_DUMP_FLOWS_TO_FILE_NUM},
                                             {CMD_KVS_MODE, no_argument, NULL, CMD_KVS_MODE_NUM},
                                             {CMD_KVS_GET_RATIO, required_argument, NULL, CMD_KVS_GET_RATIO_NUM},
                                             {CMD_TRAFFIC_DISTRIBUTION, required_argument, NULL, CMD_TRAFFIC_DISTRIBUTION_NUM},
                                             {CMD_ZIPF_PARAM, required_argument, NULL, CMD_ZIPF_PARAM_NUM},
                                             {NULL, 0, NULL, 0}};

void config_print_usage(char **argv) {
  char default_traffic_dist_str[15] = "\0";
  switch (DEFAULT_TRAFFIC_DISTRIBUTION) {
  case UNIFORM:
    sprintf(default_traffic_dist_str, "uniform");
    break;
  case ZIPF:
    sprintf(default_traffic_dist_str, "zipf");
    break;
  }

  LOG("Usage:\n"
      "%s [EAL options] --\n"
      "\t[--help]: Show this help and exit\n"
      "\t[--test]: Run test and exit\n"
      "\t[--" CMD_TOTAL_FLOWS "] <#flows>: Total number of flows (default=%" PRIu32 ")\n"
      "\t[--" CMD_PKT_SIZE "] <size>: Packet size (bytes) (default=%" PRIu64 "B)\n"
      "\t--" CMD_TX_PORT " <port>: TX port\n"
      "\t--" CMD_RX_PORT " <port>: RX port\n"
      "\t--" CMD_NUM_TX_CORES " <#cores>: Number of TX cores\n"
      "\t[--" CMD_UNIQUE_FLOWS "]: Flows are unique (default=%s)\n"
      "\t[--" CMD_RANDOM_SEED " <seed>]: random seed (default set by DPDK)\n"
      "\t[--" CMD_MARK_WARMUP_PKTS "]: mark warmup packets with a custom transport protocol (0x%x) (default=%s)\n"
      "\t[--" CMD_DUMP_FLOWS_TO_FILE "]: dump flows to pcap file (default=%s)\n"
      "\t[--" CMD_KVS_MODE "]: enable KVS mode (default=%s)\n"
      "\t[--" CMD_KVS_GET_RATIO " <ratio>]: KVS get ratio (default=%.2f)\n"
      "\t[--" CMD_TRAFFIC_DISTRIBUTION " <dist>]: traffic distribution (default=%s)\n"
      "\t[--" CMD_ZIPF_PARAM " <param>]: Zipf parameter (default=%.2f)\n",
      argv[0], DEFAULT_TOTAL_FLOWS, DEFAULT_PKT_SIZE, DEFAULT_UNIQUE_FLOWS ? "true" : "false", WARMUP_PROTO_ID,
      DEFAULT_MARK_WARMUP_PKTS ? "true" : "false", DEFAULT_DUMP_FLOWS_TO_FILE ? "true" : "false", DEFAULT_KVS_MODE ? "true" : "false",
      DEFAULT_KVS_GET_RATIO, default_traffic_dist_str, DEFAULT_ZIPF_PARAM);
}

static uintmax_t parse_int(const char *str, const char *name, int base) {
  char *temp;
  intmax_t result = strtoimax(str, &temp, base);

  // There's also a weird failure case with overflows, but let's not care
  if (temp == str || *temp != '\0') {
    rte_exit(EXIT_FAILURE, "Error while parsing '%s': %s\n", name, str);
  }

  return result;
}

static double parse_double(const char *str, const char *name) {
  char *temp;
  double result = strtod(str, &temp);

  if (temp == str || *temp != '\0') {
    rte_exit(EXIT_FAILURE, "Error while parsing '%s': %s\n", name, str);
  }

  return result;
}

#define PARSER_ASSERT(cond, fmt, ...)                                                                                                      \
  if (!(cond))                                                                                                                             \
    rte_exit(EXIT_FAILURE, fmt, ##__VA_ARGS__);

void config_init(int argc, char **argv) {
  bool custom_pkt_size = false;

  // Default configuration values
  config.seed                = time(NULL);
  config.test_and_exit       = false;
  config.num_flows           = DEFAULT_TOTAL_FLOWS;
  config.dist                = DEFAULT_TRAFFIC_DISTRIBUTION;
  config.zipf_param          = DEFAULT_ZIPF_PARAM;
  config.force_unique_flows  = DEFAULT_UNIQUE_FLOWS;
  config.pkt_size            = DEFAULT_PKT_SIZE;
  config.warmup_duration     = DEFAULT_WARMUP_DURATION;
  config.warmup_rate         = DEFAULT_WARMUP_RATE;
  config.warmup_active       = false;
  config.mark_warmup_packets = DEFAULT_MARK_WARMUP_PKTS;
  config.dump_flows_to_file  = DEFAULT_DUMP_FLOWS_TO_FILE;
  config.kvs_mode            = DEFAULT_KVS_MODE;
  config.kvs_get_ratio       = DEFAULT_KVS_GET_RATIO;
  config.rx.port             = 0;
  config.tx.port             = 1;
  config.tx.num_cores        = 1;

  // Setup runtime configuration
  config.runtime.running       = false;
  config.runtime.update_cnt    = 0;
  config.runtime.rate_per_core = 0;
  config.runtime.flow_ttl      = 0;

  unsigned nb_devices = rte_eth_dev_count_avail();
  unsigned nb_cores   = rte_lcore_count();

  if (nb_devices < 2) {
    rte_exit(EXIT_FAILURE, "Insufficient number of available devices (%" PRIu16 " detected, but we require at least 2).\n", nb_devices);
  }

  if (nb_cores < 2) {
    rte_exit(EXIT_FAILURE, "Insufficient number of cores (%" PRIu16 " given, but we require at least 2).\n", nb_cores);
  }

  if (argc <= 1) {
    config_print_usage(argv);
    exit(0);
  }

  int opt;
  while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF) {
    switch (opt) {
    case CMD_HELP_NUM: {
      config_print_usage(argv);
      exit(0);
    } break;
    case CMD_TEST_NUM: {
      config.test_and_exit = true;
    } break;
    case CMD_TOTAL_FLOWS_NUM: {
      config.num_flows = parse_int(optarg, CMD_TOTAL_FLOWS, 10);
      PARSER_ASSERT(config.num_flows >= MIN_FLOWS_NUM, "Number of flows must be >= %" PRIu32 " (requested %" PRIu32 ").\n", MIN_FLOWS_NUM,
                    config.num_flows);
    } break;
    case CMD_TRAFFIC_DISTRIBUTION_NUM: {
      if (strcmp(optarg, TRAFFIC_DISTRIBUTION_UNIFORM) == 0) {
        config.dist = UNIFORM;
      } else if (strcmp(optarg, TRAFFIC_DISTRIBUTION_ZIPF) == 0) {
        config.dist = ZIPF;
      } else {
        rte_exit(EXIT_FAILURE, "Invalid traffic distribution: %s\n", optarg);
      }
    } break;
    case CMD_ZIPF_PARAM_NUM: {
      config.zipf_param = parse_double(optarg, CMD_ZIPF_PARAM);
      PARSER_ASSERT(!(config.zipf_param < 0), "Zipf parameter must be >= 0 (requested %.2f).\n", config.zipf_param);
    } break;
    case CMD_UNIQUE_FLOWS_NUM: {
      config.force_unique_flows = true;
    } break;
    case CMD_PKT_SIZE_NUM: {
      config.pkt_size = parse_int(optarg, CMD_PKT_SIZE, 10);
      PARSER_ASSERT(config.pkt_size >= MIN_PKT_SIZE && config.pkt_size <= MAX_PKT_SIZE,
                    "Packet size must be in the interval [%" PRIu64 "-%" PRIu64 "] (requested %" PRIu64 ").\n", MIN_PKT_SIZE, MAX_PKT_SIZE,
                    config.pkt_size);
      custom_pkt_size = true;
    } break;
    case CMD_TX_PORT_NUM: {
      config.tx.port = parse_int(optarg, CMD_TX_PORT, 10);
      PARSER_ASSERT(config.tx.port < nb_devices, "Invalid TX device: requested %" PRIu16 " but only %" PRIu16 " available.\n",
                    config.tx.port, nb_devices);
    } break;
    case CMD_RX_PORT_NUM: {
      config.rx.port = parse_int(optarg, CMD_RX_PORT, 10);
      PARSER_ASSERT(config.rx.port < nb_devices, "Invalid RX device: requested %" PRIu16 " but only %" PRIu16 " available.\n",
                    config.rx.port, nb_devices);
    } break;
    case CMD_NUM_TX_CORES_NUM: {
      config.tx.num_cores = parse_int(optarg, CMD_NUM_TX_CORES, 10);
      PARSER_ASSERT(config.tx.num_cores > 0, "Number of TX cores must be positive (requested %" PRIu16 ").\n", config.tx.num_cores);
    } break;
    case CMD_RANDOM_SEED_NUM: {
      config.seed = parse_int(optarg, CMD_RANDOM_SEED, 10);
    } break;
    case CMD_MARK_WARMUP_PKTS_NUM: {
      config.mark_warmup_packets = true;
    } break;
    case CMD_DUMP_FLOWS_TO_FILE_NUM: {
      config.dump_flows_to_file = true;
    } break;
    case CMD_KVS_MODE_NUM: {
      config.kvs_mode = true;
    } break;
    case CMD_KVS_GET_RATIO_NUM: {
      config.kvs_get_ratio = parse_double(optarg, CMD_KVS_GET_RATIO);
      PARSER_ASSERT(config.kvs_get_ratio >= 0.0 && config.kvs_get_ratio <= 1.0,
                    "KVS get ratio must be in the interval [0.0-1.0] (requested %lf).\n", config.kvs_get_ratio);
    } break;
    default:
      rte_exit(EXIT_FAILURE, "Unknown option %c\n", opt);
    }
  }

  rte_srand(config.seed);

  PARSER_ASSERT(config.tx.num_cores < nb_cores, "Insufficient number of cores (main=1, tx=%" PRIu16 ", available=%" PRIu16 ").\n",
                config.tx.num_cores, nb_cores);

  PARSER_ASSERT(config.num_flows >= config.tx.num_cores, "Too many cores (%" PRIu16 ") for the requested number of flows (%" PRIu32 ").\n",
                config.tx.num_cores, config.num_flows);

  if (config.kvs_mode) {
    if (custom_pkt_size) {
      WARNING("*************************************************************************");
      WARNING("Packet size is set to %" PRIu64 " bytes, but KVS mode requires a packet size of %" PRIu64 " bytes. ", config.pkt_size,
              KVS_PKT_SIZE_BYTES);
      WARNING("Overriding packet size to %" PRIu64 " bytes.", KVS_PKT_SIZE_BYTES);
      WARNING("*************************************************************************");
    }
    config.pkt_size = MAX(KVS_PKT_SIZE_BYTES, MIN_PKT_SIZE);
  }

  unsigned idx = 0;
  unsigned lcore_id;
  RTE_LCORE_FOREACH_WORKER(lcore_id) { config.tx.cores[idx++] = lcore_id; }

  // Reset getopt
  optind = 1;
}

void config_print() {
  char traffic_dist_str[15] = "\0";
  switch (config.dist) {
  case UNIFORM:
    sprintf(traffic_dist_str, "uniform");
    break;
  case ZIPF:
    sprintf(traffic_dist_str, "zipf");
    break;
  }

  LOG("\n----- Config -----");
  LOG("RX port:          %" PRIu16, config.rx.port);
  LOG("TX port:          %" PRIu16, config.tx.port);
  LOG("TX cores:         %" PRIu16, config.tx.num_cores);
  LOG("Random seed:      %" PRIu64 "", config.seed);
  LOG("Flows:            %" PRIu16 "", config.num_flows);
  LOG("Traffic dist:     %s", traffic_dist_str);
  LOG("Zipf param:       %lf", config.zipf_param);
  LOG("Unique flows:     %s", config.force_unique_flows ? "true" : "false");
  LOG("Packet size:      %" PRIu64 " bytes", config.pkt_size);
  LOG("Mark warmup pkts: %d", config.mark_warmup_packets);
  LOG("Dump flows:       %d", config.dump_flows_to_file);
  LOG("KVS mode:         %d", config.kvs_mode);
  LOG("KVS get ratio:    %lf", config.kvs_get_ratio);
  LOG("------------------\n");
}
