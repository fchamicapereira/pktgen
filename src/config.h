#pragma once

#include "types.h"

#include <string>
#include <rte_lcore.h>
#include <pcap.h>

struct config_t {
  bool test_and_exit;
  bool dump_flows_to_file;

  uint64_t seed;
  uint32_t num_flows;
  enum traffic_dist_t dist;
  double zipf_param;
  bool force_unique_flows;
  bytes_t pkt_size;
  std::string pcap_fname;

  bool sync_cores;
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
};

extern struct config_t config;

void config_init(int argc, char **argv);
void config_print();
void config_print_usage(char **argv);
