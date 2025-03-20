#ifndef PKTGEN_SRC_FLOWS_H_
#define PKTGEN_SRC_FLOWS_H_

#include <vector>
#include <string>

#include "pktgen.h"

struct flow_t {
  rte_be32_t src_ip;
  rte_be32_t dst_ip;
  rte_be16_t src_port;
  rte_be16_t dst_port;
  kv_key_t kvs_key;
  kv_value_t kvs_value;
};

std::string flow_to_string(const flow_t &flow);
void generate_unique_flows();
const std::vector<flow_t> &get_generated_flows();
std::vector<std::vector<uint32_t>> generate_flow_idx_sequence_per_worker();

void generate_unique_flows_per_worker();
const std::vector<flow_t> &get_worker_flows(unsigned worker_id);

#endif