#pragma once

#include "types.h"
#include "config.h"

#include <vector>
#include <string>

#include <rte_byteorder.h>

struct flow_t {
  rte_be32_t src_ip;
  rte_be32_t dst_ip;
  rte_be16_t src_port;
  rte_be16_t dst_port;
  kv_key_t kvs_key;
  kv_value_t kvs_value;
};

struct flow_hash_t {
  size_t operator()(const flow_t &flow) const {
    if (config.kvs_mode) {
      size_t hash = 0;
      for (size_t i = 0; i < KEY_SIZE_BYTES; i++) {
        hash ^= std::hash<int>()(flow.kvs_key[i]);
      }
      return hash;
    } else {
      size_t hash = std::hash<int>()(flow.src_ip);
      hash ^= std::hash<int>()(flow.dst_ip);
      hash ^= std::hash<int>()(flow.src_port);
      hash ^= std::hash<int>()(flow.dst_port);
      return hash;
    }
  }
};

struct flow_comp_t {
  bool operator()(const flow_t &f1, const flow_t &f2) const {
    if (config.kvs_mode) {
      for (size_t i = 0; i < KEY_SIZE_BYTES; i++) {
        if (f1.kvs_key[i] != f2.kvs_key[i]) {
          return false;
        }
      }
      return true;
    } else {
      return f1.src_ip == f2.src_ip && f1.dst_ip == f2.dst_ip && f1.src_port == f2.src_port && f1.dst_port == f2.dst_port;
    }
  };
};

extern std::vector<flow_t> flows;
extern std::vector<uint64_t> flow_idx_seq;

std::string flow_to_string(const flow_t &flow);
void generate_flows();
const std::vector<flow_t> &get_generated_flows();
void generate_flow_idx_sequence();
std::vector<std::vector<uint64_t>> generate_flow_idx_sequence_per_worker();
void randomize_flow(uint64_t flow_idx);

void generate_unique_flows_per_worker();
const std::vector<flow_t> &get_worker_flows(unsigned worker_id);

std::vector<std::vector<enum kvs_op>> generate_kvs_ops_per_flow();

void cmd_flows_display();
void cmd_dist_display();
