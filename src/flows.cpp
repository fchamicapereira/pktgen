#include "flows.h"

#include <rte_common.h>
#include <rte_random.h>

#include <sstream>
#include <unordered_set>
#include <vector>
#include <iomanip>
#include <cmath>

#include "log.h"
#include "pktgen.h"
#include "random.h"

std::vector<flow_t> flows;

static flow_t generate_random_flow() {
  flow_t flow;

  flow.src_ip   = (rte_be32_t)(rte_rand() & 0xffffffff);
  flow.dst_ip   = (rte_be32_t)(rte_rand() & 0xffffffff);
  flow.src_port = (rte_be16_t)(rte_rand() & 0xffff);
  flow.dst_port = (rte_be16_t)(rte_rand() & 0xffff);

  for (size_t i = 0; i < KEY_SIZE_BYTES; i++) {
    flow.kvs_key[i] = (uint8_t)(rte_rand() & 0xff);
  }
  for (size_t i = 0; i < MAX_VALUE_SIZE_BYTES; i++) {
    flow.kvs_value[i] = (uint8_t)(rte_rand() & 0xff);
  }

  return flow;
}

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

void generate_unique_flows() {
  flows = std::vector<flow_t>(config.num_flows);

  std::unordered_set<flow_t, flow_hash_t, flow_comp_t> flows_set;
  std::unordered_set<crc32_t> flows_crc;

  const uint32_t crc_mask = (uint32_t)((1 << (uint64_t)(config.crc_bits)) - 1);

  LOG("Generating %u flows...", config.num_flows);

  while (flows_set.size() != config.num_flows) {
    const flow_t flow = generate_random_flow();

    // Already generated. Unlikely, but we still check...
    if (flows_set.find(flow) != flows_set.end()) {
      continue;
    }

    if (config.crc_unique_flows) {
      const int len     = config.kvs_mode ? sizeof(flow.kvs_key) + sizeof(flow.kvs_value)
                                          : sizeof(flow.src_ip) + sizeof(flow.dst_ip) + sizeof(flow.src_port) + sizeof(flow.dst_port);
      const crc32_t crc = calculate_crc32((byte_t *)&flow, len) & crc_mask;

      // Although the flow is unique, its masked CRC is not.
      if (flows_crc.find(crc) != flows_crc.end()) {
        continue;
      }

      // We're good.
      flows_crc.insert(crc);
    }

    const size_t idx = flows_set.size();
    flows[idx]       = flow;
    flows_set.insert(flow);
  }
}

const std::vector<flow_t> &get_generated_flows() { return flows; }

std::vector<std::vector<uint32_t>> generate_flow_idx_sequence_per_worker() {
  const size_t num_base_flows = config.num_flows / 2;

  LOG("Generating distribution of flow indexes...");
  std::vector<uint32_t> flow_idx_seq;
  switch (config.dist) {
  case UNIFORM:
    flow_idx_seq = generate_uniform_flow_idx_sequence(num_base_flows);
    break;
  case ZIPF:
    flow_idx_seq = generate_zipf_flow_idx_sequence(num_base_flows, config.zipf_param);
    break;
  }

  LOG("Distributing flow indexes per worker...");
  std::vector<std::vector<uint32_t>> flow_idx_seq_per_worker(config.tx.num_cores);

  uint16_t worker_id = 0;
  for (size_t i = 0; i < flow_idx_seq.size(); i++) {
    flow_idx_seq_per_worker[worker_id].push_back(flow_idx_seq[i]);
    worker_id = (worker_id + 1) % config.tx.num_cores;
  }

  return flow_idx_seq_per_worker;
}

std::string flow_to_string(const flow_t &flow) {
  std::stringstream ss;

  if (config.kvs_mode) {
    ss << "0x";
    for (size_t i = 0; i < KEY_SIZE_BYTES; i++) {
      ss << std::hex << std::setw(2) << std::setfill('0') << (int)flow.kvs_key[i];
    }
  } else {
    ss << std::dec;

    ss << ((flow.src_ip >> 0) & 0xff);
    ss << ".";
    ss << ((flow.src_ip >> 8) & 0xff);
    ss << ".";
    ss << ((flow.src_ip >> 16) & 0xff);
    ss << ".";
    ss << ((flow.src_ip >> 24) & 0xff);
    ss << ":";
    ss << rte_bswap16(flow.src_port);
    ss << " -> ";
    ss << ((flow.dst_ip >> 0) & 0xff);
    ss << ".";
    ss << ((flow.dst_ip >> 8) & 0xff);
    ss << ".";
    ss << ((flow.dst_ip >> 16) & 0xff);
    ss << ".";
    ss << ((flow.dst_ip >> 24) & 0xff);
    ss << ":";
    ss << rte_bswap16(flow.dst_port);
  }

  return ss.str();
}

void cmd_flows_display() {
  LOG();
  LOG("~~~~~~ %u flows ~~~~~~", config.num_flows);

  for (const flow_t &flow : flows) {
    LOG("%s", flow_to_string(flow).c_str());
  }
}

struct kvs_ratio_t {
  uint64_t get;
  uint64_t put;
};

static struct kvs_ratio_t calculate_kvs_ratio() {
  double get_ratio         = config.kvs_get_ratio;
  struct kvs_ratio_t ratio = {.get = 0, .put = 0};

  uint64_t total = 1;

  double lhs = -1;
  while (std::modf(get_ratio, &lhs) != 0) {
    total *= 10;
    get_ratio *= 10;
  }

  ratio.get = static_cast<uint64_t>(get_ratio);
  ratio.put = total - ratio.get;

  assert(ratio.get + ratio.put > 0 && "Invalid KVS ratio");

  return ratio;
}

std::vector<std::vector<enum kvs_op>> generate_kvs_ops_per_flow() {
  const size_t num_base_flows = config.num_flows / 2;
  std::vector<std::vector<enum kvs_op>> kvs_ops_per_flow(num_base_flows);

  const struct kvs_ratio_t ratio = calculate_kvs_ratio();

  for (size_t flow_idx = 0; flow_idx < kvs_ops_per_flow.size(); flow_idx++) {
    for (uint64_t i = 0; i < ratio.get; i++) {
      kvs_ops_per_flow[flow_idx].push_back(KVS_OP_GET);
    }
    for (uint64_t i = 0; i < ratio.put; i++) {
      kvs_ops_per_flow[flow_idx].push_back(KVS_OP_PUT);
    }
  }

  return kvs_ops_per_flow;
}
