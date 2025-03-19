#include "flows.h"

#include <rte_common.h>
#include <rte_random.h>

#include <sstream>
#include <unordered_set>
#include <vector>
#include <iomanip>

#include "log.h"
#include "pktgen.h"

std::vector<std::vector<flow_t>> flows_per_worker;

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

void generate_unique_flows_per_worker() {
  flows_per_worker = std::vector<std::vector<flow_t>>(config.tx.num_cores);

  std::unordered_set<flow_t, flow_hash_t, flow_comp_t> flows_set;
  std::unordered_set<crc32_t> flows_crc;
  int worker_idx = 0;

  uint32_t crc_mask = (uint32_t)((1 << (uint64_t)(config.crc_bits)) - 1);

  LOG("Generating %d flows...", config.num_flows);

  while (flows_set.size() != config.num_flows) {
    flow_t flow = generate_random_flow();

    // Already generated. Unlikely, but we still check...
    if (flows_set.find(flow) != flows_set.end()) {
      continue;
    }

    if (config.crc_unique_flows) {
      const int len = config.kvs_mode ? sizeof(flow.kvs_key) + sizeof(flow.kvs_value)
                                      : sizeof(flow.src_ip) + sizeof(flow.dst_ip) + sizeof(flow.src_port) + sizeof(flow.dst_port);
      crc32_t crc   = calculate_crc32((byte_t *)&flow, len) & crc_mask;

      // Although the flow is unique, its masked CRC is not.
      if (flows_crc.find(crc) != flows_crc.end()) {
        continue;
      }

      // We're good.
      flows_crc.insert(crc);
    }

    flows_set.insert(flow);
    flows_per_worker[worker_idx].push_back(flow);

    // Every worker should only see an even number of flows.
    if (flows_set.size() % 2 == 0) {
      worker_idx = (worker_idx + 1) % config.tx.num_cores;
    }
  }
}

const std::vector<flow_t> &get_worker_flows(unsigned worker_id) { return flows_per_worker[worker_id]; }

void cmd_flows_display() {
  LOG();
  LOG("~~~~~~ %u flows ~~~~~~", config.num_flows);

  for (const std::vector<flow_t> &flows : flows_per_worker) {
    for (const flow_t &flow : flows) {
      if (config.kvs_mode) {
        std::stringstream ss;
        for (size_t i = 0; i < KEY_SIZE_BYTES; i++) {
          ss << std::hex << std::setw(2) << std::setfill('0') << (int)flow.kvs_key[i];
        }
        LOG("0x%s", ss.str().c_str());
      } else {
        LOG("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (%08x:%04x -> %08x:%04x)", (flow.src_ip >> 0) & 0xff, (flow.src_ip >> 8) & 0xff,
            (flow.src_ip >> 16) & 0xff, (flow.src_ip >> 24) & 0xff, rte_bswap16(flow.src_port), (flow.dst_ip >> 0) & 0xff,
            (flow.dst_ip >> 8) & 0xff, (flow.dst_ip >> 16) & 0xff, (flow.dst_ip >> 24) & 0xff, rte_bswap16(flow.dst_port), flow.src_ip,
            flow.src_port, flow.dst_ip, flow.dst_port);
      }
    }
  }
}
