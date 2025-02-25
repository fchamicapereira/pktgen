#include "flows.h"

#include <rte_common.h>
#include <rte_random.h>

#include <sstream>
#include <unordered_set>
#include <vector>

#include "log.h"
#include "pktgen.h"

std::vector<std::vector<flow_t>> flows_per_worker;

static flow_t generate_random_flow() {
  flow_t flow;

  if (config.kvs_mode) {
    for (size_t i = 0; i < KEY_SIZE_BYTES; i++) {
      flow.kvs.key[i] = (uint8_t)(rand() & 0xff);
    }
    for (size_t i = 0; i < MAX_VALUE_SIZE_BYTES; i++) {
      flow.kvs.value[i] = (uint8_t)(rand() & 0xff);
    }
  } else {
    flow.common.src_ip   = (rte_be32_t)(rand() & 0xffffffff);
    flow.common.dst_ip   = (rte_be32_t)(rand() & 0xffffffff);
    flow.common.src_port = (rte_be16_t)(rand() & 0xffff);
    flow.common.dst_port = (rte_be16_t)(rand() & 0xffff);
  }

  return flow;
}

struct flow_hash_t {
  size_t operator()(const flow_t &flow) const {
    if (config.kvs_mode) {
      size_t hash = 0;
      for (size_t i = 0; i < KEY_SIZE_BYTES; i++) {
        hash ^= std::hash<int>()(flow.kvs.key[i]);
      }
      return hash;
    } else {
      size_t hash = std::hash<int>()(flow.common.src_ip);
      hash ^= std::hash<int>()(flow.common.dst_ip);
      hash ^= std::hash<int>()(flow.common.src_port);
      hash ^= std::hash<int>()(flow.common.dst_port);
      return hash;
    }
  }
};

struct flow_comp_t {
  bool operator()(const flow_t &f1, const flow_t &f2) const {
    if (config.kvs_mode) {
      for (size_t i = 0; i < KEY_SIZE_BYTES; i++) {
        if (f1.kvs.key[i] != f2.kvs.key[i]) {
          return false;
        }
      }
      return true;
    } else {
      return f1.common.src_ip == f2.common.src_ip && f1.common.dst_ip == f2.common.dst_ip && f1.common.src_port == f2.common.src_port &&
             f1.common.dst_port == f2.common.dst_port;
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
      crc32_t crc = calculate_crc32((byte_t *)&flow, config.kvs_mode ? sizeof(flow.kvs) : sizeof(flow.common)) & crc_mask;

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
          ss << std::hex << (int)flow.kvs.key[i];
        }
        LOG("0x%s", ss.str().c_str());
      } else {
        LOG("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u", (flow.common.src_ip >> 0) & 0xff, (flow.common.src_ip >> 8) & 0xff,
            (flow.common.src_ip >> 16) & 0xff, (flow.common.src_ip >> 24) & 0xff, rte_bswap16(flow.common.src_port),
            (flow.common.dst_ip >> 0) & 0xff, (flow.common.dst_ip >> 8) & 0xff, (flow.common.dst_ip >> 16) & 0xff,
            (flow.common.dst_ip >> 24) & 0xff, rte_bswap16(flow.common.dst_port));
      }
    }
  }
}
