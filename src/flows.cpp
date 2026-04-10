#include "flows.h"

#include <rte_common.h>
#include <rte_random.h>

#include <iostream>
#include <sstream>
#include <unordered_set>
#include <vector>
#include <iomanip>
#include <cmath>
#include <unordered_map>
#include <algorithm>

#include "log.h"
#include "random.h"
#include "config.h"
#include "pcap_reader.h"

std::vector<flow_t> flows;
std::unordered_map<flow_t, uint64_t, flow_hash_t, flow_comp_t> flow_to_idx;
std::vector<uint64_t> flow_idx_seq;

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

void generate_flows() {
  std::unordered_set<flow_t, flow_hash_t, flow_comp_t> flows_set;

  if (!config.pcap_fname.empty()) {
    LOG("PCAP file specified, reading from pcap");

    uint64_t pkt_counter = 0;
    pcap_reader_t reader(config.pcap_fname);
    packet_t packet;
    while (reader.read_next_packet(packet)) {
      pkt_counter++;
      if (pkt_counter % 10000 == 0) {
        LOG_REWRITE("Reading pcap file: %lu packets, %zu unique flows", pkt_counter, flows.size());
      }

      if (packet.flow.has_value()) {
        const flow_t &flow = packet.flow.value();
        if (flows_set.find(flow) == flows_set.end()) {
          flow_to_idx[flow] = flows.size();
          flows.push_back(flow);
          flows_set.insert(flow);
        }
        flow_idx_seq.push_back(flow_to_idx[flow]);
      }
    }
    LOG("Finished reading pcap file: %lu packets, %zu unique flows, %zu index entries.", pkt_counter, flows.size(), flow_idx_seq.size());

    return;
  }

  flows.resize(config.num_flows);

  LOG("Generating %u flows...", config.num_flows);

  // Super fast
  if (!config.force_unique_flows) {
    for (size_t i = 0; i < flows.size(); i++) {
      flows[i]              = generate_random_flow();
      flow_to_idx[flows[i]] = i;
    }
    return;
  }

  while (flows_set.size() != config.num_flows) {
    const flow_t flow = generate_random_flow();

    // Already generated. Unlikely, but we still check...
    if (flows_set.find(flow) != flows_set.end()) {
      continue;
    }

    const size_t idx  = flows_set.size();
    flows[idx]        = flow;
    flow_to_idx[flow] = idx;
    flows_set.insert(flow);
  }
}

void randomize_flow(uint64_t flow_idx) {
  assert(flow_idx < flows.size() && "Invalid flow index");
  flows[flow_idx] = generate_random_flow();
}

const std::vector<flow_t> &get_generated_flows() { return flows; }

void generate_flow_idx_sequence() {
  // Already populated during generate_flows() when reading from a PCAP file.
  if (config.pcap_fname.empty()) {
    LOG("Generating distribution of flow indexes...");
    switch (config.dist) {
    case UNIFORM:
      flow_idx_seq = generate_uniform_flow_idx_sequence(config.num_flows);
      break;
    case ZIPF:
      flow_idx_seq = generate_zipf_flow_idx_sequence(config.num_flows, config.zipf_param);
      break;
    }
  }

  if (config.logical_batch_size.has_value()) {
    const size_t logical_batch_size = config.logical_batch_size.value();
    LOG("Sorting flow index sequence in logical batches of %zu...", logical_batch_size);
    for (size_t i = 0; i < flow_idx_seq.size(); i += logical_batch_size) {
      size_t current_batch_size = std::min(logical_batch_size, flow_idx_seq.size() - i);
      std::sort(flow_idx_seq.begin() + i, flow_idx_seq.begin() + i + current_batch_size);
    }
  }
}

std::vector<std::vector<uint64_t>> generate_flow_idx_sequence_per_worker() {
  LOG("Distributing flow indexes per worker...");
  std::vector<std::vector<uint64_t>> flow_idx_seq_per_worker(config.tx.num_cores);

  // Distribute round-robin, repeating the sequence if there are fewer flows
  // than workers to ensure every worker gets at least one entry.
  size_t total_entries = std::max(flow_idx_seq.size(), (size_t)config.tx.num_cores);
  uint16_t worker_id   = 0;
  for (size_t i = 0; i < total_entries; i++) {
    flow_idx_seq_per_worker[worker_id].push_back(flow_idx_seq[i % flow_idx_seq.size()]);
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

    ss << " (";
    ss << std::hex << std::setw(8) << std::setfill('0') << (int)rte_bswap32(flow.src_ip);
    ss << ":";
    ss << std::hex << std::setw(4) << std::setfill('0') << (int)rte_bswap16(flow.src_port);
    ss << " -> ";
    ss << std::hex << std::setw(8) << std::setfill('0') << (int)rte_bswap32(flow.dst_ip);
    ss << ":";
    ss << std::hex << std::setw(4) << std::setfill('0') << (int)rte_bswap16(flow.dst_port);
    ss << ")";
  }

  return ss.str();
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
  std::vector<std::vector<enum kvs_op>> kvs_ops_per_flow(flows.size());

  const struct kvs_ratio_t ratio = calculate_kvs_ratio();

  for (size_t flow_idx = 0; flow_idx < kvs_ops_per_flow.size(); flow_idx++) {
    for (uint64_t i = 0; i < ratio.put; i++) {
      kvs_ops_per_flow[flow_idx].push_back(KVS_OP_PUT);
    }
    for (uint64_t i = 0; i < ratio.get; i++) {
      kvs_ops_per_flow[flow_idx].push_back(KVS_OP_GET);
    }
  }

  return kvs_ops_per_flow;
}

void cmd_flows_display() {
  LOG();
  LOG("~~~~~~ %u flows ~~~~~~", config.num_flows);

  for (const flow_t &flow : flows) {
    LOG("%s", flow_to_string(flow).c_str());
  }
}

void cmd_dist_display() {
  LOG();
  LOG("~~~~~~ Traffic distribution ~~~~~~");

  std::unordered_map<uint64_t, uint64_t> flow_idx_seq_count(config.num_flows);
  uint64_t total_count = 0;

  for (uint64_t flow_idx : flow_idx_seq) {
    if (flow_idx_seq_count.find(flow_idx) == flow_idx_seq_count.end()) {
      flow_idx_seq_count[flow_idx] = 0;
    }
    flow_idx_seq_count[flow_idx]++;
    total_count++;
  }

  // Sort by count
  std::vector<uint64_t> counts(flow_idx_seq_count.size());
  for (const auto &pair : flow_idx_seq_count) {
    counts[pair.first] = pair.second;
  }
  std::sort(counts.begin(), counts.end(), std::greater<uint64_t>());

  // Build a CDF
  std::vector<double> cdf;
  double cumulative_count = 0.0;
  for (const auto &count : counts) {
    cumulative_count += count;
    cdf.push_back(cumulative_count / total_count);
  }

  // Showing the CDF in 10% increments
  double last_cdf_value = 0.0;
  for (size_t i = 0; i < cdf.size(); i++) {
    if (i == 0 || cdf[i] >= last_cdf_value + 0.1 || i == cdf.size() - 1) {
      const uint64_t flows          = i + 1;
      const double flows_percentage = (static_cast<double>(flows) / (config.num_flows / 2)) * 100.0;
      const double cdf_value        = cdf[i];
      LOG("%8lu %7.2f%% : %7.2f%%", flows, flows_percentage, cdf_value * 100.0);
      last_cdf_value = cdf_value;
    }
  }
}