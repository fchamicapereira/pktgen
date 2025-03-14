#pragma once

#include <vector>
#include <cmath>
#include <cassert>
#include <unordered_set>

#include <rte_random.h>

// From Castan [SIGCOMM'18]
// Source:
// https://github.com/nal-epfl/castan/blob/master/scripts/pcap_tools/create_zipfian_distribution_pcap.py
uint64_t zipf_random_number_generator(double zipf_param, uint32_t total_flows) {
  double probability = rte_drand();
  assert(probability >= 0 && probability <= 1 && "Invalid probability");

  double p         = probability;
  uint64_t N       = total_flows + 1;
  double s         = zipf_param;
  double tolerance = 0.01;
  double x         = (double)N / 2.0;

  double D = p * (12.0 * (pow(N, 1.0 - s) - 1) / (1.0 - s) + 6.0 - 6.0 * pow(N, -s) + s - pow(N, -1.0 - s) * s);

  while (true) {
    double m    = pow(x, -2 - s);
    double mx   = m * x;
    double mxx  = mx * x;
    double mxxx = mxx * x;

    double a    = 12.0 * (mxxx - 1) / (1.0 - s) + 6.0 * (1.0 - mxx) + (s - (mx * s)) - D;
    double b    = 12.0 * mxx + 6.0 * (s * mx) + (m * s * (s + 1.0));
    double newx = std::max(1.0, x - a / b);

    if (std::abs(newx - x) <= tolerance) {
      uint64_t i = newx - 1;
      assert(i < total_flows && "Invalid index");
      return i;
    }

    x = newx;
  }
}

std::vector<uint32_t> generate_uniform_flow_idx_sequence(uint32_t num_flows) {
  std::vector<uint32_t> flow_idx_sequence(num_flows);
  for (uint32_t i = 0; i < num_flows; i++) {
    flow_idx_sequence[i] = i;
  }
  return flow_idx_sequence;
}

std::vector<uint32_t> generate_zipf_flow_idx_sequence(uint32_t num_flows, double zipf_param) {
  std::unordered_set<uint32_t> used_flow_idxs;
  std::vector<uint32_t> flow_idx_sequence;
  while (used_flow_idxs.size() < num_flows) {
    uint32_t flow_idx = zipf_random_number_generator(zipf_param, num_flows);
    used_flow_idxs.insert(flow_idx);
    flow_idx_sequence.push_back(flow_idx);
  }
  return flow_idx_sequence;
}
