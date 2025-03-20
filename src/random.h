#pragma once

#include <vector>
#include <cmath>
#include <cassert>
#include <unordered_set>

#include <rte_random.h>

#include "log.h"

// From Castan [SIGCOMM'18]
// Source:
// https://github.com/nal-epfl/castan/blob/master/scripts/pcap_tools/create_zipfian_distribution_pcap.py
inline uint64_t zipf_random_number_generator(uint32_t total_flows, double zipf_param) {
  assert(zipf_param != 1.0 && "Invalid zipf_param");

  const double probability = rte_drand();
  assert(probability >= 0 && probability <= 1 && "Invalid probability");

  const double p         = probability;
  const uint64_t N       = total_flows + 1;
  const double s         = zipf_param;
  const double tolerance = 0.01;
  double x               = (double)N / 2.0;

  const double D = p * (12.0 * (pow(N, 1.0 - s) - 1) / (1.0 - s) + 6.0 - 6.0 * pow(N, -s) + s - pow(N, -1.0 - s) * s);

  while (true) {
    const double m    = pow(x, -2 - s);
    const double mx   = m * x;
    const double mxx  = mx * x;
    const double mxxx = mxx * x;

    const double a    = 12.0 * (mxxx - 1) / (1.0 - s) + 6.0 * (1.0 - mxx) + (s - (mx * s)) - D;
    const double b    = 12.0 * mxx + 6.0 * (s * mx) + (m * s * (s + 1.0));
    const double newx = std::max(1.0, x - a / b);

    if (std::abs(newx - x) <= tolerance) {
      const uint64_t i = newx - 1;
      assert(i < total_flows && "Invalid index");
      return i;
    }

    x = newx;
  }
}

inline std::vector<uint32_t> generate_uniform_flow_idx_sequence(uint32_t num_flows) {
  std::vector<uint32_t> flow_idx_sequence(num_flows);
  for (uint32_t i = 0; i < num_flows; i++) {
    flow_idx_sequence[i] = i;
  }
  return flow_idx_sequence;
}

inline std::vector<uint32_t> generate_zipf_flow_idx_sequence(uint32_t num_flows, double zipf_param) {
  std::unordered_set<uint32_t> used_flow_idxs;
  std::vector<uint32_t> flow_idx_sequence;

  if (zipf_param == 0 || zipf_param == 1) {
    const double epsilon = 1e-12;
    LOG("WARNING: Incompatible zipf parameter of %lf, adding epsilon=%le", zipf_param, epsilon);
    zipf_param += epsilon;
  }

  while (used_flow_idxs.size() < num_flows) {
    const uint32_t flow_idx = zipf_random_number_generator(num_flows, zipf_param);
    used_flow_idxs.insert(flow_idx);
    flow_idx_sequence.push_back(flow_idx);
  }
  return flow_idx_sequence;
}
