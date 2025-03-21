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

  int progress      = 0;
  int last_progress = 0;

  for (uint32_t i = 0; i < num_flows; i++) {
    flow_idx_sequence[i] = i;

    progress = 100 * (i + 1) / num_flows;
    if (progress != last_progress) {
      last_progress = progress;
      LOG_REWRITE("Generating uniform distribution: %d%%", progress);
    }
  }

  LOG();

  return flow_idx_sequence;
}

inline std::vector<uint32_t> generate_zipf_flow_idx_sequence(uint32_t num_flows, double zipf_param) {
  std::unordered_set<uint32_t> used_flow_idxs;
  std::vector<uint32_t> flow_idx_sequence;

  if (zipf_param == 0 || zipf_param == 1) {
    const double epsilon = 1e-6;
    LOG("WARNING: Incompatible zipf parameter of %lf, adding epsilon=%le", zipf_param, epsilon);
    zipf_param += epsilon;
  }

  int progress      = 0;
  int last_progress = 0;

  while (used_flow_idxs.size() < num_flows) {
    const uint32_t flow_idx = zipf_random_number_generator(num_flows, zipf_param);
    used_flow_idxs.insert(flow_idx);
    flow_idx_sequence.push_back(flow_idx);

    progress = 100 * used_flow_idxs.size() / num_flows;
    if (progress != last_progress) {
      last_progress = progress;
      LOG_REWRITE("Generating zipfian distribution: %d%%", progress);
    }

    if (flow_idx_sequence.size() >= 1000 * num_flows) {
      break;
    }
  }

  LOG();
  if (used_flow_idxs.size() != num_flows) {
    LOG("WARNING: Zipfian distribution is taking too long to generate. Using just %lu flows (%.2f%%).", used_flow_idxs.size(),
        100.0 * used_flow_idxs.size() / num_flows);
    return flow_idx_sequence;
  }

  return flow_idx_sequence;
}
