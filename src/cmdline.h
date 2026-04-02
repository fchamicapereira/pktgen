#pragma once

#include "types.h"

struct runtime_config_t {
  bool running;
  uint64_t update_cnt;

  // Information for each TX worker
  rate_gbps_t rate_per_core;
  time_ns_t flow_ttl;
};

void cmdline_start();
void cmd_binsearch();
void cmd_start();
void cmd_stop();
void cmd_rate(rate_gbps_t rate);
void cmd_churn(churn_fpm_t churn);
void cmd_timer(time_s_t time);

extern struct runtime_config_t runtime_config;
