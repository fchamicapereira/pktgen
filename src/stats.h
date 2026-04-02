#pragma once

#include <stdint.h>

void cmd_stats_display();
void cmd_stats_display_compact();
void cmd_stats_reset();

struct stats_t {
  uint64_t rx_pkts;
  uint64_t rx_bytes;
  uint64_t tx_pkts;
  uint64_t tx_bytes;
};

struct stats_t get_stats();
