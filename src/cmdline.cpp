#include "clock.h"
#include "log.h"
#include "cmdline.h"
#include "stats.h"
#include "config.h"
#include "flows.h"

#include <cmdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>

#include <rte_atomic.h>
#include <rte_ethdev.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <unordered_map>

#define BIN_SEARCH_WARMUP_RATE_Mbps 1000 /* 1 Gbps */
#define BIN_SEARCH_IT_STEPS 10
#define BIN_SEARCH_MIN_RATE_Mbps 1      /* 1 Mbps */
#define BIN_SEARCH_MAX_RATE_Mbps 100000 /* 100 Gbps */
#define BIN_SEARCH_IT_DURATION_S 10
#define BIN_SEARCH_WARMUP_DURATION_S 5
#define BIN_SEARCH_LOSS_THRESHOLD 0.001 /* 0.1% */

struct runtime_config_t runtime_config;

#define CMDLINE_PARSE_INT_NTOKENS(NTOKENS)                                                                                                 \
  struct {                                                                                                                                 \
    void (*f)(void *, struct cmdline *, void *);                                                                                           \
    void *data;                                                                                                                            \
    const char *help_str;                                                                                                                  \
    cmdline_parse_token_hdr_t *tokens[(NTOKENS) + 1];                                                                                      \
  }

struct cmd_get_params {
  cmdline_fixed_string_t cmd;
};
struct cmd_int_params {
  cmdline_fixed_string_t cmd;
  uint32_t param;
};
struct cmd_intint_params {
  cmdline_fixed_string_t cmd;
  uint32_t param1;
  uint32_t param2;
};

#define INIT_PARAMETERLESS_COMMAND(var, cmd, str)                                                                                          \
  cmdline_parse_token_string_t(var) = TOKEN_STRING_INITIALIZER(struct cmd_get_params, cmd, (str));

#define INIT_INT_COMMAND(var, cmd, str) cmdline_parse_token_string_t(var) = TOKEN_STRING_INITIALIZER(struct cmd_int_params, cmd, (str));

/* Parameter-less commands */
INIT_PARAMETERLESS_COMMAND(cmd_quit_token_cmd, cmd, "quit");
INIT_PARAMETERLESS_COMMAND(cmd_start_token_cmd, cmd, "start");
INIT_PARAMETERLESS_COMMAND(cmd_stop_token_cmd, cmd, "stop");
INIT_PARAMETERLESS_COMMAND(cmd_stats_token_cmd, cmd, "stats");
INIT_PARAMETERLESS_COMMAND(cmd_stats_reset_token_cmd, cmd, "reset");
INIT_PARAMETERLESS_COMMAND(cmd_bench_token_cmd, cmd, "bench");
INIT_PARAMETERLESS_COMMAND(cmd_flows_token_cmd, cmd, "flows");
INIT_PARAMETERLESS_COMMAND(cmd_dist_token_cmd, cmd, "dist");

/* Commands taking just an int */
INIT_INT_COMMAND(cmd_rate_token_cmd, cmd, "rate")
INIT_INT_COMMAND(cmd_churn_token_cmd, cmd, "churn")
INIT_INT_COMMAND(cmd_run_token_cmd, cmd, "run")

cmdline_parse_token_num_t cmd_int_token_param = TOKEN_NUM_INITIALIZER(struct cmd_int_params, param, RTE_UINT32);

static inline void signal_new_config() {
  rte_smp_mb();
  rte_atomic64_inc((rte_atomic64_t *)&runtime_config.update_cnt);
}

void cmd_start() {
  runtime_config.running = true;
  signal_new_config();
}

void cmd_stop() {
  runtime_config.running = false;
  signal_new_config();
}

void cmd_rate(rate_gbps_t rate) {
  config.rate                  = rate;
  runtime_config.rate_per_core = config.rate / config.tx.num_cores;
  signal_new_config();
}

void cmd_churn(churn_fpm_t churn) {
  if (churn == 0) {
    runtime_config.flow_ttl = 0;
    signal_new_config();
    return;
  }

  double churn_fps = (double)churn / 60;
  assert(churn_fps != 0);

  time_ns_t flow_ttl = (1e9 * flows.size()) / churn_fps;

  LOG_DEBUG("Flow TTL = %" PRIu64 "ns", flow_ttl);

  runtime_config.flow_ttl = flow_ttl;
  signal_new_config();
}

void cmd_run(time_s_t duration) {
  signal_new_config();

  cmd_start();
  cmd_stats_reset();

  sleep_s(duration);

  cmd_stop();
}

void cmd_bench() {
  rate_mbps_t low      = BIN_SEARCH_MIN_RATE_Mbps;
  rate_mbps_t high     = BIN_SEARCH_MAX_RATE_Mbps;
  rate_mbps_t rate     = high;
  stats_t stable_stats = {
      .rx_pkts  = 0,
      .rx_bytes = 0,
      .tx_pkts  = 0,
      .tx_bytes = 0,
  };

  LOG("Warming up with rate %u Mbps for %u seconds...", BIN_SEARCH_WARMUP_RATE_Mbps, BIN_SEARCH_WARMUP_DURATION_S);
  cmd_rate(BIN_SEARCH_WARMUP_RATE_Mbps / 1e3);
  cmd_start();
  sleep_s(BIN_SEARCH_WARMUP_DURATION_S);

  for (int i = 0; i < BIN_SEARCH_IT_STEPS; i++) {
    LOG("Testing rate %.0lf Mbps...", rate);

    cmd_rate(rate / 1e3);
    sleep_s(2); // Let the rate stabilize before measuring
    cmd_stats_reset();
    sleep_s(BIN_SEARCH_IT_DURATION_S);

    struct stats_t stats = get_stats();

    double loss                  = (double)(stats.tx_pkts - stats.rx_pkts) / stats.tx_pkts;
    rate_mbps_t actual_rate_mbps = stats.tx_bytes * 8.0 / (BIN_SEARCH_IT_DURATION_S * 1e6);
    rate_mpps_t actual_rate_mpps = stats.tx_pkts / (BIN_SEARCH_IT_DURATION_S * 1e6);
    LOG("TX %12" PRIu64 " RX %12" PRIu64 " Rate %6.0lf Mbps %4.0lf Mpps loss %9.4f%%", stats.tx_pkts, stats.rx_pkts, actual_rate_mbps,
        actual_rate_mpps, 100 * loss);

    if (loss < BIN_SEARCH_LOSS_THRESHOLD) {
      low          = rate;
      stable_stats = stats;
      if (rate == BIN_SEARCH_MAX_RATE_Mbps) {
        break;
      }
    } else {
      high = rate;
    }

    rate = (low + high) / 2;
  }

  cmd_stop();

  rate_mbps_t actual_rate_mbps = stable_stats.tx_bytes * 8.0 / (BIN_SEARCH_IT_DURATION_S * 1e6);
  rate_mpps_t actual_rate_mpps = stable_stats.tx_pkts / (BIN_SEARCH_IT_DURATION_S * 1e6);

  LOG("Stable report:");
  LOG("\tTX %" PRIu64 " pkts %" PRIu64 " bytes", stable_stats.tx_pkts, stable_stats.tx_bytes);
  LOG("\tRX %" PRIu64 " pkts %" PRIu64 " bytes", stable_stats.rx_pkts, stable_stats.rx_bytes);
  LOG("\tElapsed %ds", BIN_SEARCH_IT_DURATION_S);
  if (actual_rate_mpps < 1) {
    LOG("\tRate %.0lf Mbps (%.0lf kpps)", actual_rate_mbps, actual_rate_mpps * 1000);
  } else {
    LOG("\tRate %.0lf Mbps (%.0lf Mpps)", actual_rate_mbps, actual_rate_mpps);
  }
}

static void cmd_quit_callback(__rte_unused void *ptr_params, struct cmdline *ctx, __rte_unused void *ptr_data) { cmdline_quit(ctx); }

static void cmd_start_callback(__rte_unused void *ptr_params, __rte_unused struct cmdline *ctx, __rte_unused void *ptr_data) {
  cmd_start();
}

static void cmd_stop_callback(__rte_unused void *ptr_params, __rte_unused struct cmdline *ctx, __rte_unused void *ptr_data) { cmd_stop(); }

static void cmd_stats_callback(__rte_unused void *ptr_params, __rte_unused struct cmdline *ctx, __rte_unused void *ptr_data) {
  cmd_stats_display_compact();
}

static void cmd_flows_callback(__rte_unused void *ptr_params, __rte_unused struct cmdline *ctx, __rte_unused void *ptr_data) {
  cmd_flows_display();
}

static void cmd_dist_callback(__rte_unused void *ptr_params, __rte_unused struct cmdline *ctx, __rte_unused void *ptr_data) {
  cmd_dist_display();
}

static void cmd_stats_reset_callback(__rte_unused void *ptr_params, __rte_unused struct cmdline *ctx, __rte_unused void *ptr_data) {
  cmd_stats_reset();
}

static void cmd_bench_callback(__rte_unused void *ptr_params, __rte_unused struct cmdline *ctx, __rte_unused void *ptr_data) {
  cmd_bench();
}

static void cmd_rate_callback(__rte_unused void *ptr_params, __rte_unused struct cmdline *ctx, __rte_unused void *ptr_data) {
  struct cmd_int_params *params = (struct cmd_int_params *)ptr_params;
  rate_gbps_t rate              = (double)params->param / 1000.0;
  cmd_rate(rate);
}

static void cmd_churn_callback(__rte_unused void *ptr_params, __rte_unused struct cmdline *ctx, __rte_unused void *ptr_data) {
  struct cmd_int_params *params = (struct cmd_int_params *)ptr_params;
  churn_fpm_t churn             = (double)params->param;
  cmd_churn(churn);
}

static void cmd_run_callback(__rte_unused void *ptr_params, __rte_unused struct cmdline *ctx, __rte_unused void *ptr_data) {
  struct cmd_int_params *params = (struct cmd_int_params *)ptr_params;
  time_s_t time                 = (double)params->param;
  cmd_run(time);
}

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_quit_cmd = {
    .f        = cmd_quit_callback,
    .data     = NULL,
    .help_str = "quit\n     Exit program",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_quit_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_start_cmd = {
    .f        = cmd_start_callback,
    .data     = NULL,
    .help_str = "start\n     Start packet generation",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_start_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_stop_cmd = {
    .f        = cmd_stop_callback,
    .data     = NULL,
    .help_str = "stop\n     Stop packet generation",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_stop_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_stats_cmd = {
    .f        = cmd_stats_callback,
    .data     = NULL,
    .help_str = "stats\n     Show stats",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_stats_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_flows_cmd = {
    .f        = cmd_flows_callback,
    .data     = NULL,
    .help_str = "flows\n     Show flows",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_flows_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_dist_cmd = {
    .f        = cmd_dist_callback,
    .data     = NULL,
    .help_str = "dist\n     Show flow distribution",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_dist_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_stats_reset_cmd = {
    .f        = cmd_stats_reset_callback,
    .data     = NULL,
    .help_str = "reset\n     Reset stats",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_stats_reset_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(1)
cmd_bench_cmd = {
    .f        = cmd_bench_callback,
    .data     = NULL,
    .help_str = "bench\n     Perform binary search",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_bench_token_cmd, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(2)
cmd_rate_cmd = {
    .f        = cmd_rate_callback,
    .data     = NULL,
    .help_str = "rate <rate>\n     Set rate in Mbps",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_rate_token_cmd, (cmdline_parse_token_hdr_t *)&cmd_int_token_param, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(2)
cmd_churn_cmd = {
    .f        = cmd_churn_callback,
    .data     = NULL,
    .help_str = "churn <churn>\n     Set churn in fpm",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_churn_token_cmd, (cmdline_parse_token_hdr_t *)&cmd_int_token_param, NULL},
};

CMDLINE_PARSE_INT_NTOKENS(2)
cmd_run_cmd = {
    .f        = cmd_run_callback,
    .data     = NULL,
    .help_str = "run <time>\n     Run for <time> seconds and then stop",
    .tokens   = {(cmdline_parse_token_hdr_t *)&cmd_run_token_cmd, (cmdline_parse_token_hdr_t *)&cmd_int_token_param, NULL},
};

cmdline_parse_ctx_t list_prompt_commands[] = {
    (cmdline_parse_inst_t *)&cmd_quit_cmd,  (cmdline_parse_inst_t *)&cmd_start_cmd,       (cmdline_parse_inst_t *)&cmd_stop_cmd,
    (cmdline_parse_inst_t *)&cmd_stats_cmd, (cmdline_parse_inst_t *)&cmd_stats_reset_cmd, (cmdline_parse_inst_t *)&cmd_flows_cmd,
    (cmdline_parse_inst_t *)&cmd_dist_cmd,  (cmdline_parse_inst_t *)&cmd_rate_cmd,        (cmdline_parse_inst_t *)&cmd_churn_cmd,
    (cmdline_parse_inst_t *)&cmd_run_cmd,   (cmdline_parse_inst_t *)&cmd_bench_cmd,       NULL,
};

void cmdline_start() {
  struct cmdline *ctx_cmdline;

  signal_new_config();

  ctx_cmdline = cmdline_stdin_new(list_prompt_commands, "Pktgen> ");
  cmdline_interact(ctx_cmdline);
  cmdline_stdin_exit(ctx_cmdline);
}
