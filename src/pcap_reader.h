#pragma once

#include <filesystem>
#include <optional>
#include <pcap.h>

#include "flows.h"

typedef uint64_t time_ns_t;

struct packet_t {
  const uint8_t *pkt;
  uint16_t hdrs_len;
  uint16_t total_len;
  time_ns_t ts;
  std::optional<flow_t> flow;
};

struct pcap_reader_t {
  pcap_t *pd;
  bool assume_ip;
  long pcap_start;
  uint64_t total_pkts;
  time_ns_t start;
  time_ns_t end;

  pcap_reader_t(const std::filesystem::path &file);

  bool read_next_packet(packet_t &read_data);
};