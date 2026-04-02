#ifndef _GNU_SOURCE
#define _GNU_SOURCE // Required for fopencookie
#endif

#include "pcap_reader.h"
#include "log.h"

#include <vector>
#include <fstream>
#include <string.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

#include <zstd.h>

namespace {

std::vector<uint8_t> get_file_signature(const std::string &filepath, size_t bytesToRead = 4) {
  std::ifstream file(filepath, std::ios::binary);
  if (!file) {
    return {};
  }

  std::vector<uint8_t> buffer(bytesToRead);
  file.read(reinterpret_cast<char *>(buffer.data()), bytesToRead);

  // Resize buffer if fewer bytes were read (e.g., small file)
  buffer.resize(file.gcount());

  return buffer;
}

struct ZstdContext {
  FILE *raw_file;
  ZSTD_DStream *dctx;

  // Input buffer (compressed data from disk)
  std::vector<uint8_t> in_buff;
  size_t in_pos;
  size_t in_len;

  // Output buffer (decompressed data for libpcap)
  std::vector<uint8_t> out_buff;
  size_t out_pos;
  size_t out_len;

  bool eof_reached;

  ZstdContext(const char *filename) : in_pos(0), in_len(0), out_pos(0), out_len(0), eof_reached(false) {
    raw_file = fopen(filename, "rb");
    if (!raw_file) {
      perror("fopen");
      exit(1);
    }

    dctx = ZSTD_createDStream();
    ZSTD_initDStream(dctx);

    in_buff.resize(ZSTD_DStreamInSize());
    out_buff.resize(ZSTD_DStreamOutSize());
  }

  ~ZstdContext() {
    if (raw_file) {
      fclose(raw_file);
    }
    ZSTD_freeDStream(dctx);
  }
};

// Libpcap calls this thinking it's reading a normal file.
// We intercept it and feed it decompressed data.
ssize_t zstd_read_fn(void *cookie, char *buf, size_t size) {
  ZstdContext *ctx    = static_cast<ZstdContext *>(cookie);
  size_t total_copied = 0;

  while (total_copied < size) {
    // 1. If we have data in the output buffer, give it to libpcap
    if (ctx->out_pos < ctx->out_len) {
      const size_t available = ctx->out_len - ctx->out_pos;
      const size_t needed    = size - total_copied;
      const size_t to_copy   = (available < needed) ? available : needed;

      memcpy(buf + total_copied, ctx->out_buff.data() + ctx->out_pos, to_copy);

      ctx->out_pos += to_copy;
      total_copied += to_copy;

      if (total_copied == size) {
        return total_copied;
      }
    }

    // 2. Output buffer is empty. We need to decompress more data.
    if (ctx->eof_reached && ctx->in_pos >= ctx->in_len) {
      return total_copied; // Real EOF
    }

    // Reset output buffer state
    ctx->out_pos = 0;
    ctx->out_len = 0;

    ZSTD_outBuffer output = {ctx->out_buff.data(), ctx->out_buff.size(), 0};

    // Decompression Loop
    // We loop until we produce *some* output or hit EOF/Error
    while (output.pos == 0) {
      // Refill input buffer if empty
      if (ctx->in_pos >= ctx->in_len) {
        if (feof(ctx->raw_file)) {
          ctx->eof_reached = true;
          // If we are at EOF and no output was produced, we are done
          if (output.pos == 0) {
            return total_copied;
          }
          break;
        }

        const size_t read = fread(ctx->in_buff.data(), 1, ctx->in_buff.size(), ctx->raw_file);
        if (read == 0) {
          ctx->eof_reached = true;
          break;
        }
        ctx->in_len = read;
        ctx->in_pos = 0;
      }

      ZSTD_inBuffer input = {ctx->in_buff.data(), ctx->in_len, ctx->in_pos};

      // The actual decompression
      const size_t ret = ZSTD_decompressStream(ctx->dctx, &output, &input);

      ctx->in_pos = input.pos;

      if (ZSTD_isError(ret)) {
        panic("Decompression failed: %s", ZSTD_getErrorName(ret));
      }

      // If frame is over (ret==0), we might need to loop again to get next frame
      // But usually we just return what we have.
      if (output.pos > 0) {
        break;
      }
    }

    ctx->out_len = output.pos;
  }

  return total_copied;
}

int zstd_close_fn(void *cookie) {
  ZstdContext *ctx = static_cast<ZstdContext *>(cookie);
  delete ctx; // Clean up our context
  return 0;
}

} // namespace

pcap_reader_t::pcap_reader_t(const std::filesystem::path &file)
    : pd(nullptr), assume_ip(false), pcap_start(0), total_pkts(0), start(0), end(0) {
  const std::vector<uint8_t> signature = get_file_signature(file.string());

  static const std::vector<uint8_t> zst_sig     = {0x28, 0xB5, 0x2F, 0xFD};
  static const std::vector<uint8_t> pcap_be_sig = {0xA1, 0xB2, 0xC3, 0xD4};
  static const std::vector<uint8_t> pcap_le_sig = {0xD4, 0xC3, 0xB2, 0xA1};
  static const std::vector<uint8_t> pcapng_sig  = {0x0A, 0x0D, 0x0D, 0x0A};

  FILE *pcap_fptr = nullptr;

  if (signature == zst_sig) {
    ZstdContext *ctx = new ZstdContext(file.c_str());

    cookie_io_functions_t funcs = {
        .read  = zstd_read_fn,
        .write = NULL, // Libpcap only reads
        .seek  = NULL, // Streaming zstd is not seekable
        .close = zstd_close_fn,
    };

    pcap_fptr = fopencookie(ctx, "r", funcs);
    if (!pcap_fptr) {
      panic("Failed to create cookie stream");
    }
  } else if (signature == pcap_be_sig || signature == pcap_le_sig) {
    pcap_fptr = fopen(file.c_str(), "rb");
    if (!pcap_fptr) {
      perror("fopen");
      panic("Failed to open pcap file");
    }
  } else if (signature == pcapng_sig) {
    // Handle PCAPNG file
    panic("PCAPNG format is not supported yet");
  } else {
    panic("Unknown file format");
  }

  assert(pcap_fptr && "Invalid pcap file pointer");
  pcap_start = ftell(pcap_fptr);

  char errbuf[PCAP_ERRBUF_SIZE];
  pd = pcap_fopen_offline(pcap_fptr, errbuf);

  if (!pd) {
    fclose(pcap_fptr);
    panic("Failed to open pcap file: %s", errbuf);
  }

  const int link_hdr_type = pcap_datalink(pd);

  switch (link_hdr_type) {
  case DLT_EN10MB:
    // Normal ethernet, as expected. Nothing to do here.
    break;
  case DLT_RAW:
    // Contains raw IP packets.
    assume_ip = true;
    break;
  default: {
    panic("Unknown header type (%d)", link_hdr_type);
  }
  }
}

bool pcap_reader_t::read_next_packet(packet_t &read_data) {
  const uint8_t *data;
  struct pcap_pkthdr *header;

  if (pcap_next_ex(pd, &header, &data) != 1) {
    return false;
  }

  read_data.pkt       = data;
  read_data.hdrs_len  = 0;
  read_data.total_len = header->len + RTE_ETHER_CRC_LEN;
  read_data.ts        = header->ts.tv_sec * 1'000'000'000 + header->ts.tv_usec * 1'000;

  if (assume_ip) {
    read_data.total_len += sizeof(rte_ether_hdr);
  } else {
    const rte_ether_hdr *ether_hdr = reinterpret_cast<const rte_ether_hdr *>(data);
    data += sizeof(rte_ether_hdr);
    read_data.hdrs_len += sizeof(rte_ether_hdr);

    uint16_t ether_type = ntohs(ether_hdr->ether_type);

    if (ether_type == RTE_ETHER_TYPE_VLAN) {
      // The VLAN header starts at the Ethernet ethertype field,
      // so we need to rollback.
      data = reinterpret_cast<const uint8_t *>(&ether_hdr->ether_type);

      // Ignore the VLAN header and advance the data pointer.
      data += sizeof(rte_vlan_hdr);

      // Grab the encapsulated ethertype and offset the data pointer.
      ether_type = ntohs(reinterpret_cast<const uint16_t *>(data)[0]);
      data += sizeof(uint16_t);
      read_data.hdrs_len += sizeof(rte_vlan_hdr) + sizeof(uint16_t);
    }

    if (ether_type != RTE_ETHER_TYPE_IPV4) {
      read_data.hdrs_len = read_data.total_len;
      return true;
    }
  }

  const rte_ipv4_hdr *ip_hdr = reinterpret_cast<const rte_ipv4_hdr *>(data);
  data += sizeof(rte_ipv4_hdr);
  read_data.hdrs_len += sizeof(rte_ipv4_hdr);

  if (ip_hdr->version != 4) {
    return true;
  }

  uint16_t sport = 0;
  uint16_t dport = 0;

  // We only support TCP/UDP
  switch (ip_hdr->next_proto_id) {
  case IPPROTO_TCP: {
    const rte_tcp_hdr *tcp_hdr = reinterpret_cast<const rte_tcp_hdr *>(data);
    data += sizeof(rte_tcp_hdr);
    read_data.hdrs_len += sizeof(rte_tcp_hdr);
    sport = tcp_hdr->src_port;
    dport = tcp_hdr->dst_port;
  } break;

  case IPPROTO_UDP: {
    const rte_udp_hdr *udp_hdr = reinterpret_cast<const rte_udp_hdr *>(data);
    data += sizeof(rte_udp_hdr);
    read_data.hdrs_len += sizeof(rte_udp_hdr);
    sport = udp_hdr->src_port;
    dport = udp_hdr->dst_port;
  } break;
  default: {
    return true;
  }
  }

  read_data.flow           = flow_t();
  read_data.flow->src_ip   = ip_hdr->src_addr;
  read_data.flow->dst_ip   = ip_hdr->dst_addr;
  read_data.flow->src_port = sport;
  read_data.flow->dst_port = dport;

  return true;
}