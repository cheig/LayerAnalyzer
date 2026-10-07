// RTP payload extraction through the Wireshark `rtp` tap (RTP2-NAT-01).
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "layanalyzer/rtp/core/RtpStreamKey.h"

struct WiresharkSession;

namespace layanalyzer::rtp {

struct RtpExtractionRequest {
  std::vector<RtpStreamKey> keys;
  std::string out_dir;
  std::map<RtpStreamKey, std::string, RtpStreamKeyHash> stream_ids;
};

struct RtpExtractionResult {
  std::string error;
  bool cancelled = false;
  uint64_t truncated_packets = 0;
  uint64_t zero_payload_packets = 0;
  std::map<std::string, std::string> rtpp_paths;
  std::map<std::string, std::string> index_paths;
  std::map<std::string, uint64_t> record_counts;
};

RtpExtractionResult extract_rtp_payloads(
    WiresharkSession *session, const std::vector<int> &frames,
    const RtpExtractionRequest &request,
    const std::function<bool(uint32_t, uint32_t)> &progress,
    uint64_t cancel_generation);

}  // namespace layanalyzer::rtp
