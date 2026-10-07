// Bounded, physical-frame SIP/SDP reads for RTP3-NAT-04.
#pragma once

#include <string>
#include <nlohmann/json.hpp>

struct WiresharkSession;

namespace layanalyzer::rtp {

// The caller must retain a SessionLease. No scan, filter or tap state is changed.
// Request: {"frames":[20,22]}, at most 64 one-based frame numbers, preserving
// order and duplicates. An empty array is valid. Errors/cancellation return no
// partial frames. sdp_only projects the same read to {frame,sdp} rows.
nlohmann::json read_rtp_setup_info(WiresharkSession *session,
                                  const std::string &request_text,
                                  bool sdp_only);

}  // namespace layanalyzer::rtp
