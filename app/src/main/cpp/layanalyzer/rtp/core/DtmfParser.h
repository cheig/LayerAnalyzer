// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// RFC 4733 telephone-event DTMF parser.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

struct DtmfPacket {
  uint8_t pt = 0;
  std::vector<uint8_t> payload;
  uint32_t at_ms = 0;
  uint32_t frame = 0;
  uint64_t rtp_timestamp = 0;
};

struct DtmfEvent {
  std::string digit;
  uint32_t at_ms = 0;
  uint32_t dur_ms = 0;
  uint8_t volume = 0;
  uint32_t frame = 0;
};

// Packets must be supplied in arrival order. Events are grouped by RTP
// timestamp, and only packets whose PT matches telephone_event_pt are parsed.
std::vector<DtmfEvent> parse_dtmf_events(
    const std::vector<DtmfPacket> &packets, uint32_t telephone_event_pt,
    unsigned clock_rate);

}  // namespace layanalyzer::rtp
