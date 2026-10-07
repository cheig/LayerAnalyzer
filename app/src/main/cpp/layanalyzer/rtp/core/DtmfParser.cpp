// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#include "layanalyzer/rtp/core/DtmfParser.h"

#include <cstddef>
#include <unordered_map>
#include <utility>

namespace layanalyzer::rtp {
namespace {

std::string digit_for_event(uint8_t event) {
  if (event <= 9u) {
    return std::string(1, static_cast<char>('0' + event));
  }
  switch (event) {
    case 10u:
      return "*";
    case 11u:
      return "#";
    case 12u:
      return "A";
    case 13u:
      return "B";
    case 14u:
      return "C";
    case 15u:
      return "D";
    default:
      return "event:" + std::to_string(event);
  }
}

uint32_t duration_milliseconds(uint16_t duration, unsigned clock_rate) {
  if (clock_rate == 0u) {
    return 0;
  }
  return static_cast<uint32_t>(
      static_cast<uint64_t>(duration) * 1000u / clock_rate);
}

}  // namespace

std::vector<DtmfEvent> parse_dtmf_events(
    const std::vector<DtmfPacket> &packets, uint32_t telephone_event_pt,
    unsigned clock_rate) {
  std::vector<DtmfEvent> events;
  std::unordered_map<uint64_t, size_t> event_by_timestamp;
  event_by_timestamp.reserve(packets.size());

  for (const DtmfPacket &packet : packets) {
    if (packet.pt != telephone_event_pt || packet.payload.size() < 4u) {
      continue;
    }

    const uint8_t event_id = packet.payload[0];
    const uint8_t flags = packet.payload[1];
    const uint8_t volume = flags & 0x3fu;
    const uint16_t duration =
        static_cast<uint16_t>((static_cast<uint16_t>(packet.payload[2]) << 8u) |
                              packet.payload[3]);
    const uint32_t dur_ms = duration_milliseconds(duration, clock_rate);

    const auto existing = event_by_timestamp.find(packet.rtp_timestamp);
    if (existing != event_by_timestamp.end()) {
      events[existing->second].dur_ms = dur_ms;
      continue;
    }

    DtmfEvent event;
    event.digit = digit_for_event(event_id);
    event.at_ms = packet.at_ms;
    event.dur_ms = dur_ms;
    event.volume = volume;
    event.frame = packet.frame;

    const size_t index = events.size();
    events.push_back(std::move(event));
    event_by_timestamp.emplace(packet.rtp_timestamp, index);
  }

  return events;
}

}  // namespace layanalyzer::rtp
