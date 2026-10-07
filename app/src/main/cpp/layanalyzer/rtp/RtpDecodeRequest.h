// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Pure request parser for the `decodeRtpAudio` JNI endpoint.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/core/RtpAudioRenderer.h"

namespace layanalyzer::rtp {

struct RtpDecodeRequest {
  uint64_t scan_generation = 0;
  std::vector<std::string> stream_ids;
  RtpTimingMode timing = RtpTimingMode::JitterBuffer;
  int jitter_ms = 50;
  bool dtmf = false;
  bool has_mix = false;
  RtpMixRequest mix;
};

// Parses:
// {"scanGeneration":7,"streams":["s0","s1"],
//  "timing":"jitter|rtp|uninterrupted","jitterMs":50,"dtmf":true,
//  "mix":{"left":"s0","right":"s1","align":"absArrival"}}
//
// Unknown fields are ignored. Missing or malformed required fields fail closed.
bool parse_rtp_decode_request(const std::string &text,
                              RtpDecodeRequest &request,
                              std::string &error);

}  // namespace layanalyzer::rtp
