// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#pragma once

#include <cstdint>

namespace layanalyzer::rtp {

// Hide a stream only when every packet is known to contain no media payload.
// A truncated capture or encrypted padding cannot prove that a stream is empty.
// Keep empty packets in mixed streams so sequence/loss statistics stay intact.
class RtpStreamPayloadEvidence {
 public:
  void observe(uint32_t payload_length, bool all_data_present, bool is_srtp,
               bool padding_set, uint32_t padding_count) {
    if (!all_data_present || is_srtp ||
        (padding_set && (padding_count == 0 || padding_count > payload_length))) {
      keep_ = true;
    } else if (payload_length > (padding_set ? padding_count : 0u)) {
      keep_ = true;
    }
  }

  bool shouldKeep() const { return keep_; }

 private:
  bool keep_ = false;
};

}  // namespace layanalyzer::rtp
