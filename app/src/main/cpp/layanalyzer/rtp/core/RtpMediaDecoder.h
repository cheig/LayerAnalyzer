// RTP payload decoder wrapper for one media stream.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "layanalyzer/rtp/core/RtpAudioDecoder.h"

namespace layanalyzer::rtp {

struct RtpMediaDecoderResult {
  bool ok = false;
  std::string reason;
};

class RtpMediaDecoder {
 public:
  // canonical_codec has already been resolved by the caller.
  explicit RtpMediaDecoder(const std::string &canonical_codec);

  bool available() const;

  RtpMediaDecoderResult decodePacket(uint32_t payload_type,
                                     const uint8_t *payload, size_t length,
                                     std::vector<int16_t> &out);

  unsigned channels() const;
  unsigned sample_rate() const;
  unsigned timestamp_rate() const;

  // Number of successfully decoded samples per channel in the last packet.
  uint32_t lastPacketSamples() const;

 private:
  bool ensureDecoderForPayloadType(uint32_t payload_type);

  std::string canonical_codec_;
  std::unique_ptr<RtpAudioDecoder> decoder_;
  bool available_ = false;
  uint32_t last_packet_samples_ = 0;
};

}  // namespace layanalyzer::rtp
