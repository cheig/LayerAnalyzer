// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// L16 decoder: big-endian 16-bit PCM to host int16_t samples.
#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace layanalyzer::rtp {
namespace {

class L16Decoder final : public RtpAudioDecoder {
 public:
  explicit L16Decoder(unsigned channels) : channels_(channels) {}

  unsigned channels() const override { return channels_; }
  unsigned sample_rate() const override { return 44100; }
  unsigned timestamp_rate() const override { return 44100; }

  bool decode(const uint8_t *payload, size_t length,
              std::vector<int16_t> &out) override {
    out.clear();
    if (length == 0 || (length % 2) != 0 || payload == nullptr) {
      return false;
    }

    out.resize(length / 2);
    for (size_t i = 0; i < out.size(); ++i) {
      const uint16_t sample =
          static_cast<uint16_t>((static_cast<uint16_t>(payload[i * 2]) << 8) |
                                static_cast<uint16_t>(payload[i * 2 + 1]));
      out[i] = static_cast<int16_t>(sample);
    }
    return true;
  }

 private:
  unsigned channels_;
};

}  // namespace

namespace detail {

std::unique_ptr<RtpAudioDecoder> create_l16_decoder(unsigned channels) {
  if (channels != 1 && channels != 2) {
    return nullptr;
  }
  return std::make_unique<L16Decoder>(channels);
}

}  // namespace detail
}  // namespace layanalyzer::rtp
