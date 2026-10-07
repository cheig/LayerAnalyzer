// RTP audio decoder interface shared by all codec implementations.
//
// This is intentionally independent from wsutil's process-global codec
// registry so decoder behavior can be tested in the host test binary.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace layanalyzer::rtp {

class RtpAudioDecoder {
 public:
  virtual ~RtpAudioDecoder() = default;

  virtual unsigned channels() const = 0;
  virtual unsigned sample_rate() const = 0;
  virtual unsigned timestamp_rate() const = 0;

  // Returns false for an invalid payload. On failure, out is empty.
  virtual bool decode(const uint8_t *payload, size_t length,
                      std::vector<int16_t> &out) = 0;
};

}  // namespace layanalyzer::rtp
