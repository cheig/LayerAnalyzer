// Streaming RIFF/WAVE PCM16 writer.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

class WavWriter {
 public:
  WavWriter() = default;
  ~WavWriter();

  WavWriter(const WavWriter &) = delete;
  WavWriter &operator=(const WavWriter &) = delete;

  bool open(const std::string &path, uint32_t sample_rate, uint16_t channels,
            std::string &error);
  bool open(const std::string &path, uint32_t sample_rate, uint16_t channels);
  bool open(const std::string &path, uint32_t sample_rate, std::string &error) {
    return open(path, sample_rate, 1, error);
  }

  bool append(const int16_t *samples, size_t sample_count);
  bool append(const std::vector<int16_t> &samples) {
    return append(samples.data(), samples.size());
  }

  bool finalize(std::string &error);
  bool finalize();

  const std::string &error() const { return error_; }
  const std::string &path() const { return path_; }

 private:
  bool fail(const std::string &error);

  std::FILE *file_ = nullptr;
  std::string path_;
  std::string error_;
  uint64_t data_bytes_ = 0;
  uint32_t sample_rate_ = 0;
  uint16_t channels_ = 0;
  bool failed_ = false;
};

}  // namespace layanalyzer::rtp
