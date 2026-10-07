// Streaming 10 ms min/max peak file builder.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

class PeaksBuilder {
 public:
  PeaksBuilder() = default;
  ~PeaksBuilder();

  PeaksBuilder(const PeaksBuilder &) = delete;
  PeaksBuilder &operator=(const PeaksBuilder &) = delete;

  bool open(const std::string &path, uint32_t sample_rate, std::string &error);
  bool open(const std::string &path, uint32_t sample_rate);
  bool append(const int16_t *samples, size_t sample_count);
  bool append(const std::vector<int16_t> &samples) {
    return append(samples.data(), samples.size());
  }

  bool finalize(std::string &error);
  bool finalize();

  const std::string &error() const { return error_; }
  const std::string &path() const { return path_; }

 private:
  bool write_current_bucket();
  bool fail(const std::string &error);

  std::FILE *file_ = nullptr;
  std::string path_;
  std::string error_;
  uint32_t sample_rate_ = 0;
  uint32_t samples_per_bucket_ = 0;
  uint32_t bucket_count_ = 0;
  uint32_t current_count_ = 0;
  int16_t current_min_ = 0;
  int16_t current_max_ = 0;
  bool failed_ = false;
};

}  // namespace layanalyzer::rtp
