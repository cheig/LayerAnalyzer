// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#include "layanalyzer/rtp/core/PeaksBuilder.h"

#include <algorithm>
#include <limits>

namespace layanalyzer::rtp {
namespace {

constexpr char kMagic[4] = {'P', 'K', 'S', '1'};
constexpr uint32_t kCountOffset = 12;
constexpr uint32_t kMinimumSampleRate = 100;

bool write_bytes(std::FILE *file, const void *data, size_t length) {
  return length == 0 || std::fwrite(data, 1, length, file) == length;
}

bool write_u16(std::FILE *file, uint16_t value) {
  const uint8_t bytes[2] = {
      static_cast<uint8_t>(value & 0xffu),
      static_cast<uint8_t>((value >> 8u) & 0xffu),
  };
  return write_bytes(file, bytes, sizeof(bytes));
}

bool write_u32(std::FILE *file, uint32_t value) {
  const uint8_t bytes[4] = {
      static_cast<uint8_t>(value & 0xffu),
      static_cast<uint8_t>((value >> 8u) & 0xffu),
      static_cast<uint8_t>((value >> 16u) & 0xffu),
      static_cast<uint8_t>((value >> 24u) & 0xffu),
  };
  return write_bytes(file, bytes, sizeof(bytes));
}

void close_file(std::FILE *&file) {
  if (file) {
    std::fclose(file);
    file = nullptr;
  }
}

}  // namespace

PeaksBuilder::~PeaksBuilder() {
  close_file(file_);
}

bool PeaksBuilder::fail(const std::string &error) {
  error_ = error;
  failed_ = true;
  close_file(file_);
  return false;
}

bool PeaksBuilder::open(const std::string &path, uint32_t sample_rate,
                        std::string &error) {
  error_.clear();
  error.clear();
  if (file_) {
    error_ = "Peaks writer is already open.";
    error = error_;
    return false;
  }
  if (path.empty()) {
    error_ = "Peaks path is empty.";
    error = error_;
    return false;
  }
  if (sample_rate < kMinimumSampleRate) {
    error_ = "Peaks sample rate must be at least 100 Hz.";
    error = error_;
    return false;
  }

  file_ = std::fopen(path.c_str(), "wb");
  if (!file_) {
    error_ = "Unable to open peaks file.";
    error = error_;
    return false;
  }

  path_ = path;
  sample_rate_ = sample_rate;
  samples_per_bucket_ = sample_rate / 100u;
  bucket_count_ = 0;
  current_count_ = 0;
  current_min_ = 0;
  current_max_ = 0;
  failed_ = false;

  const bool ok = write_bytes(file_, kMagic, sizeof(kMagic)) &&
                  write_u32(file_, sample_rate_) &&
                  write_u32(file_, samples_per_bucket_) && write_u32(file_, 0);
  if (!ok) {
    const std::string failed_path = path_;
    fail("Unable to write peaks header.");
    std::remove(failed_path.c_str());
    error = error_;
    return false;
  }
  return true;
}

bool PeaksBuilder::open(const std::string &path, uint32_t sample_rate) {
  std::string ignored;
  return open(path, sample_rate, ignored);
}

bool PeaksBuilder::write_current_bucket() {
  if (current_count_ == 0) {
    return true;
  }
  if (bucket_count_ == std::numeric_limits<uint32_t>::max()) {
    return fail("Peaks bucket count is too large.");
  }
  if (!write_u16(file_, static_cast<uint16_t>(current_min_)) ||
      !write_u16(file_, static_cast<uint16_t>(current_max_))) {
    return fail("Unable to write peaks bucket.");
  }
  ++bucket_count_;
  current_count_ = 0;
  current_min_ = 0;
  current_max_ = 0;
  return true;
}

bool PeaksBuilder::append(const int16_t *samples, size_t sample_count) {
  if (!file_) {
    return fail("Peaks writer is not open.");
  }
  if (failed_) {
    return false;
  }
  if (sample_count > 0 && samples == nullptr) {
    return fail("Peaks sample buffer is null.");
  }

  for (size_t index = 0; index < sample_count; ++index) {
    if (current_count_ == 0) {
      if (bucket_count_ == std::numeric_limits<uint32_t>::max()) {
        return fail("Peaks bucket count is too large.");
      }
      current_min_ = std::numeric_limits<int16_t>::max();
      current_max_ = std::numeric_limits<int16_t>::min();
    }

    const int16_t sample = samples[index];
    current_min_ = std::min(current_min_, sample);
    current_max_ = std::max(current_max_, sample);
    ++current_count_;
    if (current_count_ == samples_per_bucket_ &&
        !write_current_bucket()) {
      return false;
    }
  }
  return true;
}

bool PeaksBuilder::finalize(std::string &error) {
  error.clear();
  if (!file_) {
    if (error_.empty()) {
      error_ = "Peaks writer is not open.";
    }
    error = error_;
    return false;
  }
  if (failed_) {
    error = error_;
    close_file(file_);
    return false;
  }

  if (!write_current_bucket()) {
    error = error_;
    return false;
  }
  if (std::fseek(file_, kCountOffset, SEEK_SET) != 0 ||
      !write_u32(file_, bucket_count_)) {
    return fail("Unable to finalize peaks count.");
  }
  if (std::fflush(file_) != 0) {
    return fail("Unable to flush peaks file.");
  }
  if (std::fclose(file_) != 0) {
    file_ = nullptr;
    return fail("Unable to close peaks file.");
  }
  file_ = nullptr;
  error_.clear();
  return true;
}

bool PeaksBuilder::finalize() {
  std::string ignored;
  return finalize(ignored);
}

}  // namespace layanalyzer::rtp
