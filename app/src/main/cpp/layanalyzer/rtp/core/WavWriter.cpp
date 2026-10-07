// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#include "layanalyzer/rtp/core/WavWriter.h"

#include <cstring>
#include <limits>

namespace layanalyzer::rtp {
namespace {

constexpr char kRiffMagic[4] = {'R', 'I', 'F', 'F'};
constexpr char kWaveMagic[4] = {'W', 'A', 'V', 'E'};
constexpr char kFmtMagic[4] = {'f', 'm', 't', ' '};
constexpr char kDataMagic[4] = {'d', 'a', 't', 'a'};
constexpr uint32_t kPcmFormat = 1;
constexpr uint16_t kBitsPerSample = 16;
constexpr uint32_t kRiffFixedSize = 36;
constexpr uint32_t kDataOffset = 40;

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

WavWriter::~WavWriter() {
  close_file(file_);
}

bool WavWriter::fail(const std::string &error) {
  error_ = error;
  failed_ = true;
  close_file(file_);
  return false;
}

bool WavWriter::open(const std::string &path, uint32_t sample_rate,
                     uint16_t channels, std::string &error) {
  error_.clear();
  error.clear();
  if (file_) {
    error_ = "WAV writer is already open.";
    error = error_;
    return false;
  }
  if (path.empty()) {
    error_ = "WAV path is empty.";
    error = error_;
    return false;
  }
  if (sample_rate == 0) {
    error_ = "WAV sample rate must be positive.";
    error = error_;
    return false;
  }
  if (channels != 1 && channels != 2) {
    error_ = "WAV channel count must be 1 or 2.";
    error = error_;
    return false;
  }

  const uint64_t block_align =
      static_cast<uint64_t>(channels) * (kBitsPerSample / 8u);
  const uint64_t byte_rate = static_cast<uint64_t>(sample_rate) * block_align;
  if (byte_rate > std::numeric_limits<uint32_t>::max()) {
    error_ = "WAV byte rate is too large.";
    error = error_;
    return false;
  }

  file_ = std::fopen(path.c_str(), "wb");
  if (!file_) {
    error_ = "Unable to open WAV file.";
    error = error_;
    return false;
  }

  path_ = path;
  data_bytes_ = 0;
  sample_rate_ = sample_rate;
  channels_ = channels;
  failed_ = false;

  const bool ok =
      write_bytes(file_, kRiffMagic, sizeof(kRiffMagic)) &&
      write_u32(file_, kRiffFixedSize) &&
      write_bytes(file_, kWaveMagic, sizeof(kWaveMagic)) &&
      write_bytes(file_, kFmtMagic, sizeof(kFmtMagic)) &&
      write_u32(file_, 16) &&
      write_u16(file_, kPcmFormat) &&
      write_u16(file_, channels) &&
      write_u32(file_, sample_rate) &&
      write_u32(file_, static_cast<uint32_t>(byte_rate)) &&
      write_u16(file_, static_cast<uint16_t>(block_align)) &&
      write_u16(file_, kBitsPerSample) &&
      write_bytes(file_, kDataMagic, sizeof(kDataMagic)) &&
      write_u32(file_, 0);
  if (!ok) {
    const std::string failed_path = path_;
    fail("Unable to write WAV header.");
    std::remove(failed_path.c_str());
    error = error_;
    return false;
  }
  return true;
}

bool WavWriter::open(const std::string &path, uint32_t sample_rate,
                     uint16_t channels) {
  std::string ignored;
  return open(path, sample_rate, channels, ignored);
}

bool WavWriter::append(const int16_t *samples, size_t sample_count) {
  if (!file_) {
    return fail("WAV writer is not open.");
  }
  if (failed_) {
    return false;
  }

  const uint64_t max_data_bytes =
      static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) -
      kRiffFixedSize;
  if (sample_count >
      std::numeric_limits<uint64_t>::max() / sizeof(int16_t)) {
    return fail("WAV data size is too large.");
  }
  const uint64_t byte_count =
      static_cast<uint64_t>(sample_count) * sizeof(int16_t);
  if (byte_count > max_data_bytes - data_bytes_) {
    return fail("WAV file would exceed 4 GB.");
  }
  if (byte_count > 0 && samples == nullptr) {
    return fail("WAV sample buffer is null.");
  }
  if (!write_bytes(file_, samples, static_cast<size_t>(byte_count))) {
    return fail("Unable to write WAV samples.");
  }

  data_bytes_ += byte_count;
  return true;
}

bool WavWriter::finalize(std::string &error) {
  error.clear();
  if (!file_) {
    if (error_.empty()) {
      error_ = "WAV writer is not open.";
    }
    error = error_;
    return false;
  }
  if (failed_) {
    error = error_;
    close_file(file_);
    return false;
  }
  if (data_bytes_ >
      static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) -
          kRiffFixedSize) {
    return fail("WAV file would exceed 4 GB.");
  }

  const uint32_t riff_size =
      kRiffFixedSize + static_cast<uint32_t>(data_bytes_);
  if (std::fseek(file_, 4, SEEK_SET) != 0 ||
      !write_u32(file_, riff_size) ||
      std::fseek(file_, kDataOffset, SEEK_SET) != 0 ||
      !write_u32(file_, static_cast<uint32_t>(data_bytes_))) {
    return fail("Unable to finalize WAV header.");
  }
  if (std::fflush(file_) != 0) {
    return fail("Unable to flush WAV file.");
  }
  if (std::fclose(file_) != 0) {
    file_ = nullptr;
    return fail("Unable to close WAV file.");
  }
  file_ = nullptr;
  error_.clear();
  return true;
}

bool WavWriter::finalize() {
  std::string ignored;
  return finalize(ignored);
}

}  // namespace layanalyzer::rtp
