#include "layanalyzer/rtp/core/FrameMapWriter.h"

#include <limits>

namespace layanalyzer::rtp {
namespace {

constexpr char kMagic[4] = {'M', 'A', 'P', '1'};
constexpr uint32_t kCountOffset = 4;

bool write_bytes(std::FILE *file, const void *data, size_t length) {
  return length == 0 || std::fwrite(data, 1, length, file) == length;
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

FrameMapWriter::~FrameMapWriter() {
  close_file(file_);
}

bool FrameMapWriter::fail(const std::string &error) {
  error_ = error;
  failed_ = true;
  close_file(file_);
  return false;
}

bool FrameMapWriter::open(const std::string &path, std::string &error) {
  error_.clear();
  error.clear();
  if (file_) {
    error_ = "Frame map writer is already open.";
    error = error_;
    return false;
  }
  if (path.empty()) {
    error_ = "Frame map path is empty.";
    error = error_;
    return false;
  }

  file_ = std::fopen(path.c_str(), "wb");
  if (!file_) {
    error_ = "Unable to open frame map file.";
    error = error_;
    return false;
  }

  path_ = path;
  count_ = 0;
  last_at_ms_ = 0;
  has_last_at_ms_ = false;
  failed_ = false;

  if (!write_bytes(file_, kMagic, sizeof(kMagic)) || !write_u32(file_, 0)) {
    const std::string failed_path = path_;
    fail("Unable to write frame map header.");
    std::remove(failed_path.c_str());
    error = error_;
    return false;
  }
  return true;
}

bool FrameMapWriter::open(const std::string &path) {
  std::string ignored;
  return open(path, ignored);
}

bool FrameMapWriter::append(uint32_t at_ms, uint32_t frame) {
  if (!file_) {
    return fail("Frame map writer is not open.");
  }
  if (failed_) {
    return false;
  }
  if (has_last_at_ms_ && at_ms <= last_at_ms_) {
    return fail("Frame map at_ms values must be strictly increasing.");
  }
  if (count_ == std::numeric_limits<uint32_t>::max()) {
    return fail("Frame map entry count is too large.");
  }
  if (!write_u32(file_, at_ms) || !write_u32(file_, frame)) {
    return fail("Unable to write frame map entry.");
  }

  last_at_ms_ = at_ms;
  has_last_at_ms_ = true;
  ++count_;
  return true;
}

bool FrameMapWriter::finalize(std::string &error) {
  error.clear();
  if (!file_) {
    if (error_.empty()) {
      error_ = "Frame map writer is not open.";
    }
    error = error_;
    return false;
  }
  if (failed_) {
    error = error_;
    close_file(file_);
    return false;
  }
  if (std::fseek(file_, kCountOffset, SEEK_SET) != 0 ||
      !write_u32(file_, count_)) {
    return fail("Unable to finalize frame map count.");
  }
  if (std::fflush(file_) != 0) {
    return fail("Unable to flush frame map file.");
  }
  if (std::fclose(file_) != 0) {
    file_ = nullptr;
    return fail("Unable to close frame map file.");
  }
  file_ = nullptr;
  error_.clear();
  return true;
}

bool FrameMapWriter::finalize() {
  std::string ignored;
  return finalize(ignored);
}

}  // namespace layanalyzer::rtp
