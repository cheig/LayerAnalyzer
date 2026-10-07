// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Streaming packet-to-output-time frame map writer.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace layanalyzer::rtp {

class FrameMapWriter {
 public:
  FrameMapWriter() = default;
  ~FrameMapWriter();

  FrameMapWriter(const FrameMapWriter &) = delete;
  FrameMapWriter &operator=(const FrameMapWriter &) = delete;

  bool open(const std::string &path, std::string &error);
  bool open(const std::string &path);
  bool append(uint32_t at_ms, uint32_t frame);

  bool finalize(std::string &error);
  bool finalize();

  const std::string &error() const { return error_; }
  const std::string &path() const { return path_; }

 private:
  bool fail(const std::string &error);

  std::FILE *file_ = nullptr;
  std::string path_;
  std::string error_;
  uint32_t count_ = 0;
  uint32_t last_at_ms_ = 0;
  bool has_last_at_ms_ = false;
  bool failed_ = false;
};

}  // namespace layanalyzer::rtp
