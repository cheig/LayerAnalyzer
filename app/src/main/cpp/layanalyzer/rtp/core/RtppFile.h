// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// RTP payload record stream (`.rtpp`) reader/writer.
//
// The format is deliberately self-contained and uses only the C++ standard
// library so it can be exercised by host tests and reused by JNI paths.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

inline constexpr uint64_t kRtppRecordHeaderSize =
    sizeof(uint32_t) + sizeof(double) + sizeof(uint32_t) + sizeof(uint64_t) +
    sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t);

struct RtppRecordHeader {
  uint32_t frame = 0;
  double arrival_rel_sec = 0.0;
  uint32_t ext_seq = 0;
  uint64_t ext_ts = 0;
  uint8_t pt = 0;
  uint8_t marker = 0;
  uint16_t len = 0;
};

struct RtppFileRecord {
  RtppRecordHeader header;
  std::vector<uint8_t> payload;
};

struct RtppReadResult {
  std::string stream_id;
  uint32_t declared_record_count = 0;
  std::vector<RtppFileRecord> records;
};

class RtppWriter {
 public:
  RtppWriter() = default;
  ~RtppWriter();

  RtppWriter(const RtppWriter &) = delete;
  RtppWriter &operator=(const RtppWriter &) = delete;

  bool open(const std::string &path, const std::string &stream_id,
            std::string &error);
  bool append(const RtppRecordHeader &header, const uint8_t *payload);
  bool finalize(std::string &error);

  const std::string &path() const { return path_; }
  const std::vector<uint64_t> &record_offsets() const {
    return record_offsets_;
  }
  const std::vector<RtppRecordHeader> &record_headers() const {
    return record_headers_;
  }

 private:
  std::FILE *file_ = nullptr;
  std::string path_;
  uint64_t record_count_offset_ = 0;
  uint64_t next_record_offset_ = 0;
  std::vector<uint64_t> record_offsets_;
  std::vector<RtppRecordHeader> record_headers_;
};

// Reads records until EOF. A non-finalized file may contain records while its
// declared record count is still zero; that case is accepted intentionally.
bool read_rtpp_file(const std::string &path, RtppReadResult &result,
                    std::string &error);

}  // namespace layanalyzer::rtp
