// Sequence-ordered index for an RTPP payload file.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/core/RtppFile.h"

namespace layanalyzer::rtp {

struct RtppIndexEntry {
  uint64_t offset = 0;
  uint32_t length = 0;
  uint16_t record_index = 0;
};

// The header-only overload has no file-offset input, so each entry's offset is
// zero. RtpPayloadExtractor uses the overload below to substitute the absolute
// record offsets captured by RtppWriter.
std::vector<RtppIndexEntry> build_sequence_index(
    const std::vector<RtppRecordHeader> &headers);

std::vector<RtppIndexEntry> build_sequence_index(
    const std::vector<RtppRecordHeader> &headers,
    const std::vector<uint64_t> &record_offsets);

bool write_rtpp_index(const std::string &path,
                      const std::vector<RtppIndexEntry> &entries,
                      std::string &error);

bool read_rtpp_index(const std::string &path,
                     std::vector<RtppIndexEntry> &entries,
                     std::string &error);

}  // namespace layanalyzer::rtp
