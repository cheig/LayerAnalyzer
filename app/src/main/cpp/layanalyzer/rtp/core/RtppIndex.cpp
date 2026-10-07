#include "layanalyzer/rtp/core/RtppIndex.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>

namespace layanalyzer::rtp {
namespace {

constexpr char kMagic[4] = {'R', 'T', 'P', 'I'};
constexpr uint64_t kSequenceModulus = UINT64_C(0x100000000);
constexpr uint64_t kSequenceHalf = UINT64_C(0x80000000);

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

bool write_u64(std::FILE *file, uint64_t value) {
  const uint8_t bytes[8] = {
      static_cast<uint8_t>(value & 0xffu),
      static_cast<uint8_t>((value >> 8u) & 0xffu),
      static_cast<uint8_t>((value >> 16u) & 0xffu),
      static_cast<uint8_t>((value >> 24u) & 0xffu),
      static_cast<uint8_t>((value >> 32u) & 0xffu),
      static_cast<uint8_t>((value >> 40u) & 0xffu),
      static_cast<uint8_t>((value >> 48u) & 0xffu),
      static_cast<uint8_t>((value >> 56u) & 0xffu),
  };
  return write_bytes(file, bytes, sizeof(bytes));
}

bool read_bytes(std::FILE *file, void *data, size_t length) {
  return length == 0 || std::fread(data, 1, length, file) == length;
}

bool read_u16(std::FILE *file, uint16_t &value) {
  uint8_t bytes[2];
  if (!read_bytes(file, bytes, sizeof(bytes))) return false;
  value = static_cast<uint16_t>(bytes[0]) |
          static_cast<uint16_t>(static_cast<uint16_t>(bytes[1]) << 8u);
  return true;
}

bool read_u32(std::FILE *file, uint32_t &value) {
  uint8_t bytes[4];
  if (!read_bytes(file, bytes, sizeof(bytes))) return false;
  value = static_cast<uint32_t>(bytes[0]) |
          (static_cast<uint32_t>(bytes[1]) << 8u) |
          (static_cast<uint32_t>(bytes[2]) << 16u) |
          (static_cast<uint32_t>(bytes[3]) << 24u);
  return true;
}

bool read_u64(std::FILE *file, uint64_t &value) {
  uint8_t bytes[8];
  if (!read_bytes(file, bytes, sizeof(bytes))) return false;
  value = static_cast<uint64_t>(bytes[0]) |
          (static_cast<uint64_t>(bytes[1]) << 8u) |
          (static_cast<uint64_t>(bytes[2]) << 16u) |
          (static_cast<uint64_t>(bytes[3]) << 24u) |
          (static_cast<uint64_t>(bytes[4]) << 32u) |
          (static_cast<uint64_t>(bytes[5]) << 40u) |
          (static_cast<uint64_t>(bytes[6]) << 48u) |
          (static_cast<uint64_t>(bytes[7]) << 56u);
  return true;
}

int64_t unwrapped_sequence(uint32_t sequence, uint32_t anchor) {
  int64_t value = static_cast<int64_t>(sequence);
  const int64_t anchor_value = static_cast<int64_t>(anchor);
  const int64_t delta = value - anchor_value;
  if (delta > static_cast<int64_t>(kSequenceHalf)) {
    value -= static_cast<int64_t>(kSequenceModulus);
  } else if (delta < -static_cast<int64_t>(kSequenceHalf)) {
    value += static_cast<int64_t>(kSequenceModulus);
  }
  return value;
}

}  // namespace

std::vector<RtppIndexEntry> build_sequence_index(
    const std::vector<RtppRecordHeader> &headers) {
  return build_sequence_index(headers, std::vector<uint64_t>{});
}

std::vector<RtppIndexEntry> build_sequence_index(
    const std::vector<RtppRecordHeader> &headers,
    const std::vector<uint64_t> &record_offsets) {
  if (headers.empty()) return {};
  if (!record_offsets.empty() && record_offsets.size() != headers.size()) {
    return {};
  }

  struct Candidate {
    size_t record_index = 0;
    uint32_t ext_seq = 0;
    double arrival_rel_sec = 0.0;
  };

  std::map<uint32_t, Candidate> latest_by_sequence;
  for (size_t index = 0; index < headers.size(); ++index) {
    const RtppRecordHeader &header = headers[index];
    auto found = latest_by_sequence.find(header.ext_seq);
    if (found == latest_by_sequence.end() ||
        header.arrival_rel_sec > found->second.arrival_rel_sec) {
      latest_by_sequence[header.ext_seq] =
          Candidate{index, header.ext_seq, header.arrival_rel_sec};
    }
  }

  std::vector<Candidate> ordered;
  ordered.reserve(latest_by_sequence.size());
  for (const auto &entry : latest_by_sequence) {
    ordered.push_back(entry.second);
  }

  const uint32_t anchor = headers.front().ext_seq;
  std::sort(ordered.begin(), ordered.end(),
            [anchor](const Candidate &left, const Candidate &right) {
              const int64_t left_key =
                  unwrapped_sequence(left.ext_seq, anchor);
              const int64_t right_key =
                  unwrapped_sequence(right.ext_seq, anchor);
              if (left_key != right_key) return left_key < right_key;
              return left.record_index < right.record_index;
            });

  std::vector<RtppIndexEntry> result;
  result.reserve(ordered.size());
  for (const Candidate &candidate : ordered) {
    RtppIndexEntry entry;
    entry.offset = record_offsets.empty() ? 0 : record_offsets[candidate.record_index];
    entry.length = headers[candidate.record_index].len;
    entry.record_index = static_cast<uint16_t>(candidate.record_index);
    result.push_back(entry);
  }
  return result;
}

bool write_rtpp_index(const std::string &path,
                      const std::vector<RtppIndexEntry> &entries,
                      std::string &error) {
  error.clear();
  if (path.empty()) {
    error = "RTPP index path is empty.";
    return false;
  }
  if (entries.size() > std::numeric_limits<uint32_t>::max()) {
    error = "RTPP index entry count is too large.";
    return false;
  }

  std::FILE *file = std::fopen(path.c_str(), "wb");
  if (!file) {
    error = "Unable to open RTPP index file.";
    return false;
  }

  bool ok = write_bytes(file, kMagic, sizeof(kMagic)) &&
            write_u32(file, static_cast<uint32_t>(entries.size()));
  for (const RtppIndexEntry &entry : entries) {
    if (!ok) break;
    ok = write_u64(file, entry.offset) &&
         write_u32(file, entry.length) &&
         write_u16(file, entry.record_index);
  }
  if (ok && std::fflush(file) != 0) ok = false;
  if (std::fclose(file) != 0) ok = false;
  if (!ok) {
    std::remove(path.c_str());
    error = "Unable to write RTPP index file.";
    return false;
  }
  return true;
}

bool read_rtpp_index(const std::string &path,
                     std::vector<RtppIndexEntry> &entries,
                     std::string &error) {
  entries.clear();
  error.clear();

  std::FILE *file = std::fopen(path.c_str(), "rb");
  if (!file) {
    error = "Unable to open RTPP index file.";
    return false;
  }

  char magic[4] = {};
  uint32_t count = 0;
  if (!read_bytes(file, magic, sizeof(magic)) ||
      std::memcmp(magic, kMagic, sizeof(kMagic)) != 0 ||
      !read_u32(file, count)) {
    error = "Invalid RTPP index header.";
    std::fclose(file);
    return false;
  }

  entries.reserve(count);
  for (uint32_t index = 0; index < count; ++index) {
    RtppIndexEntry entry;
    if (!read_u64(file, entry.offset) ||
        !read_u32(file, entry.length) ||
        !read_u16(file, entry.record_index)) {
      error = "Truncated RTPP index file.";
      std::fclose(file);
      entries.clear();
      return false;
    }
    entries.push_back(entry);
  }

  std::fclose(file);
  return true;
}

}  // namespace layanalyzer::rtp
