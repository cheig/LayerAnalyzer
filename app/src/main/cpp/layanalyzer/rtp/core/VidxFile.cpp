#include "layanalyzer/rtp/core/VidxFile.h"

#include <cstdio>
#include <cstring>
#include <limits>

namespace layanalyzer::rtp {
namespace {

constexpr char kMagic[4] = {'V', 'I', 'D', '1'};

bool write_bytes(std::FILE *file, const void *data, size_t length) {
  return length == 0 || std::fwrite(data, 1, length, file) == length;
}

bool write_u8(std::FILE *file, uint8_t value) {
  return write_bytes(file, &value, sizeof(value));
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

bool read_u8(std::FILE *file, uint8_t &value) {
  return read_bytes(file, &value, sizeof(value));
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

// The record as the format spells it: offset, len, ptsUs, firstFrame, flags --
// u64, u32, u64, u32, u8. Written and read through these two helpers only, so
// the field order lives in exactly one place per direction and neither side can
// drift into struct-copy padding (see the header).
bool write_record(std::FILE *file, const VidxEntry &entry) {
  return write_u64(file, entry.offset) && write_u32(file, entry.length) &&
         write_u64(file, entry.pts_us) && write_u32(file, entry.first_frame) &&
         write_u8(file, entry.flags);
}

bool read_record(std::FILE *file, VidxEntry &entry) {
  return read_u64(file, entry.offset) && read_u32(file, entry.length) &&
         read_u64(file, entry.pts_us) && read_u32(file, entry.first_frame) &&
         read_u8(file, entry.flags);
}

}  // namespace

bool write_vidx_file(const std::string &path,
                     const std::vector<VidxEntry> &entries, std::string &error) {
  error.clear();
  if (path.empty()) {
    error = "VIDX path is empty.";
    return false;
  }
  if (entries.size() > std::numeric_limits<uint32_t>::max()) {
    error = "VIDX entry count is too large.";
    return false;
  }

  std::FILE *file = std::fopen(path.c_str(), "wb");
  if (!file) {
    error = "Unable to open VIDX file.";
    return false;
  }

  bool ok = write_bytes(file, kMagic, sizeof(kMagic)) &&
            write_u32(file, static_cast<uint32_t>(entries.size()));
  for (const VidxEntry &entry : entries) {
    if (!ok) break;
    ok = write_record(file, entry);
  }
  if (ok && std::fflush(file) != 0) ok = false;
  if (std::fclose(file) != 0) ok = false;
  if (!ok) {
    std::remove(path.c_str());
    error = "Unable to write VIDX file.";
    return false;
  }
  return true;
}

bool read_vidx_file(const std::string &path, std::vector<VidxEntry> &entries,
                    std::string &error) {
  entries.clear();
  error.clear();
  if (path.empty()) {
    error = "VIDX path is empty.";
    return false;
  }

  std::FILE *file = std::fopen(path.c_str(), "rb");
  if (!file) {
    error = "Unable to open VIDX file.";
    return false;
  }

  char magic[4] = {};
  if (!read_bytes(file, magic, sizeof(magic))) {
    error = "Truncated VIDX header.";
    std::fclose(file);
    return false;
  }
  if (std::memcmp(magic, kMagic, sizeof(kMagic)) != 0) {
    error = "Invalid VIDX magic.";
    std::fclose(file);
    return false;
  }

  uint32_t count = 0;
  if (!read_u32(file, count)) {
    error = "Truncated VIDX header.";
    std::fclose(file);
    return false;
  }

  // Reject a count the file cannot hold before reserve() can be asked for
  // gigabytes. A truncated record reports the same error, which is what the
  // caller sees either way.
  const long header_end = std::ftell(file);
  if (header_end < 0 || std::fseek(file, 0, SEEK_END) != 0) {
    error = "Unable to read VIDX file.";
    std::fclose(file);
    return false;
  }
  const long file_size = std::ftell(file);
  const bool positioned =
      file_size >= header_end && std::fseek(file, header_end, SEEK_SET) == 0;
  if (!positioned) {
    error = "Unable to read VIDX file.";
    std::fclose(file);
    return false;
  }
  const uint64_t available = static_cast<uint64_t>(file_size - header_end);
  if (static_cast<uint64_t>(count) > available / kVidxRecordSize) {
    error = "Truncated VIDX record.";
    std::fclose(file);
    return false;
  }

  entries.reserve(count);
  for (uint32_t index = 0; index < count; ++index) {
    VidxEntry entry;
    if (!read_record(file, entry)) {
      error = "Truncated VIDX record.";
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
