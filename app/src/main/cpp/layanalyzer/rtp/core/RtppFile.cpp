#include "layanalyzer/rtp/core/RtppFile.h"

#include <climits>
#include <cstring>
#include <limits>
#include <utility>

namespace layanalyzer::rtp {
namespace {

constexpr char kMagic[4] = {'R', 'T', 'P', 'P'};
constexpr uint32_t kVersion = 1;
constexpr uint32_t kMaxStreamIdLength = 1024 * 1024;

bool write_bytes(std::FILE *file, const void *data, size_t length) {
  return length == 0 || std::fwrite(data, 1, length, file) == length;
}

bool write_u8(std::FILE *file, uint8_t value) {
  return write_bytes(file, &value, sizeof(value));
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

bool read_u8(std::FILE *file, uint8_t &value) {
  return read_bytes(file, &value, sizeof(value));
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

bool write_double(std::FILE *file, double value) {
  uint64_t bits = 0;
  static_assert(sizeof(bits) == sizeof(value), "double must be 64 bits");
  std::memcpy(&bits, &value, sizeof(bits));
  return write_u64(file, bits);
}

bool read_double(std::FILE *file, double &value) {
  uint64_t bits = 0;
  if (!read_u64(file, bits)) return false;
  static_assert(sizeof(bits) == sizeof(value), "double must be 64 bits");
  std::memcpy(&value, &bits, sizeof(value));
  return true;
}

void close_file(std::FILE *&file) {
  if (file) {
    std::fclose(file);
    file = nullptr;
  }
}

}  // namespace

RtppWriter::~RtppWriter() {
  close_file(file_);
}

bool RtppWriter::open(const std::string &path, const std::string &stream_id,
                      std::string &error) {
  error.clear();
  if (file_) {
    error = "RTPP writer is already open.";
    return false;
  }
  if (path.empty()) {
    error = "RTPP path is empty.";
    return false;
  }
  if (stream_id.size() > std::numeric_limits<uint32_t>::max()) {
    error = "RTPP stream id is too long.";
    return false;
  }

  file_ = std::fopen(path.c_str(), "wb");
  if (!file_) {
    error = "Unable to open RTPP file.";
    return false;
  }

  path_ = path;
  record_offsets_.clear();
  record_headers_.clear();
  next_record_offset_ = 0;
  record_count_offset_ = 0;

  const uint32_t stream_id_length = static_cast<uint32_t>(stream_id.size());
  bool ok = write_bytes(file_, kMagic, sizeof(kMagic)) &&
            write_u32(file_, kVersion) &&
            write_u32(file_, stream_id_length) &&
            write_bytes(file_, stream_id.data(), stream_id.size());
  record_count_offset_ =
      static_cast<uint64_t>(sizeof(kMagic)) + 4u + 4u + stream_id_length;
  ok = ok && write_u32(file_, 0);
  if (!ok) {
    close_file(file_);
    std::remove(path.c_str());
    error = "Unable to write RTPP header.";
    return false;
  }

  next_record_offset_ =
      static_cast<uint64_t>(sizeof(kMagic)) + 4u + 4u + stream_id_length + 4u;
  return true;
}

bool RtppWriter::append(const RtppRecordHeader &header,
                        const uint8_t *payload) {
  if (!file_) return false;
  if (header.len > 0 && payload == nullptr) return false;

  const uint64_t record_offset = next_record_offset_;
  const bool ok =
      write_u32(file_, header.frame) &&
      write_double(file_, header.arrival_rel_sec) &&
      write_u32(file_, header.ext_seq) &&
      write_u64(file_, header.ext_ts) &&
      write_u8(file_, header.pt) &&
      write_u8(file_, header.marker) &&
      write_u16(file_, header.len) &&
      write_bytes(file_, payload, header.len);
  if (!ok) return false;

  record_offsets_.push_back(record_offset);
  record_headers_.push_back(header);
  next_record_offset_ += kRtppRecordHeaderSize + header.len;
  return true;
}

bool RtppWriter::finalize(std::string &error) {
  error.clear();
  if (!file_) {
    error = "RTPP writer is not open.";
    return false;
  }
  if (record_headers_.size() > std::numeric_limits<uint32_t>::max()) {
    error = "RTPP record count is too large.";
    close_file(file_);
    return false;
  }
  if (record_count_offset_ > static_cast<uint64_t>(LONG_MAX)) {
    error = "RTPP header offset is too large.";
    close_file(file_);
    return false;
  }
  if (std::fseek(file_, static_cast<long>(record_count_offset_), SEEK_SET) != 0) {
    error = "Unable to seek to RTPP record count.";
    close_file(file_);
    return false;
  }
  if (!write_u32(file_, static_cast<uint32_t>(record_headers_.size()))) {
    error = "Unable to write RTPP record count.";
    close_file(file_);
    return false;
  }
  if (std::fflush(file_) != 0) {
    error = "Unable to flush RTPP file.";
    close_file(file_);
    return false;
  }
  if (std::fclose(file_) != 0) {
    file_ = nullptr;
    error = "Unable to close RTPP file.";
    return false;
  }
  file_ = nullptr;
  return true;
}

bool read_rtpp_file(const std::string &path, RtppReadResult &result,
                    std::string &error) {
  result = RtppReadResult{};
  error.clear();

  std::FILE *file = std::fopen(path.c_str(), "rb");
  if (!file) {
    error = "Unable to open RTPP file.";
    return false;
  }

  char magic[4] = {};
  uint32_t version = 0;
  uint32_t stream_id_length = 0;
  if (!read_bytes(file, magic, sizeof(magic)) ||
      std::memcmp(magic, kMagic, sizeof(kMagic)) != 0 ||
      !read_u32(file, version) || version != kVersion ||
      !read_u32(file, stream_id_length) ||
      stream_id_length > kMaxStreamIdLength) {
    error = "Invalid RTPP header.";
    close_file(file);
    return false;
  }

  result.stream_id.resize(stream_id_length);
  if (!read_bytes(file, result.stream_id.data(), stream_id_length) ||
      !read_u32(file, result.declared_record_count)) {
    error = "Truncated RTPP header.";
    close_file(file);
    return false;
  }

  while (true) {
    uint8_t first_byte = 0;
    const size_t first_read = std::fread(&first_byte, 1, 1, file);
    if (first_read == 0) {
      if (std::feof(file)) break;
      error = "Unable to read RTPP record.";
      close_file(file);
      return false;
    }

    uint8_t frame_bytes[4] = {first_byte, 0, 0, 0};
    if (!read_bytes(file, frame_bytes + 1, 3)) {
      error = "Truncated RTPP record header.";
      close_file(file);
      return false;
    }

    RtppFileRecord record;
    record.header.frame = static_cast<uint32_t>(frame_bytes[0]) |
                          (static_cast<uint32_t>(frame_bytes[1]) << 8u) |
                          (static_cast<uint32_t>(frame_bytes[2]) << 16u) |
                          (static_cast<uint32_t>(frame_bytes[3]) << 24u);
    if (!read_double(file, record.header.arrival_rel_sec) ||
        !read_u32(file, record.header.ext_seq) ||
        !read_u64(file, record.header.ext_ts) ||
        !read_u8(file, record.header.pt) ||
        !read_u8(file, record.header.marker) ||
        !read_u16(file, record.header.len)) {
      error = "Truncated RTPP record header.";
      close_file(file);
      return false;
    }

    record.payload.resize(record.header.len);
    if (!read_bytes(file, record.payload.data(), record.payload.size())) {
      error = "Truncated RTPP payload.";
      close_file(file);
      return false;
    }
    result.records.push_back(std::move(record));
  }

  close_file(file);
  if (result.declared_record_count != 0 &&
      result.declared_record_count != result.records.size()) {
    error = "RTPP record count does not match the file.";
    return false;
  }
  return true;
}

}  // namespace layanalyzer::rtp
