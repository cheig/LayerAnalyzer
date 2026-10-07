// RTP4-NAT-06: `.fidx` frame index format host tests.

#include "doctest.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "layanalyzer/rtp/core/FidxFile.h"

using layanalyzer::rtp::FidxEntry;
using layanalyzer::rtp::kFidxFlagLate;
using layanalyzer::rtp::kFidxFlagLost;
using layanalyzer::rtp::kFidxFlagSid;
using layanalyzer::rtp::kFidxRecordSize;
using layanalyzer::rtp::read_fidx_file;
using layanalyzer::rtp::write_fidx_file;

namespace {

class TempFile {
 public:
  explicit TempFile(const std::string &suffix) {
    static std::atomic<uint64_t> sequence{0};
    const uint64_t tick = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    path_ = (std::filesystem::temp_directory_path() /
             ("layanalyzer_fidx_" + std::to_string(tick) + "_" +
              std::to_string(sequence.fetch_add(1)) + suffix))
                .string();
    std::remove(path_.c_str());
  }

  ~TempFile() {
    std::remove(path_.c_str());
  }

  const std::string &path() const { return path_; }

 private:
  std::string path_;
};

std::vector<uint8_t> read_all(const std::string &path) {
  std::vector<uint8_t> bytes;
  std::FILE *file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) return bytes;
  uint8_t buffer[64];
  size_t read = 0;
  while ((read = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
    bytes.insert(bytes.end(), buffer, buffer + read);
  }
  std::fclose(file);
  return bytes;
}

void write_all(const std::string &path, const std::vector<uint8_t> &bytes) {
  std::FILE *file = std::fopen(path.c_str(), "wb");
  if (file == nullptr) return;
  if (!bytes.empty()) {
    std::fwrite(bytes.data(), 1, bytes.size(), file);
  }
  std::fclose(file);
}

FidxEntry entry(uint64_t offset, uint32_t length, uint32_t frame,
                uint64_t ext_ts, double arrival_rel, uint8_t flags) {
  FidxEntry value;
  value.offset = offset;
  value.length = length;
  value.frame = frame;
  value.ext_ts = ext_ts;
  value.arrival_rel = arrival_rel;
  value.flags = flags;
  return value;
}

}  // namespace

TEST_CASE("FidxFile round-trips every field including all flag bits") {
  TempFile file(".fidx");
  // 0.1 is not exactly representable in binary, so the double has to survive
  // as a bit pattern rather than as "close enough".
  const double kInexactArrival = 0.1;
  const std::vector<FidxEntry> written = {
      entry(0, 32, 12, 160, 0.0, 0x00),
      entry(32, 33, 13, 320, kInexactArrival,
            static_cast<uint8_t>(kFidxFlagLost | kFidxFlagSid | kFidxFlagLate)),
      entry(65, 0, 14, 480, 0.375, kFidxFlagLost),
      entry(65, 1, 15, 0x100000001ULL, 12.5, kFidxFlagSid),
  };

  std::string error;
  REQUIRE(write_fidx_file(file.path(), written, error));
  CHECK(error.empty());

  std::vector<FidxEntry> read;
  REQUIRE(read_fidx_file(file.path(), read, error));
  CHECK(error.empty());
  REQUIRE_EQ(read.size(), written.size());

  for (size_t index = 0; index < written.size(); ++index) {
    CHECK_EQ(read[index].offset, written[index].offset);
    CHECK_EQ(read[index].length, written[index].length);
    CHECK_EQ(read[index].frame, written[index].frame);
    CHECK_EQ(read[index].ext_ts, written[index].ext_ts);
    // Bit-exact: the same double literal, not an epsilon comparison.
    CHECK(read[index].arrival_rel == written[index].arrival_rel);
    CHECK_EQ(static_cast<int>(read[index].flags),
             static_cast<int>(written[index].flags));
  }
  // The value itself, spelled out, so a change to read_double/write_double
  // cannot hide behind "the same literal on both sides".
  CHECK(read[1].arrival_rel == 0.1);
}

TEST_CASE("FidxFile writes the frozen 33-octet record layout") {
  TempFile file(".fidx");
  const std::vector<FidxEntry> written = {
      entry(0x0102030405060708ULL, 0x0A0B0C0DU, 0x11223344U,
            0x1112131415161718ULL, 0.1, 0x07),
      entry(0, 0, 0, 0, 0.0, 0),
  };

  std::string error;
  REQUIRE(write_fidx_file(file.path(), written, error));
  CHECK(error.empty());

  const std::vector<uint8_t> bytes = read_all(file.path());
  // 4 magic + 4 count + 2 x 33 octets, packed, no padding anywhere.
  REQUIRE_EQ(bytes.size(), static_cast<size_t>(8 + 2 * kFidxRecordSize));
  CHECK_EQ(kFidxRecordSize, static_cast<uint64_t>(33));

  const std::vector<uint8_t> expected = {
      // "FID1"
      0x46, 0x49, 0x44, 0x31,
      // u32 count = 2
      0x02, 0x00, 0x00, 0x00,
      // record 0 ...
      0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,  // u64 offset
      0x0D, 0x0C, 0x0B, 0x0A,                          // u32 length
      0x44, 0x33, 0x22, 0x11,                          // u32 frame (before extTs)
      0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,  // u64 extTs
      0x9A, 0x99, 0x99, 0x99, 0x99, 0x99, 0xB9, 0x3F,  // f64 0.1, little-endian
      0x07,                                            // u8 flags
      // record 1: all zero except the flags octet
      0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,
      0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,
      0x00,
  };
  CHECK(bytes == expected);
}

TEST_CASE("FidxFile round-trips an empty entry list") {
  TempFile file(".fidx");
  std::string error;
  REQUIRE(write_fidx_file(file.path(), std::vector<FidxEntry>{}, error));
  CHECK(error.empty());

  const std::vector<uint8_t> bytes = read_all(file.path());
  REQUIRE_EQ(bytes.size(), static_cast<size_t>(8));
  CHECK_EQ(bytes[0], static_cast<uint8_t>('F'));
  CHECK_EQ(bytes[1], static_cast<uint8_t>('I'));
  CHECK_EQ(bytes[2], static_cast<uint8_t>('D'));
  CHECK_EQ(bytes[3], static_cast<uint8_t>('1'));
  CHECK_EQ(bytes[4], static_cast<uint8_t>(0));
  CHECK_EQ(bytes[5], static_cast<uint8_t>(0));
  CHECK_EQ(bytes[6], static_cast<uint8_t>(0));
  CHECK_EQ(bytes[7], static_cast<uint8_t>(0));

  std::vector<FidxEntry> read;
  REQUIRE(read_fidx_file(file.path(), read, error));
  CHECK(error.empty());
  CHECK(read.empty());
}

TEST_CASE("FidxFile round-trips a zero-length lost entry") {
  TempFile file(".fidx");
  const std::vector<FidxEntry> written = {
      entry(0, 32, 7, 160, 0.02, 0x00),
      // The "no frame at this slot" placeholder: no octets in .frames, but it
      // still occupies a slot and advances the timeline.
      entry(32, 0, 9, 320, 0.06, kFidxFlagLost),
      entry(32, 31, 11, 480, 0.08, 0x00),
  };

  std::string error;
  REQUIRE(write_fidx_file(file.path(), written, error));

  std::vector<FidxEntry> read;
  REQUIRE(read_fidx_file(file.path(), read, error));
  CHECK(error.empty());
  REQUIRE_EQ(read.size(), static_cast<size_t>(3));
  CHECK_EQ(read[1].length, static_cast<uint32_t>(0));
  CHECK_EQ(static_cast<int>(read[1].flags),
           static_cast<int>(kFidxFlagLost));
  CHECK_EQ(read[1].offset, read[2].offset);
  CHECK_EQ(read[2].length, static_cast<uint32_t>(31));
}

TEST_CASE("FidxFile rejects a bad magic") {
  TempFile file(".fidx");
  // A valid-looking header whose magic is one octet off.
  write_all(file.path(),
            {'F', 'I', 'D', '2', 0x00, 0x00, 0x00, 0x00});

  std::vector<FidxEntry> read;
  std::string error;
  CHECK_FALSE(read_fidx_file(file.path(), read, error));
  CHECK_FALSE(error.empty());
  CHECK(read.empty());
}

TEST_CASE("FidxFile rejects a truncated header") {
  TempFile file(".fidx");

  // Fewer octets than the magic itself.
  write_all(file.path(), {'F', 'I'});
  std::vector<FidxEntry> read;
  std::string error;
  CHECK_FALSE(read_fidx_file(file.path(), read, error));
  CHECK_FALSE(error.empty());
  CHECK(read.empty());

  // Magic present, count cut in half.
  write_all(file.path(), {'F', 'I', 'D', '1', 0x01, 0x00});
  read.clear();
  error.clear();
  CHECK_FALSE(read_fidx_file(file.path(), read, error));
  CHECK_FALSE(error.empty());
  CHECK(read.empty());
}

TEST_CASE("FidxFile rejects a count larger than the file holds") {
  TempFile file(".fidx");
  const std::vector<FidxEntry> written = {entry(0, 4, 1, 160, 0.0, 0x00)};
  std::string error;
  REQUIRE(write_fidx_file(file.path(), written, error));

  std::vector<uint8_t> bytes = read_all(file.path());
  REQUIRE_EQ(bytes.size(), static_cast<size_t>(8 + kFidxRecordSize));
  // Claim two records while only one is present.
  bytes[4] = 0x02;
  write_all(file.path(), bytes);

  std::vector<FidxEntry> read;
  error.clear();
  CHECK_FALSE(read_fidx_file(file.path(), read, error));
  CHECK_FALSE(error.empty());
  CHECK(read.empty());
}

TEST_CASE("FidxFile rejects a truncated record") {
  TempFile file(".fidx");
  const std::vector<FidxEntry> written = {entry(0, 4, 1, 160, 0.0, 0x00)};
  std::string error;
  REQUIRE(write_fidx_file(file.path(), written, error));

  std::vector<uint8_t> bytes = read_all(file.path());
  REQUIRE_GT(bytes.size(), static_cast<size_t>(8));
  // Drop the trailing flags octet of the only record.
  bytes.pop_back();
  write_all(file.path(), bytes);

  std::vector<FidxEntry> read;
  error.clear();
  CHECK_FALSE(read_fidx_file(file.path(), read, error));
  CHECK_FALSE(error.empty());
  CHECK(read.empty());
}
