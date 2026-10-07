// RTP5-NAT-03: `.vidx` access-unit index format host tests.
//
// The format is frozen by the RTP5-NAT-03 card and task_rtp_m5_video.md section
// 3.2, and RTP5-KT-01 / RTP5-KT-03 read the same file from Kotlin, so the octets
// matter more than the values: the byte-level case below spells the whole file
// out, which is the only thing that catches a writer and a reader that agree
// with each other but not with the format. The specific trap here is that
// `ptsUs` is a u64 between two u32s, so a struct copy would insert padding and
// write 32 octets per record where the format says 25.
//
// Case names all start with "VidxFile" so that
// `run_host_tests.ps1 -Test "*Vidx*"` selects exactly this file's cases.
#include "doctest.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "layanalyzer/rtp/core/VidxFile.h"

using layanalyzer::rtp::kVidxFlagCorrupt;
using layanalyzer::rtp::kVidxFlagKey;
using layanalyzer::rtp::kVidxFlagParamSets;
using layanalyzer::rtp::kVidxRecordSize;
using layanalyzer::rtp::read_vidx_file;
using layanalyzer::rtp::VidxEntry;
using layanalyzer::rtp::write_vidx_file;

namespace {

class TempFile {
 public:
  explicit TempFile(const std::string &suffix) {
    static std::atomic<uint64_t> sequence{0};
    const uint64_t tick = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    path_ = (std::filesystem::temp_directory_path() /
             ("layanalyzer_vidx_" + std::to_string(tick) + "_" +
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

VidxEntry entry(uint64_t offset, uint32_t length, uint64_t pts_us,
                uint32_t first_frame, uint8_t flags) {
  VidxEntry value;
  value.offset = offset;
  value.length = length;
  value.pts_us = pts_us;
  value.first_frame = first_frame;
  value.flags = flags;
  return value;
}

}  // namespace

TEST_CASE("VidxFile round-trips every field including all flag bits") {
  TempFile file(".vidx");
  const std::vector<VidxEntry> written = {
      entry(0, 7, 0, 12, 0x00),
      entry(7, 7, 33333, 13,
            static_cast<uint8_t>(kVidxFlagKey | kVidxFlagCorrupt |
                                 kVidxFlagParamSets)),
      entry(14, 7, 66666, 15, kVidxFlagKey),
      // Above 32 bits in both of the wide fields, and an offset that is not a
      // multiple of anything.
      entry(0x100000001ULL, 0xFFFFFFFEU, 0x200000003ULL, 0xFFFFFFFFU,
            kVidxFlagCorrupt),
  };

  std::string error;
  REQUIRE(write_vidx_file(file.path(), written, error));
  CHECK(error.empty());

  std::vector<VidxEntry> read;
  REQUIRE(read_vidx_file(file.path(), read, error));
  CHECK(error.empty());
  REQUIRE_EQ(read.size(), written.size());

  for (size_t index = 0; index < written.size(); ++index) {
    CHECK_EQ(read[index].offset, written[index].offset);
    CHECK_EQ(read[index].length, written[index].length);
    CHECK_EQ(read[index].pts_us, written[index].pts_us);
    CHECK_EQ(read[index].first_frame, written[index].first_frame);
    CHECK_EQ(static_cast<int>(read[index].flags),
             static_cast<int>(written[index].flags));
  }
  // The flag bits themselves, spelled out, because they are what NAT-05 copies
  // over from VideoAuRecord and KT-01 reads back as "key frame".
  CHECK_EQ(static_cast<int>(kVidxFlagKey), 0x01);
  CHECK_EQ(static_cast<int>(kVidxFlagCorrupt), 0x02);
  CHECK_EQ(static_cast<int>(kVidxFlagParamSets), 0x04);
}

TEST_CASE("VidxFile writes the frozen 25-octet record layout") {
  TempFile file(".vidx");
  const std::vector<VidxEntry> written = {
      entry(0x0102030405060708ULL, 0x0A0B0C0DU, 0x1112131415161718ULL,
            0x21222324U, 0x07),
      entry(0, 0, 0, 0, 0),
  };

  std::string error;
  REQUIRE(write_vidx_file(file.path(), written, error));
  CHECK(error.empty());

  const std::vector<uint8_t> bytes = read_all(file.path());
  // 4 magic + 4 count + 2 x 25 octets, packed, no padding anywhere.
  REQUIRE_EQ(bytes.size(), static_cast<size_t>(8 + 2 * kVidxRecordSize));
  CHECK_EQ(kVidxRecordSize, static_cast<uint64_t>(25));

  const std::vector<uint8_t> expected = {
      // "VID1"
      0x56, 0x49, 0x44, 0x31,
      // u32 count = 2
      0x02, 0x00, 0x00, 0x00,
      // record 0 ...
      0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,  // u64 offset
      0x0D, 0x0C, 0x0B, 0x0A,                          // u32 len
      0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,  // u64 ptsUs (after len)
      0x24, 0x23, 0x22, 0x21,                          // u32 firstFrame
      0x07,                                            // u8 flags
      // record 1: all zero except the flags octet
      0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,
      0x00,
  };
  CHECK(bytes == expected);
}

TEST_CASE("VidxFile round-trips an empty entry list") {
  TempFile file(".vidx");
  std::string error;
  REQUIRE(write_vidx_file(file.path(), std::vector<VidxEntry>{}, error));
  CHECK(error.empty());

  const std::vector<uint8_t> bytes = read_all(file.path());
  REQUIRE_EQ(bytes.size(), static_cast<size_t>(8));
  CHECK_EQ(bytes[0], static_cast<uint8_t>('V'));
  CHECK_EQ(bytes[1], static_cast<uint8_t>('I'));
  CHECK_EQ(bytes[2], static_cast<uint8_t>('D'));
  CHECK_EQ(bytes[3], static_cast<uint8_t>('1'));
  CHECK_EQ(bytes[4], static_cast<uint8_t>(0));
  CHECK_EQ(bytes[5], static_cast<uint8_t>(0));
  CHECK_EQ(bytes[6], static_cast<uint8_t>(0));
  CHECK_EQ(bytes[7], static_cast<uint8_t>(0));

  std::vector<VidxEntry> read;
  REQUIRE(read_vidx_file(file.path(), read, error));
  CHECK(error.empty());
  CHECK(read.empty());
}

TEST_CASE("VidxFile rejects a bad magic") {
  TempFile file(".vidx");
  // A valid-looking header whose magic is one octet off.
  write_all(file.path(), {'V', 'I', 'D', '2', 0x00, 0x00, 0x00, 0x00});

  std::vector<VidxEntry> read;
  std::string error;
  CHECK_FALSE(read_vidx_file(file.path(), read, error));
  CHECK_FALSE(error.empty());
  CHECK(read.empty());
}

TEST_CASE("VidxFile rejects a truncated header") {
  TempFile file(".vidx");

  // Fewer octets than the magic itself.
  write_all(file.path(), {'V', 'I'});
  std::vector<VidxEntry> read;
  std::string error;
  CHECK_FALSE(read_vidx_file(file.path(), read, error));
  CHECK_FALSE(error.empty());
  CHECK(read.empty());

  // Magic present, count cut in half.
  write_all(file.path(), {'V', 'I', 'D', '1', 0x01, 0x00});
  read.clear();
  error.clear();
  CHECK_FALSE(read_vidx_file(file.path(), read, error));
  CHECK_FALSE(error.empty());
  CHECK(read.empty());
}

TEST_CASE("VidxFile rejects a count larger than the file holds") {
  TempFile file(".vidx");
  const std::vector<VidxEntry> written = {entry(0, 4, 0, 1, 0x00)};
  std::string error;
  REQUIRE(write_vidx_file(file.path(), written, error));

  std::vector<uint8_t> bytes = read_all(file.path());
  REQUIRE_EQ(bytes.size(), static_cast<size_t>(8 + kVidxRecordSize));
  // Claim two records while only one is present.
  bytes[4] = 0x02;
  write_all(file.path(), bytes);

  std::vector<VidxEntry> read;
  error.clear();
  CHECK_FALSE(read_vidx_file(file.path(), read, error));
  CHECK_FALSE(error.empty());
  CHECK(read.empty());
}

TEST_CASE("VidxFile rejects a truncated record") {
  TempFile file(".vidx");
  const std::vector<VidxEntry> written = {entry(0, 4, 0, 1, 0x00)};
  std::string error;
  REQUIRE(write_vidx_file(file.path(), written, error));

  std::vector<uint8_t> bytes = read_all(file.path());
  REQUIRE_GT(bytes.size(), static_cast<size_t>(8));
  // Drop the trailing flags octet of the only record.
  bytes.pop_back();
  write_all(file.path(), bytes);

  std::vector<VidxEntry> read;
  error.clear();
  CHECK_FALSE(read_vidx_file(file.path(), read, error));
  CHECK_FALSE(error.empty());
  CHECK(read.empty());
}

TEST_CASE("VidxFile fails closed on an empty path and a missing file") {
  std::vector<VidxEntry> read;
  std::string error;
  CHECK_FALSE(read_vidx_file("", read, error));
  CHECK_FALSE(error.empty());
  CHECK_FALSE(write_vidx_file("", std::vector<VidxEntry>{}, error));
  CHECK_FALSE(error.empty());

  // A path that does not exist: write fails closed (and removes nothing that is
  // not there), read fails closed.
  TempFile file(".vidx");
  const std::string missing = file.path() + ".missing";
  std::remove(missing.c_str());
  error.clear();
  CHECK_FALSE(read_vidx_file(missing, read, error));
  CHECK_FALSE(error.empty());
}
