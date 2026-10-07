// RTP2-NAT-01: `.rtpp` record format host tests.

#include "doctest.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "layanalyzer/rtp/core/RtppFile.h"

using layanalyzer::rtp::RtppReadResult;
using layanalyzer::rtp::RtppRecordHeader;
using layanalyzer::rtp::RtppWriter;

namespace {

class TempFile {
 public:
  explicit TempFile(const std::string &suffix) {
    static std::atomic<uint64_t> sequence{0};
    const uint64_t tick = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    path_ = (std::filesystem::temp_directory_path() /
             ("layanalyzer_" + std::to_string(tick) + "_" +
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

RtppRecordHeader record(uint32_t frame, double arrival, uint32_t sequence,
                        uint64_t timestamp, uint8_t pt, uint8_t marker,
                        uint16_t length) {
  RtppRecordHeader header;
  header.frame = frame;
  header.arrival_rel_sec = arrival;
  header.ext_seq = sequence;
  header.ext_ts = timestamp;
  header.pt = pt;
  header.marker = marker;
  header.len = length;
  return header;
}

}  // namespace

TEST_CASE("RtppFile writes and reads all fields and finalizes record count") {
  TempFile file(".rtpp");
  RtppWriter writer;
  std::string error;
  REQUIRE(writer.open(file.path(), "s0", error));

  const std::vector<RtppRecordHeader> headers = {
      record(1, 0.0, 10, 1000, 8, 0, 3),
      record(2, 0.125, 11, 1160, 8, 1, 2),
      record(3, 0.25, 12, 1320, 8, 0, 0),
      record(4, 0.375, 11, 1480, 8, 0, 4),
      record(5, 0.5, 13, 1640, 8, 1, 1),
  };
  const std::vector<std::vector<uint8_t>> payloads = {
      {0x01, 0x02, 0x03},
      {0xaa, 0xbb},
      {},
      {0x10, 0x20, 0x30, 0x40},
      {0xff},
  };

  for (size_t index = 0; index < headers.size(); ++index) {
    REQUIRE(writer.append(headers[index], payloads[index].data()));
  }
  REQUIRE(writer.finalize(error));
  CHECK(error.empty());

  RtppReadResult read;
  REQUIRE(read_rtpp_file(file.path(), read, error));
  CHECK(error.empty());
  CHECK_EQ(read.stream_id, std::string("s0"));
  CHECK_EQ(read.declared_record_count, static_cast<uint32_t>(headers.size()));
  REQUIRE_EQ(read.records.size(), headers.size());

  for (size_t index = 0; index < headers.size(); ++index) {
    const RtppRecordHeader &expected = headers[index];
    const RtppRecordHeader &actual = read.records[index].header;
    CHECK_EQ(actual.frame, expected.frame);
    CHECK(actual.arrival_rel_sec == expected.arrival_rel_sec);
    CHECK_EQ(actual.ext_seq, expected.ext_seq);
    CHECK_EQ(actual.ext_ts, expected.ext_ts);
    CHECK_EQ(actual.pt, expected.pt);
    CHECK_EQ(actual.marker, expected.marker);
    CHECK_EQ(actual.len, expected.len);
    CHECK(read.records[index].payload == payloads[index]);
  }
}

TEST_CASE("RtppFile remains readable when destructed without finalize") {
  TempFile file(".rtpp");
  {
    RtppWriter writer;
    std::string error;
    REQUIRE(writer.open(file.path(), "s1", error));
    REQUIRE(writer.append(record(10, 1.5, 100, 200, 0, 1, 2),
                          reinterpret_cast<const uint8_t *>("\x01\x02")));
    REQUIRE(writer.append(record(11, 1.52, 101, 360, 0, 0, 1),
                          reinterpret_cast<const uint8_t *>("\x03")));
    // No finalize: the destructor closes the file without deleting it.
  }

  RtppReadResult read;
  std::string error;
  REQUIRE(read_rtpp_file(file.path(), read, error));
  CHECK_EQ(read.declared_record_count, 0u);
  REQUIRE_EQ(read.records.size(), static_cast<size_t>(2));
  CHECK_EQ(read.records[0].header.frame, 10u);
  CHECK_EQ(read.records[1].header.frame, 11u);
}
