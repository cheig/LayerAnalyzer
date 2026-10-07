// RTP2-NAT-01: sequence index ordering and duplicate-resolution host tests.

#include "doctest.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "layanalyzer/rtp/core/RtppIndex.h"

using layanalyzer::rtp::RtppIndexEntry;
using layanalyzer::rtp::RtppRecordHeader;
using layanalyzer::rtp::build_sequence_index;
using layanalyzer::rtp::read_rtpp_index;
using layanalyzer::rtp::write_rtpp_index;

namespace {

class TempIndexFile {
 public:
  TempIndexFile() {
    static std::atomic<uint64_t> sequence{0};
    const uint64_t tick = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    path_ = (std::filesystem::temp_directory_path() /
             ("layanalyzer_" + std::to_string(tick) + "_" +
              std::to_string(sequence.fetch_add(1)) + ".rtpp.idx"))
                .string();
    std::remove(path_.c_str());
  }

  ~TempIndexFile() {
    std::remove(path_.c_str());
  }

  const std::string &path() const { return path_; }

 private:
  std::string path_;
};

RtppRecordHeader header(uint32_t sequence, double arrival, uint16_t length) {
  RtppRecordHeader value;
  value.ext_seq = sequence;
  value.arrival_rel_sec = arrival;
  value.len = length;
  return value;
}

}  // namespace

TEST_CASE("RtppIndex sorts sequential records") {
  const std::vector<RtppRecordHeader> headers = {
      header(10, 0.0, 1),
      header(20, 0.02, 2),
      header(30, 0.04, 3),
  };
  const std::vector<RtppIndexEntry> index = build_sequence_index(headers);
  REQUIRE_EQ(index.size(), static_cast<size_t>(3));
  CHECK_EQ(index[0].record_index, static_cast<uint16_t>(0));
  CHECK_EQ(index[0].length, 1u);
  CHECK_EQ(index[1].record_index, static_cast<uint16_t>(1));
  CHECK_EQ(index[1].length, 2u);
  CHECK_EQ(index[2].record_index, static_cast<uint16_t>(2));
  CHECK_EQ(index[2].length, 3u);
}

TEST_CASE("RtppIndex sorts out-of-order records by extended sequence") {
  const std::vector<RtppRecordHeader> headers = {
      header(30, 0.04, 3),
      header(10, 0.0, 1),
      header(20, 0.02, 2),
  };
  const std::vector<RtppIndexEntry> index = build_sequence_index(headers);
  REQUIRE_EQ(index.size(), static_cast<size_t>(3));
  CHECK_EQ(index[0].record_index, static_cast<uint16_t>(1));
  CHECK_EQ(index[1].record_index, static_cast<uint16_t>(2));
  CHECK_EQ(index[2].record_index, static_cast<uint16_t>(0));
}

TEST_CASE("RtppIndex duplicate sequence keeps the latest arrival") {
  const std::vector<RtppRecordHeader> headers = {
      header(20, 0.10, 2),
      header(10, 0.00, 1),
      header(20, 0.30, 5),
      header(30, 0.40, 3),
  };
  const std::vector<RtppIndexEntry> index = build_sequence_index(headers);
  REQUIRE_EQ(index.size(), static_cast<size_t>(3));
  CHECK_EQ(index[0].record_index, static_cast<uint16_t>(1));
  CHECK_EQ(index[1].record_index, static_cast<uint16_t>(2));
  CHECK_EQ(index[1].length, 5u);
  CHECK_EQ(index[2].record_index, static_cast<uint16_t>(3));
}

TEST_CASE("RtppIndex unwraps extended sequence around zero") {
  const std::vector<RtppRecordHeader> headers = {
      header(0x00000000u, 0.00, 1),
      header(0xFFFFFFFEu, 0.01, 2),
      header(0x00000001u, 0.02, 3),
      header(0xFFFFFFFFu, 0.03, 4),
  };
  const std::vector<RtppIndexEntry> index = build_sequence_index(headers);
  REQUIRE_EQ(index.size(), static_cast<size_t>(4));
  CHECK_EQ(index[0].record_index, static_cast<uint16_t>(1));  // FFFFFFFE
  CHECK_EQ(index[1].record_index, static_cast<uint16_t>(3));  // FFFFFFFF
  CHECK_EQ(index[2].record_index, static_cast<uint16_t>(0));  // 0
  CHECK_EQ(index[3].record_index, static_cast<uint16_t>(2));  // 1
}

TEST_CASE("RtppIndex writes absolute offsets and reads them back") {
  TempIndexFile file;
  const std::vector<RtppRecordHeader> headers = {
      header(30, 0.04, 3),
      header(10, 0.00, 1),
      header(20, 0.02, 2),
  };
  const std::vector<uint64_t> offsets = {300, 100, 200};
  const std::vector<RtppIndexEntry> index =
      build_sequence_index(headers, offsets);
  REQUIRE_EQ(index.size(), static_cast<size_t>(3));
  CHECK_EQ(index[0].offset, 100u);
  CHECK_EQ(index[1].offset, 200u);
  CHECK_EQ(index[2].offset, 300u);

  std::string error;
  REQUIRE(write_rtpp_index(file.path(), index, error));
  CHECK(error.empty());

  std::vector<RtppIndexEntry> read;
  REQUIRE(read_rtpp_index(file.path(), read, error));
  CHECK(error.empty());
  REQUIRE_EQ(read.size(), index.size());
  for (size_t position = 0; position < index.size(); ++position) {
    CHECK_EQ(read[position].offset, index[position].offset);
    CHECK_EQ(read[position].length, index[position].length);
    CHECK_EQ(read[position].record_index, index[position].record_index);
  }
}
