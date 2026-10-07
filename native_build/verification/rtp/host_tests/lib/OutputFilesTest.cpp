// RTP2-NAT-05: WAV, peaks, and frame map output format tests.

#include "doctest.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

#include "layanalyzer/rtp/core/FrameMapWriter.h"
#include "layanalyzer/rtp/core/PeaksBuilder.h"
#include "layanalyzer/rtp/core/WavWriter.h"

using layanalyzer::rtp::FrameMapWriter;
using layanalyzer::rtp::PeaksBuilder;
using layanalyzer::rtp::WavWriter;

namespace {

class TempFile {
 public:
  explicit TempFile(const std::string &suffix) {
    static std::atomic<uint64_t> sequence{0};
    const uint64_t tick = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    path_ = (std::filesystem::temp_directory_path() /
             ("layanalyzer_output_" + std::to_string(tick) + "_" +
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

std::vector<uint8_t> read_file(const std::string &path) {
  std::ifstream input(path, std::ios::binary);
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(input),
                              std::istreambuf_iterator<char>());
}

uint16_t read_u16(const std::vector<uint8_t> &bytes, size_t offset) {
  return static_cast<uint16_t>(bytes[offset]) |
         static_cast<uint16_t>(static_cast<uint16_t>(bytes[offset + 1]) << 8u);
}

uint32_t read_u32(const std::vector<uint8_t> &bytes, size_t offset) {
  return static_cast<uint32_t>(bytes[offset]) |
         (static_cast<uint32_t>(bytes[offset + 1]) << 8u) |
         (static_cast<uint32_t>(bytes[offset + 2]) << 16u) |
         (static_cast<uint32_t>(bytes[offset + 3]) << 24u);
}

int16_t read_i16(const std::vector<uint8_t> &bytes, size_t offset) {
  const uint16_t value = read_u16(bytes, offset);
  int16_t result = 0;
  std::memcpy(&result, &value, sizeof(result));
  return result;
}

}  // namespace

TEST_CASE("WavWriter writes a RIFF PCM header and finalizes sizes") {
  TempFile file(".wav");
  WavWriter writer;
  std::string error;
  REQUIRE(writer.open(file.path(), 8000, 1, error));

  std::vector<int16_t> samples(1000);
  for (size_t index = 0; index < samples.size(); ++index) {
    samples[index] = static_cast<int16_t>(
        static_cast<int>(index % 200) - 100);
  }
  REQUIRE(writer.append(samples));
  REQUIRE(writer.finalize(error));
  CHECK(writer.error().empty());

  const std::vector<uint8_t> bytes = read_file(file.path());
  const uint32_t data_size = 1000u * sizeof(int16_t);
  REQUIRE_EQ(bytes.size(), 44u + data_size);
  CHECK_EQ(std::string(bytes.begin(), bytes.begin() + 4), "RIFF");
  CHECK_EQ(read_u32(bytes, 4), 36u + data_size);
  CHECK_EQ(std::string(bytes.begin() + 8, bytes.begin() + 12), "WAVE");
  CHECK_EQ(std::string(bytes.begin() + 12, bytes.begin() + 16), "fmt ");
  CHECK_EQ(read_u32(bytes, 16), 16u);
  CHECK_EQ(read_u16(bytes, 20), 1u);
  CHECK_EQ(read_u16(bytes, 22), 1u);
  CHECK_EQ(read_u32(bytes, 24), 8000u);
  CHECK_EQ(read_u32(bytes, 28), 16000u);
  CHECK_EQ(read_u16(bytes, 32), 2u);
  CHECK_EQ(read_u16(bytes, 34), 16u);
  CHECK_EQ(std::string(bytes.begin() + 36, bytes.begin() + 40), "data");
  CHECK_EQ(read_u32(bytes, 40), data_size);
  for (size_t index = 0; index < samples.size(); ++index) {
    CHECK_EQ(read_i16(bytes, 44 + index * sizeof(int16_t)), samples[index]);
  }
}

TEST_CASE("WavWriter rejects invalid parameters and RIFF size overflow") {
  TempFile file(".wav");
  WavWriter writer;
  std::string error;

  CHECK_FALSE(writer.open("", 8000, 1, error));
  CHECK_FALSE(error.empty());
  CHECK_FALSE(writer.open(file.path(), 0, 1, error));
  CHECK_FALSE(error.empty());
  CHECK_FALSE(writer.open(file.path(), 8000, 3, error));
  CHECK_FALSE(error.empty());
  REQUIRE(writer.open(file.path(), 8000, 1, error));
  CHECK(writer.append(nullptr, 0));

  const uint64_t max_data_bytes =
      static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) - 36u;
  const size_t overflow_samples =
      static_cast<size_t>(max_data_bytes / sizeof(int16_t) + 1u);
  CHECK_FALSE(writer.append(nullptr, overflow_samples));
  CHECK_FALSE(writer.error().empty());
  CHECK_FALSE(writer.finalize(error));

  const std::vector<uint8_t> bytes = read_file(file.path());
  CHECK_EQ(bytes.size(), 44u);
}

TEST_CASE("PeaksBuilder writes 10 ms buckets including the final partial bucket") {
  TempFile file(".peaks");
  PeaksBuilder builder;
  std::string error;
  REQUIRE(builder.open(file.path(), 8000, error));

  std::vector<int16_t> samples(170);
  for (size_t index = 0; index < samples.size(); ++index) {
    samples[index] = static_cast<int16_t>(static_cast<int>(index) - 100);
  }
  REQUIRE(builder.append(samples));
  REQUIRE(builder.finalize(error));
  CHECK(builder.error().empty());

  const std::vector<uint8_t> bytes = read_file(file.path());
  REQUIRE_EQ(bytes.size(), 16u + 3u * 4u);
  CHECK_EQ(std::string(bytes.begin(), bytes.begin() + 4), "PKS1");
  CHECK_EQ(read_u32(bytes, 4), 8000u);
  CHECK_EQ(read_u32(bytes, 8), 80u);
  CHECK_EQ(read_u32(bytes, 12), 3u);
  CHECK_EQ(read_i16(bytes, 16), -100);
  CHECK_EQ(read_i16(bytes, 18), -21);
  CHECK_EQ(read_i16(bytes, 20), -20);
  CHECK_EQ(read_i16(bytes, 22), 59);
  CHECK_EQ(read_i16(bytes, 24), 60);
  CHECK_EQ(read_i16(bytes, 26), 69);
}

TEST_CASE("FrameMapWriter writes ascending entries and rejects non-ascending input") {
  TempFile file(".map");
  FrameMapWriter writer;
  std::string error;
  REQUIRE(writer.open(file.path(), error));
  REQUIRE(writer.append(0, 10));
  REQUIRE(writer.append(20, 11));
  REQUIRE(writer.append(45, 12));
  REQUIRE(writer.finalize(error));
  CHECK(writer.error().empty());

  const std::vector<uint8_t> bytes = read_file(file.path());
  REQUIRE_EQ(bytes.size(), 8u + 3u * 8u);
  CHECK_EQ(std::string(bytes.begin(), bytes.begin() + 4), "MAP1");
  CHECK_EQ(read_u32(bytes, 4), 3u);
  CHECK_EQ(read_u32(bytes, 8), 0u);
  CHECK_EQ(read_u32(bytes, 12), 10u);
  CHECK_EQ(read_u32(bytes, 16), 20u);
  CHECK_EQ(read_u32(bytes, 20), 11u);
  CHECK_EQ(read_u32(bytes, 24), 45u);
  CHECK_EQ(read_u32(bytes, 28), 12u);

  TempFile invalid_file(".map");
  FrameMapWriter invalid;
  REQUIRE(invalid.open(invalid_file.path(), error));
  REQUIRE(invalid.append(100, 1));
  CHECK_FALSE(invalid.append(100, 2));
  CHECK_FALSE(invalid.error().empty());
  CHECK_FALSE(invalid.finalize(error));
}

TEST_CASE("Output writers reject appends before open and invalid paths") {
  WavWriter wav;
  PeaksBuilder peaks;
  FrameMapWriter map;
  const int16_t sample = 0;
  std::string error;

  CHECK_FALSE(wav.append(&sample, 1));
  CHECK_FALSE(peaks.append(&sample, 1));
  CHECK_FALSE(map.append(0, 1));
  CHECK_FALSE(wav.open("", 8000, 1, error));
  CHECK_FALSE(peaks.open("", 8000, error));
  CHECK_FALSE(map.open("", error));
}
