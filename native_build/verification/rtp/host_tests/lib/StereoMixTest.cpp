// RTP3-NAT-02: stereo alignment, linear upsampling, and empty-track tests.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/RtpDecodeRequest.h"
#include "layanalyzer/rtp/core/RtpAudioRenderer.h"

using layanalyzer::rtp::mix_stereo;
using layanalyzer::rtp::parse_rtp_decode_request;
using layanalyzer::rtp::RtpDecodeRequest;
using layanalyzer::rtp::RtpMixRequest;
using layanalyzer::rtp::RtpMixedAudio;

namespace {

std::vector<int16_t> ramp(size_t count, int16_t first = 1) {
  std::vector<int16_t> samples(count);
  for (size_t index = 0; index < count; ++index) {
    samples[index] = static_cast<int16_t>(first + index);
  }
  return samples;
}

}  // namespace

TEST_CASE("StereoMix aligns a 180 ms right-channel offset") {
  const std::vector<int16_t> left = ramp(160, 100);
  const std::vector<int16_t> right = ramp(160, -100);
  RtpMixRequest request;

  const RtpMixedAudio mixed =
      mix_stereo(left, 8000, 10.0, right, 8000, 10.180, request);

  REQUIRE(mixed.error.empty());
  CHECK_EQ(mixed.sample_rate, 8000u);
  CHECK_EQ(mixed.left_offset_ms, 0);
  CHECK_EQ(mixed.right_offset_ms, 180);
  CHECK_FALSE(mixed.resampled);
  CHECK_EQ(mixed.interleaved.size(), static_cast<size_t>(1600 * 2));
  CHECK_EQ(mixed.interleaved[0], left[0]);
  CHECK_EQ(mixed.interleaved[180 * 8 * 2], 0);
  CHECK_EQ(mixed.interleaved[180 * 8 * 2 + 1], right[0]);
}

TEST_CASE("StereoMix keeps the other channel silent when one track is empty") {
  const std::vector<int16_t> right = ramp(160, 20);
  RtpMixRequest request;

  const RtpMixedAudio mixed =
      mix_stereo({}, 8000, 0.0, right, 8000, 0.0, request);

  REQUIRE(mixed.error.empty());
  CHECK_EQ(mixed.sample_rate, 8000u);
  CHECK_EQ(mixed.left_offset_ms, 0);
  CHECK_EQ(mixed.right_offset_ms, 0);
  CHECK_FALSE(mixed.resampled);
  CHECK_EQ(mixed.interleaved.size(), static_cast<size_t>(320));
  for (size_t index = 0; index < right.size(); ++index) {
    CHECK_EQ(mixed.interleaved[index * 2u], 0);
    CHECK_EQ(mixed.interleaved[index * 2u + 1u], right[index]);
  }
}

TEST_CASE("StereoMix linearly upsamples the lower-rate track") {
  const std::vector<int16_t> left = {0, 1000, 2000, 3000};
  const std::vector<int16_t> right = {4000, 5000, 6000, 7000};
  RtpMixRequest request;

  const RtpMixedAudio mixed =
      mix_stereo(left, 8000, 1.0, right, 16000, 1.0, request);

  REQUIRE(mixed.error.empty());
  CHECK_EQ(mixed.sample_rate, 16000u);
  CHECK(mixed.resampled);
  CHECK_EQ(mixed.left_offset_ms, 0);
  CHECK_EQ(mixed.right_offset_ms, 0);
  CHECK_EQ(mixed.interleaved.size(), static_cast<size_t>(8 * 2));
  CHECK_EQ(mixed.interleaved[0], 0);
  CHECK_EQ(mixed.interleaved[1], 4000);
  CHECK_EQ(mixed.interleaved[2], 500);
  CHECK_EQ(mixed.interleaved[3], 5000);
  CHECK_EQ(mixed.interleaved[4], 1000);
  CHECK_EQ(mixed.interleaved[5], 6000);
  CHECK_EQ(mixed.interleaved[6], 1500);
  CHECK_EQ(mixed.interleaved[7], 7000);
}

TEST_CASE("StereoMix returns empty audio when both tracks are empty") {
  RtpMixRequest request;

  const RtpMixedAudio mixed =
      mix_stereo({}, 8000, 0.0, {}, 8000, 0.0, request);

  CHECK(mixed.error.empty());
  CHECK(mixed.interleaved.empty());
  CHECK_EQ(mixed.sample_rate, 0u);
  CHECK_EQ(mixed.left_offset_ms, 0);
  CHECK_EQ(mixed.right_offset_ms, 0);
  CHECK_FALSE(mixed.resampled);
}

TEST_CASE("StereoMix request parses the nested alignment fields") {
  const std::string json =
      R"({"scanGeneration":7,"streams":["s0","s1"],"timing":"jitter","mix":{"left":"s0","right":"s1","align":"absArrival"}})";
  RtpDecodeRequest request;
  std::string error;

  REQUIRE(parse_rtp_decode_request(json, request, error));
  CHECK(error.empty());
  CHECK(request.has_mix);
  CHECK_EQ(request.mix.left_stream_id, "s0");
  CHECK_EQ(request.mix.right_stream_id, "s1");
  CHECK(request.mix.align_abs_arrival);
  CHECK_EQ(request.mix.out_sample_rate, 0u);
}

TEST_CASE("StereoMix request rejects malformed alignment fields") {
  RtpDecodeRequest request;
  std::string error;

  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0","s1"],"timing":"jitter","mix":{"left":"s0","right":"s1","align":"other"}})",
      request, error));
  CHECK_FALSE(error.empty());

  error.clear();
  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0","s1"],"timing":"jitter","mix":{"left":"s0","right":"s0","align":"absArrival"}})",
      request, error));
  CHECK_FALSE(error.empty());

  error.clear();
  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0"],"timing":"jitter","mix":{"left":"s0","right":"s1","align":"absArrival"}})",
      request, error));
  CHECK_FALSE(error.empty());
}
