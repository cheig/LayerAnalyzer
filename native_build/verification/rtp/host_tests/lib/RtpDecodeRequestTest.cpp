// RTP2-NAT-06: decodeRtpAudio request parser tests.

#include "doctest.h"

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "layanalyzer/rtp/RtpDecodeRequest.h"

using layanalyzer::rtp::parse_rtp_decode_request;
using layanalyzer::rtp::RtpDecodeRequest;
using layanalyzer::rtp::RtpTimingMode;

TEST_CASE("RtpDecodeRequest parses the frozen request shape") {
  const std::string json =
      R"({"scanGeneration":7,"streams":["s0","s1"],"timing":"jitter","jitterMs":50})";
  RtpDecodeRequest request;
  std::string error;

  REQUIRE(parse_rtp_decode_request(json, request, error));
  CHECK(error.empty());
  CHECK_EQ(request.scan_generation, 7u);
  CHECK_EQ(request.stream_ids,
           std::vector<std::string>({"s0", "s1"}));
  CHECK(request.timing == RtpTimingMode::JitterBuffer);
  CHECK_EQ(request.jitter_ms, 50);
}

TEST_CASE("RtpDecodeRequest maps timing values and defaults jitterMs") {
  RtpDecodeRequest request;
  std::string error;

  REQUIRE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0"],"timing":"rtp"})", request,
      error));
  CHECK(request.timing == RtpTimingMode::RtpTimestamp);
  CHECK_EQ(request.jitter_ms, 50);

  REQUIRE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0"],"timing":"uninterrupted","jitterMs":0})",
      request, error));
  CHECK(request.timing == RtpTimingMode::Uninterrupted);
  CHECK_EQ(request.jitter_ms, 0);
}

TEST_CASE("RtpDecodeRequest ignores unknown fields and deduplicates streams") {
  const std::string json =
      R"({"streams":["s1","s1","s0"],"timing":"jitter","unknown":{"x":[1,true,null]},"scanGeneration":42})";
  RtpDecodeRequest request;
  std::string error;

  REQUIRE(parse_rtp_decode_request(json, request, error));
  CHECK_EQ(request.scan_generation, 42u);
  CHECK_EQ(request.stream_ids,
           std::vector<std::string>({"s1", "s0"}));
}

TEST_CASE("RtpDecodeRequest rejects missing and malformed fields") {
  RtpDecodeRequest request;
  std::string error;

  CHECK_FALSE(parse_rtp_decode_request(
      R"({"streams":["s0"],"timing":"jitter"})", request, error));
  CHECK_FALSE(error.empty());

  error.clear();
  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":-1,"streams":["s0"],"timing":"jitter"})",
      request, error));
  CHECK_FALSE(error.empty());

  error.clear();
  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":[],"timing":"bad"})", request,
      error));
  CHECK_FALSE(error.empty());

  error.clear();
  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":[""],"timing":"jitter"})", request,
      error));
  CHECK_FALSE(error.empty());

  error.clear();
  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0"],"timing":"jitter","jitterMs":-1})",
      request, error));
  CHECK_FALSE(error.empty());

  error.clear();
  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0"],"timing":"jitter","jitterMs":1.5})",
      request, error));
  CHECK_FALSE(error.empty());
}

TEST_CASE("RtpDecodeRequest rejects invalid JSON and duplicate known fields") {
  RtpDecodeRequest request;
  std::string error;

  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0"],"timing":"jitter",})",
      request, error));
  CHECK_FALSE(error.empty());

  error.clear();
  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"scanGeneration":2,"streams":["s0"],"timing":"jitter"})",
      request, error));
  CHECK_FALSE(error.empty());

  error.clear();
  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":18446744073709551616,"streams":["s0"],"timing":"jitter"})",
      request, error));
  CHECK_FALSE(error.empty());
}

TEST_CASE("RtpDecodeRequest allows an empty selected stream list") {
  RtpDecodeRequest request;
  std::string error;

  REQUIRE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":[],"timing":"jitter"})", request,
      error));
  CHECK(request.stream_ids.empty());
}
