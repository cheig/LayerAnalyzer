// RTP2-NAT-03: stream-level RTP media decoder tests.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/core/RtpMediaDecoder.h"

using layanalyzer::rtp::RtpMediaDecoder;
using layanalyzer::rtp::RtpMediaDecoderResult;

TEST_CASE("RtpMediaDecoder decodes a G.711A 20 ms packet") {
  RtpMediaDecoder decoder("g711A");
  REQUIRE(decoder.available());
  CHECK_EQ(decoder.channels(), 1u);
  CHECK_EQ(decoder.sample_rate(), 8000u);
  CHECK_EQ(decoder.timestamp_rate(), 8000u);
  CHECK_EQ(decoder.lastPacketSamples(), 0u);

  const std::vector<uint8_t> payload(160, 0xD5);
  std::vector<int16_t> out;
  const RtpMediaDecoderResult result =
      decoder.decodePacket(8, payload.data(), payload.size(), out);

  CHECK(result.ok);
  CHECK(result.reason.empty());
  CHECK_EQ(out.size(), static_cast<size_t>(160));
  CHECK_EQ(decoder.lastPacketSamples(), 160u);
}

TEST_CASE("RtpMediaDecoder rejects an empty payload and clears output") {
  RtpMediaDecoder decoder("g711A");
  REQUIRE(decoder.available());

  const uint8_t dummy_payload = 0;
  std::vector<int16_t> out = {1, 2, 3};
  const RtpMediaDecoderResult result =
      decoder.decodePacket(8, &dummy_payload, 0, out);

  CHECK_FALSE(result.ok);
  CHECK_EQ(result.reason, "decodeFailed");
  CHECK(out.empty());
  CHECK_EQ(decoder.lastPacketSamples(), 0u);
}

TEST_CASE("RtpMediaDecoder keeps lastPacketSamples after a failed packet") {
  RtpMediaDecoder decoder("g711U");
  REQUIRE(decoder.available());

  const std::vector<uint8_t> payload(160, 0xFF);
  std::vector<int16_t> out;
  REQUIRE(decoder.decodePacket(0, payload.data(), payload.size(), out).ok);
  REQUIRE_EQ(decoder.lastPacketSamples(), 160u);

  const uint8_t dummy_payload = 0;
  const RtpMediaDecoderResult result =
      decoder.decodePacket(0, &dummy_payload, 0, out);
  CHECK_FALSE(result.ok);
  CHECK_EQ(result.reason, "decodeFailed");
  CHECK(out.empty());
  CHECK_EQ(decoder.lastPacketSamples(), 160u);
}

TEST_CASE("RtpMediaDecoder selects L16 stereo for payload type 10") {
  RtpMediaDecoder decoder("L16");
  REQUIRE(decoder.available());

  const std::vector<uint8_t> payload = {
      0x12, 0x34, 0xAB, 0xCD, 0x00, 0x01, 0xFF, 0xFE,
  };
  std::vector<int16_t> out;
  const RtpMediaDecoderResult result =
      decoder.decodePacket(10, payload.data(), payload.size(), out);

  CHECK(result.ok);
  CHECK_EQ(decoder.channels(), 2u);
  CHECK_EQ(decoder.sample_rate(), 44100u);
  CHECK_EQ(decoder.timestamp_rate(), 44100u);
  CHECK_EQ(out.size(), static_cast<size_t>(4));
  CHECK_EQ(decoder.lastPacketSamples(), 2u);
}

TEST_CASE("RtpMediaDecoder selects L16 mono for payload type 11 and others") {
  const std::vector<uint8_t> payload = {0x12, 0x34, 0xAB, 0xCD};
  const uint32_t payload_types[] = {11, 96};

  for (uint32_t payload_type : payload_types) {
    RtpMediaDecoder decoder("L16");
    REQUIRE(decoder.available());

    std::vector<int16_t> out;
    const RtpMediaDecoderResult result =
        decoder.decodePacket(payload_type, payload.data(), payload.size(), out);

    CAPTURE(payload_type);
    CHECK(result.ok);
    CHECK_EQ(decoder.channels(), 1u);
    CHECK_EQ(out.size(), static_cast<size_t>(2));
    CHECK_EQ(decoder.lastPacketSamples(), 2u);
  }
}

TEST_CASE("RtpMediaDecoder reports unsupported codecs without output") {
  // AMR is decoded through MediaCodec (RTP4-KT-02), never through
  // RtpDecoderFactory, so it stays unavailable here. This case used to name
  // g722, which RTP4-NAT-01 implemented; the assertions are unchanged.
  RtpMediaDecoder decoder("AMR");
  CHECK_FALSE(decoder.available());
  CHECK_EQ(decoder.channels(), 0u);
  CHECK_EQ(decoder.sample_rate(), 0u);
  CHECK_EQ(decoder.timestamp_rate(), 0u);

  const std::vector<uint8_t> payload = {0x00};
  std::vector<int16_t> out = {1, 2, 3};
  const RtpMediaDecoderResult result =
      decoder.decodePacket(9, payload.data(), payload.size(), out);

  CHECK_FALSE(result.ok);
  CHECK_EQ(result.reason, "unsupported");
  CHECK(out.empty());
  CHECK_EQ(decoder.lastPacketSamples(), 0u);
}

TEST_CASE("RtpMediaDecoder clears output and keeps state on L16 decode failure") {
  RtpMediaDecoder decoder("L16");
  REQUIRE(decoder.available());

  const std::vector<uint8_t> valid = {0x12, 0x34, 0xAB, 0xCD};
  std::vector<int16_t> out;
  REQUIRE(decoder.decodePacket(11, valid.data(), valid.size(), out).ok);
  REQUIRE_EQ(decoder.lastPacketSamples(), 2u);

  const std::vector<uint8_t> odd = {0x12, 0x34, 0x56};
  const RtpMediaDecoderResult result =
      decoder.decodePacket(11, odd.data(), odd.size(), out);

  CHECK_FALSE(result.ok);
  CHECK_EQ(result.reason, "decodeFailed");
  CHECK(out.empty());
  CHECK_EQ(decoder.lastPacketSamples(), 2u);
}
