// RTP2-NAT-02: L16 big-endian PCM decoder tests.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

using layanalyzer::rtp::make_audio_decoder;
using layanalyzer::rtp::RtpAudioDecoder;

TEST_CASE("L16 mono decodes big-endian samples") {
  const std::unique_ptr<RtpAudioDecoder> decoder =
      make_audio_decoder("L16");
  REQUIRE(decoder);
  CHECK_EQ(decoder->channels(), 1u);
  CHECK_EQ(decoder->sample_rate(), 44100u);
  CHECK_EQ(decoder->timestamp_rate(), 44100u);

  const std::vector<uint8_t> payload = {0x12, 0x34, 0xAB, 0xCD};
  std::vector<int16_t> out;
  REQUIRE(decoder->decode(payload.data(), payload.size(), out));
  REQUIRE_EQ(out.size(), static_cast<size_t>(2));
  CHECK_EQ(out[0], static_cast<int16_t>(0x1234));
  CHECK_EQ(out[1], static_cast<int16_t>(0xABCD));
}

TEST_CASE("L16 stereo decodes interleaved big-endian samples") {
  const std::unique_ptr<RtpAudioDecoder> decoder =
      make_audio_decoder("L16", 2);
  REQUIRE(decoder);
  CHECK_EQ(decoder->channels(), 2u);
  CHECK_EQ(decoder->sample_rate(), 44100u);
  CHECK_EQ(decoder->timestamp_rate(), 44100u);

  const std::vector<uint8_t> payload = {
      0x12, 0x34, 0xAB, 0xCD, 0x00, 0x01, 0xFF, 0xFE,
  };
  std::vector<int16_t> out;
  REQUIRE(decoder->decode(payload.data(), payload.size(), out));
  REQUIRE_EQ(out.size(), static_cast<size_t>(4));
  CHECK_EQ(out[0], static_cast<int16_t>(0x1234));
  CHECK_EQ(out[1], static_cast<int16_t>(0xABCD));
  CHECK_EQ(out[2], static_cast<int16_t>(0x0001));
  CHECK_EQ(out[3], static_cast<int16_t>(0xFFFE));
}

TEST_CASE("L16 rejects empty and odd-length payloads") {
  const std::unique_ptr<RtpAudioDecoder> decoder =
      make_audio_decoder("L16");
  REQUIRE(decoder);

  std::vector<int16_t> out = {1, 2, 3};
  CHECK_FALSE(decoder->decode(nullptr, 0, out));
  CHECK(out.empty());

  const std::vector<uint8_t> odd = {0x12, 0x34, 0x56};
  CHECK_FALSE(decoder->decode(odd.data(), odd.size(), out));
  CHECK(out.empty());
}

TEST_CASE("L16 channel selection rejects unsupported channel counts") {
  CHECK_FALSE(make_audio_decoder("L16", 0) == nullptr);
  CHECK_FALSE(make_audio_decoder("L16", 3));
}
