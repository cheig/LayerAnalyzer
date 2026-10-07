// RTP4-NAT-01: G.722 decoder and the 16 kHz / 8 kHz two-rate contract.
//
// RFC 3551 section 4.5.2: G.722's RTP clock rate is 8000 Hz while its actual
// sampling rate is 16000 Hz. The decoder reports both, and the renderer takes
// both from RtpRenderPacket -- so the difference needs no G.722 special case
// anywhere in RtpAudioRenderer. These cases pin that down.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"
#include "layanalyzer/rtp/core/RtpAudioRenderer.h"
#include "layanalyzer/rtp/core/RtpMediaDecoder.h"

using layanalyzer::rtp::is_decoder_available;
using layanalyzer::rtp::make_audio_decoder;
using layanalyzer::rtp::render_rtp_audio;
using layanalyzer::rtp::RtpAudioDecoder;
using layanalyzer::rtp::RtpMediaDecoder;
using layanalyzer::rtp::RtpRenderPacket;
using layanalyzer::rtp::RtpRenderResult;

namespace {

// One 20 ms G.722 packet carries 160 payload octets, which decode to 320
// samples at 16 kHz.
constexpr size_t kPacketBytes = 160;
constexpr size_t kPacketSamples = 320;
constexpr unsigned kSampleRate = 16000;
constexpr unsigned kTimestampRate = 8000;
// The RTP timestamp moves on the 8 kHz clock: 0.02 s * 8000 = 160 per packet,
// i.e. half the number of decoded samples.
constexpr uint64_t kTimestampStep = 160;

RtpRenderPacket g722_packet(uint32_t sequence, uint64_t timestamp, double arrival,
                            int16_t sample_value) {
  RtpRenderPacket packet;
  packet.frame_number = 100 + sequence;
  packet.arrival_rel_sec = arrival;
  packet.ext_seq = sequence;
  packet.ext_ts = timestamp;
  packet.samples.assign(kPacketSamples, sample_value);
  packet.channels = 1;
  packet.sample_rate = kSampleRate;
  packet.timestamp_rate = kTimestampRate;
  return packet;
}

}  // namespace

TEST_CASE("G722 decoder reports a 16 kHz sampling rate and an 8 kHz clock") {
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("g722");
  REQUIRE(decoder);
  CHECK_EQ(decoder->channels(), 1u);
  CHECK_EQ(decoder->sample_rate(), 16000u);
  CHECK_EQ(decoder->timestamp_rate(), 8000u);

  // 160 all-zero octets: silence. g722_decode emits two 16-bit samples per
  // payload octet (one low-band and one high-band sample from the QMF), so the
  // decoded block is 320 samples.
  const std::vector<uint8_t> payload(kPacketBytes, 0x00);
  std::vector<int16_t> out;
  REQUIRE(decoder->decode(payload.data(), payload.size(), out));
  CHECK_EQ(out.size(), kPacketSamples);
}

TEST_CASE("G722 renderer keeps the 8 kHz clock and the 16 kHz sample rate apart") {
  // Two consecutive 20 ms G.722 packets. The packet period is
  // 320 / 16000 = 20 ms and rtp_time advances by 160 / 8000 = 20 ms per packet,
  // so the two agree and the renderer writes both blocks back to back.
  //
  // This is the regression the two rates exist for: had the decoder reported
  // timestamp_rate() == 16000 (the sampling rate), the same ext_ts step would
  // put rtp_time 10 ms behind the packet period and the renderer would record a
  // wrongTimestamp event with negative silence. Hence events and gaps must both
  // be empty, and map[1].at_ms must be exactly 20.
  std::vector<RtpRenderPacket> packets;
  for (uint32_t i = 0; i < 2; ++i) {
    packets.push_back(g722_packet(
        i + 1, 1000u + kTimestampStep * i, 0.020 * static_cast<double>(i),
        static_cast<int16_t>(i + 1)));
  }

  const RtpRenderResult result = render_rtp_audio(packets, {});
  CHECK(result.error.empty());
  CHECK_EQ(result.sample_rate, kSampleRate);
  CHECK_EQ(result.samples.size(), 2u * kPacketSamples);
  CHECK_EQ(result.prepend_samples, 0u);
  CHECK_EQ(result.dropped_late, 0u);
  CHECK(result.gaps.empty());
  CHECK(result.events.empty());
  REQUIRE_EQ(result.map.size(), 2u);
  CHECK_EQ(result.map[0].at_ms, 0u);
  CHECK_EQ(result.map[1].at_ms, 20u);
  CHECK_EQ(result.map[0].frame, 101u);
  CHECK_EQ(result.map[1].frame, 102u);

  // The assertion that actually discriminates is events.empty(): the
  // discrepancy between the two rates is negative, so the renderer inserts no
  // silence either way and map[1].at_ms would land on 20 ms even with the wrong
  // rate. Substituting the sampling rate for the clock rate on the same packets
  // makes the renderer record a wrongTimestamp event instead, which is what
  // this test would then fail on.
  std::vector<RtpRenderPacket> wrong_rate = packets;
  wrong_rate[1].timestamp_rate = kSampleRate;
  const RtpRenderResult wrong_result = render_rtp_audio(wrong_rate, {});
  REQUIRE_EQ(wrong_result.events.size(), 1u);
  CHECK_EQ(wrong_result.events[0].type, "wrongTimestamp");
}

TEST_CASE("G722 decoder rejects an odd payload length") {
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("g722");
  REQUIRE(decoder);

  // Half an octet cannot be coded, so an odd payload is malformed: decode()
  // reports failure and leaves nothing behind.
  const std::vector<uint8_t> odd(kPacketBytes + 1, 0x00);
  std::vector<int16_t> out = {1, 2, 3};
  CHECK_FALSE(decoder->decode(odd.data(), odd.size(), out));
  CHECK(out.empty());

  // A null payload with a non-zero length is malformed in the same way.
  std::vector<int16_t> null_out = {1, 2, 3};
  CHECK_FALSE(decoder->decode(nullptr, 4, null_out));
  CHECK(null_out.empty());
}

TEST_CASE("G722 is registered in the decoder factory as mono only") {
  CHECK(is_decoder_available("g722"));
  CHECK(make_audio_decoder("g722") != nullptr);
  CHECK(make_audio_decoder("g722", 1) != nullptr);
  // G.722 has exactly one channel; a stereo request must not silently fall back
  // to the mono decoder.
  CHECK_FALSE(make_audio_decoder("g722", 2));
  // As for L16, an unspecified channel count means mono.
  CHECK(make_audio_decoder("g722", 0) != nullptr);
  CHECK_EQ(make_audio_decoder("g722", 0)->channels(), 1u);
}

TEST_CASE("RtpMediaDecoder forwards the G722 rates and sample count") {
  RtpMediaDecoder decoder("g722");
  REQUIRE(decoder.available());
  CHECK_EQ(decoder.channels(), 1u);
  CHECK_EQ(decoder.sample_rate(), 16000u);
  CHECK_EQ(decoder.timestamp_rate(), 8000u);
  CHECK_EQ(decoder.lastPacketSamples(), 0u);

  const std::vector<uint8_t> payload(kPacketBytes, 0x00);
  std::vector<int16_t> out;
  const auto result = decoder.decodePacket(9, payload.data(), payload.size(), out);
  CHECK(result.ok);
  CHECK(result.reason.empty());
  CHECK_EQ(out.size(), kPacketSamples);
  CHECK_EQ(decoder.lastPacketSamples(), static_cast<uint32_t>(kPacketSamples));
}
