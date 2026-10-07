// RTP4-NAT-08: iLBC -- the payload framing, the mode switch and the build
// option.
//
// Nothing here asserts anything about decoded *audio quality*. An all-zero
// payload is structurally valid for libilbc but meaningless as speech; what can
// actually go wrong in ILBC.cpp is the framing (38 octets is 20 ms and 160
// samples, 50 octets is 30 ms and 240 samples), the branch order when a length
// is divisible by both, the re-initialisation when the mode changes, and the
// registration that the build option gates. Those are what these cases pin.
//
// The file compiles in both build configurations. With LAYANALYZER_ENABLE_ILBC
// undefined there is no libilbc header to include and no libilbc symbol to
// reference (the decoder is reached through the factory only), so the decoder
// cases print a visible doctest WARN and check nothing, while the registration
// case still runs its "unavailable" half -- that half is the OFF
// configuration's actual contract, not a skipped case.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

using layanalyzer::rtp::is_decoder_available;
using layanalyzer::rtp::make_audio_decoder;
using layanalyzer::rtp::RtpAudioDecoder;

namespace {

// iLBC's two frame shapes, from the vendored defines.h: 38 octets / 160 samples
// for a 20 ms frame and 50 octets / 240 samples for a 30 ms one, both at 8 kHz.
constexpr size_t kFrameBytes20Ms = 38;
constexpr size_t kFrameBytes30Ms = 50;
constexpr size_t kSamples20Ms = 160;
constexpr size_t kSamples30Ms = 240;

// The message every skipped case prints, so an OFF run says out loud what it
// did not cover instead of passing quietly.
#define ILBC_SKIP_WARN()                                                     \
  DOCTEST_WARN_MESSAGE(                                                      \
      false,                                                                 \
      "LAYANALYZER_ENABLE_ILBC is off: this build has no iLBC decoder "      \
      "(RTP4-NAT-08; the option defaults off) and the case is skipped")

}  // namespace

TEST_CASE("ILBC payload framing: 38/50 octets per frame, 160/240 samples each") {
#ifdef LAYANALYZER_ENABLE_ILBC
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("iLBC");
  REQUIRE(decoder);

  // A single 20 ms frame: 38 octets in, 160 samples out.
  std::vector<int16_t> out;
  const std::vector<uint8_t> one_20ms(kFrameBytes20Ms, 0x00);
  CHECK(decoder->decode(one_20ms.data(), one_20ms.size(), out));
  CHECK_EQ(out.size(), kSamples20Ms);

  // A single 30 ms frame: 50 octets in, 240 samples out.
  const std::vector<uint8_t> one_30ms(kFrameBytes30Ms, 0x00);
  CHECK(decoder->decode(one_30ms.data(), one_30ms.size(), out));
  CHECK_EQ(out.size(), kSamples30Ms);

  // Two 20 ms frames back to back: nothing in the payload separates them, which
  // is why the slicing has to be exactly 38 octets.
  const std::vector<uint8_t> two_20ms(2 * kFrameBytes20Ms, 0x00);
  CHECK(decoder->decode(two_20ms.data(), two_20ms.size(), out));
  CHECK_EQ(out.size(), 2 * kSamples20Ms);

  // Two 30 ms frames.
  const std::vector<uint8_t> two_30ms(2 * kFrameBytes30Ms, 0x00);
  CHECK(decoder->decode(two_30ms.data(), two_30ms.size(), out));
  CHECK_EQ(out.size(), 2 * kSamples30Ms);
#else
  ILBC_SKIP_WARN();
#endif
}

TEST_CASE("ILBC a length divisible by both 38 and 50 takes the 20 ms branch") {
#ifdef LAYANALYZER_ENABLE_ILBC
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("iLBC");
  REQUIRE(decoder);

  // 950 = 25 x 38 = 19 x 50, so both framings fit it exactly and the branch
  // order decides the answer. iLBCdecode.c tests 38 first, so this is 25 frames
  // of 20 ms -> 4000 samples; reading it as 19 frames of 30 ms would give 4560.
  // The case exists to pin that order, which is the one thing a rewrite of the
  // framing rule is most likely to flip.
  const std::vector<uint8_t> ambiguous(950, 0x00);
  std::vector<int16_t> out;
  CHECK(decoder->decode(ambiguous.data(), ambiguous.size(), out));
  CHECK_EQ(out.size(), (950 / kFrameBytes20Ms) * kSamples20Ms);
  CHECK_EQ(out.size(), 4000u);
  CHECK(out.size() != (950 / kFrameBytes30Ms) * kSamples30Ms);
#else
  ILBC_SKIP_WARN();
#endif
}

TEST_CASE("ILBC rejects payload lengths that are neither 38n nor 50n") {
#ifdef LAYANALYZER_ENABLE_ILBC
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("iLBC");
  REQUIRE(decoder);

  // 3 octets is shorter than either frame shape and 1 octet is shorter still;
  // no iLBC packetisation produces either. decode() has to say so: false with
  // an empty out is how the caller learns to record a gap instead of rendering
  // the silence of a truncated frame.
  const std::vector<uint8_t> three = {0x00, 0x00, 0x00};
  std::vector<int16_t> out;
  CHECK_FALSE(decoder->decode(three.data(), three.size(), out));
  CHECK(out.empty());

  const std::vector<uint8_t> one = {0x00};
  CHECK_FALSE(decoder->decode(one.data(), one.size(), out));
  CHECK(out.empty());

  // A null payload with a non-zero length is rejected the same way.
  CHECK_FALSE(decoder->decode(nullptr, three.size(), out));
  CHECK(out.empty());

  // Zero octets is 0 x 38: no frames at all, and not an error. G722.cpp /
  // G726.cpp / G729.cpp all return true with an empty out for length == 0, so
  // this decoder does too -- pinned here so the choice is explicit rather than
  // incidental, and so the re-init stays off the null-payload path.
  CHECK(decoder->decode(nullptr, 0, out));
  CHECK(out.empty());
#else
  ILBC_SKIP_WARN();
#endif
}

TEST_CASE("ILBC re-initialises when the frame mode changes mid-stream") {
#ifdef LAYANALYZER_ENABLE_ILBC
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("iLBC");
  REQUIRE(decoder);

  // 20 ms -> 30 ms -> 20 ms on one decoder instance. WebRtcIlbcfix_DecoderInit()
  // rewrites blockl/nsub/no_of_bytes and the whole synthesis and enhancer state
  // inside the instance, and iLBCdecode.c tracks the mode explicitly for that
  // reason (ILBC.cpp mirrors it).
  //
  // Note what this case does and does not isolate: upstream's
  // WebRtcIlbcfix_Decode() has an automatic mode-switch path of its own
  // (ilbc.c:159-186), so a shell that never re-initialised would usually be
  // rescued by the library and still produce the numbers below. The case
  // therefore asserts the observable contract -- each packet yields its own
  // frame geometry's sample count -- rather than the internal call sequence,
  // which no black-box test can see. What it does catch is a shell that gets
  // the geometry wrong (one blockl for both modes, a mis-sized output buffer)
  // or that chunks a payload into a length WebRtcIlbcfix_Decode rejects.
  std::vector<int16_t> out;

  const std::vector<uint8_t> packet_20ms(kFrameBytes20Ms, 0x00);
  CHECK(decoder->decode(packet_20ms.data(), packet_20ms.size(), out));
  CHECK_EQ(out.size(), kSamples20Ms);

  const std::vector<uint8_t> packet_30ms(kFrameBytes30Ms, 0x00);
  CHECK(decoder->decode(packet_30ms.data(), packet_30ms.size(), out));
  CHECK_EQ(out.size(), kSamples30Ms);

  CHECK(decoder->decode(packet_20ms.data(), packet_20ms.size(), out));
  CHECK_EQ(out.size(), kSamples20Ms);

  // And a second 30 ms packet straight after the 30 ms one must NOT re-init: it
  // has to decode with the mode already in place, which is what makes the
  // "only when the mode changed" rule observable rather than incidental.
  CHECK(decoder->decode(packet_30ms.data(), packet_30ms.size(), out));
  CHECK_EQ(out.size(), kSamples30Ms);
#else
  ILBC_SKIP_WARN();
#endif
}

TEST_CASE("ILBC reports mono 8 kHz and refuses a stereo request") {
#ifdef LAYANALYZER_ENABLE_ILBC
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("iLBC");
  REQUIRE(decoder);

  // RFC 3952 has no stereo mode, so both rates are 8000 and the channel count
  // is 1 (there is no G.722-style split between clock rate and sampling rate).
  CHECK_EQ(decoder->channels(), 1u);
  CHECK_EQ(decoder->sample_rate(), 8000u);
  CHECK_EQ(decoder->timestamp_rate(), 8000u);

  // Mono only, like G.711 / G.722 / G.726 / G.729: a stereo request must not
  // silently fall back to the mono decoder. An unspecified channel count means
  // mono.
  CHECK_FALSE(make_audio_decoder("iLBC", 2));
  const std::unique_ptr<RtpAudioDecoder> default_channels =
      make_audio_decoder("iLBC", 0);
  REQUIRE(default_channels);
  CHECK_EQ(default_channels->channels(), 1u);
#else
  ILBC_SKIP_WARN();
#endif
}

TEST_CASE("ILBC registration follows the LAYANALYZER_ENABLE_ILBC build option") {
  // The canonical id is mixed-case "iLBC" (README section 4.3) -- the only id in
  // that table that is not lower-case -- and every lookup in this factory is
  // case-sensitive, so the two other spellings must stay unknown in both
  // configurations. Checked outside the #ifdef on purpose: it is the ON build
  // that would be tempted to accept them.
  CHECK_FALSE(is_decoder_available("ilbc"));
  CHECK_FALSE(is_decoder_available("ILBC"));

#ifdef LAYANALYZER_ENABLE_ILBC
  CHECK(is_decoder_available("iLBC"));

  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("iLBC");
  REQUIRE(decoder);
  CHECK_EQ(decoder->channels(), 1u);

  CHECK(make_audio_decoder("ilbc") == nullptr);
  CHECK(make_audio_decoder("ILBC") == nullptr);
#else
  ILBC_SKIP_WARN();

  // With the build option off the whole register is inert: the name is unknown
  // and no decoder can be constructed from it. This is the default
  // configuration, so this half is the one that usually runs.
  CHECK_FALSE(is_decoder_available("iLBC"));
  CHECK(make_audio_decoder("iLBC") == nullptr);
  CHECK(make_audio_decoder("iLBC", 1) == nullptr);
#endif
}
