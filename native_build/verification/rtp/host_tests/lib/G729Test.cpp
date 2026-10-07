// RTP4-NAT-03: G.729 / G.729A / G.729B -- the payload framing and the build
// option.
//
// The codec call itself is one line into bcg729, so what can actually go wrong
// here is the framing: a voice frame is 10 octets and produces 80 samples, an
// Annex B SID frame is 2 octets and produces 80 comfort-noise samples, a payload
// is therefore 10n or 10n+2 octets, and every other length must be rejected
// rather than decoded as if the frames ended somewhere convenient.
//
// The file compiles in both build configurations. With LAYANALYZER_ENABLE_G729
// undefined there is no bcg729 header to include and no bcg729 symbol to
// reference (the decoder is reached through the factory only), so the decoder
// cases print a visible doctest WARN and check nothing, while the registration
// case still runs its "unavailable" half -- that half is the OFF
// configuration's actual contract, not a skipped case.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <vector>

#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

#ifdef LAYANALYZER_ENABLE_G729
// Same extern "C" wrapper as G729.cpp: bcg729's public headers have no linkage
// guards of their own, so a C++ consumer has to supply them.
extern "C" {
#include "bcg729/decoder.h"
}

// Pin the property that shapes G729.cpp's SID handling: bcg729Decoder() returns
// void, so there is no sample count to compare against zero and the card's
// "skip the packet when 0 samples came back" rule cannot be written literally.
// If bcg729 ever grew a return value, this file would stop compiling and the
// decision in G729.cpp would get reviewed instead of quietly becoming wrong.
static_assert(std::is_void<decltype(bcg729Decoder(nullptr, nullptr, 0, 0, 0, 0,
                                                  nullptr))>::value,
              "bcg729Decoder() is expected to return void (bcg729 1.1.1); "
              "G729.cpp sizes its output buffer up front on that basis");
#endif

using layanalyzer::rtp::is_decoder_available;
using layanalyzer::rtp::make_audio_decoder;
using layanalyzer::rtp::RtpAudioDecoder;

namespace {

// G.729 codes 10 ms of speech into 80 bits, i.e. 10 octets, and 10 ms at 8 kHz
// is 80 samples. The Annex B SID frame is 2 octets and fills the same 80-sample
// frame with comfort noise.
constexpr size_t kVoiceFrameBytes = 10;
constexpr size_t kSidFrameBytes = 2;
constexpr size_t kSamplesPerFrame = 80;

// The message every skipped case prints, so an OFF run says out loud what it
// did not cover instead of passing quietly.
#define G729_SKIP_WARN()                                                     \
  DOCTEST_WARN_MESSAGE(                                                      \
      false,                                                                 \
      "LAYANALYZER_ENABLE_G729 is off: this build has no G.729 decoder "     \
      "(RTP4-BLD-02) and the case is skipped (RTP4-NAT-03)")

}  // namespace

TEST_CASE("G729 a 10-octet voice frame decodes to exactly 80 samples") {
#ifdef LAYANALYZER_ENABLE_G729
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("g729");
  REQUIRE(decoder);

  // An all-zero frame is not meaningful audio, but it is well formed as far as
  // bcg729 is concerned: the decoder validates nothing and every 10-octet frame
  // maps onto its parameter table. That is exactly what makes it the right
  // input here -- a crash would be a buffer-sizing mistake in G729.cpp, not the
  // codec reacting to odd input.
  const std::vector<uint8_t> frame(kVoiceFrameBytes, 0x00);
  std::vector<int16_t> out;
  CHECK(decoder->decode(frame.data(), frame.size(), out));
  CHECK_EQ(out.size(), kSamplesPerFrame);
#else
  G729_SKIP_WARN();
#endif
}

TEST_CASE("G729 a 2-octet Annex B SID frame decodes to whole 80-sample blocks") {
#ifdef LAYANALYZER_ENABLE_G729
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("g729");
  REQUIRE(decoder);

  // The SID frame (RFC 3551 section 4.5.1.3, Annex B) is two octets carrying
  // L0/L1/L2/Gain. bcg729 handles it in a branch of its own (decoder.c:165-201)
  // that writes L_FRAME == 80 comfort-noise samples and returns void, so "0
  // samples" is not a state it can report. The card allows 0 or 80 here, hence
  // the modulo assertion; the MESSAGE records what this implementation actually
  // produces, so a change in the library is visible rather than absorbed.
  const std::vector<uint8_t> sid(kSidFrameBytes, 0x00);
  std::vector<int16_t> out;
  CHECK(decoder->decode(sid.data(), sid.size(), out));
  MESSAGE("2-octet SID frame produced " << out.size() << " samples");
  CHECK_EQ(out.size() % kSamplesPerFrame, 0u);
#else
  G729_SKIP_WARN();
#endif
}

TEST_CASE("G729 a 20-octet payload decodes as two voice frames") {
#ifdef LAYANALYZER_ENABLE_G729
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("g729");
  REQUIRE(decoder);

  // 20 ms of G.729 is two 10-octet frames back to back; nothing in the payload
  // separates them, which is why the slicing has to be exactly 10 octets.
  const std::vector<uint8_t> packet(2 * kVoiceFrameBytes, 0x00);
  std::vector<int16_t> out;
  CHECK(decoder->decode(packet.data(), packet.size(), out));
  CHECK_EQ(out.size(), 2 * kSamplesPerFrame);
#else
  G729_SKIP_WARN();
#endif
}

TEST_CASE("G729 rejects payload lengths that are neither 10n nor 10n+2") {
#ifdef LAYANALYZER_ENABLE_G729
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("g729");
  REQUIRE(decoder);

  // 3 octets is neither a whole voice frame (10) nor a whole SID frame (2), and
  // no G.729 packetization produces it. decode() has to say so: false with an
  // empty out is how the caller learns to record a gap instead of rendering the
  // silence of half a frame.
  const std::vector<uint8_t> three = {0x00, 0x00, 0x00};
  std::vector<int16_t> out;
  CHECK_FALSE(decoder->decode(three.data(), three.size(), out));
  CHECK(out.empty());

  // A null payload with a non-zero length is rejected the same way.
  CHECK_FALSE(decoder->decode(nullptr, three.size(), out));
  CHECK(out.empty());

  // Zero octets is 10 * 0: no frames at all, and not an error. G722.cpp and
  // G726.cpp return true with an empty out for length == 0, so this decoder
  // does too -- pinned here so the choice is explicit rather than incidental.
  CHECK(decoder->decode(nullptr, 0, out));
  CHECK(out.empty());
#else
  G729_SKIP_WARN();
#endif
}

TEST_CASE("G729 framing boundaries: a trailing SID frame and a one-octet payload") {
#ifdef LAYANALYZER_ENABLE_G729
  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("g729");
  REQUIRE(decoder);

  // 12 octets is the shortest payload that carries both kinds of frame: one
  // voice frame followed by the Annex B SID frame that may trail it (10 * 1 +
  // 2). It must be accepted, and it can never yield fewer than the 80 samples
  // the voice frame alone contributes -- the SID frame either adds its own 80
  // comfort-noise samples or, in the looser reading the card allows for SID
  // frames, adds nothing. Both readings satisfy the two checks below, so the
  // case stays honest without pretending to know which one bcg729 implements.
  const std::vector<uint8_t> voice_plus_sid(1 * kVoiceFrameBytes + kSidFrameBytes,
                                            0x00);
  std::vector<int16_t> out;
  CHECK(decoder->decode(voice_plus_sid.data(), voice_plus_sid.size(), out));
  MESSAGE("12-octet voice+SID payload produced " << out.size() << " samples");
  CHECK_EQ(out.size() % kSamplesPerFrame, 0u);
  CHECK(out.size() >= kSamplesPerFrame);

  // The other side of the same boundary: one octet is shorter than both frame
  // sizes, so it is malformed, not a truncated voice frame to be padded.
  const std::vector<uint8_t> one = {0x00};
  CHECK_FALSE(decoder->decode(one.data(), one.size(), out));
  CHECK(out.empty());
#else
  G729_SKIP_WARN();
#endif
}

TEST_CASE("G729 registration follows the LAYANALYZER_ENABLE_G729 build option") {
  // The canonical id is lower-case "g729" (README section 4.3); G729 / G729A /
  // G729B are aliases that RtpCodecNames normalises to it before the factory is
  // reached, which is why the alias spellings are not names here. Checked in
  // both configurations so the OFF build pins its own contract too.
  CHECK_FALSE(is_decoder_available("G729"));

#ifdef LAYANALYZER_ENABLE_G729
  CHECK(is_decoder_available("g729"));

  const std::unique_ptr<RtpAudioDecoder> decoder = make_audio_decoder("g729");
  REQUIRE(decoder);
  CHECK_EQ(decoder->channels(), 1u);
  CHECK_EQ(decoder->sample_rate(), 8000u);
  CHECK_EQ(decoder->timestamp_rate(), 8000u);

  // Mono only, like G.711 / G.722 / G.726: a stereo request must not silently
  // fall back to the mono decoder. An unspecified channel count means mono.
  CHECK_FALSE(make_audio_decoder("g729", 2));
  const std::unique_ptr<RtpAudioDecoder> default_channels =
      make_audio_decoder("g729", 0);
  REQUIRE(default_channels);
  CHECK_EQ(default_channels->channels(), 1u);
#else
  G729_SKIP_WARN();

  // With the build option off the whole register is inert: the name is unknown
  // and no decoder can be constructed from it (RTP4-BLD-02 / RTP4-NAT-03).
  CHECK_FALSE(is_decoder_available("g729"));
  CHECK(make_audio_decoder("g729") == nullptr);
  CHECK(make_audio_decoder("g729", 1) == nullptr);
#endif
}
