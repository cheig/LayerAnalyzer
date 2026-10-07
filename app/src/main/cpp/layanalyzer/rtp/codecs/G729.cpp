// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// G.729 / G.729A / G.729B decoder (RTP4-NAT-03).
//
// The codec itself is the vendored bcg729 (RTP4-BLD-02); this file is only the
// RtpAudioDecoder shell, mirroring the call sequence of Wireshark 4.0.10's
// plugins/codecs/G729/G729decode.c:
//
//   context = initBcg729DecoderChannel();
//   bcg729Decoder(context, in, in_len, 0, 0, 0, out);   /* 80 samples, void */
//   closeBcg729DecoderChannel(context);
//
// Two things differ from that reference, both of them deliberate:
//
//   * G729decode.c only ever hands bcg729 whole 10-octet voice frames and
//     derives its output size as 80 * (in_len / 10). This shell also frames the
//     Annex B SID frame (2 octets), so a payload is 10n or 10n+2 octets and
//     anything else is malformed: decode() returns false rather than guessing
//     where the frames end.
//   * bcg729Decoder() returns void, so there is no sample count to test against
//     zero. Both of its paths write L_FRAME == 80 samples unconditionally --
//     decoder.c:229-303 for a speech frame, decoder.c:165-201 for a SID frame
//     (the two-subframe loop runs either way and fills signal[0..79]) -- so the
//     card's "skip the packet when 0 samples came back" has no literal form and
//     is expressed as its honest equivalent: every frame that passes the
//     framing check contributes exactly 80 samples.
//
// G.729A and G.729B are not separate decoders here. bcg729 decodes all three
// from the same entry point (Annex B is the SID path above) and the canonical id
// is the single name "g729" (cards/README.md section 4.3); the G729 / G729A /
// G729B spellings are aliases normalised to it by RtpCodecNames long before the
// factory sees them.
#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

// Licence: bcg729 is GPL-3.0 (RTP4-ARCH-01), so a build with
// LAYANALYZER_ENABLE_G729=ON -- the default -- is a combined work conveyed
// under GPL-3.0 rather than GPL-2.0-or-later; see THIRD_PARTY_NOTICES.md and
// third_party/bcg729/COPYING.
//
// The guard also covers the include below, and it has to: with the option off,
// third_party/bcg729/include is not on the include path at all, so an unguarded
// #include "bcg729/decoder.h" would not compile in that configuration.
#ifdef LAYANALYZER_ENABLE_G729

#include <cstddef>
#include <cstdint>
#include <vector>

// bcg729's public headers carry no extern "C" guards (upstream is a C library
// and its only in-tree consumer, Wireshark's G729decode.c, is C too). Included
// from C++ without this wrapper, every declaration below would get C++ linkage
// and the link would fail on the mangled names -- the definitions in
// third_party/bcg729/src/*.c are plain C functions.
extern "C" {
#include "bcg729/decoder.h"
}

namespace layanalyzer::rtp {
namespace {

// bcg729's frame geometry, from its public header and decoder.c: a voice frame
// is 10 octets (10 ms of speech coded into 80 bits) and produces L_FRAME == 80
// samples; an Annex B SID frame is 2 octets and produces the same 80 samples of
// comfort noise.
constexpr size_t kVoiceFrameBytes = 10;
constexpr size_t kSidFrameBytes = 2;
constexpr size_t kSamplesPerFrame = 80;

// Owns one bcg729 decode context. The context is created by the factory (so an
// allocation failure is reported by returning nullptr instead of by
// constructing an unusable decoder) and released here on every exit path --
// the same ownership pattern as G722.cpp / G726.cpp.
class G729Decoder final : public RtpAudioDecoder {
 public:
  explicit G729Decoder(bcg729DecoderChannelContextStruct *context)
      : context_(context) {}

  ~G729Decoder() override { closeBcg729DecoderChannel(context_); }

  unsigned channels() const override { return 1; }

  // RFC 3551 sections 4.5.1.1 / 4.5.1.2: G.729's RTP clock rate and its actual
  // sampling rate are both 8000 Hz, so unlike G.722 there is no split to report.
  unsigned sample_rate() const override { return 8000; }
  unsigned timestamp_rate() const override { return 8000; }

  bool decode(const uint8_t *payload, size_t length,
              std::vector<int16_t> &out) override {
    out.clear();
    if (payload == nullptr && length != 0) {
      return false;
    }

    // Framing: n whole voice frames (n >= 1), optionally followed by one SID
    // frame -- 10n or 10n+2 octets. Every other length is malformed; the caller
    // records a gap for it, and returning false with an empty out is exactly
    // that. A failed decode never renders silence.
    const size_t voice_frames = length / kVoiceFrameBytes;
    const size_t remainder = length % kVoiceFrameBytes;
    if (remainder != 0u && remainder != kSidFrameBytes) {
      return false;
    }
    const size_t sid_frames = remainder == kSidFrameBytes ? 1u : 0u;

    // A zero-length payload is 10 * 0 -- no frames at all -- and it is not an
    // error: G722.cpp and G726.cpp both return true with an empty out for
    // length == 0, and the arithmetic below already produces that. In
    // particular no decoder call is made, so a null payload is never
    // dereferenced.

    // bcg729Decoder() returns void and fills exactly 80 samples per call on
    // every path (see the file header), so the buffer is sized up front and
    // each frame is decoded straight into its own 80-sample slot. Nothing is
    // ever appended for a frame bcg729 did not write, because there is no such
    // frame -- the "skip the packet when 0 samples came back" rule of the card
    // would be dead code here, and pretending otherwise with a sentinel or a
    // sample count would be inventing a signal the library does not provide.
    out.assign((voice_frames + sid_frames) * kSamplesPerFrame, 0);

    for (size_t i = 0; i < voice_frames; ++i) {
      // frameErasureFlag = 0, SIDFrameFlag = 0, rfc3389PayloadFlag = 0: packet
      // loss is reported by decode() returning false, not by asking bcg729 to
      // extrapolate a frame that never arrived.
      bcg729Decoder(context_, payload + i * kVoiceFrameBytes,
                    static_cast<uint8_t>(kVoiceFrameBytes), 0, 0, 0,
                    out.data() + i * kSamplesPerFrame);
    }

    if (sid_frames != 0u) {
      // SIDFrameFlag = 1: Annex B comfort noise. The 2 octets carry the SID's
      // L0/L1/L2/Gain fields, which bcg729's own decodeSIDframe() decodes.
      // rfc3389PayloadFlag stays 0 because this is the Annex B SID format, not
      // an RFC 3389 CN payload.
      bcg729Decoder(context_, payload + voice_frames * kVoiceFrameBytes,
                    static_cast<uint8_t>(kSidFrameBytes), 0, 1, 0,
                    out.data() + voice_frames * kSamplesPerFrame);
    }

    return true;
  }

 private:
  bcg729DecoderChannelContextStruct *context_;
};

}  // namespace

namespace detail {

std::unique_ptr<RtpAudioDecoder> create_g729_decoder() {
  // NULL asks bcg729 to allocate the context itself, exactly as
  // G729decode.c's codec_g729_init() does. A null return is the only failure
  // signal the API offers -- upstream does not check its own malloc, and memsets
  // the block before returning, so an allocation failure would crash inside
  // bcg729 rather than surface here -- and it is treated as an allocation
  // failure, the same way G722.cpp / G726.cpp treat their codec's.
  bcg729DecoderChannelContextStruct *context = initBcg729DecoderChannel();
  if (context == nullptr) {
    return nullptr;
  }
  return std::make_unique<G729Decoder>(context);
}

}  // namespace detail
}  // namespace layanalyzer::rtp

#endif  // LAYANALYZER_ENABLE_G729
