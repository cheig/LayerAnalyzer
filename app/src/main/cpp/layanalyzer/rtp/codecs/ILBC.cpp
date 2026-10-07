// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// iLBC (RFC 3952) decoder -- RTP4-NAT-08, the optional iLBC card.
//
// The codec itself is the vendored WebRTC libilbc subset (see
// THIRD_PARTY_NOTICES.md); this file is only the RtpAudioDecoder shell,
// mirroring the call sequence of Wireshark 4.0.10's
// plugins/codecs/iLBC/iLBCdecode.c:
//
//   ctx = WebRtcIlbcfix_DecoderCreate(&ctx);              /* codec_iLBC_init */
//   WebRtcIlbcfix_DecoderInit(ctx, 20 | 30);              /* mode changed    */
//   n = WebRtcIlbcfix_Decode(ctx, in, in_len, out, &speechType);
//   WebRtcIlbcfix_DecoderFree(ctx);                       /* codec_iLBC_release */
//
// Two things differ from that reference, both of them deliberate and both of
// them forced by what the reference actually accepts:
//
//   * iLBCdecode.c hands WebRtcIlbcfix_Decode() the whole RTP payload in one
//     call. Upstream's entry point only accepts 1, 2 or 3 frames per call --
//     ilbc.c:154-158 compares len against no_of_bytes, 2x and 3x, and returns
//     -1 for anything else (its encoder counterpart carries the same "A maximum
//     of 3 frames/packet is allowed" comment) -- so the reference silently
//     fails on any payload longer than three frames. This shell decodes in
//     groups of at most three frames instead, which is what makes a payload of
//     an arbitrary whole number of frames decodable at all.
//   * iLBCdecode.c casts the payload length down to int16_t when calling
//     WebRtcIlbcfix_Decode(). The parameter is a size_t in ilbc.h, so the cast
//     only truncates; this shell passes the size_t through unchanged.
//
// What is deliberately NOT different is the framing rule and the mode
// bookkeeping, because those are what the card pins:
//
//   * payload length % 38 == 0 selects the 20 ms mode, else length % 50 == 0
//     selects the 30 ms mode, tested in that order (iLBCdecode.c:96-115). 38 is
//     checked first, so a length divisible by both -- e.g. 950 = 25 x 38 =
//     19 x 50 -- takes the 20 ms branch.
//   * the decoder is stateful and mode-bound (WebRtcIlbcfix_DecoderInit()
//     rewrites blockl/nsub/no_of_bytes inside the instance), so it is
//     re-initialised only when the mode changes since the previous call, which
//     is iLBCdecode.c's `payload_len` tracking.
//
// iLBC is a narrowband speech codec with no companion SID/comfort-noise frame
// format in RFC 3952, so unlike G729.cpp there is no second payload shape to
// frame here.
#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

// The guard also covers the include below, and it has to: with the option off,
// third_party/libilbc is not on the include path at all, so an unguarded
// #include would not compile in that configuration. It is also what keeps every
// libilbc symbol out of a build that did not ask for one.
#ifdef LAYANALYZER_ENABLE_ILBC

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

// Unlike bcg729 (G729.cpp), libilbc's public header does carry extern "C"
// guards of its own (ilbc.h wraps its declarations in
// `#ifdef __cplusplus extern "C" { ... }`), so no wrapper is needed here. The
// check is worth making explicitly rather than assuming: without those guards
// every declaration would get C++ linkage and the link would fail on mangled
// names, since the definitions in the vendored .c files are plain C.
#include "modules/audio_coding/codecs/ilbc/ilbc.h"

namespace layanalyzer::rtp {
namespace {

// iLBC frame geometry, from the vendored defines.h: a 20 ms frame is 38 octets
// coded into BLOCKL_20MS == 160 samples, a 30 ms frame is 50 octets coded into
// BLOCKL_30MS == 240 samples, all at FS == 8000 Hz.
constexpr size_t kFrameBytes20Ms = 38;
constexpr size_t kFrameBytes30Ms = 50;
constexpr size_t kBlockl20Ms = 160;
constexpr size_t kBlockl30Ms = 240;

// WebRtcIlbcfix_Decode() (ilbc.c:154-158) accepts exactly 1, 2 or 3 whole frames
// of the instance's current mode in one call and returns -1 for anything else.
// Chunking the payload at this size is what lets a longer payload decode.
constexpr size_t kMaxFramesPerCall = 3;

// Owns one libilbc decode instance. The instance is created by the factory (so
// an allocation failure is reported by returning nullptr instead of by
// constructing an unusable decoder) and released here on every exit path -- the
// same ownership pattern as G722.cpp / G726.cpp / G729.cpp.
class ILBCDecoder final : public RtpAudioDecoder {
 public:
  explicit ILBCDecoder(IlbcDecoderInstance *instance) : instance_(instance) {}

  ~ILBCDecoder() override { WebRtcIlbcfix_DecoderFree(instance_); }

  // iLBC is a single-channel codec (RFC 3952 has no stereo mode, and
  // iLBCdecode.c's codec_iLBC_get_channels() returns 1 unconditionally).
  unsigned channels() const override { return 1; }

  // iLBC's RTP clock rate and its actual sampling rate are both 8000 Hz
  // (iLBCdecode.c's codec_iLBC_get_frequency() returns 8000), so unlike G.722
  // there is no split to report.
  unsigned sample_rate() const override { return 8000; }
  unsigned timestamp_rate() const override { return 8000; }

  bool decode(const uint8_t *payload, size_t length,
              std::vector<int16_t> &out) override {
    out.clear();
    if (payload == nullptr && length != 0) {
      return false;
    }

    // Framing, in exactly the reference's order: 38 is tested before 50, so a
    // length divisible by both (950 = 25 x 38 = 19 x 50) is 20 ms. Getting this
    // backwards would silently decode such a payload as 19 frames of 240
    // samples instead of 25 frames of 160.
    size_t frame_bytes = 0;
    size_t samples_per_frame = 0;
    int16_t mode = 0;
    if (length % kFrameBytes20Ms == 0) {
      frame_bytes = kFrameBytes20Ms;
      samples_per_frame = kBlockl20Ms;
      mode = 20;
    } else if (length % kFrameBytes30Ms == 0) {
      frame_bytes = kFrameBytes30Ms;
      samples_per_frame = kBlockl30Ms;
      mode = 30;
    } else {
      // Neither 38n nor 50n: malformed. The caller records a gap for it, and
      // returning false with an empty out is exactly that. A failed decode
      // never renders silence.
      return false;
    }

    // A zero-length payload is 0 x 38 -- no frames at all, not a malformed
    // length. G722.cpp / G726.cpp / G729.cpp all return true with an empty out
    // for length == 0, and so does this decoder; in particular no decoder call
    // is made and no re-init happens, so a null payload is never dereferenced.
    if (length == 0) {
      return true;
    }

    // Mode switch: the instance keeps mode-dependent state (blockl, nsub,
    // no_of_bytes, the LSF memory and the enhancer buffers), so a 30 ms packet
    // arriving after a 20 ms one has to re-initialise it. WebRtcIlbcfix_Decode()
    // has an automatic-switch path of its own for the same case, but relying on
    // it would leave the shell's own view of the mode stale; the reference
    // tracks the mode explicitly and so does this.
    if (mode_ != mode) {
      WebRtcIlbcfix_DecoderInit(instance_, mode);
      mode_ = mode;
    }

    const size_t frames = length / frame_bytes;
    out.assign(frames * samples_per_frame, 0);

    size_t done = 0;
    size_t produced_total = 0;
    while (done < frames) {
      const size_t chunk = std::min(kMaxFramesPerCall, frames - done);
      // speechType is set to 1 (normal speech) unconditionally by
      // WebRtcIlbcfix_Decode -- iLBC has no VAD/CNG -- and is unused here.
      int16_t speech_type = 0;
      const int produced = WebRtcIlbcfix_Decode(
          instance_, payload + done * frame_bytes, chunk * frame_bytes,
          out.data() + done * samples_per_frame, &speech_type);
      // The API returns -1 on error and > 0 samples otherwise, with no "0
      // samples" state of its own; both are treated as a failed decode here.
      if (produced <= 0) {
        out.clear();
        return false;
      }
      produced_total += static_cast<size_t>(produced);
      done += chunk;
    }

    // The buffer was sized from the framing rule; trimming it to what the
    // library actually wrote is what keeps a change in the library visible as
    // a short read rather than as a buffer of trailing zeros.
    out.resize(produced_total);
    return true;
  }

 private:
  IlbcDecoderInstance *instance_;
  // The frame length (20 or 30) passed to the last WebRtcIlbcfix_DecoderInit,
  // or 0 for "not initialised yet". iLBCdecode.c keeps the same thing in its
  // ilbc_ctx_t::payload_len.
  int16_t mode_ = 0;
};

}  // namespace

namespace detail {

std::unique_ptr<RtpAudioDecoder> create_ilbc_decoder() {
  // WebRtcIlbcfix_DecoderCreate() mallocs the instance and returns -1 (leaving
  // the out parameter NULL) if that fails, which is the only failure signal the
  // API offers; a NULL result is treated as an allocation failure, the same way
  // G722.cpp / G726.cpp / G729.cpp treat their codec's.
  IlbcDecoderInstance *instance = nullptr;
  if (WebRtcIlbcfix_DecoderCreate(&instance) != 0 || instance == nullptr) {
    return nullptr;
  }
  // No WebRtcIlbcfix_DecoderInit() here: the mode is not known until the first
  // payload arrives, and decode() re-initialises on the first call because
  // mode_ starts at 0.
  return std::make_unique<ILBCDecoder>(instance);
}

}  // namespace detail
}  // namespace layanalyzer::rtp

#endif  // LAYANALYZER_ENABLE_ILBC
