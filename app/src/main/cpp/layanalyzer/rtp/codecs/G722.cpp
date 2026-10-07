// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// G.722 decoder (RTP4-NAT-01).
//
// The codec itself is the vendored spandsp subset (RTP4-BLD-01); this file is
// only the RtpAudioDecoder shell, mirroring the call sequence of Wireshark
// 4.0.10's plugins/codecs/G722/G722decode.c:
//
//   state = g722_decode_init(NULL, 64000, 0);
//   samples = g722_decode(state, out, in, (int)len);
//   g722_decode_free(state);          /* not g722_decode_release */
//
// RFC 3551 section 4.5.2 is the trap this shell exists to express: G.722's RTP
// clock rate is 8000 Hz, but its actual sampling rate is 16000 Hz. The renderer
// reads both numbers off the decoder (timestamp_rate() for rtp_time,
// sample_rate() for the packet period), so the difference is reported here and
// nowhere else -- the renderer deliberately has no G.722 special case.
#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

#include <cstddef>
#include <cstdint>
#include <vector>

// spandsp's public headers are not self-contained (see third_party/spandsp-lite/
// README.md section 4.4): <inttypes.h> supplies int16_t/uint8_t and
// spandsp/telephony.h supplies SPAN_DECLARE, both of which spandsp/g722.h needs.
// The order below is the one that header requires.
//
// spandsp/telephony.h:29-36 expands SPAN_DECLARE to __declspec(dllimport) under
// MSVC unless LIBSPANDSP_EXPORTS is defined. We link the subset statically, so
// the import form would leave __imp_g722_decode unresolved; the dllexport form
// links against the static library exactly like the plain one. The host test
// project defines this for the spandsp translation units themselves; the
// Android build (clang, where _M_X64 is never defined) does not take this branch.
#if (defined(_M_IX86) || defined(_M_X64)) && !defined(LIBSPANDSP_EXPORTS)
#define LIBSPANDSP_EXPORTS
#endif

#include <inttypes.h>

#include "spandsp/telephony.h"
#include "spandsp/g722.h"

namespace layanalyzer::rtp {
namespace {

// Owns one spandsp decode state. The state is created by the factory (so an
// allocation failure can be reported by returning nullptr instead of by
// constructing an unusable decoder) and freed here on every exit path.
class G722Decoder final : public RtpAudioDecoder {
 public:
  explicit G722Decoder(g722_decode_state_t *state) : state_(state) {}

  ~G722Decoder() override { g722_decode_free(state_); }

  unsigned channels() const override { return 1; }

  // RFC 3551 section 4.5.2: the decoded audio is 16 kHz ...
  unsigned sample_rate() const override { return 16000; }

  // ... while the RTP clock rate is 8 kHz "due to a historic error" (the same
  // note Wireshark 4.0.10's G722decode.c carries). The renderer reads both
  // numbers off the decoder, so this is the only place they are stated.
  unsigned timestamp_rate() const override { return 8000; }

  bool decode(const uint8_t *payload, size_t length,
              std::vector<int16_t> &out) override {
    out.clear();
    if (payload == nullptr && length != 0) {
      return false;
    }
    // Fail closed on an odd length: RTP4-NAT-01 mandates a false return here,
    // and the host test fixes that edge. A whole number of octets is itself
    // decodable -- each octet codes one complete 16 kHz sample pair, so G.722
    // has no sub-octet framing -- so this is not implied by the codec's
    // structure; it is a deliberate choice to report a malformed packet rather
    // than silently decode it.
    if ((length % 2u) != 0u) {
      return false;
    }
    if (length == 0) {
      return true;
    }

    // g722_decode returns the number of 16-bit samples it wrote.
    out.resize(length * 2u);
    const int decoded =
        g722_decode(state_, out.data(), payload, static_cast<int>(length));
    out.resize(static_cast<size_t>(decoded));
    return true;
  }

 private:
  g722_decode_state_t *state_;
};

}  // namespace

namespace detail {

std::unique_ptr<RtpAudioDecoder> create_g722_decoder() {
  // RTP/AVP requires 64 kbit/s, aligned at octets; NULL asks spandsp to
  // allocate the state itself, exactly as G722decode.c does.
  g722_decode_state_t *state = g722_decode_init(nullptr, 64000, 0);
  if (state == nullptr) {
    return nullptr;  // out of memory
  }
  return std::make_unique<G722Decoder>(state);
}

}  // namespace detail
}  // namespace layanalyzer::rtp
