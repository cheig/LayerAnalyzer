// G.726 decoder (RTP4-NAT-02).
//
// The codec itself is the vendored spandsp subset (RTP4-BLD-01); this file is
// only the RtpAudioDecoder shell, mirroring the call sequence of Wireshark
// 4.0.10's plugins/codecs/G726/G726decode.c:
//
//   state = g726_init(NULL, bit_rate, G726_ENCODING_LINEAR, packing);
//   samples = g726_decode(state, out, in, (int)len);
//   g726_free(state);                 /* not g726_release */
//
// Unlike G.722 there is no two-rate split here: G.726's RTP clock rate and its
// sampling rate are both 8000 Hz, so sample_rate() == timestamp_rate() == 8000.
//
// The one trap this shell exists to express is the packing. RFC 3551 section
// 4.5.3 defines G726-16/24/32/40 with G726_PACKING_RIGHT, while section 4.5.4
// defines the AAL2-G726-16/24/32/40 variants with G726_PACKING_LEFT. The two
// families are otherwise identical -- same bit rate, same algorithm, same
// sample count -- so a wrong packing table is invisible except as garbage
// audio, and no bit rate is hard-coded at the call site: the name alone picks
// both the bit rate and the packing (see kG726Variants below).
#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// spandsp's public headers are not self-contained (see third_party/spandsp-lite/
// README.md section 4.4): <inttypes.h> supplies int16_t/uint8_t and
// spandsp/telephony.h supplies SPAN_DECLARE, both of which spandsp/g726.h needs.
// The order below is the one that header requires.
//
// spandsp/telephony.h:29-36 expands SPAN_DECLARE to __declspec(dllimport) under
// MSVC unless LIBSPANDSP_EXPORTS is defined. We link the subset statically, so
// the import form would leave __imp_g726_decode unresolved; the dllexport form
// links against the static library exactly like the plain one. The host test
// project defines this for the spandsp translation units themselves; the
// Android build (clang, where _M_X64 is never defined) does not take this branch.
#if (defined(_M_IX86) || defined(_M_X64)) && !defined(LIBSPANDSP_EXPORTS)
#define LIBSPANDSP_EXPORTS
#endif

#include <inttypes.h>

#include "spandsp/telephony.h"
#include "spandsp/g726.h"

namespace layanalyzer::rtp {
namespace {

// The eight names this translation unit serves, with the bit rate and the
// packing RFC 3551 assigns to each. The G726-* family is RIGHT-packed
// (section 4.5.3); the AAL2-G726-* family is LEFT-packed (section 4.5.4).
// Everything else about a variant follows from bit_rate: spandsp derives
// bits_per_sample = bit_rate / 8000, which is what makes a payload of N octets
// decode to about N * 8 / bits_per_sample samples.
struct G726Variant {
  const char *name;
  int bit_rate;
  int packing;
};

constexpr G726Variant kG726Variants[] = {
    {"G726-16", 16000, G726_PACKING_RIGHT},
    {"G726-24", 24000, G726_PACKING_RIGHT},
    {"G726-32", 32000, G726_PACKING_RIGHT},
    {"G726-40", 40000, G726_PACKING_RIGHT},
    {"AAL2-G726-16", 16000, G726_PACKING_LEFT},
    {"AAL2-G726-24", 24000, G726_PACKING_LEFT},
    {"AAL2-G726-32", 32000, G726_PACKING_LEFT},
    {"AAL2-G726-40", 40000, G726_PACKING_LEFT},
};

const G726Variant *lookup_g726_variant(const std::string &canonical_codec_id) {
  for (const G726Variant &variant : kG726Variants) {
    if (canonical_codec_id == variant.name) {
      return &variant;
    }
  }
  return nullptr;
}

// Owns one spandsp decode state. The state is created by the factory (so an
// allocation failure can be reported by returning nullptr instead of by
// constructing an unusable decoder) and freed here on every exit path.
class G726Decoder final : public RtpAudioDecoder {
 public:
  explicit G726Decoder(g726_state_t *state) : state_(state) {}

  ~G726Decoder() override { g726_free(state_); }

  unsigned channels() const override { return 1; }

  // G.726 is an 8 kHz codec and, unlike G.722, its RTP clock rate is the same
  // 8 kHz (RFC 3551 section 4.5.3), so both accessors report one rate.
  unsigned sample_rate() const override { return 8000; }
  unsigned timestamp_rate() const override { return 8000; }

  bool decode(const uint8_t *payload, size_t length,
              std::vector<int16_t> &out) override {
    out.clear();
    if (payload == nullptr && length != 0) {
      return false;
    }
    if (length == 0) {
      return true;
    }

    // g726_decode returns the number of 16-bit samples it actually wrote, which
    // is what the caller must believe. Its output can never exceed
    // length * 8 / bits_per_sample samples, and bits_per_sample is at least 2
    // (16 kbit/s), so length * 4 is a hard upper bound for the buffer; the
    // trailing slack only covers a hypothetical off-by-one and the block is
    // resized down to the real count right after.
    //
    // A payload shorter than one whole sample is not an error: g726_decode
    // stops at the last complete code, so e.g. one octet at 40 kbit/s yields a
    // single sample and the leftover bits stay in the state for the next call.
    // That mirrors what G726decode.c does and is pinned by the host test.
    out.resize(length * 4u + 4u);
    const int decoded =
        g726_decode(state_, out.data(), payload, static_cast<int>(length));
    out.resize(decoded > 0 ? static_cast<size_t>(decoded) : 0u);
    return true;
  }

 private:
  g726_state_t *state_;
};

}  // namespace

namespace detail {

std::unique_ptr<RtpAudioDecoder> create_g726_decoder(
    const std::string &canonical_codec_id) {
  const G726Variant *variant = lookup_g726_variant(canonical_codec_id);
  if (variant == nullptr) {
    return nullptr;  // not one of the eight G.726 names
  }

  // Interworking with 16-bit signed linear PCM, exactly as G726decode.c does.
  // NULL asks spandsp to allocate the state itself.
  g726_state_t *state = g726_init(nullptr, variant->bit_rate,
                                  G726_ENCODING_LINEAR, variant->packing);
  if (state == nullptr) {
    return nullptr;  // out of memory
  }
  return std::make_unique<G726Decoder>(state);
}

}  // namespace detail
}  // namespace layanalyzer::rtp
