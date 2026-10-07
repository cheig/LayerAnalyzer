#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

namespace layanalyzer::rtp {
namespace {

// RTP4-NAT-02: the eight G.726 names of RFC 3551 section 4.5.3 (G726-*, RIGHT
// packed) and section 4.5.4 (AAL2-G726-*, LEFT packed). The comparison is
// case-sensitive because the canonical IDs are; the bit rate and the packing
// are derived from the name inside create_g726_decoder().
bool is_g726_codec(const std::string &canonical_codec_id) {
  return canonical_codec_id == "G726-16" || canonical_codec_id == "G726-24" ||
         canonical_codec_id == "G726-32" || canonical_codec_id == "G726-40" ||
         canonical_codec_id == "AAL2-G726-16" ||
         canonical_codec_id == "AAL2-G726-24" ||
         canonical_codec_id == "AAL2-G726-32" ||
         canonical_codec_id == "AAL2-G726-40";
}

#ifdef LAYANALYZER_ENABLE_G729
// RTP4-NAT-03: the single canonical G.729 id (README section 4.3). G.729A and
// G.729B do not get names of their own -- RtpCodecNames maps the G729 / G729A /
// G729B spellings onto "g729", and bcg729 decodes all three from the same entry
// point (Annex B is its SID-frame path, handled inside the decoder). The
// comparison is case-sensitive, like every other canonical id here.
//
// Guarded along with its three call sites because the whole codec is build
// option dependent (RTP4-BLD-02): with LAYANALYZER_ENABLE_G729 undefined this
// helper would be an unused function in an anonymous namespace.
bool is_g729_codec(const std::string &canonical_codec_id) {
  return canonical_codec_id == "g729";
}
#endif  // LAYANALYZER_ENABLE_G729

#ifdef LAYANALYZER_ENABLE_ILBC
// RTP4-NAT-08: the single canonical iLBC id (README section 4.3). It is the one
// id in that table that is not lower-case, and it stays that way here: the
// comparison is case-sensitive like every other canonical id, so "ilbc" and
// "ILBC" are not names this factory knows.
//
// Guarded along with its three call sites because the whole codec is build
// option dependent (LAYANALYZER_ENABLE_ILBC defaults OFF): with the macro
// undefined this helper would be an unused function in an anonymous namespace,
// and no libilbc symbol would be referenced anywhere.
bool is_ilbc_codec(const std::string &canonical_codec_id) {
  return canonical_codec_id == "iLBC";
}
#endif  // LAYANALYZER_ENABLE_ILBC

}  // namespace

std::unique_ptr<RtpAudioDecoder> make_audio_decoder(
    const std::string &canonical_codec_id) {
  if (canonical_codec_id == "g711A") {
    return detail::create_g711a_decoder();
  }
  if (canonical_codec_id == "g711U") {
    return detail::create_g711u_decoder();
  }
  if (canonical_codec_id == "L16") {
    return detail::create_l16_decoder(1);
  }
  if (canonical_codec_id == "g722") {
    return detail::create_g722_decoder();
  }
  if (is_g726_codec(canonical_codec_id)) {
    return detail::create_g726_decoder(canonical_codec_id);
  }
#ifdef LAYANALYZER_ENABLE_G729
  if (is_g729_codec(canonical_codec_id)) {
    return detail::create_g729_decoder();
  }
#endif
#ifdef LAYANALYZER_ENABLE_ILBC
  if (is_ilbc_codec(canonical_codec_id)) {
    return detail::create_ilbc_decoder();
  }
#endif
  return nullptr;
}

std::unique_ptr<RtpAudioDecoder> make_audio_decoder(
    const std::string &canonical_codec_id, unsigned channels) {
  if (channels == 0) {
    channels = 1;
  }
  if (canonical_codec_id == "g711A") {
    return channels == 1 ? detail::create_g711a_decoder() : nullptr;
  }
  if (canonical_codec_id == "g711U") {
    return channels == 1 ? detail::create_g711u_decoder() : nullptr;
  }
  if (canonical_codec_id == "L16") {
    return detail::create_l16_decoder(channels);
  }
  if (canonical_codec_id == "g722") {
    return channels == 1 ? detail::create_g722_decoder() : nullptr;
  }
  if (is_g726_codec(canonical_codec_id)) {
    return channels == 1 ? detail::create_g726_decoder(canonical_codec_id)
                         : nullptr;
  }
#ifdef LAYANALYZER_ENABLE_G729
  // G.729 is mono only, exactly like G.711 / G.722 / G.726 above.
  if (is_g729_codec(canonical_codec_id)) {
    return channels == 1 ? detail::create_g729_decoder() : nullptr;
  }
#endif
#ifdef LAYANALYZER_ENABLE_ILBC
  // iLBC is mono only as well (RFC 3952 defines no stereo mode).
  if (is_ilbc_codec(canonical_codec_id)) {
    return channels == 1 ? detail::create_ilbc_decoder() : nullptr;
  }
#endif
  return nullptr;
}

bool is_decoder_available(const std::string &canonical_codec_id) {
  bool available = canonical_codec_id == "g711A" ||
                   canonical_codec_id == "g711U" ||
                   canonical_codec_id == "L16" ||
                   canonical_codec_id == "g722" ||
                   is_g726_codec(canonical_codec_id);
#ifdef LAYANALYZER_ENABLE_G729
  // RTP4-NAT-03: reported available only when bcg729 was compiled in. With the
  // build option off, the name is unknown here and callers answer
  // "unsupported" instead of failing later at decode time.
  available = available || is_g729_codec(canonical_codec_id);
#endif
#ifdef LAYANALYZER_ENABLE_ILBC
  // RTP4-NAT-08: same contract for iLBC, except that the option defaults off,
  // so an ordinary build reports "iLBC" as unknown.
  available = available || is_ilbc_codec(canonical_codec_id);
#endif
  return available;
}

}  // namespace layanalyzer::rtp
