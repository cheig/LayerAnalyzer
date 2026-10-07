// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Factory for the self-contained RTP audio decoders.
#pragma once

#include <memory>
#include <string>

#include "layanalyzer/rtp/core/RtpAudioDecoder.h"

namespace layanalyzer::rtp {

// canonical_codec_id is one of g711A, g711U, L16, g722, g729, iLBC, or one of
// the eight G.726 names (G726-16/24/32/40 and AAL2-G726-16/24/32/40,
// case-sensitive -- the name carries both the bit rate and the RFC 3551
// packing). g729 is build-option dependent: it is available only in a build
// made with LAYANALYZER_ENABLE_G729 on (RTP4-BLD-02), otherwise the id is
// simply unknown to this factory. iLBC is build-option dependent in the same
// way but defaults off (LAYANALYZER_ENABLE_ILBC, RTP4-NAT-08). L16 defaults to
// mono.
std::unique_ptr<RtpAudioDecoder> make_audio_decoder(
    const std::string &canonical_codec_id);

// Explicit channel selection for L16. G.711, G.722, G.726, G.729 and iLBC only
// accept one channel.
std::unique_ptr<RtpAudioDecoder> make_audio_decoder(
    const std::string &canonical_codec_id, unsigned channels);

bool is_decoder_available(const std::string &canonical_codec_id);

namespace detail {

std::unique_ptr<RtpAudioDecoder> create_g711a_decoder();
std::unique_ptr<RtpAudioDecoder> create_g711u_decoder();
std::unique_ptr<RtpAudioDecoder> create_l16_decoder(unsigned channels);
std::unique_ptr<RtpAudioDecoder> create_g722_decoder();

// Returns nullptr for any name outside the eight G.726 variants.
std::unique_ptr<RtpAudioDecoder> create_g726_decoder(
    const std::string &canonical_codec_id);

// RTP4-NAT-03: the single canonical G.729 id (README section 4.3; the G729 /
// G729A / G729B spellings are aliases that RtpCodecNames normalises to "g729"
// before the factory is reached). Defined -- and reachable -- only in a build
// with LAYANALYZER_ENABLE_G729 on, since bcg729 is GPL-3.0 (RTP4-BLD-02).
std::unique_ptr<RtpAudioDecoder> create_g729_decoder();

// RTP4-NAT-08: the single canonical iLBC id (README section 4.3), mixed case.
// Unlike every other canonical id here it is not lower-case, and the comparison
// in the factory is case-sensitive, so "ilbc" and "ILBC" are unknown names.
// Defined -- and reachable -- only in a build with LAYANALYZER_ENABLE_ILBC on
// (the option defaults off, because this card is optional).
std::unique_ptr<RtpAudioDecoder> create_ilbc_decoder();

}  // namespace detail

}  // namespace layanalyzer::rtp
