// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Access-unit assembly and `.vidx` records for the video export -- RTP5-NAT-03.
// See VideoAccessUnitBuilder.h for the contract and for the decisions the task
// card left open; this file is the assembler itself.

#include "layanalyzer/rtp/depack/VideoAccessUnitBuilder.h"

#include <cstddef>

namespace layanalyzer::rtp {
namespace {

// Card rule 7: every NAL unit is written behind this four-octet start code, and
// an access unit's byte range is its NAL units plus these prefixes and nothing
// else -- no padding, no length prefixes (MediaMuxer converts Annex-B itself,
// README C17).
constexpr uint8_t kStartCode[4] = {0x00, 0x00, 0x00, 0x01};

// NAL unit types this builder classifies. The two codecs number them
// independently, and `VideoCodec::PS` reads both sets (header decision 14).
constexpr uint8_t kH264Idr = 5;
constexpr uint8_t kH264Sps = 7;
constexpr uint8_t kH264Pps = 8;
constexpr uint8_t kH265IrapFirst = 16;  // BLA_W_LP
constexpr uint8_t kH265IrapLast = 23;   // RSV_IRAP_VCL23
constexpr uint8_t kH265Vps = 32;
constexpr uint8_t kH265Sps = 33;
constexpr uint8_t kH265Pps = 34;

void append_start_code_and(std::vector<uint8_t> &out,
                           const std::vector<uint8_t> &nal) {
  out.insert(out.end(), kStartCode, kStartCode + sizeof(kStartCode));
  out.insert(out.end(), nal.begin(), nal.end());
}

}  // namespace

VideoAccessUnitBuilder::VideoAccessUnitBuilder(
    const VideoAuBuilderOptions &options)
    : options_(options) {}

void VideoAccessUnitBuilder::onPacket(
    uint32_t frame_number, uint64_t ext_ts, bool marker,
    const std::vector<std::vector<uint8_t>> &nals, bool corrupt,
    bool sequence_gap) {
  // The stream's own origin: the PTS scale (decision 3) and the injected pseudo
  // access unit's first_frame (decision 7). Recorded before anything can be
  // dropped or injected, so it does not depend on what survives.
  if (!first_packet_seen_) {
    first_packet_seen_ = true;
    first_frame_ = frame_number;
    first_ext_ts_ = ext_ts;
  }

  // Card rule 1, read the way a marker bit has to be read: the packet that
  // carries marker = 1 is the *last* packet of the access unit that just ended,
  // and a change of ext_ts ends it too (decision 1). Both at once is still one
  // boundary, and the accumulator is reset here so that damage carried by a
  // packet of the finished unit cannot leak into the next one (decision 5).
  if (have_previous_ && (previous_marker_ || ext_ts != previous_ext_ts_)) {
    finalize_au();
    au_damage_ = false;
    au_first_valid_ = false;
  }

  // Card rules 5 and 6 at the packet level: this packet belongs to the access
  // unit being accumulated, whether or not it brought a NAL unit.
  if (corrupt || sequence_gap) {
    au_damage_ = true;
  }

  if (!au_first_valid_) {
    au_first_valid_ = true;
    au_.ext_ts = ext_ts;
    au_.first_frame = frame_number;
  }

  for (const std::vector<uint8_t> &nal : nals) {
    // Decision 12: a zero-length NAL unit cannot be expressed in Annex-B.
    if (nal.empty()) {
      continue;
    }
    if (!au_open_) {
      au_open_ = true;
      au_.offset = es_.size();
      au_.length = 0;
      au_.flags = 0;
    }
    append_start_code_and(es_, nal);
    au_.length += sizeof(kStartCode) + nal.size();
    classify_nal(nal);
  }

  have_previous_ = true;
  previous_ext_ts_ = ext_ts;
  previous_marker_ = marker;
}

void VideoAccessUnitBuilder::classify_nal(const std::vector<uint8_t> &nal) {
  const uint8_t first = nal[0];

  if (options_.codec == VideoCodec::H264 || options_.codec == VideoCodec::PS) {
    const uint8_t type = static_cast<uint8_t>(first & 0x1Fu);
    if (type == kH264Idr) {
      au_.flags |= kVideoAuFlagKey;
    } else if (type == kH264Sps) {
      saw_sps_ = true;
      au_.flags |= kVideoAuFlagParamSets;
    } else if (type == kH264Pps) {
      saw_pps_ = true;
      au_.flags |= kVideoAuFlagParamSets;
    }
  }

  if (options_.codec == VideoCodec::H265 || options_.codec == VideoCodec::PS) {
    const uint8_t type = static_cast<uint8_t>((first >> 1) & 0x3Fu);
    if (type >= kH265IrapFirst && type <= kH265IrapLast) {
      au_.flags |= kVideoAuFlagKey;
    } else if (type == kH265Vps) {
      saw_vps_ = true;
      au_.flags |= kVideoAuFlagParamSets;
    } else if (type == kH265Sps) {
      saw_sps_ = true;
      au_.flags |= kVideoAuFlagParamSets;
    } else if (type == kH265Pps) {
      saw_pps_ = true;
      au_.flags |= kVideoAuFlagParamSets;
    }
  }
}

void VideoAccessUnitBuilder::finalize_au() {
  if (!au_open_) {
    // Every packet between the last boundary and this one brought nothing, so
    // there is no access unit to record (decision 1).
    return;
  }
  VideoAuRecord record;
  record.byte_offset = au_.offset;
  record.byte_length = static_cast<uint32_t>(au_.length);
  record.pts_us = pts_us_for(au_.ext_ts);
  record.first_frame = au_.first_frame;
  record.flags = au_.flags;
  if (au_damage_) {
    // Card rule 6: the flag is recorded here and only acted on in finish(), so
    // that drop_corrupt = false can still write the frame out marked.
    record.flags |= kVideoAuFlagCorrupt;
  }
  records_.push_back(record);
  au_open_ = false;
}

uint64_t VideoAccessUnitBuilder::pts_us_for(uint64_t ext_ts) const {
  // Decision 2: options.timestamp_rate, with the 90000 default standing in for
  // a rate that cannot be divided by.
  const uint32_t rate =
      options_.timestamp_rate != 0 ? options_.timestamp_rate : 90000u;
  // Decision 4: signed, so that a packet arriving behind the stream's first one
  // (a B-frame reorder, or a capture that starts mid-GOP) is a small negative
  // difference rather than a wrapped 2^64 one, and clamped at zero because an
  // unsigned microsecond PTS cannot carry a negative time.
  const int64_t delta =
      static_cast<int64_t>(ext_ts) - static_cast<int64_t>(first_ext_ts_);
  if (delta <= 0) {
    return 0;
  }
  return static_cast<uint64_t>(delta) * 1000000ull / rate;
}

std::vector<uint8_t> VideoAccessUnitBuilder::build_injection() const {
  std::vector<uint8_t> injected;
  // Card rule 4's order. A VPS only ever belongs to an H.265 stream, so the
  // H.264 path ignores `options_.vps` entirely; that is a property of the codec
  // rather than a silent drop of data.
  const bool with_vps = options_.codec != VideoCodec::H264;
  if (with_vps && !saw_vps_) {
    for (const std::vector<uint8_t> &nal : options_.vps) {
      if (!nal.empty()) append_start_code_and(injected, nal);
    }
  }
  if (!saw_sps_) {
    for (const std::vector<uint8_t> &nal : options_.sps) {
      if (!nal.empty()) append_start_code_and(injected, nal);
    }
  }
  if (!saw_pps_) {
    for (const std::vector<uint8_t> &nal : options_.pps) {
      if (!nal.empty()) append_start_code_and(injected, nal);
    }
  }
  return injected;
}

std::vector<VideoAuRecord> VideoAccessUnitBuilder::finish(
    std::vector<uint8_t> &out_es) {
  // One-shot (decision 13): the second call would otherwise re-emit records
  // whose bytes have already been handed over.
  if (finished_) {
    return {};
  }
  finished_ = true;

  // The stream ended: the last access unit has no marker and no successor to
  // carry the boundary.
  finalize_au();

  // Card rule 6 first, card rule 5 second (decision 10).
  std::vector<VideoAuRecord> kept;
  kept.reserve(records_.size());
  for (const VideoAuRecord &record : records_) {
    if (options_.drop_corrupt && (record.flags & kVideoAuFlagCorrupt) != 0) {
      continue;
    }
    kept.push_back(record);
  }

  size_t begin = 0;
  if (options_.start_at_keyframe) {
    size_t first_keyframe = kept.size();
    for (size_t index = 0; index < kept.size(); ++index) {
      if ((kept[index].flags & kVideoAuFlagKey) != 0) {
        first_keyframe = index;
        break;
      }
    }
    if (first_keyframe == kept.size()) {
      // Decision 9: nothing to start at, so nothing is written at all.
      error_ = "noKeyframe";
      return {};
    }
    begin = first_keyframe;
  }

  const size_t keep_count = kept.size() - begin;

  // Card rule 4: the injected bytes are for the stream, so a stream that kept no
  // access unit at all gets no pseudo access unit either.
  std::vector<uint8_t> injected;
  if (keep_count > 0) {
    injected = build_injection();
  }

  std::vector<VideoAuRecord> result;
  result.reserve(keep_count + (injected.empty() ? 0u : 1u));

  // Decision 13: `out_es` is appended to, so the offsets are absolute in the ES
  // file the caller will write -- including whatever the vector already held.
  uint64_t cursor = out_es.size();

  if (!injected.empty()) {
    VideoAuRecord record;
    record.byte_offset = cursor;
    record.byte_length = static_cast<uint32_t>(injected.size());
    // Decision 7: the pseudo access unit carries the parameter sets for the
    // first access unit that survived, so it takes that unit's PTS, and the
    // stream's first frame number rather than the first kept one's.
    record.pts_us = kept[begin].pts_us;
    record.first_frame = first_frame_;
    record.flags = kVideoAuFlagParamSets;
    out_es.insert(out_es.end(), injected.begin(), injected.end());
    cursor += injected.size();
    result.push_back(record);
  }

  for (size_t index = begin; index < kept.size(); ++index) {
    VideoAuRecord record = kept[index];
    record.byte_offset = cursor;
    const std::vector<uint8_t>::const_iterator first =
        es_.begin() + static_cast<std::ptrdiff_t>(kept[index].byte_offset);
    out_es.insert(out_es.end(), first,
                  first + static_cast<std::ptrdiff_t>(kept[index].byte_length));
    cursor += kept[index].byte_length;
    result.push_back(record);
  }

  // The bytes now live in `out_es`; hand the buffer back rather than holding the
  // whole stream twice (decision 13).
  std::vector<uint8_t>().swap(es_);
  records_.clear();
  return result;
}

std::string VideoAccessUnitBuilder::error() const { return error_; }

}  // namespace layanalyzer::rtp
