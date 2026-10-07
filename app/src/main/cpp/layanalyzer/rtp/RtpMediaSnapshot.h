// M2 media metadata snapshot shared by RTP decode/export JNI entry points.
//
// M1 keeps publishing RtpScanSnapshot in WiresharkSession::rtp_last_scan.
// M2 adds this independent snapshot for the stream id -> key/media metadata
// mapping consumed after a successful decode. The two snapshots coexist so M1
// callers remain source-compatible.
#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "layanalyzer/rtp/core/RtpDecodability.h"
#include "layanalyzer/rtp/core/RtpStreamKey.h"

namespace layanalyzer::rtp {

struct RtpStreamMediaInfo {
  std::string codec;
  uint32_t clock_rate = 0;
  int32_t primary_pt = -1;
  int32_t telephone_event_pt = -1;
  RtpDecodability decodable = RtpDecodability::Unsupported;
  bool is_srtp = false;
  uint64_t first_abs_epoch_us = 0;
  uint32_t sample_rate = 0;
  // RTP5-NAT-01: the stream-clock rate a video consumer needs, which is its own
  // field rather than `clock_rate` above -- that one is the RTP clock the
  // stream's PT mapping or the static table happens to carry, and it is 0 for
  // an H265/PS stream whose name is not in the dynamic clock map (H264 is).
  // This field is the rate the video access-unit builder converts timestamps
  // with (VideoAuBuilderOptions::timestamp_rate), so it is 90000 for a codec in
  // kSupportedVideoCodecs (H264 / H265 / PS, RtpCodecNames.h) and 0 for
  // everything else: "this stream has no video timeline" rather than a guessed
  // default.
  uint32_t video_timestamp_rate = 0;
  // RTP5-NAT-01: the canonical id (README §4.3), i.e. `codec` above after
  // canonical_codec(). Kept as a separate field because the JSON `codec` field
  // is a UI-facing string, while the video path selects a depacketizer by
  // exact id: `codec == "H264"` has to mean the canonical H.264 and not, say,
  // a raw alias or one of the tables' case variants.
  std::string primary_codec_id;
};

struct RtpMediaSnapshot {
  uint64_t scan_generation = 0;
  bool limit_to_display_filter = false;
  std::string filter_expression;
  std::map<std::string, RtpStreamKey> stream_keys;
  std::map<std::string, RtpStreamMediaInfo> media;
};

}  // namespace layanalyzer::rtp
