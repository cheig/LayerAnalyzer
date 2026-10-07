// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Access-unit assembly and `.vidx` records for the video export -- RTP5-NAT-03.
//
// NAT-01 / NAT-02 turn one RTP payload into the NAL units it carried; this class
// is what turns a *stream* of those payloads into access units, in one Annex-B
// elementary stream, with the byte range, presentation time and flags of every
// access unit recorded next to it. It sits between the depacketizers and
// NAT-05's `exportRtpVideo`, and the two things it decides -- where one access
// unit ends and what its PTS is -- are what the exported MP4 is worth or is not.
//
// The interface is frozen by task_rtp_m5_video.md section 3.1 and the RTP5-NAT-03
// card; the rules below it are the card's rules 1-8. Anything the card left open
// is resolved in the numbered decision list at the end of this file.
//
// How the bytes are produced: every NAL unit is written as `00 00 00 01` followed
// by the NAL's bytes (card rule 7), and an access unit's byte range is exactly its
// NAL units plus those start codes -- nothing else is inserted, and the in-band
// parameter sets keep their original position (card rule 4). Access units are
// buffered until finish(), because the parameter-set decision cannot be made
// before the stream ends (see decision 6), and finish() hands the ES over in one
// piece -- see decision 13 for how that stays a single copy.
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

enum class VideoCodec { H264, H265, PS };

// One access unit as the caller will index it. Field names and defaults are the
// card's; KT-01 reads them back out of the `.vidx` file (VidxFile.h) field for
// field.
struct VideoAuRecord {
  uint64_t byte_offset = 0;   // 指向 ES 文件
  uint32_t byte_length = 0;
  uint64_t pts_us = 0;
  uint32_t first_frame = 0;   // 该访问单元第一个包的数据包号
  uint8_t flags = 0;          // 0x01 key, 0x02 corrupt, 0x04 hasParamSets
};

// `flags` bits, named so that NAT-05 and the tests do not spell out literals.
inline constexpr uint8_t kVideoAuFlagKey = 0x01;
inline constexpr uint8_t kVideoAuFlagCorrupt = 0x02;
inline constexpr uint8_t kVideoAuFlagParamSets = 0x04;

struct VideoAuBuilderOptions {
  VideoCodec codec = VideoCodec::H264;
  uint32_t timestamp_rate = 90000;
  bool start_at_keyframe = true;
  bool drop_corrupt = false;
  // 来自 SDP 的参数集（可选；**只有当流里完全没有对应的参数集时才注入到流开头**）
  //
  // Each element is one NAL unit *without* a start code, exactly as KT-00
  // decodes `sprop-parameter-sets` / `sprop-vps` / `sprop-sps` / `sprop-pps`.
  std::vector<std::vector<uint8_t>> sps, pps, vps;
};

class VideoAccessUnitBuilder {
 public:
  explicit VideoAccessUnitBuilder(const VideoAuBuilderOptions &options);

  // 每包：frames 与 ext_ts 为 RTP 元数据；nals 是解包后的 NAL（不含起始码）
  // sequence_gap / corrupt 由解包器提供；marker 与 ext_ts 用于切分
  //
  // One RTP payload per call, in arrival order -- the order the caller has
  // already sorted by extended sequence number. The packet's bytes reach the ES
  // through `nals`; `corrupt` and `sequence_gap` are the depacketizer's own two
  // flags (NAT-01 rule 3 / rule 5), and both are *kept*, not merged: see
  // decision 5 for the rule that turns them into the access unit's 0x02.
  void onPacket(uint32_t frame_number, uint64_t ext_ts, bool marker,
                const std::vector<std::vector<uint8_t>> &nals, bool corrupt,
                bool sequence_gap);

  // 遍历结束后调用；返回写出的访问单元（ES 字节由 out_es 追加）
  //
  // Appends the whole elementary stream to `out_es` and returns the records in
  // the order they must be written -- the injected parameter-set pseudo access
  // unit first when there is one (decision 7). `byte_offset` is absolute within
  // the ES *file*, so it counts whatever `out_es` already held when finish() was
  // called (decision 13); with the empty vector NAT-05 passes, that is simply the
  // offset in the appended bytes.
  //
  // Returns nothing -- and appends nothing -- on the "noKeyframe" path
  // (decision 9), so a caller that honours error() cannot produce a partial file.
  std::vector<VideoAuRecord> finish(std::vector<uint8_t> &out_es);

  std::string error() const;      // 例如 "noKeyframe"

 private:
  // A record while it is being accumulated: `length` counts octets already
  // appended to es_, so `offset + length == es_.size()` right after the NAL that
  // closed it.
  struct AuState {
    uint64_t offset = 0;
    uint64_t length = 0;
    uint64_t ext_ts = 0;        // the timestamp of the AU's first packet
    uint32_t first_frame = 0;   // the frame number of the AU's first packet
    uint8_t flags = 0;          // kVideoAuFlagKey | kVideoAuFlagParamSets
  };

  void finalize_au();
  void classify_nal(const std::vector<uint8_t> &nal);
  uint64_t pts_us_for(uint64_t ext_ts) const;
  std::vector<uint8_t> build_injection() const;

  VideoAuBuilderOptions options_;
  std::string error_;

  // The ES under construction, and the access units in it, in arrival order.
  std::vector<uint8_t> es_;
  std::vector<VideoAuRecord> records_;

  // The access unit being accumulated. `first_valid` says "some packet has been
  // assigned to the current (post-boundary) position already", whether or not it
  // produced a NAL unit -- see decision 11.
  AuState au_;
  bool au_open_ = false;
  bool au_first_valid_ = false;
  bool au_damage_ = false;

  // The stream's first packet: the origin of the PTS scale (decision 3) and the
  // `first_frame` of the injected pseudo access unit (decision 7).
  bool first_packet_seen_ = false;
  uint32_t first_frame_ = 0;
  uint64_t first_ext_ts_ = 0;

  // The previous packet, which is what decides whether this one is a boundary.
  bool have_previous_ = false;
  uint64_t previous_ext_ts_ = 0;
  bool previous_marker_ = false;

  // Has this set kind been seen in band anywhere in the stream (decision 6)?
  bool saw_sps_ = false;
  bool saw_pps_ = false;
  bool saw_vps_ = false;

  bool finished_ = false;
};

}  // namespace layanalyzer::rtp

// ---------------------------------------------------------------------------
// Decisions the task card left open, resolved here (RTP5-NAT-03).
//
// 1. The boundary is detected from the *previous* packet, not the current one:
//    an access unit ends at the packet that carried marker = 1, and also ends
//    when the next packet's ext_ts differs. Rule 1 reads as one test on the
//    current packet ("marker == true 或 ext_ts 与上一包不同"), but a marker bit
//    means "this packet is the last of an access unit", so the packet that
//    carries it belongs to the unit that just ended, and the packet after it
//    opens the next one. Both conditions firing at once is one boundary
//    (card rule 1), and an access unit is only ever *opened* by a packet that
//    brought at least one non-empty NAL unit, so an empty access unit cannot be
//    recorded -- a stream whose packets all produced nothing yields no records
//    at all rather than a run of zero-length ones.
// 2. The PTS rate is `options.timestamp_rate` (default 90000), not the literal
//    90000 the card's formula spells out -- the option exists for exactly this
//    and NAT-05 fills it from `RtpStreamMediaInfo::video_timestamp_rate`. A rate
//    of 0 is not a timebase: it is replaced by the 90000 default rather than
//    dividing by zero, which is the only value NAT-01's field can take that the
//    formula cannot use (`video_timestamp_rate` is 0 for a codec that is not
//    H264/H265/PS, and exporting video for such a stream is a caller error -- but
//    it must not be a crash).
// 3. `first_ext_ts` is the ext_ts of the first packet the builder was given,
//    whether or not that packet produced a NAL unit -- the same "流的第一帧" the
//    card fixes for the pseudo access unit's `first_frame`. It is deliberately
//    *not* rebased when start_at_keyframe drops the leading access units: the
//    PTS of an access unit then keeps saying when it arrived on the stream's own
//    timeline, and a rebase would make the injected pseudo access unit's PTS
//    (decision 7) depend on which access unit happened to survive.
// 4. `pts_us = (ext_ts - first_ext_ts) * 1000000 / rate` in arrival order and
//    without sorting (card rule 2). The difference is taken as a signed value:
//    RTP timestamps are not monotonic in a B-frame stream, and a capture that
//    starts mid-GOP can put a packet *behind* the first one, where an unsigned
//    subtraction would wrap to ~1.8e19 microseconds. A negative difference is
//    written as 0 -- the smallest value an unsigned `pts_us` can carry and the
//    only one MediaMuxer accepts -- and the records keep their arrival order, so
//    this is a clamp and not a reordering. KT-01's monotonicity guard owns what
//    happens to two records that share a PTS (card rule 8).
// 5. An access unit is corrupt when *any* packet belonging to it reported
//    `corrupt` or arrived with `sequence_gap` -- including a packet that
//    produced no NAL unit at all. That last case is the one that matters: when a
//    packet is lost in the middle of an FU-A, NAT-01 drops the partial NAL and
//    reports `fuSequenceGap` on the *next* packet that arrives, which brings no
//    NAL with it (NAT-01 header note 2). "Contributed to it" therefore means
//    "lies between the same two boundaries", not "brought bytes". A packet that
//    starts a new access unit contributes its damage to *that* unit, and the
//    damage accumulator is cleared at every boundary, so a dropped packet never
//    taints the unit that follows it.
// 6. The injection decision scans **every** access unit of the stream, not the
//    first N (the card says "前 N 个" without fixing N, which is not implementable
//    as written). A set kind is injected only when it never appeared in band
//    anywhere -- in which case not one byte of the stream is moved, which is what
//    QA-01's byte-for-byte comparison against the Lua plugin depends on. The
//    scan covers access units that start_at_keyframe later drops: whether a
//    parameter set exists in the stream is a property of the stream, and the
//    decision is made before anything is dropped anyway (the two filters run in
//    finish(), decision 10).
// 7. The injected bytes form record 0: `flags = 0x04`, `first_frame` = the
//    stream's first frame number (not the first *kept* access unit's), and
//    `pts_us` = the PTS of the first kept access unit -- the pseudo access unit
//    introduces no time of its own, and giving it 0 while start_at_keyframe drops
//    a leading second of video would stretch the exported duration by exactly
//    that much. It survives start_at_keyframe (card rule 5) because it is the
//    only copy of the parameter sets in the stream.
// 8. `0x04` means "this access unit contains parameter-set NAL units", so it is
//    set on the injected pseudo access unit *and* on any access unit that
//    carried in-band sets -- the flag is named `hasParamSets`, not
//    `isInjected`. Nothing in the frozen contracts keys on it (KT-01 reads only
//    0x01), and it never affects the ES bytes.
// 9. "noKeyframe" is raised only when `start_at_keyframe` is true, which is
//    where the card's rule 5 puts it. With the option off -- the setting QA-01
//    compares against the Lua plugin -- a stream with no IDR/IRAP at all (a
//    capture that begins mid-GOP) is exported as it stands; refusing it there
//    would fail the comparison the card's own rule 6 exists to enable.
// 10. The two filters run in this order: `drop_corrupt` first, then "the first
//     keyframe" is located among the survivors. So with both options on, the
//     stream starts at the first keyframe the caller asked to keep, and an ES
//     that would have begun with a damaged keyframe does not. If that leaves no
//     keyframe at all, the answer is "noKeyframe": the caller did ask for
//     damaged data to be dropped, and an ES with no keyframe cannot be muxed
//     (QA-02 requires the first frame not to be corrupt when startAtKeyframe is
//     on).
// 11. `first_frame` is the frame number of the access unit's first *packet*,
//     whether or not that packet produced a NAL unit -- a packet that brought
//     nothing still lies between the same two boundaries, and it is the packet a
//     viewer jumping to this access unit (KT-03) wants to land on.
// 12. A zero-length NAL is skipped: a start code with nothing after it is not a
//     NAL unit, so writing one would make the ES ill-formed, and neither
//     depacketizer can produce one (NAT-01 rule 4 / NAT-02 skip zero-length
//     aggregation entries). A packet whose NAL list is empty or all-empty
//     therefore opens no access unit -- decision 1's "no empty access unit".
// 13. finish() appends to `out_es` instead of filling it, as the frozen comment
//     says, and the ES is copied into it exactly once: the access units are
//     accumulated in one internal buffer while the stream is read, and finish()
//     appends the injected bytes (if any) and then each surviving unit's byte
//     range from that buffer -- never a second copy of the whole stream, and
//     never a per-access-unit temporary. The internal buffer is released once
//     `out_es` owns the bytes. finish() is a one-shot call: a second call
//     returns nothing and appends nothing.
// 14. `VideoCodec::PS` accepts *both* codecs' types: keyframes are H.264's IDR
//     (type 5) and H.265's IRAP (types 16-23), parameter sets are H.264's SPS/PPS
//     (7/8) and H.265's VPS/SPS/PPS (32/33/34). Rationale: a PS stream is H.264
//     or H.265 depending on the PSM's `stream_type` (0x1B or 0x24, NAT-06), and
//     neither this class nor its frozen interface is told which -- the demuxer
//     hands over ES bytes with the RTP layer already gone. Choice (b), treating
//     PS as H.264 only, would silently declare every HEVC GB28181 stream
//     keyframe-less and, with startAtKeyframe on, fail it with "noKeyframe". The
//     cost of (a) is a false positive: an H.264 NAL whose first octet happens to
//     put types 16-23 in H.265's type field (H.264's filler and the reserved
//     12-15 with NRI bits set) is read as a keyframe. That can only set 0x01 or
//     move the start_at_keyframe point; it can never change the ES bytes. The
//     H264 and H265 paths are unaffected: each reads only its own type set.
