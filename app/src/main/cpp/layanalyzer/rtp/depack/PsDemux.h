// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// PS (program stream) de-multiplexing for GB28181 -- RTP5-NAT-06.
//
// GB/T 28181 sends one H.264 or H.265 elementary stream inside an ISO 13818-1
// program stream, which is then cut into RTP payloads. The camera's RTP packets
// therefore carry *PS* structure -- a pack header, a system header, a program
// stream map and PES packets -- and not NAL units, so RTP5-NAT-01/02 cannot be
// used on them at all: a PS payload handed to H264Depack would be read as a NAL
// unit whose first octet is 0x00. This class is the layer between: it reassembles
// the RTP payloads into PS packets, parses the PS structures, and hands the video
// elementary stream up as NAL units -- the shape NAT-03 consumes, with the RTP
// layer gone -- together with the access-unit boundary and the PES timestamps
// NAT-03 needs to cut and time the access units.
//
// Input: one RTP payload at a time, in arrival order (the caller sorts by the
// extended sequence number first, like every other depacketizer here). Output:
// whole access units, each a vector of NAL units without start codes.
//
// The PS structures parsed, and what each is for:
//
//   pack_header        00 00 01 BA   14 octets (6 of SCR + markers, 3 of
//                                    program_mux_rate + markers, 1 for
//                                    reserved + pack_stuffing_length), then the
//                                    stuffing the last 3 bits declare
//   system_header      00 00 01 BB   header_length (16) then that many octets
//   program stream map 00 00 01 BC   program_stream_map_length (16), then the
//                                    descriptors and the elementary stream map:
//                                    stream_type 0x1B = H.264, 0x24 = H.265,
//                                    0x90 = G.711A (GB28181's private value)
//   PES packets        00 00 01 E0   video (PES header, PTS/DTS, then ES)
//                      00 00 01 C0   audio (parsed, dropped and counted)
//   program_end_code   00 00 01 B9   ends the PS packet
//
// How it maps onto RTP5-NAT-03. The demuxer *is* the access-unit boundary for a
// PS stream, so the caller's loop is:
//
//   layanalyzer::rtp::VideoAuBuilderOptions options;
//   options.codec = layanalyzer::rtp::VideoCodec::PS;   // both codecs' NAL types
//   options.timestamp_rate = 90000;                     // the PES PTS scale
//   options.start_at_keyframe = true;                   // as the export dialog says
//   layanalyzer::rtp::VideoAccessUnitBuilder builder(options);
//
//   // per RTP payload, in sequence order:
//   layanalyzer::rtp::PsDemuxOutput out = demux.onPacket(
//       payload, length, marker, timestamp, frame_number, sequence_gap);
//   for (const layanalyzer::rtp::PsAccessUnit &au : out.access_units) {
//     builder.onPacket(au.first_frame, au.pts, true,
//                      au.nals, au.corrupt, au.sequence_gap);
//   }
//   // once, after the last payload:
//   for (const layanalyzer::rtp::PsAccessUnit &au : demux.finish().access_units) {
//     builder.onPacket(au.first_frame, au.pts, true,
//                      au.nals, au.corrupt, au.sequence_gap);
//   }
//   std::vector<uint8_t> es;
//   std::vector<layanalyzer::rtp::VideoAuRecord> records = builder.finish(es);
//
// Four things about that mapping are load-bearing:
//
//   * `marker` is `true` on every call to the builder, and it is *not* the RTP
//     marker bit. The RTP marker was consumed by the PS reassembly (decision 1);
//     what reaches the builder is already exactly one access unit per element of
//     `access_units`, so every call is its own boundary.
//   * `ext_ts` is `au.pts`, the PES PTS in 90 kHz units. With
//     `timestamp_rate = 90000`, NAT-03's
//     `pts_us = (ext_ts - first_ext_ts) * 1000000 / timestamp_rate` comes out in
//     microseconds, and `first_ext_ts` is the PTS of the stream's first access
//     unit, so the exported timeline starts where the stream does.
//   * `au.corrupt` and `au.sequence_gap` are forwarded as they are: NAT-03 keeps
//     them apart on purpose (its decision 5) and turns either into the record's
//     0x02 flag.
//   * `au.first_frame` is the data-packet number of the RTP payload that carried
//     the PS packet in which the access unit's first NAL unit's start code
//     appeared -- the packet a viewer jumping to this access unit (KT-03) wants
//     to land on. The caller passes that number in; the demuxer cannot know it.
//
// Nothing here is wired into `jni/RtpJni.cpp`: reaching `exportRtpVideo` through
// this class is a separate change (NAT-06's card keeps the wiring out of scope).
//
// Decisions the task card left open, resolved here (RTP5-NAT-06):
//
// 1. A PS packet is completed by the RTP marker bit -- GB28181's senders set it
//    on the last RTP payload of a PS packet -- and *also* by a change of RTP
//    timestamp while one is still unfinished. The timestamp case does not throw
//    the collected bytes away: the sender has plainly moved on to the next PS
//    packet, and the bytes already here are real data that NAT-03 can still write
//    out behind a 0x02 flag, so the packet is parsed best-effort, every access
//    unit it produces is marked `corrupt`, and the event is counted in
//    `marker_missing`. No `error` string is raised for it, because nothing was
//    lost that the caller could act on -- the same `error` vs `corrupt` split
//    NAT-01 makes. A caller that would rather have nothing than a suspect frame
//    has NAT-03's `drop_corrupt`.
// 2. A completed PS packet must begin with `00 00 01 BA`. When it does not -- the
//    capture started mid-PS-packet, or a packet was lost -- the parser scans
//    forward to the next `00 00 01 BA`, counts a `resync`, and marks the packet
//    corrupt; if there is no pack header anywhere in the buffer, the packet is
//    dropped, counted in `ps_packets_dropped`, and reported as
//    `error = "noPackStart"`. Rejected alternative: parsing from offset 0 anyway,
//    which would read the inside of a PES payload as a table of start codes and
//    hand NAT-03 a NAL list built from arbitrary bytes.
// 3. Every structure in a PS packet declares its own length (the pack header's
//    fixed 14 octets plus `pack_stuffing_length`, the system header's
//    `header_length`, the PSM's `program_stream_map_length`, a PES's
//    `PES_packet_length`), so the parser can always skip to the next start code.
//    A start code that this class does not know cannot be skipped -- nothing in
//    the packet gives its length -- so the rest of the PS packet is abandoned
//    (what was parsed before it is kept), counted in `unknown_start_codes`, and
//    reported as `error = "unknownStartCode"`. `is_pes_like()` is
//    `stream_id >= 0xBD`, which covers the elementary streams (0xC0-0xDF,
//    0xE0-0xEF) and the three private/padding ids, and leaves the MPEG-1 video
//    and slice start codes (0x00-0xB8) as the only way to get here.
// 4. NAL unit boundaries are Annex-B start codes -- `00 00 01`, of which the
//    four-octet `00 00 00 01` is the same code preceded by `leading_zero_8bits` --
//    scanned over the video elementary stream *as one continuous byte stream*
//    across PES packets and PS packets. That is what makes a NAL unit split
//    across two PES packets or two PS packets come out as one NAL unit instead of
//    two fragments. The bytes between two start codes are the NAL unit, with
//    trailing `0x00` octets stripped: ISO/IEC 14496-10 Annex B puts them outside
//    the NAL unit (`trailing_zero_8bits` are how a four-octet start code is
//    written), and keeping them would put a stray octet at the end of every NAL
//    unit that is followed by one. The cost, stated plainly: a `cabac_zero_word`
//    at the end of a slice is stripped with them, which ffmpeg and every decoder
//    ignore, and which nothing in this pipeline reads. A start code with no data
//    between it and the next one is not a NAL unit and is skipped (NAT-03's
//    decision 12).
// 5. An access unit is one video PES packet -- the card's "PES boundary" -- but
//    it opens and closes at *start codes*, not at the boundary itself: at the end
//    of a PES packet the demuxer cannot know whether the bytes it holds are a
//    whole NAL unit or the first half of one, and only the next start code tells
//    it (decision 4). So an access unit opens at the start code that begins its
//    first NAL unit's data, and closes right after the NAL unit that the first
//    start code following a PES boundary terminated. A PES packet whose data
//    continues a NAL unit therefore joins the access unit in progress, which is
//    the whole point; a PES packet that starts a NAL unit of its own closes it.
//    The visible consequence is one PES packet of latency: an access unit is
//    handed over in the call that processes the *next* PES packet's data (or by
//    finish() for the last one), which costs the caller nothing because NAT-03
//    buffers the whole stream until its own finish() anyway.
// 6. The output is whole access units -- a vector per call, usually empty or one
//    element -- rather than a raw NAL list plus a "boundary" flag. A PS packet
//    can carry the tail of one access unit and the head of the next, and a single
//    NAT-03 call can only ever cut at its own end (its marker is per call), so a
//    flag-plus-NALs output could not describe that packet at all: the caller
//    would have to split its NAL list across two builder calls by hand, guessing
//    the split point the demuxer already knows. Returning the units is what keeps
//    the caller's loop four lines long.
// 7. `pts` is the PTS of the video PES packet in which the access unit's first
//    NAL unit's *start code* appeared, and `has_pts` says whether that PES packet
//    really carried one. A PES packet with no PTS gets the last PTS the demuxer
//    handed out (0 before the first one), because NAT-03 consumes `pts` as a
//    difference from the stream's first value: a made-up 0 would look like a
//    backwards jump of most of a day on a 33-bit 90 kHz clock, while the held
//    value makes that access unit share its predecessor's time and leaves the tie
//    to KT-01's monotonicity guard (NAT-03 card rule 8).
// 8. The PSM's elementary stream map is the authority for the ids it names, and
//    an id it does not name keeps ISO 13818-1's reserved range: 0xE0-0xEF is
//    video, 0xC0-0xDF is audio, and the kind is `Unknown` because no PSM said
//    which codec it is. That fallback is also what a PES packet that arrives
//    *before* any PSM gets, because senders do put the PSM only in the first PS
//    packet of a burst, or omit it for the audio stream -- and dropping a video
//    PES packet because the map has not arrived yet would lose the first frames
//    of the stream. `video_kind()` reports the codec a PSM named; the NAL units
//    handed to NAT-03 do not depend on it (`VideoCodec::PS` reads both codecs'
//    type sets, NAT-03's decision 14), so an `Unknown` kind costs nothing but the
//    caller's ability to name the codec in its result.
// 9. Audio elementary stream is dropped and counted in `pes_audio`, never
//    exposed. Feeding a G.711A stream to NAT-03's PS path would shred it into
//    pseudo-NAL units on the same start-code scan, and its octets could set the
//    keyframe or parameter-set flags. The audio of a call is M3's and M4's
//    business (README C16 keeps SIP and its media out of this pipeline); what
//    matters here is that the drop is visible in a number rather than inferred
//    from a shorter file.
// 10. An unsupported `stream_type` skips the **PES packet**, counted in
//     `pes_unsupported` -- the counted unit is the PES packet, not the stream,
//     because a PSM can be re-sent and the same `stream_type` recurs in every PES
//     packet of that stream: counting the stream would count one and hide how
//     much data was dropped. It is never an `error` and never marks an access
//     unit corrupt (the card's rule 4), which is what makes a GB28181 stream with
//     an AC-3 or AAC track beside the video exportable.
// 11. Damage to an access unit is accumulated while it is open and reported on it
//     as `corrupt` (a PS-level resync, a truncated structure, a NAL unit past the
//     cap) and `sequence_gap` (the caller's RTP-level gap flag for a payload that
//     arrived while it was open), separately, because NAT-03 keeps the two apart.
//     Damage that arrives while no access unit is open attaches to the next one
//     that opens; a unit that has been handed over starts clean. What this cannot
//     express: a gap that lands after a PS packet's last NAL unit and before the
//     next unit's first, which the demuxer sees while the earlier unit is still
//     open and therefore charges to the earlier unit. That is stated rather than
//     guessed at, and it errs on the side of flagging.
// 12. Errors are per call, and the first one of a call wins: it is the one that
//     describes where the structure was lost, and the ones after it are usually
//     its consequences. Every occurrence is counted separately in `PsDemuxStats`,
//     so no error is reported only once and then forgotten. The strings are
//     `"empty"` (a zero-length RTP payload, nothing to reassemble), `"noPackStart"`
//     (decision 2), `"psPacketTooLarge"` (decision 13), `"badPackHeader"` (a pack
//     header shorter than its fixed 14 octets, or stuffing past the end of the
//     packet), `"badSystemHeader"` (a declared `header_length` under the 6 octets
//     of the fixed part, or past the end of the packet), `"badPsm"` (a
//     `program_stream_map_length` or `elementary_stream_map_length` that does not
//     fit, or an elementary stream loop that does not exactly fill its own
//     length), `"badPes"` (a PES header past the end of the PES packet, a missing
//     `'10'` marker, or a `PES_header_data_length` that runs past it),
//     `"unknownStartCode"` (decision 3) and `"nalTooLarge"` (decision 13). A
//     caller that only wants the frames can ignore `error` and use
//     `access_units`, which is non-empty in the calls that recovered data.
// 13. Two caps, both checked before the buffer grows: `kMaxPsPacketBytes` (8 MiB)
//     for the PS packet being reassembled -- dropping it, clearing the
//     reassembly, and counting it in `ps_packets_dropped` -- and `kMaxNalBytes`
//     (4 MiB, the value the two depacketizers use) for the NAL unit being
//     scanned. A NAL unit past the cap is *not* truncated into something that
//     would look whole to NAT-03: the bytes are dropped and everything up to the
//     next start code is discarded, counted in `nal_too_large`. Access units are
//     not capped: their size is bounded by the stream itself, exactly as NAT-03's
//     own ES buffer is, and a cap there would need an options struct that nothing
//     else in this pipeline has.
// 14. `finish()` is one-shot, like NAT-03's (its decision 13), and it also closes
//     the demuxer: an unfinished PS packet is parsed best-effort, counted in
//     `truncated_ps_packets` and flagged corrupt; the bytes after the last start
//     code become the last NAL unit; and the access unit still open is released.
//     A second call returns nothing at all.
// 15. `onPacket()` takes `frame_number` and `sequence_gap` in addition to the
//     card's suggested `(payload, length, marker, ext_ts)`. Neither can be derived
//     here and both are needed by the mapping above: the frame number is the data
//     packet the access unit's `first_frame` names (KT-03 seeks with it), and the
//     gap flag is computed from extended sequence numbers, which this class never
//     sees. A caller that has neither may pass 0 and false; the record's
//     `first_frame` is then 0 and `sequence_gap` stays unset.
// 16. `PTS_DTS_flags` of 0b11 (both, as a stream with B-frames has) reads only the
//     PTS and skips the DTS with it -- NAT-03's `pts_us` is a presentation time
//     and nothing here consumes a decode time. `ESCR_flag`, `ES_rate_flag`, the
//     trick-mode, additional-copy-info, CRC and extension flags are inside
//     `PES_header_data_length` and are skipped by that length rather than parsed.
// 17. A PSM with `current_next_indicator == 0` describes a program that is not in
//     effect yet, so it is ignored -- counted in `psm_ignored` so the ignore is
//     visible -- and the previous map (or the id-range fallback) stays in force.
//     An applied PSM replaces the map, which is what its version field is for.
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

// 一条基本流的规范化分类：PSM 的 stream_type 表（ISO 13818-1 table 2-34）里本
// 类认识的那几项，加上 GB28181 的私有取值。
enum class PsStreamKind {
  Unknown,  // 没有任何 PSM 说过这条流是什么（见 decision 8）
  H264,     // stream_type 0x1B
  H265,     // stream_type 0x24
  G711A,    // stream_type 0x90（GB28181 的私有取值）
  Other,    // PSM 里出现过、但不是本类认识的 stream_type
};

// 解复用过程中的累计计数。这里没有一项是「只报一次」的：每一次丢弃、跳过、
// 重同步都在这里留下数字，调用方据此说明「为什么导出的帧比抓包里的少」。
struct PsDemuxStats {
  uint64_t rtp_payloads = 0;           // 交给 onPacket 的 RTP 负载数
  uint64_t ps_packets = 0;             // 解析过的完整 PS 包
  uint64_t ps_packets_dropped = 0;     // 丢弃的 PS 包（noPackStart / psPacketTooLarge）
  uint64_t resyncs = 0;                // 靠向后扫描 00 00 01 BA 才重新对齐的次数
  uint64_t marker_missing = 0;         // 靠时间戳变化而不是 marker 结束的 PS 包
  uint64_t truncated_ps_packets = 0;   // 流结束时仍未结束的 PS 包
  uint64_t system_headers = 0;         // 跳过的 system_header
  uint64_t psm_count = 0;              // 生效的 PSM
  uint64_t psm_ignored = 0;            // current_next_indicator == 0 而被忽略的 PSM
  uint64_t pes_video = 0;              // 视频 PES 包（送进 NAL 扫描器）
  uint64_t pes_audio = 0;              // 音频 PES 包（丢弃，decision 9）
  uint64_t pes_unsupported = 0;        // 不认识的 stream_type 的 PES 包（跳过，decision 10）
  uint64_t other_pes = 0;              // 其它 PES（padding / private_stream）
  uint64_t unknown_start_codes = 0;    // PS 包里认不出的起始码（decision 3）
  uint64_t parse_errors = 0;           // badPackHeader / badSystemHeader / badPsm / badPes
  uint64_t nal_too_large = 0;          // 超过 kMaxNalBytes 而被丢弃的 NAL（decision 13）
  uint64_t access_units = 0;           // 交出去的访问单元数
};

// 一个完整的访问单元：NAT-03 的 onPacket 需要的全部东西。
struct PsAccessUnit {
  // 该访问单元的 NAL 单元，每个是原始字节且**不含起始码**（与 H264Depack /
  // H265Depack 交给 NAT-03 的形状完全相同）。
  std::vector<std::vector<uint8_t>> nals;
  // 该访问单元第一个 NAL 的起始码所在的 PS 包的首个 RTP 数据包号。
  uint32_t first_frame = 0;
  // 该访问单元的 PES PTS，90 kHz（decision 7）。
  uint64_t pts = 0;
  // 上面这个 PTS 是否真的来自 PES；false = 沿用上一个（decision 7）。
  bool has_pts = false;
  // 收集期间发生过丢包或解析失败（decision 11）。
  bool corrupt = false;
  // 收集期间调用方报过 RTP 序号不连续（decision 11）。
  bool sequence_gap = false;
  // 该访问单元来自哪条视频流（decision 8；PSM 未命名时为 Unknown）。
  PsStreamKind kind = PsStreamKind::Unknown;
};

// 一次 onPacket / finish 的结果。`access_units` 是这次调用**完成**的访问单元
// （通常是 0 或 1 个，见 decision 6）；`error` 说的是这次调用本身（decision 12），
// 两者互不影响：带着 error 的调用一样可能交出恢复出来的访问单元。
struct PsDemuxOutput {
  std::string error;
  std::vector<PsAccessUnit> access_units;
};

// GB28181 的 PS 解复用器。一个对象对应一条流；不持有任何 epan/JNI 状态。
class PsDemux {
 public:
  // 一个 RTP 负载。`marker` 是 RTP 头的标记位，`ext_ts` 是 32 位扩展后的 RTP
  // 时间戳（用于判断「上一个 PS 包被发方放弃了」，见 decision 1），
  // `frame_number` 是调用方的数据包号（进 `first_frame`），`sequence_gap` 是调用方
  // 判断的「本包与上一包之间 RTP 序号不连续」（进 `sequence_gap`，见 decision 15）。
  PsDemuxOutput onPacket(const uint8_t *payload, size_t length, bool marker,
                         uint64_t ext_ts, uint32_t frame_number,
                         bool sequence_gap);

  // 流结束时调用一次：冲刷最后一个 NAL、释放还开着的访问单元（decision 14）。
  PsDemuxOutput finish();

  // PSM 命名的视频编码（elementary stream id 最小的那条视频流）；没有 PSM 或
  // PSM 里没有视频项时返回 Unknown（decision 8）。
  PsStreamKind video_kind() const;

  // 累计计数（decision 12）。
  const PsDemuxStats &stats() const { return stats_; }

  // PS 包重组的上限，以及单个 NAL 的上限（decision 13）。后者与 H264Depack /
  // H265Depack 的 kMaxNalBytes 同值，理由相同：RTP 负载受 MTU 限制，一个 NAL 却
  // 没有。
  static constexpr size_t kMaxPsPacketBytes = 8u * 1024 * 1024;
  static constexpr size_t kMaxNalBytes = 4u * 1024 * 1024;

 private:
  // 一个 PES 包的头部解析结果。
  struct PesInfo {
    size_t payload_begin = 0;  // ES 负载的第一个字节
    size_t pes_end = 0;        // PES 包之后的那个字节
    bool has_header = false;   // padding_stream / private_stream_2 没有 PES 头
    bool has_pts = false;
    uint64_t pts = 0;
  };

  void parse_ps_packet(size_t size);
  bool parse_pes(size_t pos, size_t size, PesInfo *info);
  void feed_video_es(const uint8_t *es, size_t length, uint64_t pts, bool has_pts,
                     PsStreamKind kind);
  void append_pending(const uint8_t *bytes, size_t length);
  void flush_pending_nal();
  void open_access_unit();
  void close_access_unit();
  void mark_damage(bool gap);
  void set_error(const std::string &error);
  PsStreamKind classify_es_id(uint8_t es_id) const;

  // --- PS 包重组（decision 1）---
  std::vector<uint8_t> ps_buffer_;
  bool ps_have_ts_ = false;
  uint64_t ps_ext_ts_ = 0;
  uint32_t ps_first_frame_ = 0;

  // --- Annex-B 扫描（decision 4）---
  std::vector<uint8_t> pending_;      // 上一个起始码之后的全部字节
  bool discarding_nal_ = false;       // 超限后丢弃到下一个起始码（decision 13）

  // --- 正在收集的访问单元（decision 5）---
  bool au_open_ = false;
  std::vector<std::vector<uint8_t>> au_nals_;
  uint32_t au_first_frame_ = 0;
  uint64_t au_pts_ = 0;
  bool au_has_pts_ = false;
  bool au_corrupt_ = false;
  bool au_gap_ = false;
  PsStreamKind au_kind_ = PsStreamKind::Unknown;
  bool damage_for_next_au_ = false;
  bool gap_for_next_au_ = false;
  bool close_pending_ = false;        // 上一个视频 PES 已结束（decision 5）

  // --- 访问单元的「开头」候选：最近一个起始码所在的 PES（decision 5、7）---
  uint64_t candidate_pts_ = 0;
  bool candidate_has_pts_ = false;
  uint32_t candidate_frame_ = 0;
  PsStreamKind candidate_kind_ = PsStreamKind::Unknown;
  bool candidate_set_ = false;

  // --- PTS 沿用（decision 7）---
  uint64_t last_pts_ = 0;

  // --- 当前正在解析的 PS 包 ---
  uint32_t parsing_frame_ = 0;
  std::map<uint8_t, PsStreamKind> es_map_;

  // --- 单次调用 ---
  std::string call_error_;
  std::vector<PsAccessUnit> released_;
  bool finished_ = false;
  PsDemuxStats stats_;
};

}  // namespace layanalyzer::rtp
