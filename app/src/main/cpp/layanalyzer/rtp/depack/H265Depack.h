// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// H.265 de-packetization (RFC 7798) -- RTP5-NAT-02.
//
// Input: one RTP payload at a time, in arrival order (the caller sorts by the
// extended sequence number first, so "arrival" is the stream's own order).
// Output: the NAL units that payload carried, each as its raw bytes and
// *without* a start code. NAT-03 adds the `00 00 00 01` prefixes when it writes
// the Annex-B elementary stream, and NAT-04 parses parameter sets straight out
// of these bytes, so this class must hand over exactly the NAL as it was
// packetized -- no header rewriting beyond the FU rebuild below, no padding.
//
// The class is deliberately isomorphic to H264Depack (RTP5-NAT-01): the same
// entry points, the same output members and the same error strings wherever the
// two specs share a rule, so NAT-05 can select one or the other by canonical
// codec id and drive both through one loop. What differs is the NAL unit
// header, and it is *two* octets rather than H.264's one -- both of them carry
// bits the de-packetizer has to reproduce:
//
//   octet 0:  F (1) | nal_unit_type (6) | nuh_layer_id's top bit (1)
//   octet 1:  nuh_layer_id's low 5 bits (5) | nuh_temporal_id_plus1 (3)
//
// RFC 7798 section 4.4 assigns the packetization modes like this:
//
//   type  0..47   single NAL unit packet -- the payload *is* one NAL unit
//   type  48      AP   -- several whole NALs, 16-bit lengths, optional DONL
//   type  49      FU   -- one NAL split over several packets
//   type  50      PACI -- payload content information, no NAL unit of its own
//   type 51..63   reserved
//
// so `nal_type = (payload[0] >> 1) & 0x3F` and the single-NAL range *starts* at
// zero: 0 is a real HEVC NAL unit type (TRAIL_N), not RFC 6184's "unspecified".
//
// The whole state machine is one buffer for the FU being assembled. Losing a
// packet in the middle of an FU is what this class exists to survive, and
// `sequence_gap` is how the caller reports it -- see onPacket(). The depack
// layer knows nothing about access units or keyframes: `corrupt` says "the
// caller's stream lost something around this packet", and NAT-03 decides what
// that means for the frame being built.
//
// Decisions the task card left open, resolved here (RTP5-NAT-02):
//
// 1. `donl_present` is a constructor argument: `explicit H265Depack(bool
//    donl_present = false)`. The card fixes only that the caller supplies it
//    and that it is a stream-level property (`sprop-max-don-diff > 0` in the
//    stream's SDP fmtp), and one stream is one depacketizer, so the value
//    cannot differ between two packets of a stream. Keeping it out of
//    onPacket() is what keeps that signature identical to H264Depack's -- the
//    property NAT-05 relies on when it picks a depacketizer by codec id and
//    drives both through the same code -- and the default argument keeps
//    `H265Depack depack;` valid, so the two classes stay interchangeable at
//    construction as well. Rejected: a third onPacket() parameter, which would
//    break that interchangeability for a value that never varies per packet.
// 2. The FU's rebuilt header is two octets, and the card's `payload[0] & 0x81`
//    keeps the F bit (0x80) *and* the top bit of nuh_layer_id (0x01), because
//    H.265 packs the 6-bit layer id across both header octets -- the low bit of
//    octet 0 is not spare. H264Depack's formula (`& 0x60`) drops F; the two
//    formulas differ because RFC 7798 section 4.4.3 rebuilds the header from
//    the FU packet's PayloadHdr (F and LayerId) plus the FU header (FuType),
//    while the H.264 card froze a formula that carries only the NRI bits.
//    Octet 1 is copied verbatim from the FU packet: the FU header replaced only
//    the type field, so the layer id's low bits and the temporal id are
//    unchanged.
// 3. `donl_present` is honoured for type 48 only. Only the AP payload header
//    carries a DONL field; a single NAL unit packet or an FU packet has nowhere
//    to put one, so a stream whose `sprop-max-don-diff` is positive still
//    de-packetizes those normally. That is also why the card's "整体" means
//    "this packet is rejected whole", not "this stream is unusable".
// 4. The DONL rejection sets `unsupported_type = 48` as well as the error. The
//    packet is a well-formed AP that this stream's property makes unusable, and
//    the count is what a caller reports as "packets that produced nothing"; the
//    error string is what says why. Nothing is emitted and an FU in progress is
//    untouched.
// 5. PACI (50) and the reserved types (51..63) take H.264's unsupported path
//    verbatim: `unsupported_type` = the type, `error = "unsupported"`, nothing
//    emitted, and an FU being assembled is left alone -- they belong to a
//    different packetization mode and carry nothing that could complete an FU.
// 6. A FU shorter than four octets (2-octet payload header + FU header + at
//    least one data octet) carries no fragment data and is rejected with
//    `error == "badFu"`; H.264's limit is three octets for exactly the same
//    reason, one less because its payload header is one octet. The card fixes
//    no string for a truncated FU.
// 7. The AP length-overrun error is `"badAp"`. H.264's `"badStap"` names
//    H.264's STAP-A, a term RFC 7798 never uses, while every rule the two cards
//    share keeps H.264's string: `"empty"`, `"badFu"`, `"fuWithoutStart"`,
//    `"fuSequenceGap"`, `"nalTooLarge"`, `"unsupported"`.
// 8. `corrupt` is set in exactly the two places the card names -- rule 2 (a
//    single NAL behind a gap) and rule 4's gap bullet. A gap before an AP sets
//    nothing, and neither does a fragment that arrives with no FU to join
//    (`fuWithoutStart`): in both cases the depacketizer still hands up every
//    byte it can account for, and NAT-03 receives the same `sequence_gap` flag
//    separately, so the access-unit level is where a broader "this frame is
//    damaged" rule can live.
// 9. `kMaxNalBytes` is enforced while an FU is being reassembled, which is the
//    only path that can reach it: an RTP payload is bounded by the transport
//    MTU, so a single NAL unit packet or an AP entry cannot grow to 4 MiB,
//    while a fragmented NAL is unbounded by construction. The two rebuilt
//    header octets count towards the cap with the fragment data, and the limit
//    is checked before appending, so a runaway stream cannot make this class
//    allocate past the cap.
// 10. When a gap discards an in-progress FU *and* the current packet carries
//    S = 1, the packet is reassembled as a normal new FU start but `error`
//    stays `"fuSequenceGap"` and `corrupt` stays true -- the card's gap bullet
//    keeps the error, and the FU-start exception it carves out only concerns
//    the FU state. The one visible consequence is the corner where that packet
//    also carries E = 1: it is a whole NAL unit in one packet, so it is emitted
//    *and* the error is set. `corrupt` is the field to trust for "the stream
//    lost data around here"; `error` only says which packetization rule fired.
// 11. Only the FU rule touches the FU buffer. A single NAL unit packet or an AP
//    (including one rejected for DONL) that arrives while an FU is being
//    assembled is handled on its own and the buffer is left where it was: a
//    sender is not supposed to interleave packetization modes inside one NAL,
//    so the fragments already collected are still the fragments of the NAL that
//    started them, and dropping them here would throw away data the stream
//    really did carry. The buffer is dropped by reset() at end of stream if
//    that NAL never completes.
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

struct H265DepackOutput {
  std::string error;                     // 非空 = 该包不可用（长度非法、不支持的包型）
  std::vector<std::vector<uint8_t>> nals;// 每个 NAL 的原始字节（不含起始码）
  bool corrupt = false;                  // 本包使当前访问单元损坏（FU 中途丢包/缺 S 包）
  uint32_t unsupported_type = 0;         // 不支持的包型号（只计数，不输出）
};

class H265Depack {
 public:
  // donl_present: 流的 `sprop-max-don-diff > 0`（由调用方传入；见上面第 1 条）
  //
  // The value is fixed for the life of the object because it is a property of
  // the stream, not of a packet -- see header decision 1, including the
  // alternative that was rejected. With the default argument the class stays
  // constructible as `H265Depack depack;`, exactly like H264Depack.
  explicit H265Depack(bool donl_present = false);

  // sequence_gap: 调用方判断“本包的 RTP 序号不连续”时传 true
  //
  // The flag is only ever *read* here; the caller computes it from the extended
  // sequence numbers (NAT-05 compares `ext_seq` with the previous packet's
  // `ext_seq + 1`). One packet in, one result out -- no state is carried
  // besides the FU being assembled, so a caller that stops feeding packets
  // loses nothing that has not already been reported.
  H265DepackOutput onPacket(const uint8_t *payload, size_t length,
                            bool sequence_gap);

  // 流结束时清理正在组装的 FU
  //
  // Called at end of stream (or when the caller moves to another stream): an
  // FU that never saw its E fragment is dropped rather than completed, because
  // the bytes it is missing are exactly the ones no later packet will carry.
  void reset();

  // True while an FU has been started and not yet completed. NAT-05 uses it to
  // count a stream whose last access unit was cut short.
  bool hasPartialFu() const;

  static constexpr size_t kMaxNalBytes = 4u * 1024 * 1024;

 private:
  // The FU being reassembled, whether the buffer holds one, and the stream's
  // DONL property. The frozen interface lists only the constructor and the
  // methods above; these three are implementation detail and stay private
  // (H264Depack's FU state is the precedent).
  std::vector<uint8_t> fu_buffer_;
  bool fu_in_progress_ = false;
  bool donl_present_ = false;
};

}  // namespace layanalyzer::rtp
