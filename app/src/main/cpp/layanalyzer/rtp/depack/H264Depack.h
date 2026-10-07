// H.264 de-packetization (RFC 6184) -- RTP5-NAT-01.
//
// Input: one RTP payload at a time, in arrival order (the caller sorts by the
// extended sequence number first, so "arrival" is the stream's own order).
// Output: the NAL units that payload carried, each as its raw bytes and
// *without* a start code. NAT-03 adds the `00 00 00 01` prefixes when it writes
// the Annex-B elementary stream, and NAT-04 parses parameter sets straight out
// of these bytes, so this class must hand over exactly the NAL as it was
// packetized -- no header rewriting beyond the FU-A rebuild below, no padding.
//
// RFC 6184 section 5.4 defines four packetization modes; only two of them can
// be reassembled from the packet stream alone, and this class implements those
// two plus the trivial case:
//
//   type  1..23  single NAL unit packet -- the payload *is* one NAL unit
//   type 24      STAP-A                 -- several whole NALs, 16-bit lengths
//   type 28      FU-A                   -- one NAL split over several packets
//   type 0, 25-27, 29, 30, 31  unusable -- STAP-B / MTAP16 / MTAP24 / FU-B need
//                                          a DON or a 24-bit offset that the RTP
//                                          header does not carry, so they are
//                                          counted (`unsupported_type`) and
//                                          nothing is emitted for them.
//
// The whole state machine is one buffer for the FU being assembled. Losing a
// packet in the middle of an FU is what this class exists to survive, and
// `sequence_gap` is how the caller reports it -- see onPacket(). The depack
// layer knows nothing about access units or keyframes: `corrupt` says "the
// caller's stream lost something around this packet", and NAT-03 decides what
// that means for the frame being built.
//
// Decisions the task card left open, resolved here (RTP5-NAT-01):
//
// 1. The card defines `NRI = fu_indicator & 0x60` and the rebuilt NAL header as
//    `(NRI) | type`, so the F bit (0x80) of the FU indicator is *not* copied.
//    RFC 6184 section 5.8.1.1 does copy it, but F is the forbidden_zero_bit: it
//    MUST be zero in a conforming stream, and the card's formula is the frozen
//    contract.
// 2. `corrupt` is set in exactly the two places the card names -- rule 3 (a
//    single NAL behind a gap) and rule 5's gap bullet. A gap before a STAP-A
//    sets nothing, and neither does a fragment that arrives with no FU to join
//    (`fuWithoutStart`): in both cases the depacketizer still hands up every
//    byte it can account for, and NAT-03 receives the same `sequence_gap` flag
//    separately, so the access-unit level is where a broader "this frame is
//    damaged" rule can live.
// 3. A NAL unit type the card does not list anywhere (0) takes the unsupported
//    path. RFC 6184 has no packetization for it -- type 0 is "unspecified" and
//    MUST NOT be sent -- and the error string is what distinguishes it from a
//    packet that had nothing unsupported in it, since type 0 leaves
//    `unsupported_type` at its default value of 0.
// 4. `kMaxNalBytes` is enforced while an FU is being reassembled, which is the
//    only path that can reach it: an RTP payload is bounded by the transport
//    MTU, so a single NAL unit packet or a STAP-A entry cannot grow to 4 MiB,
//    while a fragmented NAL is unbounded by construction. The card's test 10
//    pins exactly this path. The limit is checked before appending, so a
//    runaway stream cannot make this class allocate past the cap.
// 5. A FU-A shorter than three octets (indicator + header + at least one data
//    octet) has no data to contribute and is rejected with `error == "badFu"`;
//    the card fixes no string for a truncated FU-A.
// 6. When a gap discards an in-progress FU *and* the current packet carries
//    S = 1, the packet is reassembled as a normal new FU start but `error`
//    stays `"fuSequenceGap"` and `corrupt` stays true -- the card's gap bullet
//    keeps the error, and the FU-start exception it carves out only concerns
//    the FU state. The one visible consequence is the corner where that packet
//    also carries E = 1: it is a whole NAL unit in one packet, so it is emitted
//    *and* the error is set. `corrupt` is the field to trust for "the stream
//    lost data around here"; `error` only says which packetization rule fired.
// 7. Only rule 5 touches the FU buffer. A single NAL unit packet or a STAP-A
//    that arrives while an FU is being assembled is handed up on its own and
//    the buffer is left where it was: a sender is not supposed to interleave
//    packetization modes inside one NAL, so the fragments already collected
//    are still the fragments of the NAL that started them, and dropping them
//    here would throw away data the stream really did carry. The buffer is
//    dropped by reset() at end of stream if that NAL never completes.
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

struct H264DepackOutput {
  std::string error;                     // 非空 = 该包不可用（长度非法、不支持的包型）
  std::vector<std::vector<uint8_t>> nals;// 每个 NAL 的原始字节（不含起始码）
  bool corrupt = false;                  // 本包使当前访问单元损坏（FU 中途丢包/缺 S 包）
  uint32_t unsupported_type = 0;         // 不支持的包型号（只计数，不输出）
};

class H264Depack {
 public:
  // sequence_gap: 调用方判断“本包的 RTP 序号不连续”时传 true
  //
  // The flag is only ever *read* here; the caller computes it from the extended
  // sequence numbers (NAT-05 compares `ext_seq` with the previous packet's
  // `ext_seq + 1`). One packet in, one result out -- no state is carried
  // besides the FU being assembled, so a caller that stops feeding packets
  // loses nothing that has not already been reported.
  H264DepackOutput onPacket(const uint8_t *payload, size_t length, bool sequence_gap);

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
  // The FU being reassembled, and whether the buffer holds one. The frozen
  // interface lists only the four members above; these two are implementation
  // detail and stay private (AmrModeDetector's counters are the precedent).
  std::vector<uint8_t> fu_buffer_;
  bool fu_in_progress_ = false;
};

}  // namespace layanalyzer::rtp
