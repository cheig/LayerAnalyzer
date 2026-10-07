// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// AMR / AMR-WB de-packetization (RFC 4867) -- RTP4-NAT-04.
//
// Input: one RTP payload. Output: its frames in *storage format* (RFC 4867
// section 5) -- one ToC octet followed by that frame's payload bits, octet
// aligned, with the spare low bits of the final octet zeroed. That is exactly
// what Android's MediaCodec "audio/amr" and "audio/amr-wb" decoders consume
// (RTP4-NAT-06 writes it to .frames, RTP4-KT-01 feeds it in), so the octets
// have to be exact rather than approximately right.
//
// Both payload formats are supported, and they are not variations of one
// another:
//   RFC 4867 section 4.4  octet-aligned      -- CMR + (ToC + octets), byte aligned
//   RFC 4867 section 4.3  bandwidth-efficient -- CMR + F + FT + Q + bit-packed data
// The bandwidth-efficient one is where implementations go wrong; see read_bits()
// and the FT-masking note in AmrDepack.cpp.
//
// Two things the task card leaves open, resolved here (RTP4-NAT-04):
//
// 1. The card's trailing comment says "called 时 mode=Auto 会用内部探测状态", but
//    the frozen signature has no mode parameter, and a single-payload function
//    cannot hold detection state anyway. The signature wins: AmrModeDetector is
//    how the caller decides, and the chosen mode is then passed in as
//    `octet_aligned`. Auto detection lives only in the detector; result() never
//    returns AmrMode::Auto -- it is the caller's "not decided yet" value.
// 2. crc / interleaving are stream-level properties (SDP fmtp `crc=1`,
//    `robust-sorting=1`), not something one payload reveals, so the 4-argument
//    form cannot express them. They get the overload below; the 4-argument form
//    is that overload with both flags false.
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

enum class AmrMode { Auto, OctetAligned, BandwidthEfficient };

struct AmrFrame {
  uint8_t toc;
  std::vector<uint8_t> data;
  bool is_sid = false;
  bool no_data = false;
};

struct AmrDepackResult {
  std::string error;                 // 非空表示这个包不可用
  std::vector<AmrFrame> frames;      // storage 格式：toc + 数据（按字节对齐，末字节高位补 0）
  bool speech_lost = false;          // 该包内出现了 speech lost（Q=0）
  bool no_data = false;              // NO_DATA 帧（CMR/静音指示）
};

// 解一包（一个 RTP 负载）；called 时 mode=Auto 会用内部探测状态
//
// RTP4-NAT-04: the mode is *not* detected here -- see point 1 in the file
// header. AmrModeDetector picks it, the caller passes the answer in.
//
// `is_wb` selects the FT table (AMR-NB vs AMR-WB); the two tables disagree on
// both frame sizes and SID ranges, so a payload cannot be parsed without it.
//
// On failure `error` is non-empty and everything else in the result is empty /
// false: a payload that cannot be fully accounted for yields no partial frames.
AmrDepackResult depack_amr(const uint8_t *payload, size_t length, bool is_wb,
                           bool octet_aligned);

// RTP4-NAT-04: crc / interleaved come from the SDP fmtp (crc=1, robust-sorting=1)
// and cannot be inferred from a payload, so they are passed in by the caller.
// The 4-argument form above is this overload with both flags false.
//
// Either flag set is unsupported (RFC 4867 section 4.4.3 interleaves the frames
// and appends a CRC over them, so the payload is no longer a plain frame list)
// and returns error == "unsupported: crc"; the caller records the stream as
// unsupported instead of silently mis-parsing it.
AmrDepackResult depack_amr(const uint8_t *payload, size_t length, bool is_wb,
                           bool octet_aligned, bool crc, bool interleaved);

// 自动探测：对前 50 个包分别按两种模式解析，返回合法率高的那个；平局返回 bandwidth-efficient
//
// A payload is observed by parsing it both ways with the 4-argument depack_amr()
// and counting the parses that came back with an empty error. The third
// argument is `is_wb`: the FT tables are band-specific, so a parse needs it and
// the detector cannot guess it.
//
// "Valid" means the parse accounted for the whole payload, not merely that it
// stopped without running off the end -- otherwise every octet-aligned packet
// would also look like a valid bandwidth-efficient one (the BE interpretation of
// CMR+ToC reads a short FT and stops early), and the detector could never answer
// OctetAligned. See depack_be()/depack_oa() for the exact rule.
//
// The observation count stops at 50, so the result is the same whether the
// caller stops feeding packets at 50 or keeps going. A tie -- including zero
// observations, which is a 0:0 tie -- resolves to BandwidthEfficient, as the
// card mandates.
struct AmrModeDetector {
  void observe(const uint8_t *payload, size_t length, bool is_wb);
  AmrMode result() const;

 private:
  // The frozen interface lists only the two methods above; the counters are
  // implementation detail and stay private.
  static constexpr uint32_t kMaxObservations = 50;
  uint32_t observations_ = 0;
  uint32_t octet_aligned_valid_ = 0;
  uint32_t bandwidth_efficient_valid_ = 0;
};

}  // namespace layanalyzer::rtp
