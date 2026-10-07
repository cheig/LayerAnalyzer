// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// RTP 流标识（RTP1-NAT-01）。
//
// 移植自 Wireshark 4.0.10 的 ui/rtp_stream_id.c：rtpstream_id_t /
// rtpstream_id_copy_pinfo / rtpstream_id_to_hash / rtpstream_id_equal。
// 与原版的唯一区别是**不保存 epan 指针**：原版对 address 做深拷贝，这里改存
// 已经渲染好的地址文本，这样 key 可以脱离 packet_info、跨帧长期缓存
// （session->rtp_last_scan 会保存它）。
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace layanalyzer::rtp {

struct RtpStreamKey {
  std::string src;  // 规范化地址文本，如 "10.0.0.1" / "2001:db8::1"
  std::string dst;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint32_t ssrc = 0;
  bool operator==(const RtpStreamKey &other) const;
  bool operator!=(const RtpStreamKey &other) const { return !(*this == other); }
};

struct RtpStreamKeyHash {
  size_t operator()(const RtpStreamKey &key) const noexcept;
  // RtpExtractionRequest freezes stream_ids as std::map<..., RtpStreamKeyHash>.
  // std::map requires a binary comparator, so this overload supplies a stable
  // lexicographic ordering while the one-argument overload remains the hash for
  // unordered containers.
  bool operator()(const RtpStreamKey &left,
                  const RtpStreamKey &right) const noexcept;
};

/** "10.0.0.1:40000-10.0.0.2:30000/0x1a2b3c4d"（SSRC 小写、补足 8 位）。 */
std::string rtp_stream_key_to_string(const RtpStreamKey &key);

}  // namespace layanalyzer::rtp
