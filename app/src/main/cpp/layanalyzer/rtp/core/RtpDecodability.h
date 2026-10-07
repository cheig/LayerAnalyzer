// RTP 流可解码判定（RTP1-NAT-06）。
//
// 输入由 scanRtpStreams 按「override > sdp > static」算出的编码信息 + 流的
// 统计字段组装；输出给 UI（decodable / decodableReason）。
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstdint>
#include <string>

namespace layanalyzer::rtp {

enum class RtpDecodability { Yes, NeedsMapping, Srtp, Unsupported, Truncated };

// "yes" / "needsMapping" / "srtp" / "unsupported" / "truncated"。
const char *rtp_decodability_name(RtpDecodability value);

struct RtpDecodabilityInput {
  bool is_srtp = false;
  std::string canonical_codec;   // 已是规范 ID，或原始字符串，或空
  bool codec_known = false;      // canonical_codec 在 §4.3 表里
  uint32_t primary_pt = 0;
  bool primary_pt_is_event = false;   // CN / telephone-event
  bool any_non_event_codec = false;   // 流里存在至少一个非事件的已识别编码
  uint64_t packets = 0;
  uint64_t truncated = 0;
};

// 判定顺序严格按卡片（顺序不能变）：
//   1. is_srtp → Srtp
//   2. 没有非事件编码 且 primary_pt ∈ 96..127 → NeedsMapping
//   3. codec ∈ kSupportedVideoCodecs → Truncated / Yes（RTP5-NAT-01 新增，
//      在音频判定之前；截断规则与音频相同，见下）
//   4. codec 为空或不在 kSupportedAudioCodecs → Unsupported
//   5. packets > 0 && truncated * 2 > packets → Truncated
//   6. 否则 Yes
//
// RTP5-NAT-01（m5.md 第 12 行）把判定扩展到视频：`kSupportedVideoCodecs`
// （H264/H265/PS，定义在 RtpCodecNames.h，此处复用不重定义）在音频分支**之前**
// 判定，命中即走与音频相同的截断规则 —— 视频流同样会因抓包截断而不完整，
// `truncated` 的口径不变。视频与音频两个集合不相交，所以「谁先判」只影响
// 可读性，不影响结果。
RtpDecodability rtp_decodability(const RtpDecodabilityInput &input);

// 中文说明，给 UI 用。
std::string rtp_decodability_reason(const RtpDecodabilityInput &input);

}  // namespace layanalyzer::rtp
