// RTP 流可解码判定（RTP1-NAT-06）—— 见 RtpDecodability.h 顶部说明。

#include "layanalyzer/rtp/core/RtpDecodability.h"

#include "layanalyzer/rtp/core/RtpCodecNames.h"

namespace layanalyzer::rtp {
namespace {

// RTP5-NAT-01：canonical_id 是否属于 kSupportedVideoCodecs（H264/H265/PS）。
// 集合本身只有 RtpCodecNames.h 那一处定义，这里只做成员判断 —— 不另起一张表，
// 就是因为「哪些视频编码可解码」必须是单一定义处。
bool is_supported_video_codec(const std::string &canonical_id) {
  for (const char *id : kSupportedVideoCodecs) {
    if (canonical_id == id) {
      return true;
    }
  }
  return false;
}

}  // namespace

const char *rtp_decodability_name(RtpDecodability value) {
  switch (value) {
    case RtpDecodability::Yes:
      return "yes";
    case RtpDecodability::NeedsMapping:
      return "needsMapping";
    case RtpDecodability::Srtp:
      return "srtp";
    case RtpDecodability::Unsupported:
      return "unsupported";
    case RtpDecodability::Truncated:
      return "truncated";
  }
  return "unsupported";
}

RtpDecodability rtp_decodability(const RtpDecodabilityInput &input) {
  // 顺序不能变（卡片 §判定规则）：SRTP 即使 PT 未映射也要报 srtp。
  if (input.is_srtp) {
    return RtpDecodability::Srtp;
  }
  if (!input.any_non_event_codec && input.primary_pt >= 96 &&
      input.primary_pt <= 127) {
    return RtpDecodability::NeedsMapping;
  }
  // RTP5-NAT-01：视频编码在音频判定之前先判（m5.md 第 12 行）。截断规则与音频
  // 完全相同 —— 视频流一样会因抓包 snaplen 截断而缺数据 —— 所以这里只是把音频
  // 分支的两步重排成「先认集合，再判截断」，判定口径一个字都没变。
  if (!input.canonical_codec.empty() &&
      is_supported_video_codec(input.canonical_codec)) {
    if (input.packets > 0 && input.truncated * 2 > input.packets) {
      return RtpDecodability::Truncated;
    }
    return RtpDecodability::Yes;
  }
  if (input.canonical_codec.empty() ||
      !rtp_codec_is_supported_audio(input.canonical_codec)) {
    return RtpDecodability::Unsupported;
  }
  if (input.packets > 0 && input.truncated * 2 > input.packets) {
    return RtpDecodability::Truncated;
  }
  return RtpDecodability::Yes;
}

std::string rtp_decodability_reason(const RtpDecodabilityInput &input) {
  switch (rtp_decodability(input)) {
    case RtpDecodability::Srtp:
      return "加密媒体流，无法解码";
    case RtpDecodability::NeedsMapping:
      return "动态负载类型未映射，请手动指定编码";
    case RtpDecodability::Unsupported:
      if (input.canonical_codec.empty()) {
        return "未知编码";
      }
      // RTP4-KT-05：两个可选编解码器「本构建没编进来」是最常见的一类
      // unsupported，文案必须点名（BLD-02 验收 2 逐字要求「此构建未包含 G.729」）。
      // 判定顺序与 rtp_decodability() 一致：只有真的到了 Unsupported 分支才会
      // 走到这里，所以挑 build 判断之前先确认确实没编进来。
      if (input.canonical_codec == "g729" && !kBuildIncludesG729) {
        return "此构建未包含 G.729";
      }
      if (input.canonical_codec == "iLBC" && !kBuildIncludesIlbc) {
        return "此构建未包含 iLBC";
      }
      // 其余：表外的名字（FOO）、或本构建带了编码但用户没映射到可解码的编码。
      // 文案不再提「M1」—— M4 之后这张表由 kSupportedAudioCodecs 决定。
      return "编码 " + input.canonical_codec + " 不支持解码";
    case RtpDecodability::Truncated:
      return "超过一半的包在抓包时被截断";
    case RtpDecodability::Yes:
      // RTP5-NAT-01：视频流不再被说成「音频」。两个集合不相交，所以这里再判
      // 一次视频集合，等价于问「rtp_decodability() 走的是哪一支」，只是不用把
      // 分支结论回传。文案保持「可解码为 <规范 ID> <类型>」的形式不变。
      if (is_supported_video_codec(input.canonical_codec)) {
        return "可解码为 " + input.canonical_codec + " 视频";
      }
      return "可解码为 " + input.canonical_codec + " 音频";
  }
  return std::string();
}

}  // namespace layanalyzer::rtp
