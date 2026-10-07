// RTP 编码名规范化（RTP1-NAT-06）。
//
// 本文件是 README §4.3「编码名规范 ID 表」的唯一权威实现（C13）：
// 静态 PT（< 96）的 info_payload_type_str 是 NULL，SDP 里的名字大小写各异
// （PCMA / G722 / opus），统一经 canonical_codec() 转成规范 ID。JSON 里的
// codec 字段一律用规范 ID；Kotlin 侧的 RtpCodecCatalog（RTP1-KT-04）必须与
// 本表保持一致。
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace layanalyzer::rtp {

struct CodecInfo {
  std::string id;
  int default_clock_rate = 0;
  bool is_audio = false;
  bool is_video = false;
  bool is_event = false;
};

// 大小写不敏感；未命中返回 id = 原字符串（去掉首尾空白）、
// default_clock_rate = 0、所有 kind = false。
CodecInfo canonical_codec(const std::string &raw_name);

// raw_name（规范 ID 或别名，大小写不敏感、忽略首尾空白）是否命中 §4.3 的表。
// 供「codec_known」判定使用：只有确实命中表的名字才算 known。
bool rtp_codec_is_known(const std::string &raw_name);

// 自带的静态 PT → 规范 ID 小表，只需 0/8/9/10/11/13/18/19：
//   0→g711U、8→g711A、9→g722、10→L16、11→L16、13→CN、18→g729、19→CN。
// 未命中返回 nullptr。**不链接** epan 的 rtp_payload_type_short_vals。
const char *rtp_static_pt_codec_name(uint32_t pt);

namespace detail {

// RTP4-KT-05：两个可选编解码器各自给 kSupportedAudioCodecs 增加的长度。
// 之所以要有这两个常量，是因为 std::array 的长度必须在编译期定下来 —— 数组
// 字面量里的 #if 只能决定「多不多一项」，多出来的长度得在这里算。
#ifdef LAYANALYZER_ENABLE_G729
inline constexpr size_t kG729SupportedAudioCodecCount = 1;
#else
inline constexpr size_t kG729SupportedAudioCodecCount = 0;
#endif
#ifdef LAYANALYZER_ENABLE_ILBC
inline constexpr size_t kIlbcSupportedAudioCodecCount = 1;
#else
inline constexpr size_t kIlbcSupportedAudioCodecCount = 0;
#endif

}  // namespace detail

// ---------------------------------------------------------------------------
// RTP4-KT-05：本迭代真正能解码的音频编码集合，仍是**唯一**定义处（勿分散）。
//
// 这张表是 rtp_decodability() 判 decodable 的依据，所以它必须覆盖本迭代所有
// 用户侧「能解码」的编码 —— 包括走 MediaCodec 的 AMR / AMR-WB / opus：
// RtpDecoderFactory（原生直接解码）不认识它们，但 decodable 一旦把它们报成
// unsupported，RTP4-KT-02 的 MEDIACODEC 路由就永远走不到了。
//
// 两个可选编解码器按构建开关条件编译（RTP4-BLD-02 / RTP4-NAT-08）。三个分支
// （G729 ON/OFF × iLBC ON/OFF）都必须能编译，默认构建是 ON + OFF。
//
// 顺序即 getRtpCodecCapabilities() 里 audio 数组的顺序，也是 host 用例
// RtpCodecNamesTest 记录的顺序；改顺序不算错，但会让那份用例的集合断言失去
// 排序以外的意义 —— 它断言的是集合，不是顺序。
// ---------------------------------------------------------------------------
inline constexpr size_t kSupportedAudioCodecBaseCount = 15;
inline constexpr std::array<
    const char *,
    kSupportedAudioCodecBaseCount + detail::kG729SupportedAudioCodecCount +
        detail::kIlbcSupportedAudioCodecCount>
    kSupportedAudioCodecs = {
        "g711A",
        "g711U",
        "L16",
        "g722",
        "G726-16",
        "G726-24",
        "G726-32",
        "G726-40",
        "AAL2-G726-16",
        "AAL2-G726-24",
        "AAL2-G726-32",
        "AAL2-G726-40",
        "AMR",
        "AMR-WB",
        "opus",
#ifdef LAYANALYZER_ENABLE_G729
        "g729",
#endif
#ifdef LAYANALYZER_ENABLE_ILBC
        "iLBC",
#endif
};

// canonical_id 是否属于 kSupportedAudioCodecs。
bool rtp_codec_is_supported_audio(const std::string &canonical_id);

// ---------------------------------------------------------------------------
// RTP4-KT-05：本构建是否链接了那两个可选编解码器。
//
// 只在这一处判断宏，两处消费：rtp_decodability_reason() 的「此构建未包含 X」
// 文案（BLD-02 验收 2）与 getRtpCodecCapabilities() 的 g729 / ilbc 布尔值。
// 分成两份判断会让「原生说什么」和「能力接口报什么」有机会漂移。
// ---------------------------------------------------------------------------
#ifdef LAYANALYZER_ENABLE_G729
inline constexpr bool kBuildIncludesG729 = true;
#else
inline constexpr bool kBuildIncludesG729 = false;
#endif
#ifdef LAYANALYZER_ENABLE_ILBC
inline constexpr bool kBuildIncludesIlbc = true;
#else
inline constexpr bool kBuildIncludesIlbc = false;
#endif

// ---------------------------------------------------------------------------
// 视频编码集合（RTP4-KT-05）。值的依据是 m5.md 第 12 行
// （`kSupportedVideoCodecs = {"H264","H265","PS"}`）—— M5 才会拿它扩展
// rtp_decodability()，本卡只要求 getRtpCodecCapabilities() 把这一份报给 Kotlin
// （仪器测试用它做「audio 里不得出现 H264/H265」的反例）。所以这里定义一次，
// M5 直接复用，不要另起一份。
// ---------------------------------------------------------------------------
inline constexpr std::array<const char *, 3> kSupportedVideoCodecs = {
    "H264", "H265", "PS"};

// 事件编码：CN / telephone-event。
bool rtp_codec_is_event(const std::string &canonical_id);

}  // namespace layanalyzer::rtp
