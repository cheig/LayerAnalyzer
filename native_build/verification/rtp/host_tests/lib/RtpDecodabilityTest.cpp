// RTP1-NAT-06：可解码判定的 host 单测（全部分支）。
//
// 只测纯标准库那一层（core/RtpDecodability.cpp）。判定顺序照抄卡片：
//   1. is_srtp → Srtp
//   2. 没有非事件编码 且 primary_pt ∈ 96..127 → NeedsMapping
//   3. codec 为空或不在 kSupportedAudioCodecs → Unsupported
//   4. packets > 0 && truncated*2 > packets → Truncated
//   5. 否则 Yes
//
// 用例名统一以 RtpDecodability 开头，便于 run_host_tests.ps1 -Test "RtpDecodability*"。

#include "doctest.h"

#include <cstdint>
#include <string>

#include "layanalyzer/rtp/core/RtpDecodability.h"

using layanalyzer::rtp::RtpDecodability;
using layanalyzer::rtp::RtpDecodabilityInput;
using layanalyzer::rtp::rtp_decodability;
using layanalyzer::rtp::rtp_decodability_name;
using layanalyzer::rtp::rtp_decodability_reason;

namespace {

// 默认是一份「能解码」的输入：PCMA（静态 PT 8，受支持），100 个包全未截断。
RtpDecodabilityInput decodable_input() {
    RtpDecodabilityInput input;
    input.is_srtp = false;
    input.canonical_codec = "g711A";
    input.codec_known = true;
    input.primary_pt = 8;
    input.primary_pt_is_event = false;
    input.any_non_event_codec = true;
    input.packets = 100;
    input.truncated = 0;
    return input;
}

}  // namespace

TEST_CASE("RtpDecodability 分支5：编码受支持且无异常 → yes") {
    const RtpDecodabilityInput input = decodable_input();
    CHECK(rtp_decodability(input) == RtpDecodability::Yes);
    CHECK_EQ(std::string(rtp_decodability_name(rtp_decodability(input))), std::string("yes"));
    CHECK_EQ(rtp_decodability_reason(input), std::string("可解码为 g711A 音频"));
}

TEST_CASE("RtpDecodability 分支1：SRTP 且 PT 未映射仍判为 srtp") {
    RtpDecodabilityInput input = decodable_input();
    input.is_srtp = true;
    // PT 未映射：否则这一份输入会被判成 needsMapping；SRTP 优先级更高。
    input.canonical_codec.clear();
    input.codec_known = false;
    input.any_non_event_codec = false;
    input.primary_pt = 100;

    CHECK(rtp_decodability(input) == RtpDecodability::Srtp);
    CHECK_EQ(std::string(rtp_decodability_name(rtp_decodability(input))), std::string("srtp"));
    CHECK_EQ(rtp_decodability_reason(input), std::string("加密媒体流，无法解码"));
}

TEST_CASE("RtpDecodability 分支1：SRTP 即使编码受支持也判为 srtp") {
    RtpDecodabilityInput input = decodable_input();
    input.is_srtp = true;
    CHECK(rtp_decodability(input) == RtpDecodability::Srtp);
}

TEST_CASE("RtpDecodability 分支2：动态 PT 未映射 → needsMapping") {
    RtpDecodabilityInput input = decodable_input();
    input.canonical_codec.clear();
    input.codec_known = false;
    input.any_non_event_codec = false;
    input.primary_pt = 96;

    CHECK(rtp_decodability(input) == RtpDecodability::NeedsMapping);
    CHECK_EQ(std::string(rtp_decodability_name(rtp_decodability(input))),
             std::string("needsMapping"));
    CHECK_EQ(rtp_decodability_reason(input),
             std::string("动态负载类型未映射，请手动指定编码"));

    // 上界 127 也命中。
    input.primary_pt = 127;
    CHECK(rtp_decodability(input) == RtpDecodability::NeedsMapping);
    // 128 不在 96..127：落到分支 3（codec 为空 → unsupported）。
    input.primary_pt = 128;
    CHECK(rtp_decodability(input) == RtpDecodability::Unsupported);
}

TEST_CASE("RtpDecodability 分支3：编码为空 → unsupported") {
    RtpDecodabilityInput input = decodable_input();
    input.canonical_codec.clear();
    input.codec_known = false;
    input.any_non_event_codec = false;
    input.primary_pt = 8;  // 静态 PT，不触发分支 2

    CHECK(rtp_decodability(input) == RtpDecodability::Unsupported);
    CHECK_EQ(std::string(rtp_decodability_name(rtp_decodability(input))),
             std::string("unsupported"));
    CHECK_EQ(rtp_decodability_reason(input), std::string("未知编码"));
}

// RTP4-KT-05 把 AMR 加进了 kSupportedAudioCodecs（本迭代起由 MediaCodec 解码），
// 于是本用例原来的样本 AMR 不再是「已识别但不支持」的编码。改用 H264：它仍在
// 编码表里（codec_known），但不在音频支持集合内，所以分支与断言意图不变。
//
// RTP5-NAT-01 又把 H264 加进了 kSupportedVideoCodecs（decodable 判定扩展到视频），
// 于是同一个理由再来一次：现在在表里、既不受音频支持、也不受视频支持的编码是
// CN（§4.3 表里的事件编码，静态 PT 13/19）。用例标题与意图照旧，只换样本；
// 断言一个都没有放宽。
TEST_CASE("RtpDecodability 分支3：已识别但不在支持集合 → unsupported") {
    RtpDecodabilityInput input = decodable_input();
    input.canonical_codec = "CN";
    input.codec_known = true;
    input.any_non_event_codec = true;
    input.primary_pt = 96;

    CHECK(rtp_decodability(input) == RtpDecodability::Unsupported);
    CHECK_EQ(rtp_decodability_reason(input),
             std::string("编码 CN 不支持解码"));
}

TEST_CASE("RtpDecodability 分支3：未识别的原始名字 → unsupported") {
    RtpDecodabilityInput input = decodable_input();
    input.canonical_codec = "FOO";
    input.codec_known = false;
    input.any_non_event_codec = false;
    input.primary_pt = 8;

    CHECK(rtp_decodability(input) == RtpDecodability::Unsupported);
    // RTP4-KT-05：文案里的「M1」已随支持集合的宽化去掉，见 RtpDecodability.cpp。
    CHECK_EQ(rtp_decodability_reason(input),
             std::string("编码 FOO 不支持解码"));
}

TEST_CASE("RtpDecodability 分支4：截断超过一半 → truncated") {
    RtpDecodabilityInput input = decodable_input();
    input.packets = 100;
    input.truncated = 51;

    CHECK(rtp_decodability(input) == RtpDecodability::Truncated);
    CHECK_EQ(std::string(rtp_decodability_name(rtp_decodability(input))),
             std::string("truncated"));
    CHECK_EQ(rtp_decodability_reason(input), std::string("超过一半的包在抓包时被截断"));
}

TEST_CASE("RtpDecodability 边界：截断正好 50%（truncated*2 == packets）不算 truncated") {
    RtpDecodabilityInput input = decodable_input();
    input.packets = 100;
    input.truncated = 50;  // 50*2 == 100，不满足 >，判 yes
    CHECK(rtp_decodability(input) == RtpDecodability::Yes);

    input.truncated = 49;
    CHECK(rtp_decodability(input) == RtpDecodability::Yes);
}

TEST_CASE("RtpDecodability 边界：没有包时不判 truncated") {
    RtpDecodabilityInput input = decodable_input();
    input.packets = 0;
    input.truncated = 5;  // packets > 0 为假，不进入分支 4
    CHECK(rtp_decodability(input) == RtpDecodability::Yes);
}

TEST_CASE("RtpDecodability name 五个取值") {
    CHECK_EQ(std::string(rtp_decodability_name(RtpDecodability::Yes)), std::string("yes"));
    CHECK_EQ(std::string(rtp_decodability_name(RtpDecodability::NeedsMapping)),
             std::string("needsMapping"));
    CHECK_EQ(std::string(rtp_decodability_name(RtpDecodability::Srtp)), std::string("srtp"));
    CHECK_EQ(std::string(rtp_decodability_name(RtpDecodability::Unsupported)),
             std::string("unsupported"));
    CHECK_EQ(std::string(rtp_decodability_name(RtpDecodability::Truncated)),
             std::string("truncated"));
}
