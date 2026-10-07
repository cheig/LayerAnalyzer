// RTP1-NAT-06：编码名规范化的 host 单测。
//
// 只测纯标准库那一层（core/RtpCodecNames.cpp）。期望值全部来自
// layanalyzer/rtp/core/RtpCodecNames.cpp 的规范 ID 表。
//
// 用例名统一以 RtpCodecNames 开头，便于 run_host_tests.ps1 -Test "RtpCodecNames*"。

#include "doctest.h"

#include <cstdint>
#include <set>
#include <string>

#include "layanalyzer/rtp/core/RtpCodecNames.h"

using layanalyzer::rtp::canonical_codec;
using layanalyzer::rtp::kSupportedAudioCodecs;
using layanalyzer::rtp::rtp_codec_is_event;
using layanalyzer::rtp::rtp_codec_is_known;
using layanalyzer::rtp::rtp_codec_is_supported_audio;
using layanalyzer::rtp::rtp_static_pt_codec_name;

namespace {

// rtp_static_pt_codec_name 返回 nullptr 时序列化成 "<null>"，避免 std::string(nullptr)。
std::string static_name(uint32_t pt) {
    const char *name = rtp_static_pt_codec_name(pt);
    return name != nullptr ? std::string(name) : std::string("<null>");
}

}  // namespace

TEST_CASE("RtpCodecNames 别名映射到规范 ID") {
    // §4.3 的别名大小写不敏感。
    CHECK_EQ(canonical_codec("PCMA").id, std::string("g711A"));
    CHECK_EQ(canonical_codec("pcma").id, std::string("g711A"));
    CHECK_EQ(canonical_codec("g711A").id, std::string("g711A"));
    CHECK_EQ(canonical_codec("PCMU").id, std::string("g711U"));
    CHECK_EQ(canonical_codec("g711u").id, std::string("g711U"));
    CHECK_EQ(canonical_codec("G722").id, std::string("g722"));
    CHECK_EQ(canonical_codec(" HEVC ").id, std::string("H265"));
    CHECK_EQ(canonical_codec("16-bit audio, monaural").id, std::string("L16"));
    CHECK_EQ(canonical_codec("16-bit audio, stereo").id, std::string("L16"));
    CHECK_EQ(canonical_codec("MP2P").id, std::string("PS"));
    CHECK_EQ(canonical_codec("CN(old)").id, std::string("CN"));
    CHECK_EQ(canonical_codec("G729B").id, std::string("g729"));
    CHECK_EQ(canonical_codec("AMR-WB").id, std::string("AMR-WB"));
    CHECK_EQ(canonical_codec("opus").id, std::string("opus"));
    CHECK_EQ(canonical_codec("telephone-event").id, std::string("telephone-event"));
}

TEST_CASE("RtpCodecNames 规范 ID 带默认时钟与 kind") {
    const auto pcma = canonical_codec("PCMA");
    CHECK_EQ(pcma.default_clock_rate, 8000);
    CHECK(pcma.is_audio);
    CHECK_FALSE(pcma.is_video);
    CHECK_FALSE(pcma.is_event);

    CHECK_EQ(canonical_codec("G722").default_clock_rate, 8000);
    CHECK_EQ(canonical_codec("L16").default_clock_rate, 44100);
    CHECK_EQ(canonical_codec("AMR-WB").default_clock_rate, 16000);
    CHECK_EQ(canonical_codec("opus").default_clock_rate, 48000);

    const auto h265 = canonical_codec("HEVC");
    CHECK_FALSE(h265.is_audio);
    CHECK(h265.is_video);
    CHECK_FALSE(h265.is_event);
    CHECK_EQ(h265.default_clock_rate, 90000);

    const auto cn = canonical_codec("CN");
    CHECK(cn.is_event);
    CHECK_FALSE(cn.is_audio);
    CHECK_EQ(cn.default_clock_rate, 8000);
}

TEST_CASE("RtpCodecNames 未知名原样返回且所有 kind 为 false") {
    const auto unknown = canonical_codec("FOO");
    CHECK_EQ(unknown.id, std::string("FOO"));
    CHECK_EQ(unknown.default_clock_rate, 0);
    CHECK_FALSE(unknown.is_audio);
    CHECK_FALSE(unknown.is_video);
    CHECK_FALSE(unknown.is_event);

    // 只去首尾空白，内部空白保留。
    CHECK_EQ(canonical_codec("  bar baz  ").id, std::string("bar baz"));
    CHECK_EQ(canonical_codec("").id, std::string(""));
    CHECK_EQ(canonical_codec("   ").id, std::string(""));
}

TEST_CASE("RtpCodecNames 静态 PT 名称表只覆盖 0/8/9/10/11/13/18/19") {
    CHECK_EQ(static_name(0), std::string("g711U"));
    CHECK_EQ(static_name(8), std::string("g711A"));
    CHECK_EQ(static_name(9), std::string("g722"));
    CHECK_EQ(static_name(10), std::string("L16"));
    CHECK_EQ(static_name(11), std::string("L16"));
    CHECK_EQ(static_name(13), std::string("CN"));
    CHECK_EQ(static_name(18), std::string("g729"));
    CHECK_EQ(static_name(19), std::string("CN"));

    CHECK(rtp_static_pt_codec_name(1) == nullptr);
    CHECK(rtp_static_pt_codec_name(12) == nullptr);
    CHECK(rtp_static_pt_codec_name(96) == nullptr);
    CHECK(rtp_static_pt_codec_name(127) == nullptr);
    CHECK(rtp_static_pt_codec_name(0xFFFFFFFFu) == nullptr);
}

TEST_CASE("RtpCodecNames kSupportedAudioCodecs 与查询函数一致") {
    // RTP4-KT-05 改了这条断言（本卡三条获准改动的既有断言之一）：
    //   旧：CHECK_EQ(kSupportedAudioCodecs.size(), 3)，钉的是 M1 的 {g711A,g711U,L16}；
    //   新：断言**内容集合**。KT-05 的交付物就是这个集合本身（本迭代全部可解码的
    //   音频编码），而长度随两个构建开关变化（LAYANALYZER_ENABLE_G729 默认 ON、
    //   LAYANALYZER_ENABLE_ILBC 默认 OFF），写死数字在三种组合里必然错两个。
    //   断言集合则不依赖构建参数，只依赖卡片的清单。
    std::set<std::string> expected = {
        "g711A", "g711U", "L16", "g722",
        "G726-16", "G726-24", "G726-32", "G726-40",
        "AAL2-G726-16", "AAL2-G726-24", "AAL2-G726-32", "AAL2-G726-40",
        "AMR", "AMR-WB", "opus"};
#ifdef LAYANALYZER_ENABLE_G729
    expected.insert("g729");
#endif
#ifdef LAYANALYZER_ENABLE_ILBC
    expected.insert("iLBC");
#endif

    std::set<std::string> actual;
    for (const char *id : kSupportedAudioCodecs) {
        actual.insert(id);
        CHECK(rtp_codec_is_supported_audio(id));
        // 集合里的每一项都必须确实是音频编码（防止表里写错 kind）。
        CHECK(canonical_codec(id).is_audio);
    }
    CHECK_EQ(actual.size(), kSupportedAudioCodecs.size());  // 表里没有重复项
    CHECK(actual == expected);                              // 也没有漏项

    // RTP4-KT-05 改了这条断言（三条获准改动的既有断言之二）：
    //   旧：CHECK_FALSE(rtp_codec_is_supported_audio("AMR"))，因为 M1 只解 G.711/L16；
    //   新：AMR 从本迭代起是受支持的 —— 它由 MediaCodec 解码（RTP4-KT-02 的
    //   MEDIACODEC 路由），但 decodable 的判据只有这一张表，所以它必须在这里，
    //   否则媒体路由永远走不到。「表外的名字仍为 false」由下面几条继续钉住。
    CHECK(rtp_codec_is_supported_audio("AMR"));
    CHECK(rtp_codec_is_supported_audio("AMR-WB"));
    CHECK(rtp_codec_is_supported_audio("opus"));
    CHECK(rtp_codec_is_supported_audio("g722"));
#ifdef LAYANALYZER_ENABLE_G729
    CHECK(rtp_codec_is_supported_audio("g729"));
#else
    CHECK_FALSE(rtp_codec_is_supported_audio("g729"));
#endif
#ifdef LAYANALYZER_ENABLE_ILBC
    CHECK(rtp_codec_is_supported_audio("iLBC"));
#else
    CHECK_FALSE(rtp_codec_is_supported_audio("iLBC"));
#endif
    CHECK_FALSE(rtp_codec_is_supported_audio("telephone-event"));
    CHECK_FALSE(rtp_codec_is_supported_audio("H264"));  // 在 §4.3 表里，但是视频
    CHECK_FALSE(rtp_codec_is_supported_audio("FOO"));   // 表外
    CHECK_FALSE(rtp_codec_is_supported_audio(""));

    CHECK(rtp_codec_is_event("CN"));
    CHECK(rtp_codec_is_event("telephone-event"));
    CHECK_FALSE(rtp_codec_is_event("g711A"));
    CHECK_FALSE(rtp_codec_is_event(""));

    CHECK(rtp_codec_is_known("PCMA"));
    CHECK(rtp_codec_is_known("g711A"));
    CHECK(rtp_codec_is_known(" HEVC "));
    CHECK_FALSE(rtp_codec_is_known("FOO"));
    CHECK_FALSE(rtp_codec_is_known(""));
}
