// RTP1-NAT-06：会话级负载类型覆盖表的 host 单测。
//
// 只测纯标准库那一层（core/RtpPayloadOverrides.h，header-only）。输入形状固定为
//   {"overrides":[{"pt":96,"codec":"AMR-WB","clockRate":16000,"channels":1}]}
// host 上没有 nlohmann，因此这里验证自带的最小解析器的各种边界。
//
// 用例名统一以 RtpPayloadOverrides 开头，便于
// run_host_tests.ps1 -Test "RtpPayloadOverrides*"。

#include "doctest.h"

#include <cstdint>
#include <string>

#include "layanalyzer/rtp/core/RtpPayloadOverrides.h"

using layanalyzer::rtp::RtpPayloadOverride;
using layanalyzer::rtp::RtpPayloadOverrides;

TEST_CASE("RtpPayloadOverrides 正常解析并按 pt 升序返回") {
    RtpPayloadOverrides overrides;
    std::string error;
    const bool ok = overrides.set_from_json(
        "{\"overrides\":["
        "{\"pt\":96,\"codec\":\"AMR-WB\",\"clockRate\":16000,\"channels\":1},"
        "{\"pt\":8,\"codec\":\"PCMA\",\"clockRate\":8000}]}",
        error);
    REQUIRE(ok);
    CHECK(error.empty());
    CHECK_EQ(overrides.size(), static_cast<size_t>(2));

    const RtpPayloadOverride *amr_wb = overrides.find(96);
    REQUIRE(amr_wb != nullptr);
    CHECK_EQ(amr_wb->codec, std::string("AMR-WB"));
    CHECK_EQ(amr_wb->clock_rate, 16000);
    CHECK_EQ(amr_wb->channels, 1);

    const RtpPayloadOverride *pcma = overrides.find(8);
    REQUIRE(pcma != nullptr);
    CHECK_EQ(pcma->codec, std::string("PCMA"));

    CHECK(overrides.find(99) == nullptr);

    const std::vector<RtpPayloadOverride> items = overrides.items();
    REQUIRE_EQ(items.size(), static_cast<size_t>(2));
    CHECK_EQ(items[0].pt, static_cast<uint32_t>(8));
    CHECK_EQ(items[1].pt, static_cast<uint32_t>(96));
}

TEST_CASE("RtpPayloadOverrides 缺失 clockRate/channels 用默认值") {
    RtpPayloadOverrides overrides;
    std::string error;
    REQUIRE(overrides.set_from_json(
        "{\"overrides\":[{\"pt\":97,\"codec\":\"opus\"}]}", error));

    const RtpPayloadOverride *item = overrides.find(97);
    REQUIRE(item != nullptr);
    CHECK_EQ(item->clock_rate, 0);
    CHECK_EQ(item->channels, 1);
}

TEST_CASE("RtpPayloadOverrides 多余字段被忽略") {
    RtpPayloadOverrides overrides;
    std::string error;
    const bool ok = overrides.set_from_json(
        "{\"overrides\":[{\"pt\":98,\"codec\":\"AMR\",\"note\":\"x\",\"flag\":true,"
        "\"pi\":3.14,\"nothing\":null,\"nested\":{\"a\":[1,2,{\"b\":\"c\"}]}}],"
        "\"topLevelUnknown\":123}",
        error);
    REQUIRE(ok);
    CHECK_EQ(overrides.size(), static_cast<size_t>(1));
    const RtpPayloadOverride *item = overrides.find(98);
    REQUIRE(item != nullptr);
    CHECK_EQ(item->codec, std::string("AMR"));
}

TEST_CASE("RtpPayloadOverrides 空白容忍") {
    RtpPayloadOverrides overrides;
    std::string error;
    REQUIRE(overrides.set_from_json(
        "  {\n\t\"overrides\" : [ { \"pt\" : 96 , \"codec\" : \"AMR-WB\" , "
        "\"clockRate\" : 16000 } ]\n}  ",
        error));
    const RtpPayloadOverride *item = overrides.find(96);
    REQUIRE(item != nullptr);
    CHECK_EQ(item->clock_rate, 16000);
}

TEST_CASE("RtpPayloadOverrides 字符串转义") {
    RtpPayloadOverrides overrides;
    std::string error;
    REQUIRE(overrides.set_from_json(
        "{\"overrides\":[{\"pt\":99,\"codec\":\"a\\\"b\\\\c\"}]}", error));
    const RtpPayloadOverride *item = overrides.find(99);
    REQUIRE(item != nullptr);
    CHECK_EQ(item->codec, std::string("a\"b\\c"));
}

TEST_CASE("RtpPayloadOverrides 非法 pt 拒绝且整体不替换") {
    RtpPayloadOverrides overrides;
    std::string error;
    REQUIRE(overrides.set_from_json(
        "{\"overrides\":[{\"pt\":8,\"codec\":\"PCMA\"}]}", error));
    REQUIRE_EQ(overrides.size(), static_cast<size_t>(1));

    error.clear();
    CHECK_FALSE(overrides.set_from_json(
        "{\"overrides\":[{\"pt\":300,\"codec\":\"AMR\"}]}", error));
    CHECK_FALSE(error.empty());
    // fail-closed：原表保持不变。
    CHECK_EQ(overrides.size(), static_cast<size_t>(1));
    CHECK(overrides.find(8) != nullptr);
    CHECK(overrides.find(300) == nullptr);

    error.clear();
    CHECK_FALSE(overrides.set_from_json(
        "{\"overrides\":[{\"pt\":-1,\"codec\":\"AMR\"}]}", error));
    CHECK_FALSE(error.empty());
    CHECK_EQ(overrides.size(), static_cast<size_t>(1));
}

TEST_CASE("RtpPayloadOverrides 空 codec 拒绝且整体不替换") {
    RtpPayloadOverrides overrides;
    std::string error;
    REQUIRE(overrides.set_from_json(
        "{\"overrides\":[{\"pt\":96,\"codec\":\"AMR\"}]}", error));

    error.clear();
    CHECK_FALSE(overrides.set_from_json(
        "{\"overrides\":[{\"pt\":96,\"codec\":\"\"}]}", error));
    CHECK_FALSE(error.empty());
    CHECK_EQ(overrides.size(), static_cast<size_t>(1));
    const RtpPayloadOverride *item = overrides.find(96);
    REQUIRE(item != nullptr);
    CHECK_EQ(item->codec, std::string("AMR"));
}

TEST_CASE("RtpPayloadOverrides 结构性错误全部拒绝且不替换") {
    const char *const kBadInputs[] = {
        "{\"overrides\":[{\"pt\":96,",                 // 未闭合
        "not json",                                    // 不是对象
        "{\"other\":[]}",                              // 缺 overrides
        "{\"overrides\":{}}",                          // overrides 不是数组
        "{\"overrides\":[{\"pt\":96,\"codec\":\"AMR\"}]}garbage",  // 结尾有垃圾
        "{\"overrides\":[{\"pt\":96,\"codec\":123}]}",             // codec 类型错
        "{\"overrides\":[{\"pt\":96,\"codec\":\"AMR\",\"clockRate\":1.5}]}",  // 非整数
        "{\"overrides\":[\"x\"]}",                     // 元素不是对象
    };
    for (const char *bad : kBadInputs) {
        RtpPayloadOverrides overrides;
        std::string error;
        REQUIRE(overrides.set_from_json(
            "{\"overrides\":[{\"pt\":8,\"codec\":\"PCMA\"}]}", error));
        REQUIRE_EQ(overrides.size(), static_cast<size_t>(1));

        error.clear();
        CHECK_FALSE(overrides.set_from_json(bad, error));
        CHECK_FALSE(error.empty());
        CHECK_EQ(overrides.size(), static_cast<size_t>(1));
        CHECK(overrides.find(8) != nullptr);
    }
}

TEST_CASE("RtpPayloadOverrides 重复 pt 后者覆盖前者") {
    RtpPayloadOverrides overrides;
    std::string error;
    REQUIRE(overrides.set_from_json(
        "{\"overrides\":["
        "{\"pt\":100,\"codec\":\"A\",\"clockRate\":8000},"
        "{\"pt\":100,\"codec\":\"B\",\"clockRate\":16000}]}",
        error));
    CHECK_EQ(overrides.size(), static_cast<size_t>(1));
    const RtpPayloadOverride *item = overrides.find(100);
    REQUIRE(item != nullptr);
    CHECK_EQ(item->codec, std::string("B"));
    CHECK_EQ(item->clock_rate, 16000);
}

TEST_CASE("RtpPayloadOverrides 空数组清空旧表") {
    RtpPayloadOverrides overrides;
    std::string error;
    REQUIRE(overrides.set_from_json(
        "{\"overrides\":[{\"pt\":8,\"codec\":\"PCMA\"}]}", error));
    REQUIRE_EQ(overrides.size(), static_cast<size_t>(1));

    REQUIRE(overrides.set_from_json("{\"overrides\":[]}", error));
    CHECK_EQ(overrides.size(), static_cast<size_t>(0));
    CHECK(overrides.find(8) == nullptr);
}

TEST_CASE("RtpPayloadOverrides 非标准 clockRate 仍接受") {
    RtpPayloadOverrides overrides;
    std::string error;
    REQUIRE(overrides.set_from_json(
        "{\"overrides\":[{\"pt\":101,\"codec\":\"AMR\",\"clockRate\":12345}]}",
        error));
    const RtpPayloadOverride *item = overrides.find(101);
    REQUIRE(item != nullptr);
    CHECK_EQ(item->clock_rate, 12345);
}

TEST_CASE("RtpPayloadOverrides clear 清空") {
    RtpPayloadOverrides overrides;
    std::string error;
    REQUIRE(overrides.set_from_json(
        "{\"overrides\":[{\"pt\":8,\"codec\":\"PCMA\"}]}", error));
    REQUIRE_EQ(overrides.size(), static_cast<size_t>(1));

    overrides.clear();
    CHECK_EQ(overrides.size(), static_cast<size_t>(0));
    CHECK(overrides.find(8) == nullptr);
}
