// RTP1-NAT-01：RtpStreamKey 的 host 单测。
//
// 只测纯标准库的那一层（core/RtpStreamKey.cpp）。地址文本的规范化
// （address_to_str 把 IPv6 压成 2001:db8::1 这种形式）发生在 epan 层的
// RtpStreamKeyEpan.cpp，host 上编不过，因此这里固定用 address_to_str
// 的输出风格写期望值，并断言本层只做逐字比较。
//
// 用例名统一以 RtpStreamKey 开头，便于 run_host_tests.ps1 -Test "RtpStreamKey*"。

#include "doctest.h"

#include <string>
#include <unordered_map>

#include "layanalyzer/rtp/core/RtpStreamKey.h"

using layanalyzer::rtp::RtpStreamKey;
using layanalyzer::rtp::RtpStreamKeyHash;
using layanalyzer::rtp::rtp_stream_key_to_string;

TEST_CASE("RtpStreamKey IPv4 同五元组不同 SSRC 不相等") {
    RtpStreamKey first{"10.0.0.1", "10.0.0.2", 40000, 30000, 0x1a2b3c4d};
    RtpStreamKey second{"10.0.0.1", "10.0.0.2", 40000, 30000, 0x00000001};

    CHECK(first != second);
    CHECK_FALSE(first == second);

    // SSRC 相同则完全相等（其余四个字段一致）。
    RtpStreamKey same_ssrc{"10.0.0.1", "10.0.0.2", 40000, 30000, 0x1a2b3c4d};
    CHECK(first == same_ssrc);
    CHECK_FALSE(first != same_ssrc);
}

TEST_CASE("RtpStreamKey IPv6 地址文本按 address_to_str 风格逐字比较") {
    // 期望值与 address_to_str 的输出一致：压缩形式、小写。
    RtpStreamKey canonical{"2001:db8::1", "2001:db8::2", 50000, 50001, 0xdeadbeef};
    CHECK_EQ(canonical.src, std::string("2001:db8::1"));
    CHECK_EQ(canonical.dst, std::string("2001:db8::2"));

    // 同一地址的另一种写法（补零）在本层**不做归一**：这是 epan 侧
    // address_to_str 的职责，本层只保存并逐字比较文本。
    RtpStreamKey expanded{"2001:0db8::1", "2001:db8::2", 50000, 50001, 0xdeadbeef};
    CHECK(canonical != expanded);

    RtpStreamKey same_canonical{"2001:db8::1", "2001:db8::2", 50000, 50001, 0xdeadbeef};
    CHECK(canonical == same_canonical);
}

TEST_CASE("RtpStreamKey 端口相同但地址不同不相等") {
    RtpStreamKey loopback{"127.0.0.1", "127.0.0.1", 40000, 30000, 0x1a2b3c4d};
    RtpStreamKey lan{"10.0.0.1", "127.0.0.1", 40000, 30000, 0x1a2b3c4d};

    CHECK(loopback != lan);

    // 只改目标地址也不同。
    RtpStreamKey other_dst{"127.0.0.1", "10.0.0.2", 40000, 30000, 0x1a2b3c4d};
    CHECK(loopback != other_dst);

    // 地址相同、端口不同也不同。
    RtpStreamKey other_port{"127.0.0.1", "127.0.0.1", 40001, 30000, 0x1a2b3c4d};
    CHECK(loopback != other_port);
}

TEST_CASE("RtpStreamKey to_string 固定输出") {
    RtpStreamKey key{"10.0.0.1", "10.0.0.2", 40000, 30000, 0x1a2b3c4d};
    CHECK_EQ(rtp_stream_key_to_string(key),
             std::string("10.0.0.1:40000-10.0.0.2:30000/0x1a2b3c4d"));

    // SSRC 小写、补足 8 位。
    RtpStreamKey small_ssrc{"192.168.1.10", "192.168.1.20", 5060, 5061, 0xabcd};
    CHECK_EQ(rtp_stream_key_to_string(small_ssrc),
             std::string("192.168.1.10:5060-192.168.1.20:5061/0x0000abcd"));

    // IPv6 文本原样拼接。
    RtpStreamKey v6{"2001:db8::1", "2001:db8::2", 50000, 50001, 0x00000000};
    CHECK_EQ(rtp_stream_key_to_string(v6),
             std::string("2001:db8::1:50000-2001:db8::2:50001/0x00000000"));
}

TEST_CASE("RtpStreamKey 相等的 key 哈希一致且可用于 unordered_map") {
    const RtpStreamKeyHash hasher;
    RtpStreamKey a{"10.0.0.1", "10.0.0.2", 40000, 30000, 0x1a2b3c4d};
    RtpStreamKey b{"10.0.0.1", "10.0.0.2", 40000, 30000, 0x1a2b3c4d};
    CHECK_EQ(hasher(a), hasher(b));

    std::unordered_map<RtpStreamKey, int, RtpStreamKeyHash> streams;
    streams[a] = 1;
    streams[b] = 2;  // 同一个 key：覆盖而不是新增
    CHECK_EQ(streams.size(), static_cast<size_t>(1));
    CHECK_EQ(streams[a], 2);
}
