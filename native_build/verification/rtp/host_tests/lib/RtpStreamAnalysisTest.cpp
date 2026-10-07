// RTP1-NAT-02：抖动 / delta / skew 分析的 host 单测。
//
// 只测纯标准库那一层（core/RtpStreamAnalysis.cpp）。所有期望值都按
// Wireshark 4.0.10 的 ui/tap-rtp-analysis.c:162-533 手工核算，逐条写在注释里。
//
// 关键公式（照抄 4.0.10）：
//   arrivaltime = current_time - start_time
//   nominaltime = uint32_wraparound_diff(ts, first_timestamp) / (clock_rate/1000)  // 整数除法
//   expected_time = time + (nominaltime - lastnominaltime)
//   current_diff  = |current_time - expected_time|
//   jitter = (15*jitter + current_diff) / 16
//   skew   = nominaltime - arrivaltime   （max_skew 按 |skew|>|max_skew| 取带符号值）
//   mean_delta  = (mean_delta*(n-1) + delta) / n     // n = 此处尚未自增的 total_nr
//   mean_jitter = (mean_jitter*(n-1) + current_jitter) / n
//   expected = stop_seq_nr + seq_cycles*0x10000 - start_seq_nr + 1
//   lost     = expected - total_nr     // 可以为负，不截断
//
// 用例名统一以 RtpStreamAnalysis 开头，便于 run_host_tests.ps1 -Test "RtpStreamAnalysis*"。

#include "doctest.h"

#include <cstdint>

#include "layanalyzer/rtp/core/RtpStreamAnalysis.h"

using layanalyzer::rtp::RtpPacketObservation;
using layanalyzer::rtp::RtpStreamAnalysis;
using layanalyzer::rtp::RtpStreamStats;
using layanalyzer::rtp::rtp_dynamic_clock_rate;
using layanalyzer::rtp::rtp_static_clock_rate;

namespace {

// 造一个包观测。默认 PT 8（PCMA，静态表命中 8000）、名字 nullptr（静态 PT 的真实情况）。
RtpPacketObservation packet(double arrival_ms, uint32_t frame, uint16_t seq, uint32_t timestamp,
                            uint32_t pt = 8, const char *name = nullptr, int rate = 0,
                            bool marker = false) {
    RtpPacketObservation obs;
    obs.arrival_ms = arrival_ms;
    obs.frame_number = frame;
    obs.seq_num = seq;
    obs.timestamp = timestamp;
    obs.payload_type = pt;
    obs.payload_type_name = name;
    obs.payload_rate = rate;
    obs.marker = marker;
    return obs;
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. 20 个连续包（8000 Hz、20 ms 间隔）
//    第 i 个包：arrival = i*20 ms，seq = i+1，ts = i*160（20ms @ 8000Hz），frame = i+1。
//    expected = 20 - 1 + 1 = 20；收到 20 -> lost = 0；无异常 -> seq_errors = 0。
//    时间戳与到达时间同步前进 -> 每包 diff 都是 0 -> jitter 恒为 0。
//    19 个 delta 都是 20 ms -> min = mean = max = 20；max_delta 首次刷新在 frame 2。
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis 连续 20 包") {
    RtpStreamAnalysis analysis;
    for (int i = 0; i < 20; ++i) {
        analysis.onPacket(packet(i * 20.0, static_cast<uint32_t>(i + 1),
                                 static_cast<uint16_t>(i + 1), static_cast<uint32_t>(i) * 160));
    }
    analysis.finalize();
    const RtpStreamStats &s = analysis.stats();

    CHECK_EQ(s.packets, 20u);
    CHECK_EQ(s.expected, 20u);
    CHECK_EQ(s.lost, 0);
    CHECK_EQ(s.lost_pct, doctest::Approx(0.0));
    CHECK_EQ(s.seq_errors, 0u);
    CHECK_EQ(s.out_of_order, 0u);

    CHECK_EQ(s.min_jitter_ms, doctest::Approx(0.0));
    CHECK_EQ(s.mean_jitter_ms, doctest::Approx(0.0));
    CHECK_EQ(s.max_jitter_ms, doctest::Approx(0.0));
    CHECK_EQ(s.min_delta_ms, doctest::Approx(20.0));
    CHECK_EQ(s.mean_delta_ms, doctest::Approx(20.0));
    CHECK_EQ(s.max_delta_ms, doctest::Approx(20.0));

    CHECK_EQ(s.max_delta_frame, 2u);
    CHECK_EQ(s.first_frame, 1u);
    CHECK_EQ(s.last_frame, 20u);
    CHECK_EQ(s.start_rel_ms, doctest::Approx(0.0));
    CHECK_EQ(s.end_rel_ms, doctest::Approx(380.0));  // 19*20
    CHECK_EQ(s.clock_rate, 8000u);
    CHECK(s.jitter_available);
    CHECK_FALSE(s.problem);
    CHECK_EQ(s.reg_pt, 8);
    CHECK_EQ(s.max_skew_ms, doctest::Approx(0.0));
    CHECK_EQ(analysis.primaryPayloadType(), 8u);
}

// ---------------------------------------------------------------------------
// 2. 丢 1 个包（seq 跳到 +2）
//    19 个包：seq 1..10, 12..20（缺 11）。arrival/ts 按到达顺序每包 +20 ms / +160。
//    expected = 20 - 1 + 1 = 20；收到 19 -> lost = 1；lost_pct = 1*100/20 = 5.0。
//    seq 从 10 直接跳到 12 -> 命中"跨环跳跃"分支（seq_num+1 < seq）-> seq_errors = 1，
//    该分支不是 late/duplicated -> out_of_order = 0。
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis 丢 1 个包") {
    RtpStreamAnalysis analysis;
    uint32_t frame = 1;
    int index = 0;
    for (uint16_t seq = 1; seq <= 20; ++seq) {
        if (seq == 11) {
            continue;  // 丢包
        }
        analysis.onPacket(packet(index * 20.0, frame++, seq, static_cast<uint32_t>(index) * 160));
        ++index;
    }
    analysis.finalize();
    const RtpStreamStats &s = analysis.stats();

    CHECK_EQ(s.packets, 19u);
    CHECK_EQ(s.expected, 20u);
    CHECK_EQ(s.lost, 1);
    CHECK_EQ(s.lost_pct, doctest::Approx(5.0));
    CHECK_EQ(s.seq_errors, 1u);
    CHECK_EQ(s.out_of_order, 0u);
}

// ---------------------------------------------------------------------------
// 3. 乱序（seq 10 之后又来了一个 8）
//    21 个包：seq 1..10, 8, 11..20（捕获顺序里那个 8 是重复/迟到到达）。
//    收到 21 个，覆盖 seq 1..20 -> expected = 20 - 1 + 1 = 20。
//    迟到包命中 late/duplicated 分支（seq_num+1 > seq）-> seq_errors = 1、out_of_order = 1。
//    found lost = expected - packets = 20 - 21 = -1：
//    乱序包不会被"算成丢包"（lost 不会变成 +1），它是一次额外到达，故 lost 为负（C12 允许）。
//    后续 seq 11 = seq_num+1 正常接上，没有额外 seq_error。
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis 乱序") {
    RtpStreamAnalysis analysis;
    uint32_t frame = 1;
    int index = 0;
    for (uint16_t seq = 1; seq <= 10; ++seq) {
        analysis.onPacket(packet(index * 20.0, frame++, seq, static_cast<uint32_t>(index) * 160));
        ++index;
    }
    analysis.onPacket(packet(index * 20.0, frame++, 8, static_cast<uint32_t>(index) * 160));
    ++index;
    for (uint16_t seq = 11; seq <= 20; ++seq) {
        analysis.onPacket(packet(index * 20.0, frame++, seq, static_cast<uint32_t>(index) * 160));
        ++index;
    }
    analysis.finalize();
    const RtpStreamStats &s = analysis.stats();

    CHECK_EQ(s.packets, 21u);
    CHECK_EQ(s.expected, 20u);
    CHECK_EQ(s.seq_errors, 1u);
    CHECK_EQ(s.out_of_order, 1u);
    CHECK_EQ(s.lost, -1);
}

// ---------------------------------------------------------------------------
// 4. 重复包（seq 5 连续两次）
//    21 个包：seq 1,2,3,4,5,5,6,...,20。
//    第二个 seq5 命中 late/duplicated 分支 -> seq_errors = 1、out_of_order = 1。
//    expected = 20 - 1 + 1 = 20；收到 21 -> lost = -1（负值，不截断），lost_pct = -5.0。
//    seq5 之后的 seq6 = seq_num+1，正常接上。
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis 重复包") {
    RtpStreamAnalysis analysis;
    uint32_t frame = 1;
    uint16_t seq = 1;
    for (int i = 0; i < 21; ++i) {
        analysis.onPacket(packet(i * 20.0, frame++, seq, static_cast<uint32_t>(i) * 160));
        if (i == 4) {
            // 第 6 个包仍然是 seq 5（重复）
            continue;
        }
        ++seq;
    }
    analysis.finalize();
    const RtpStreamStats &s = analysis.stats();

    CHECK_EQ(s.packets, 21u);
    CHECK_EQ(s.expected, 20u);
    CHECK_EQ(s.lost, -1);
    CHECK_EQ(s.lost_pct, doctest::Approx(-5.0));
    CHECK_EQ(s.seq_errors, 1u);
    CHECK_EQ(s.out_of_order, 1u);
}

// ---------------------------------------------------------------------------
// 5. 序号回绕
//    8 个包：seq 65530, 65531, ..., 65535, 0, 1。每包 arrival +20 ms、ts +160。
//    start_seq_nr = 65530；到 0 时在 274 行的第二个分支把 seq_cycles 记 1（under = true）。
//    expected = stop(1) + seq_cycles(1)*0x10000 - start(65530) + 1 = 1 + 65536 - 65530 + 1 = 8。
//    收到 8 -> lost = 0；全程 seq 正常 -> seq_errors = 0。
//    （stats 里没有 seq_cycles 字段，expected = 8 即反证 seq_cycles = 1。）
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis 序号回绕") {
    RtpStreamAnalysis analysis;
    const uint16_t seqs[8] = {65530, 65531, 65532, 65533, 65534, 65535, 0, 1};
    for (int i = 0; i < 8; ++i) {
        analysis.onPacket(packet(i * 20.0, static_cast<uint32_t>(i + 1), seqs[i],
                                 static_cast<uint32_t>(i) * 160));
    }
    analysis.finalize();
    const RtpStreamStats &s = analysis.stats();

    CHECK_EQ(s.packets, 8u);
    CHECK_EQ(s.expected, 8u);
    CHECK_EQ(s.lost, 0);
    CHECK_EQ(s.seq_errors, 0u);
    CHECK_EQ(s.out_of_order, 0u);
}

// ---------------------------------------------------------------------------
// 6. 时间戳回绕
//    2 个包：pt1 ts = 0xFFFFFF00 @ arrival 0；pkt2 ts = 0x00000010 @ arrival 4 ms。
//    in_time_sequence：走 251 行的回绕分支
//      (0xFFFFFFFF-0xFFFFFF00) + (0x10-0) = 0xFF + 0x10 = 0x10F < 0x80000000 -> true
//      （若把回绕算错就会置 WRONG_TIMESTAMP，problem 会变 true）。
//    nominaltime = guint32_wraparound_diff(0x10, 0xFFFFFF00) = 0x10+0xFFFFFFFF-0xFFFFFF00+1 = 0x110 = 272
//                  -> /(8000/1000) = 272/8 = 34.0 ms
//    expected_time = 0 + (34.0 - 0) = 34.0；diff = |4 - 34| = 30；jitter = 30/16 = 1.875
//    delta = 4 - 0 = 4；skew = 34.0 - 4 = 30.0 -> max_skew = 30.0
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis 时间戳回绕") {
    RtpStreamAnalysis analysis;
    analysis.onPacket(packet(0.0, 1, 1, 0xFFFFFF00u));
    analysis.onPacket(packet(4.0, 2, 2, 0x00000010u));
    analysis.finalize();
    const RtpStreamStats &s = analysis.stats();

    CHECK_FALSE(s.problem);  // in_time_sequence == true
    CHECK_EQ(s.max_skew_ms, doctest::Approx(30.0).epsilon(1e-12));
    CHECK_EQ(s.mean_delta_ms, doctest::Approx(4.0).epsilon(1e-12));
    CHECK_EQ(s.max_jitter_ms, doctest::Approx(1.875).epsilon(1e-12));
    CHECK_EQ(s.min_jitter_ms, doctest::Approx(1.875).epsilon(1e-12));
    CHECK_EQ(s.clock_rate, 8000u);
    CHECK(s.jitter_available);
    CHECK_EQ(s.packets, 2u);
    CHECK_EQ(s.expected, 2u);
    CHECK_EQ(s.lost, 0);
}

// ---------------------------------------------------------------------------
// 7. CN 包（PT 13）夹在中间
//    5 个包：PT = 8,8,13,8,8；seq = 1..5；
//    arrival = 0,20,100,120,140；ts = 0,160,320,480,640。
//    CN 包命中 STAT_FLAG_PT_CN，其后的第一个包命中 FOLLOW_PT_CN，二者都不进入
//    "常规包"分支（449-454 行的条件），因此不更新 max/mean/min delta 与 jitter。
//    delta：
//      frame2: delta = 20（计入）-> max/min/mean = 20
//      frame3(CN): delta = 100-20 = 80（★被排除）
//      frame4(FOLLOW): delta = 120-100 = 20（★被排除）
//      frame5: delta = 140-120 = 20（计入）-> mean = (20*(4-1)+20)/4 = 20
//    jitter（jitter_ 递推本身不被 CN 门控，但只有在"常规包"处才记 max/mean/min）：
//      frame2: diff=0 -> jitter=0（记录，max=mean=min=0）
//      frame3(CN): nominal=40, expected=20+(40-20)=40, diff=|100-40|=60 -> jitter=(0+60)/16=3.75（★不记录）
//      frame4: expected=100+(60-40)=120, diff=0 -> jitter=15*3.75/16=3.515625（★不记录）
//      frame5: expected=120+(80-60)=140, diff=0 -> jitter=3.515625*15/16=3.2958984375（记录 -> max）
//      mean_jitter = (0*(4-1)+3.2958984375)/4 = 0.823974609375
//    packets = 5、end_rel_ms = 140（CN 不影响计数与收尾时间）；reg_pt 保持 8。
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis CN 包不计入 delta 与 jitter 的 max/mean") {
    RtpStreamAnalysis analysis;
    analysis.onPacket(packet(0.0, 1, 1, 0u, 8));
    analysis.onPacket(packet(20.0, 2, 2, 160u, 8));
    analysis.onPacket(packet(100.0, 3, 3, 320u, 13));  // CN
    analysis.onPacket(packet(120.0, 4, 4, 480u, 8));
    analysis.onPacket(packet(140.0, 5, 5, 640u, 8));
    analysis.finalize();
    const RtpStreamStats &s = analysis.stats();

    CHECK_EQ(s.packets, 5u);
    CHECK_EQ(s.end_rel_ms, doctest::Approx(140.0));
    CHECK_EQ(s.max_delta_ms, doctest::Approx(20.0));  // CN 的 80 ms 没有被计入
    CHECK_EQ(s.mean_delta_ms, doctest::Approx(20.0));
    CHECK_EQ(s.min_delta_ms, doctest::Approx(20.0));
    CHECK_EQ(s.max_jitter_ms, doctest::Approx(3.2958984375).epsilon(1e-12));
    CHECK_EQ(s.mean_jitter_ms, doctest::Approx(0.823974609375).epsilon(1e-12));
    CHECK_EQ(s.min_jitter_ms, doctest::Approx(0.0));
    CHECK_EQ(s.reg_pt, 8);
    CHECK_EQ(s.seq_errors, 0u);
}

// ---------------------------------------------------------------------------
// 8. telephone-event 包（PT 101，名字 "telephone-event"）
//    整条流只有 telephone-event：3 个包，arrival = 0,20,40，ts = 0,160,320。
//    clock_rate == 0（347 行）-> jitter 永不计算：jitter_available = false、
//    max/mean_jitter = 0，min_jitter 保持初始 -1；delta 仍然统计（>=0 的部分不受 clock_rate 影响）。
//    primaryPayloadType：telephone-event 被排除，没有候选 -> 0xFFFFFFFF。
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis telephone-event 抖动不可用") {
    RtpStreamAnalysis analysis;
    analysis.onPacket(packet(0.0, 1, 1, 0u, 101, "telephone-event"));
    analysis.onPacket(packet(20.0, 2, 2, 160u, 101, "telephone-event"));
    analysis.onPacket(packet(40.0, 3, 3, 320u, 101, "telephone-event"));
    analysis.finalize();
    const RtpStreamStats &s = analysis.stats();

    CHECK_EQ(s.packets, 3u);
    CHECK_EQ(s.clock_rate, 0u);
    CHECK_FALSE(s.jitter_available);
    CHECK_EQ(s.max_jitter_ms, doctest::Approx(0.0));
    CHECK_EQ(s.mean_jitter_ms, doctest::Approx(0.0));
    CHECK_EQ(s.min_jitter_ms, doctest::Approx(-1.0));
    CHECK_EQ(s.seq_errors, 0u);
    CHECK_FALSE(s.problem);
    CHECK_EQ(s.expected, 3u);
    CHECK_EQ(s.lost, 0);
    // 没有候选 PT（PT 101 是 telephone-event）-> 0xFFFFFFFF
    CHECK_EQ(analysis.primaryPayloadType(), 0xFFFFFFFFu);
}

// ---------------------------------------------------------------------------
// 9. 静态 PT 8 + payload_type_name == nullptr -> clock_rate = 8000（静态 clock_map）
//    2 个包，足以进入非首包分支的 clock_rate 判定。
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis 静态 PT 走 clock_map") {
    RtpStreamAnalysis analysis;
    analysis.onPacket(packet(0.0, 1, 1, 0u, 8, nullptr));
    analysis.onPacket(packet(20.0, 2, 2, 160u, 8, nullptr));
    analysis.finalize();
    const RtpStreamStats &s = analysis.stats();

    CHECK_EQ(s.clock_rate, 8000u);
    CHECK(s.jitter_available);
    CHECK_EQ(analysis.primaryPayloadType(), 8u);
}

// ---------------------------------------------------------------------------
// 补充：rtp_static_clock_rate / rtp_dynamic_clock_rate 的命中与未命中
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis 时钟表命中与未命中") {
    // 静态表（clock_map）：命中
    CHECK_EQ(rtp_static_clock_rate(0), 8000u);    // PCMU
    CHECK_EQ(rtp_static_clock_rate(8), 8000u);    // PCMA
    CHECK_EQ(rtp_static_clock_rate(10), 44100u);  // L16 stereo
    CHECK_EQ(rtp_static_clock_rate(11), 44100u);  // L16 mono
    CHECK_EQ(rtp_static_clock_rate(18), 8000u);   // G729
    CHECK_EQ(rtp_static_clock_rate(14), 90000u);  // MPA
    // 静态表：未命中
    CHECK_EQ(rtp_static_clock_rate(20), 0u);
    CHECK_EQ(rtp_static_clock_rate(96), 0u);
    CHECK_EQ(rtp_static_clock_rate(100), 0u);

    // 动态表（mimetype_and_clock_map）：命中
    CHECK_EQ(rtp_dynamic_clock_rate("telephone-event"), 8000u);
    CHECK_EQ(rtp_dynamic_clock_rate("AMR"), 8000u);
    CHECK_EQ(rtp_dynamic_clock_rate("AMR-WB"), 16000u);  // 反序查找：不能误命中 "AMR"
    CHECK_EQ(rtp_dynamic_clock_rate("EVRCWB"), 16000u);  // 反序查找：不能误命中 "EVRC"
    CHECK_EQ(rtp_dynamic_clock_rate("H264"), 90000u);
    CHECK_EQ(rtp_dynamic_clock_rate("G726-32"), 8000u);
    CHECK_EQ(rtp_dynamic_clock_rate("g729e"), 8000u);  // 大小写不敏感
    // 动态表：未命中
    CHECK_EQ(rtp_dynamic_clock_rate("opus"), 0u);  // Wireshark 的这张表里没有 opus
    CHECK_EQ(rtp_dynamic_clock_rate("bogus"), 0u);
    CHECK_EQ(rtp_dynamic_clock_rate(nullptr), 0u);
}

// ---------------------------------------------------------------------------
// 10. 44100 Hz 的 L16（PT 11）-> nominaltime = diff / 44（整数除法，不是 44.1）
//    2 个包：arrival = 0, 10 ms；ts = 0, 441（441 个采样 = 10 ms @ 44.1kHz）。
//    clock_rate = 44100 -> clock_rate/1000 = 44（整数除法）-> nominaltime = 441/44 = 10.0227272...
//    skew = 10.0227272... - 10 = 0.0227272...（若错用 44.1，nominaltime 会是 10.0，skew 变 0）。
//    diff = |10 - 10.0227272| = 0.0227272；jitter = 0.0227272/16 = 0.001420454...
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis L16 44100 用整数除法 44") {
    RtpStreamAnalysis analysis;
    analysis.onPacket(packet(0.0, 1, 1, 0u, 11, nullptr));
    analysis.onPacket(packet(10.0, 2, 2, 441u, 11, nullptr));
    analysis.finalize();
    const RtpStreamStats &s = analysis.stats();

    CHECK_EQ(s.clock_rate, 44100u);
    CHECK_EQ(s.max_skew_ms, doctest::Approx(441.0 / 44.0 - 10.0).epsilon(1e-12));
    CHECK(s.max_skew_ms > 0.02);  // 用 44.1 的话这里会是 0
    CHECK(s.max_skew_ms < 0.03);
    CHECK_EQ(s.max_jitter_ms, doctest::Approx((441.0 / 44.0 - 10.0) / 16.0).epsilon(1e-12));
    CHECK_EQ(s.mean_delta_ms, doctest::Approx(10.0));
    CHECK_EQ(rtp_static_clock_rate(11), 44100u);
}

// ---------------------------------------------------------------------------
// 补充：primaryPayloadType 的选择与并列规则
// ---------------------------------------------------------------------------
TEST_CASE("RtpStreamAnalysis 主负载类型排除 CN 与 telephone-event") {
    // 最多的是 g711A(8)，CN(13) 与 telephone-event(101) 被排除
    RtpStreamAnalysis a;
    a.onPacket(packet(0.0, 1, 1, 0u, 8));
    a.onPacket(packet(20.0, 2, 2, 160u, 8));
    a.onPacket(packet(40.0, 3, 3, 320u, 8));
    a.onPacket(packet(60.0, 4, 4, 480u, 101, "telephone-event"));
    a.onPacket(packet(80.0, 5, 5, 640u, 101, "telephone-event"));
    a.onPacket(packet(100.0, 6, 6, 800u, 13));  // CN
    CHECK_EQ(a.primaryPayloadType(), 8u);

    // 并列取较小的 PT：PT 8 与 PT 96 各 1 个 -> 8
    RtpStreamAnalysis b;
    b.onPacket(packet(0.0, 1, 1, 0u, 96, "H264"));
    b.onPacket(packet(20.0, 2, 2, 160u, 8));
    CHECK_EQ(b.primaryPayloadType(), 8u);

    // 没有候选 -> 0xFFFFFFFF（对应 Wireshark 的 PT_UNDEFINED = -1）
    RtpStreamAnalysis c;
    c.onPacket(packet(0.0, 1, 1, 0u, 13));
    c.onPacket(packet(20.0, 2, 2, 160u, 101, "telephone-event"));
    CHECK_EQ(c.primaryPayloadType(), 0xFFFFFFFFu);

    // 一个包都没收到 -> 也是 0xFFFFFFFF；finalize 后 expected/lost 保持 0
    RtpStreamAnalysis empty;
    CHECK_EQ(empty.primaryPayloadType(), 0xFFFFFFFFu);
    empty.finalize();
    CHECK_EQ(empty.stats().expected, 0u);
    CHECK_EQ(empty.stats().lost, 0);
    CHECK_FALSE(empty.stats().has_first_packet);
}
