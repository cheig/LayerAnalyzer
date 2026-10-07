// RTP 流抖动 / delta / skew 统计（RTP1-NAT-02）。
//
// 逐行移植自 Wireshark 4.0.10 的 ui/tap-rtp-analysis.c：
//   clock_map[] / get_clock_rate() / mimetype_and_clock_map[] /
//   get_dyn_pt_clock_rate() / rtppacket_analyse()（163-527 行），
// 以及 wsutil/pint.h:199 的 guint32_wraparound_diff（此处自己写一份等价实现）。
// 统计字段对应 ui/tap-rtp-analysis.h:43-88 的 tap_rtp_stat_t。
//
// 与 Wireshark 的差别（均由卡片 RTP1-NAT-02 / README §2 的 C10、C12 规定）：
//   - 到达时间不由本层读取：调用方按 C10 把 (abs_ts - 抓包第 0 帧 abs_ts) 换算成
//     毫秒填进 RtpPacketObservation::arrival_ms（本项目 pinfo->rel_ts 恒为 0，
//     不能照抄 Wireshark 的 nstime_to_msec(&pinfo->rel_ts)）。
//   - expected/lost/lost_pct 需要在 tap 收尾时才算，因此增加了 finalize()：
//     Wireshark 是在 rtpstream_info_calculate()（ui/tap-rtp-common.c:444-472）里算的，
//     NAT-03 的 RtpStreamCollector::finalize() 会调用它。
//   - last_frame 记录真实的最后一帧（Wireshark 的 last_packet_num 其实是 max_nr）。
//   - out_of_order / problem 是本项目的补充统计，语义见 .cpp。
//   - 不使用 info_extended_seq_num / info_extended_timestamp（那是 M2 排序索引用的）。
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstdint>
#include <vector>

namespace layanalyzer::rtp {

// 每个包由调用方（tap 回调）填好，字段与 rtp_info 对应。
struct RtpPacketObservation {
    double arrival_ms = 0.0;                  // abs_ts - 抓包第 0 帧 abs_ts，再转毫秒（见 C10）
    uint32_t frame_number = 0;                // pinfo->num（1 起）
    uint16_t seq_num = 0;                     // info_seq_num
    uint32_t timestamp = 0;                   // info_timestamp
    bool marker = false;                      // info_marker_set
    uint32_t payload_type = 0;                // info_payload_type
    const char *payload_type_name = nullptr;  // info_payload_type_str，可为 nullptr
    int payload_rate = 0;                     // info_payload_rate
};

struct RtpStreamStats {
    uint32_t packets = 0;          // packet_count（含乱序、重复、截断）
    uint32_t expected = 0;         // rtpstream_info_calculate 的 packet_expected
    int64_t lost = 0;              // expected - total_nr，可以为负
    double lost_pct = 0.0;         // expected ? lost*100/expected : 0
    uint32_t seq_errors = 0;       // sequence
    uint32_t out_of_order = 0;     // 本项目定义，见下
    uint32_t truncated = 0;        // info_all_data_present == FALSE 的包数
    double min_delta_ms = -1.0, mean_delta_ms = 0.0, max_delta_ms = 0.0;
    double min_jitter_ms = -1.0, mean_jitter_ms = 0.0, max_jitter_ms = 0.0;
    double max_skew_ms = 0.0;      // 带符号
    uint32_t max_delta_frame = 0;  // Wireshark 的 max_nr
    double start_rel_ms = 0.0, end_rel_ms = 0.0;
    uint32_t first_frame = 0, last_frame = 0;  // last_frame 用真实最后一帧，见 C12
    uint32_t clock_rate = 0;       // 最后一次非零的 clock_rate，0 表示抖动不可用
    bool jitter_available = false; // 曾经出现过 clock_rate != 0
    bool problem = false;          // 出现过 WRONG_TIMESTAMP 或 WRONG_SEQ
    int reg_pt = -1;               // 常规负载类型（PT_UNDEFINED = -1）
    bool has_first_packet = false;
};

class RtpStreamAnalysis {
public:
    RtpStreamAnalysis();

    void onPacket(const RtpPacketObservation &observation);  // 逐包调用，顺序 = tap 顺序
    const RtpStreamStats &stats() const { return stats_; }
    // 主负载类型：包数最多的、非 CN/telephone-event 的 PT；并列取较小的 PT。
    // 没有任何候选（例如全部是 CN/telephone-event，或一个包都没收到）时返回
    // kPtUndefined（= 0xFFFFFFFF，对应 Wireshark 的 PT_UNDEFINED(-1)）。
    uint32_t primaryPayloadType() const;
    // 收尾：填 stats_.expected / lost / lost_pct（幂等，可重复调用）。
    // 一个包都没收到时三个字段都保持 0。见 C12。
    void finalize();

private:
    void syncStats(uint32_t frame_number, double arrival_ms);

    RtpStreamStats stats_;
    std::vector<uint32_t> payload_type_counts_;  // 256 项
    // 每个 PT 是否出现过 telephone-event 名字（primaryPayloadType 要排除它）。
    std::vector<uint8_t> telephone_event_pt_;  // 256 项

    // 内部状态照抄 tap_rtp_stat_t（ui/tap-rtp-analysis.h:43-88）：
    // seq_num / start_seq_nr / stop_seq_nr / seq_cycles / under / time / start_time /
    // lastnominaltime / jitter / diff / total_nr / pt / first_timestamp 等。
    bool first_packet_ = true;
    uint32_t flags_ = 0;
    uint16_t seq_num_ = 0;
    uint32_t timestamp_ = 0;
    uint32_t first_timestamp_ = 0;
    uint32_t total_nr_ = 0;
    double delta_ = 0.0;
    double jitter_ = 0.0;
    double diff_ = 0.0;
    double skew_ = 0.0;
    double time_ = 0.0;        // 单位 ms
    double start_time_ = 0.0;  // 单位 ms
    double lastnominaltime_ = 0.0;
    double min_delta_ = -1.0;
    double max_delta_ = 0.0;
    double mean_delta_ = 0.0;
    double min_jitter_ = -1.0;
    double max_jitter_ = 0.0;
    double max_skew_ = 0.0;
    double mean_jitter_ = 0.0;
    uint32_t max_nr_ = 0;
    uint16_t start_seq_nr_ = 0;
    uint16_t stop_seq_nr_ = 0;
    uint32_t sequence_ = 0;
    bool under_ = false;
    int seq_cycles_ = 0;
    uint32_t pt_ = 0;
    int reg_pt_ = -1;
    uint32_t first_packet_num_ = 0;

    // 本项目补充：
    uint32_t out_of_order_ = 0;    // 走到 late/duplicated 分支的次数（见 C12）
    uint32_t clock_rate_ = 0;      // 最后一次非零的 clock_rate
    bool jitter_available_ = false;
    bool problem_ = false;         // 出现过 WRONG_TIMESTAMP 或 WRONG_SEQ
};

// 供 tap 使用：按 PT 查时钟频率（静态表和动态表，与 Wireshark 相同）
uint32_t rtp_static_clock_rate(uint32_t payload_type);           // 未命中返回 0
uint32_t rtp_dynamic_clock_rate(const char *payload_type_name);  // 未命中返回 0

}  // namespace layanalyzer::rtp
