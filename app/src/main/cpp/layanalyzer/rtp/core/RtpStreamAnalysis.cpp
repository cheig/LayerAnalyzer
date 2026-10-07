// RTP 流抖动 / delta / skew 统计（RTP1-NAT-02）—— 见 RtpStreamAnalysis.h 顶部说明。
//
// 本文件逐行移植 Wireshark 4.0.10 的 ui/tap-rtp-analysis.c:163-533
// （rtppacket_analyse）与其时钟表 43-157 行。行号注释均指该 4.0.10 源码。
// 严禁任何"优化"：数值必须与 tshark golden 一致。

#include "layanalyzer/rtp/core/RtpStreamAnalysis.h"

#include <cmath>
#include <cstddef>
#include <cstring>

namespace layanalyzer::rtp {

namespace {

// ---------------------------------------------------------------------------
// tap_rtp_stat_t 的 flags（tap-rtp-analysis.h:98-108）
// ---------------------------------------------------------------------------
enum : uint32_t {
    kStatFlagFirst = 0x001,
    kStatFlagMarker = 0x002,
    kStatFlagWrongSeq = 0x004,
    kStatFlagPtChange = 0x008,
    kStatFlagPtCn = 0x010,
    kStatFlagFollowPtCn = 0x020,
    kStatFlagRegPtChange = 0x040,
    kStatFlagWrongTimestamp = 0x080,
    kStatFlagPtTEvent = 0x100,
    kStatFlagDupPkt = 0x200,
};

// 静态 PT 编号（packet-rtp.c:341-377；注释里的编号与 Wireshark 一致）
constexpr uint32_t kPtPcmu = 0;
constexpr uint32_t kPt1016 = 1;
constexpr uint32_t kPtG721 = 2;
constexpr uint32_t kPtGsm = 3;
constexpr uint32_t kPtG723 = 4;
constexpr uint32_t kPtDvi4_8000 = 5;
constexpr uint32_t kPtDvi4_16000 = 6;
constexpr uint32_t kPtLpc = 7;
constexpr uint32_t kPtPcma = 8;
constexpr uint32_t kPtG722 = 9;
constexpr uint32_t kPtL16Stereo = 10;
constexpr uint32_t kPtL16Mono = 11;
constexpr uint32_t kPtQcelp = 12;
constexpr uint32_t kPtCn = 13;
constexpr uint32_t kPtMpa = 14;
constexpr uint32_t kPtG728 = 15;
constexpr uint32_t kPtDvi4_11025 = 16;
constexpr uint32_t kPtDvi4_22050 = 17;
constexpr uint32_t kPtG729 = 18;
constexpr uint32_t kPtCnOld = 19;
constexpr uint32_t kPtCelb = 25;
constexpr uint32_t kPtJpeg = 26;
constexpr uint32_t kPtNv = 28;
constexpr uint32_t kPtH261 = 31;
constexpr uint32_t kPtMpv = 32;
constexpr uint32_t kPtMp2t = 33;
constexpr uint32_t kPtH263 = 34;

constexpr uint32_t kPayloadTypeCount = 256;
// 对应 Wireshark 的 PT_UNDEFINED(-1)：本接口返回 uint32_t，故用全 1 表示。
constexpr uint32_t kPtUndefined = 0xFFFFFFFFu;

// guint32_wraparound_diff（wsutil/pint.h:199）：
//   (higher>lower) ? (higher-lower) : (higher+0xffffffff-lower+1)
// 即按 32 位无符号回绕求差（等价于 (higher - lower) mod 2^32）。
uint32_t guint32_wraparound_diff(uint32_t higher, uint32_t lower) {
    return (higher > lower) ? (higher - lower) : (higher + 0xFFFFFFFFu - lower + 1u);
}

// TIMESTAMP_DIFFERENCE(v1,v2)（tap-rtp-analysis.c:159）：(gint64)v2 - (gint64)v1
int64_t timestamp_difference(uint32_t v1, uint32_t v2) {
    return static_cast<int64_t>(v2) - static_cast<int64_t>(v1);
}

// g_ascii_strncasecmp 的等价实现：只折叠 ASCII 大小写，最多比较 n 个字符。
int ascii_strncasecmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = static_cast<unsigned char>(a[i]);
        unsigned char cb = static_cast<unsigned char>(b[i]);
        if (ca >= 'A' && ca <= 'Z') {
            ca = static_cast<unsigned char>(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = static_cast<unsigned char>(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return static_cast<int>(ca) - static_cast<int>(cb);
        }
        if (ca == '\0') {
            break;
        }
    }
    return 0;
}

// 名字以 "telephone-event" 开头（大小写不敏感），等价于 tap-rtp-analysis.c:347。
bool is_telephone_event(const char *payload_type_name) {
    return payload_type_name != nullptr &&
           ascii_strncasecmp("telephone-event", payload_type_name,
                             std::strlen("telephone-event")) == 0;
}

// clock_map[]（tap-rtp-analysis.c:43-72）。注意原表里 PT_G728 出现了两次，照抄。
struct KeyValue {
    uint32_t key;
    uint32_t value;
};

const KeyValue kClockMap[] = {
    {kPtPcmu, 8000},
    {kPt1016, 8000},
    {kPtG721, 8000},
    {kPtGsm, 8000},
    {kPtG723, 8000},
    {kPtDvi4_8000, 8000},
    {kPtDvi4_16000, 16000},
    {kPtLpc, 8000},
    {kPtPcma, 8000},
    {kPtG722, 8000},
    {kPtL16Stereo, 44100},
    {kPtL16Mono, 44100},
    {kPtQcelp, 8000},
    {kPtCn, 8000},
    {kPtMpa, 90000},
    {kPtG728, 8000},
    {kPtG728, 8000},
    {kPtDvi4_11025, 11025},
    {kPtDvi4_22050, 22050},
    {kPtG729, 8000},
    {kPtCnOld, 8000},
    {kPtCelb, 90000},
    {kPtJpeg, 90000},
    {kPtNv, 90000},
    {kPtH261, 90000},
    {kPtMpv, 90000},
    {kPtMp2t, 90000},
    {kPtH263, 90000},
};

// get_clock_rate（tap-rtp-analysis.c:76-86）
uint32_t get_clock_rate(uint32_t key) {
    for (const KeyValue &entry : kClockMap) {
        if (entry.key == key) {
            return entry.value;
        }
    }
    return 0;
}

// mimetype_and_clock_map[]（tap-rtp-analysis.c:102-140），保持原表的
// 大小写不敏感字母序（反序查找依赖它的顺序）。
struct MimeTypeAndClock {
    const char *pt_mime_name_str;
    uint32_t value;
};

const MimeTypeAndClock kMimetypeAndClockMap[] = {
    {"AMR", 8000},
    {"AMR-WB", 16000},
    {"BMPEG", 90000},
    {"BT656", 90000},
    {"DV", 90000},
    {"EVRC", 8000},
    {"EVRC0", 8000},
    {"EVRC1", 8000},
    {"EVRCB", 8000},
    {"EVRCB0", 8000},
    {"EVRCB1", 8000},
    {"EVRCWB", 16000},
    {"EVRCWB0", 16000},
    {"EVRCWB1", 16000},
    {"EVS", 16000},
    {"G7221", 16000},
    {"G726-16", 8000},
    {"G726-24", 8000},
    {"G726-32", 8000},
    {"G726-40", 8000},
    {"G729D", 8000},
    {"G729E", 8000},
    {"GSM-EFR", 8000},
    {"H263-1998", 90000},
    {"H263-2000", 90000},
    {"H264", 90000},
    {"MP1S", 90000},
    {"MP2P", 90000},
    {"MP4V-ES", 90000},
    {"mpa-robust", 90000},
    {"pointer", 90000},
    {"raw", 90000},
    {"red", 1000},
    {"SMV", 8000},
    {"SMV0", 8000},
    {"t140", 1000},
    {"telephone-event", 8000},
};

// get_dyn_pt_clock_rate（tap-rtp-analysis.c:144-157）：反序查找，避免表项名字是
// payload_type_str 前缀时误匹配（例如 "AMR" 之于 "AMR-WB"）。
uint32_t get_dyn_pt_clock_rate(const char *payload_type_str) {
    if (payload_type_str == nullptr) {
        return 0;
    }
    const size_t count = sizeof(kMimetypeAndClockMap) / sizeof(kMimetypeAndClockMap[0]);
    for (size_t i = count; i-- > 0;) {
        const char *name = kMimetypeAndClockMap[i].pt_mime_name_str;
        if (ascii_strncasecmp(name, payload_type_str, std::strlen(name)) == 0) {
            return kMimetypeAndClockMap[i].value;
        }
    }
    return 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// 对外：时钟频率查询
// ---------------------------------------------------------------------------
uint32_t rtp_static_clock_rate(uint32_t payload_type) {
    return get_clock_rate(payload_type);
}

uint32_t rtp_dynamic_clock_rate(const char *payload_type_name) {
    return get_dyn_pt_clock_rate(payload_type_name);
}

// ---------------------------------------------------------------------------
// 构造
// ---------------------------------------------------------------------------
RtpStreamAnalysis::RtpStreamAnalysis()
    : payload_type_counts_(kPayloadTypeCount, 0),
      telephone_event_pt_(kPayloadTypeCount, 0) {}

// ---------------------------------------------------------------------------
// 逐包分析：rtppacket_analyse（tap-rtp-analysis.c:162-533）
// ---------------------------------------------------------------------------
void RtpStreamAnalysis::onPacket(const RtpPacketObservation &observation) {
    // current_time = nstime_to_msec(&pinfo->rel_ts)（181 行）。
    // 本项目 pinfo->rel_ts 恒为 0（C10），到达时间由调用方按 abs_ts 之差算好传入。
    const double current_time = observation.arrival_ms;

    // primaryPayloadType 的计数（本项目补充，不影响统计口径）
    if (observation.payload_type < kPayloadTypeCount) {
        payload_type_counts_[observation.payload_type] += 1;
        if (is_telephone_event(observation.payload_type_name)) {
            telephone_event_pt_[observation.payload_type] = 1;
        }
    }

    // ---- 第一个包：只做初始化（tap-rtp-analysis.c:181-223），然后返回 ----
    if (first_packet_) {
        start_seq_nr_ = observation.seq_num;
        stop_seq_nr_ = observation.seq_num;
        seq_num_ = observation.seq_num;
        start_time_ = current_time;
        timestamp_ = observation.timestamp;
        first_timestamp_ = observation.timestamp;
        time_ = current_time;
        lastnominaltime_ = 0;
        pt_ = observation.payload_type;
        reg_pt_ = static_cast<int>(observation.payload_type);
        // bandwidth / bw_history / total_bytes 不在本接口范围（见头文件说明）。
        delta_ = 0;
        max_delta_ = 0;
        min_delta_ = -1;
        mean_delta_ = 0;
        jitter_ = 0;
        min_jitter_ = -1;
        max_jitter_ = 0;
        diff_ = 0;

        total_nr_++;
        flags_ |= kStatFlagFirst;
        if (observation.marker) {
            flags_ |= kStatFlagMarker;
        }
        first_packet_num_ = observation.frame_number;
        first_packet_ = false;

        syncStats(observation.frame_number, current_time);
        return;
    }

    // Reset flags（226 行）
    flags_ = 0;

    // ---- 时间戳是否在序列上（247-259 行）----
    bool in_time_sequence;
    if (first_timestamp_ <= observation.timestamp &&
        timestamp_difference(first_timestamp_, observation.timestamp) < 0x80000000LL) {
        // Normal timestamp sequence
        in_time_sequence = true;
    } else if (first_timestamp_ > observation.timestamp &&
               (timestamp_difference(first_timestamp_, 0xFFFFFFFFu) +
                timestamp_difference(0u, observation.timestamp)) < 0x80000000LL) {
        // Normal timestamp sequence with wraparound
        in_time_sequence = true;
    } else {
        // New packet is not in sequence (is in past)
        in_time_sequence = false;
        flags_ |= kStatFlagWrongTimestamp;
    }

    // ---- 序号回绕计数（264-285 行）----
    if ((observation.seq_num < start_seq_nr_) && in_time_sequence && (under_ == false)) {
        seq_cycles_++;
        under_ = true;
    } else if ((observation.seq_num == 0) && (stop_seq_nr_ == 65535) && in_time_sequence &&
               (under_ == false)) {
        seq_cycles_++;
        under_ = true;
    } else if ((observation.seq_num > start_seq_nr_) && in_time_sequence && (under_ != false)) {
        // the whole round is over, so reset the flag
        under_ = false;
    }

    // ---- seq_num 的四个分支（294-321 行）----
    if (in_time_sequence &&
        ((seq_num_ + 1 == observation.seq_num) || (flags_ & kStatFlagFirst))) {
        seq_num_ = observation.seq_num;
    } else if (in_time_sequence && ((seq_num_ == 65535) && (observation.seq_num == 0))) {
        // If the first one is 65535 we wrap
        seq_num_ = observation.seq_num;
    } else if (in_time_sequence &&
               ((seq_num_ + 1 < observation.seq_num) ||
                (seq_num_ - observation.seq_num > 0xFF00))) {
        // Lost packets（跨环跳跃，issue #5958）
        seq_num_ = observation.seq_num;
        sequence_++;
        flags_ |= kStatFlagWrongSeq;
    } else if (seq_num_ + 1 > observation.seq_num) {
        // Late or duplicated
        sequence_++;
        flags_ |= kStatFlagWrongSeq;
        out_of_order_++;  // 本项目扩展（C12）：走到 late/duplicated 分支就 +1
    }

    // ---- 检查负载类型（324-335 行）----
    if (observation.payload_type == kPtCn || observation.payload_type == kPtCnOld) {
        flags_ |= kStatFlagPtCn;
    }
    if (pt_ == kPtCn || pt_ == kPtCnOld) {
        flags_ |= kStatFlagFollowPtCn;
    }
    if (observation.payload_type != pt_) {
        flags_ |= kStatFlagPtChange;
    }
    pt_ = observation.payload_type;

    // ---- 时钟频率（338-360 行）----
    uint32_t clock_rate;
    if (pt_ < 96) {
        clock_rate = get_clock_rate(pt_);
    } else {  // Dynamic PT
        if (observation.payload_type_name != nullptr) {
            // telephone-event 的时间戳不递增，会破坏抖动/skew/时钟漂移，见 RFC 4733 §2.2.1
            if (is_telephone_event(observation.payload_type_name)) {
                clock_rate = 0;
                flags_ |= kStatFlagPtTEvent;
            } else {
                if (observation.payload_rate != 0) {
                    clock_rate = static_cast<uint32_t>(observation.payload_rate);
                } else {
                    clock_rate = get_dyn_pt_clock_rate(observation.payload_type_name);
                }
            }
        } else {
            clock_rate = 0;
        }
    }

    // 本项目：把流级别的 clock_rate / jitter_available 记下来。
    // 注意 Wireshark 只在 in_time_sequence 且 clock_rate != 0 时才写 statinfo->clock_rate；
    // 这里是流属性快照，不影响任何数值计算（数值都用下面的局部 clock_rate）。
    if (clock_rate != 0) {
        clock_rate_ = clock_rate;
        jitter_available_ = true;
    }

    // ---- diff/jitter/skew：只对在序列上的包算（362-417 行）----
    double current_jitter = 0;
    double current_diff = 0;
    if (in_time_sequence) {
        // Handle wraparound ?
        const double arrivaltime = current_time - start_time_;
        double nominaltime =
            static_cast<double>(guint32_wraparound_diff(observation.timestamp, first_timestamp_));

        // Can only analyze defined sampling rates
        if (clock_rate != 0) {
            // Convert from sampling clock to ms（整数除法：44100 -> 44）
            nominaltime = nominaltime / (clock_rate / 1000);

            // Calculate the current jitter (in ms)
            if (!first_packet_) {
                const double expected_time = time_ + (nominaltime - lastnominaltime_);
                current_diff = std::fabs(current_time - expected_time);
                current_jitter = (15 * jitter_ + current_diff) / 16;

                delta_ = current_time - time_;
                jitter_ = current_jitter;
                diff_ = current_diff;
            }
            lastnominaltime_ = nominaltime;
            // Skew is positive if TS (nominal) is too fast
            skew_ = nominaltime - arrivaltime;
            const double absskew = std::fabs(skew_);
            if (absskew > std::fabs(max_skew_)) {
                max_skew_ = skew_;  // 取当前带符号值
            }
            // sumt/sumTS/sumt2/sumtTS（skew 最小二乘）不在本接口输出范围内，略去。
        } else {
            if (!first_packet_) {
                delta_ = current_time - time_;
            }
        }
    }

    // bandwidth / bw_history 不在本接口范围（419-441 行），略去。

    // ---- 标记位（444-447 行）----
    if (observation.marker) {
        flags_ |= kStatFlagMarker;
    }

    // ---- 常规包统计（449-506 行）----
    if (!(flags_ & kStatFlagFirst) && !(flags_ & kStatFlagMarker) &&
        !(flags_ & kStatFlagPtCn) && !(flags_ & kStatFlagWrongTimestamp) &&
        !(flags_ & kStatFlagFollowPtCn)) {
        // Include it in maximum delta calculation
        if (delta_ > max_delta_) {
            max_delta_ = delta_;
            max_nr_ = observation.frame_number;
        }
        // Include it in minimum delta calculation
        if (min_delta_ == -1) {
            min_delta_ = delta_;
        } else if (delta_ < min_delta_) {
            min_delta_ = delta_;
        }
        // Mean delta：除以的是 delta 的个数（= total_nr_），此处 total_nr_ >= 1。
        mean_delta_ = (mean_delta_ * (total_nr_ - 1) + delta_) / total_nr_;

        if (clock_rate != 0) {
            // Maximum jitter
            if (jitter_ > max_jitter_) {
                max_jitter_ = jitter_;
            }
            // Mean jitter：除以的是 diff 的个数（= total_nr_）。
            mean_jitter_ = (mean_jitter_ * (total_nr_ - 1) + current_jitter) / total_nr_;

            // Minimum jitter
            if (min_jitter_ == -1) {
                min_jitter_ = jitter_;
            } else if (jitter_ < min_jitter_) {
                min_jitter_ = jitter_;
            }
        }
    }

    // ---- 常规负载类型变化（507-519 行）----
    if (!(flags_ & kStatFlagFirst) && !(flags_ & kStatFlagPtCn)) {
        if ((static_cast<int>(pt_) != reg_pt_) && (reg_pt_ != -1)) {
            flags_ |= kStatFlagRegPtChange;
        }
    }
    if (!(flags_ & kStatFlagPtCn)) {
        reg_pt_ = static_cast<int>(pt_);
    }

    // 本项目补充统计：出现过 WRONG_TIMESTAMP 或 WRONG_SEQ
    if (flags_ & (kStatFlagWrongTimestamp | kStatFlagWrongSeq)) {
        problem_ = true;
    }

    if (in_time_sequence) {
        // 只记在序列上的包的时间，diff 才正确
        time_ = current_time;
    }
    timestamp_ = observation.timestamp;
    stop_seq_nr_ = observation.seq_num;
    total_nr_++;
    // last_payload_len 不在本接口范围（530 行）。

    syncStats(observation.frame_number, current_time);
}

// ---------------------------------------------------------------------------
// 把内部状态快照进 stats_（每个包结束时调用）
// ---------------------------------------------------------------------------
void RtpStreamAnalysis::syncStats(uint32_t frame_number, double arrival_ms) {
    stats_.packets = total_nr_;
    stats_.seq_errors = sequence_;
    stats_.out_of_order = out_of_order_;
    // stats_.truncated 由 tap 层填（info_all_data_present），本层无从判断，保持 0。
    stats_.min_delta_ms = min_delta_;
    stats_.mean_delta_ms = mean_delta_;
    stats_.max_delta_ms = max_delta_;
    stats_.min_jitter_ms = min_jitter_;
    stats_.mean_jitter_ms = mean_jitter_;
    stats_.max_jitter_ms = max_jitter_;
    stats_.max_skew_ms = max_skew_;
    stats_.max_delta_frame = max_nr_;
    stats_.start_rel_ms = start_time_;
    stats_.end_rel_ms = arrival_ms;
    stats_.first_frame = first_packet_num_;
    stats_.last_frame = frame_number;  // 真实最后一帧（C12）
    stats_.clock_rate = clock_rate_;
    stats_.jitter_available = jitter_available_;
    stats_.problem = problem_;
    stats_.reg_pt = reg_pt_;
    stats_.has_first_packet = !first_packet_;
}

// ---------------------------------------------------------------------------
// 收尾：expected / lost / lost_pct（rtpstream_info_calculate，tap-rtp-common.c:444-472）
// ---------------------------------------------------------------------------
void RtpStreamAnalysis::finalize() {
    if (total_nr_ == 0) {
        // 没有任何包：不构造 "expected = 1" 这种无意义的值（Wireshark 只会为真实存在的流收尾）。
        stats_.expected = 0;
        stats_.lost = 0;
        stats_.lost_pct = 0.0;
        return;
    }

    const int64_t expected = static_cast<int64_t>(stop_seq_nr_) +
                             static_cast<int64_t>(seq_cycles_) * 0x10000 -
                             static_cast<int64_t>(start_seq_nr_) + 1;
    stats_.expected = static_cast<uint32_t>(expected);
    // lost 用 int64 且允许为负（重复包），不截断（C12）。
    stats_.lost = static_cast<int64_t>(stats_.expected) - static_cast<int64_t>(total_nr_);
    stats_.lost_pct = stats_.expected != 0
                          ? static_cast<double>(stats_.lost) * 100.0 /
                                static_cast<double>(stats_.expected)
                          : 0.0;
}

// ---------------------------------------------------------------------------
// 主负载类型
// ---------------------------------------------------------------------------
uint32_t RtpStreamAnalysis::primaryPayloadType() const {
    uint32_t best_pt = kPtUndefined;
    uint32_t best_count = 0;
    for (uint32_t pt = 0; pt < kPayloadTypeCount; ++pt) {
        const uint32_t count = payload_type_counts_[pt];
        if (count == 0) {
            continue;
        }
        if (pt == kPtCn || pt == kPtCnOld) {  // 非 CN(13)/CN_OLD(19)
            continue;
        }
        if (telephone_event_pt_[pt] != 0) {  // 非 telephone-event
            continue;
        }
        if (count > best_count) {  // 严格大于 -> 并列取较小的 PT
            best_count = count;
            best_pt = pt;
        }
    }
    return best_pt;
}

}  // namespace layanalyzer::rtp
