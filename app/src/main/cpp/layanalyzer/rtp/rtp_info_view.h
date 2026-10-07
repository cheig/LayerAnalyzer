// `_rtp_info` → `RtpPacketObservation` 的字段映射（RTP1-NAT-03）。
//
// 本文件**不包含任何 Wireshark / GLib / JNI 头文件**，只依赖标准库和
// `core/RtpStreamAnalysis.h`。映射刻意拆成两层：
//   * `make_rtp_observation`：只吃基本类型参数的纯函数（host 可单独单测）；
//   * 从 `const struct _rtp_info *` 取值的薄包装：放在
//     `RtpStreamCollector.cpp`（那个 TU 才依赖 epan）。
// 这样以后给纯函数补 host 测试时不需要把 epan 拉进来。
#pragma once

#include <cstdint>

#include "layanalyzer/rtp/core/RtpStreamAnalysis.h"

namespace layanalyzer::rtp {

/**
 * 构造一条观察记录。参数与 packet-rtp.h 的 `struct _rtp_info` 字段一一对应：
 *   seq_num          ← info_seq_num
 *   timestamp        ← info_timestamp
 *   marker           ← info_marker_set
 *   payload_type     ← info_payload_type
 *   payload_type_name← info_payload_type_str（静态 PT 时为 nullptr，原样透传）
 *   payload_rate     ← info_payload_rate
 * `arrival_ms` 由调用方按 C10 用 `abs_ts` 之差算好；`frame_number` 为
 * `pinfo->num`（1 起）。
 */
inline RtpPacketObservation make_rtp_observation(double arrival_ms,
                                                 uint32_t frame_number,
                                                 uint16_t seq_num,
                                                 uint32_t timestamp,
                                                 bool marker,
                                                 uint32_t payload_type,
                                                 const char *payload_type_name,
                                                 int payload_rate) {
    RtpPacketObservation observation;
    observation.arrival_ms = arrival_ms;
    observation.frame_number = frame_number;
    observation.seq_num = seq_num;
    observation.timestamp = timestamp;
    observation.marker = marker;
    observation.payload_type = payload_type;
    observation.payload_type_name = payload_type_name;
    observation.payload_rate = payload_rate;
    return observation;
}

/** nstime（secs + nsecs）→ epoch 毫秒，用于首包绝对时间（M3 的 `firstAbsEpochUs`）。 */
inline double nstime_parts_to_epoch_ms(int64_t secs, int32_t nsecs) {
    return static_cast<double>(secs) * 1000.0 +
           static_cast<double>(nsecs) / 1e6;
}

}  // namespace layanalyzer::rtp
