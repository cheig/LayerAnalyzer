// `rtp` tap 收集器（RTP1-NAT-03）。
//
// 在一遍 `dissect_frame_with_taps` 遍历里通过 "rtp" tap 收集所有流，逐包喂给
// `RtpStreamAnalysis`（RTP1-NAT-02），遍历结束后 `finalize()` 收尾
// （expected / lost / lost_pct、排序）。
//
// 依赖 epan，放在 `layanalyzer/rtp/` 根目录，不进 host 单测。
// 线程模型：tap 回调在 **持有 `session->dissect_mutex`** 的解析线程里同步执行，
// 所以内部容器不需要再加锁；`registerTap` / `removeTap` 也必须在持有同一个
// mutex 时调用（tap 注册表是进程全局的）。
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/rtp/core/RtpStreamAnalysis.h"
#include "layanalyzer/rtp/core/RtpStreamKey.h"
#include "layanalyzer/rtp/core/RtpStreamPayloadEvidence.h"

struct _rtp_info;
struct WiresharkSession;

namespace layanalyzer::rtp {

struct RtpPayloadOverrides;

struct RtpCollectedStream {
  RtpStreamKey key;
  RtpStreamStats stats;                 // NAT-02 的结果（离开 tap 前调用 finalize() 收尾）
  std::string codec_name;               // 规范前的原始名字（info_payload_type_str 或空）
  int payload_rate = 0;                 // info_payload_rate
  uint32_t setup_frame = 0;             // info_setup_frame_num
  bool is_srtp = false;
  uint32_t primary_pt = 0;              // 包数最多的 PT
  int32_t telephone_event_pt = -1;      // finalize() 按覆盖表/名字确定
  std::vector<uint8_t> payload_types_seen;   // 升序，PT 中途切换的证据
  // Per-PT SDP names are needed after the scan to resolve the primary codec
  // independently from telephone-event/CN packets. Static PTs have no name.
  std::map<uint8_t, std::string> payload_type_names;
  uint32_t bytes = 0;                   // info_data_len + (IPv6 ? 48 : 28) 之和，仅供参考
  uint64_t first_abs_epoch_us = 0;      // 首包 pinfo->abs_ts，epoch 微秒
};

class RtpStreamCollector {
 public:
  // `session` 用于过滤其他会话触发的 tap 回调（进程全局）；`first_frame_abs_ms`
  // 是抓包第 0 帧的 `nstime_to_msec(&fd.abs_ts)`，由调用方（NAT-04）算好后传入：
  // 到达时间一律用 `pinfo->abs_ts` 减去它（C10，本项目 `pinfo->rel_ts` 恒为 0）。
  explicit RtpStreamCollector(WiresharkSession *session,
                              double first_frame_abs_ms);
  ~RtpStreamCollector();  // 保证 remove_tap_listener

  RtpStreamCollector(const RtpStreamCollector &) = delete;
  RtpStreamCollector &operator=(const RtpStreamCollector &) = delete;

  // 调用方必须已持有 session->dissect_mutex。失败返回 false，error 带回
  // tap_error->str。
  bool registerTap(std::string &error);
  // 幂等；调用方必须已持有 session->dissect_mutex。
  void removeTap();
  // 由 tap 回调调用。
  void onPacket(packet_info *pinfo, const struct _rtp_info *rtp_info);
  // 遍历结束后调用：计算 expected/lost、确定 telephone-event PT、排序。
  // overrides 为扫描开始时取得的会话覆盖表快照；nullptr 表示无覆盖表。
  void finalize(const RtpPayloadOverrides *overrides = nullptr);
  // 按 first_frame 升序；`id` 由消费者按下标生成（"s" + 下标），不是本结构体的字段。
  const std::vector<RtpCollectedStream> &streams() const;
  bool truncated_streams() const { return streams_truncated_; }
  static constexpr size_t kMaxStreams = 4096;

 private:
  struct StreamState {
    RtpStreamAnalysis analysis;
    RtpStreamPayloadEvidence payload_evidence;
    RtpCollectedStream out;
    uint32_t truncated = 0;  // info_all_data_present == FALSE 的包数（tap 层统计）
  };

  WiresharkSession *session_ = nullptr;
  double first_frame_abs_ms_ = 0.0;
  bool registered_ = false;
  bool streams_truncated_ = false;
  std::unordered_map<RtpStreamKey, StreamState, RtpStreamKeyHash> by_key_;
  std::vector<RtpCollectedStream> ordered_;
};

}  // namespace layanalyzer::rtp
