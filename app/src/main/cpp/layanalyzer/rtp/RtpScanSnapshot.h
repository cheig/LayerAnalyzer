// RTP 扫描快照（RTP1-NAT-04）。
//
// `scanRtpStreams` 成功后把一次遍历的结果发布到 `session->rtp_last_scan`，
// 供 M2 的解码/导出入口（`decodeRtpAudio` 等）复用：它们必须先在
// `scanGeneration` 与 `session->rtp_scan_generation` 比对通过后，才能信任
// 下游消费者按下标生成的 `id = "s" + 下标`。
//
// header-only，只保存纯数据：`RtpCollectedStream` 本身不持有任何 epan 指针。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/RtpStreamCollector.h"

namespace layanalyzer::rtp {

struct RtpScanSnapshot {
  uint64_t generation = 0;
  std::vector<RtpCollectedStream> streams;
  bool limit_to_display_filter = false;
  std::string filter_expression;
};

}  // namespace layanalyzer::rtp
