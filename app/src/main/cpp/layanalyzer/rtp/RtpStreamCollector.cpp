// `rtp` tap 收集器实现（RTP1-NAT-03）。
//
// 依赖 epan：注册 "rtp" tap，把每个包的 `_rtp_info` 映射成 `RtpPacketObservation`
// 后交给 `RtpStreamAnalysis`。回调里只做 O(1) 的计数与拷贝，不做 I/O、不分配大
// 缓冲、不解析负载（M1 不碰负载）。
#include "layanalyzer/rtp/RtpStreamCollector.h"

#include <algorithm>
#include <cctype>

#include <epan/dissectors/packet-rtp.h>
#include <wsutil/nstime.h>

#include "layanalyzer/rtp/RtpStreamKeyEpan.h"
#include "layanalyzer/rtp/rtp_info_view.h"
#include "layanalyzer/rtp/core/RtpCodecNames.h"
#include "layanalyzer/rtp/core/RtpPayloadOverrides.h"
#include "layanalyzer/session/WiresharkSession.h"

namespace layanalyzer::rtp {
namespace {

bool has_telephone_event_prefix(const std::string &name) {
  static constexpr char kPrefix[] = "telephone-event";
  constexpr size_t kPrefixLength = sizeof(kPrefix) - 1;
  if (name.size() < kPrefixLength) return false;
  for (size_t index = 0; index < kPrefixLength; ++index) {
    const unsigned char value = static_cast<unsigned char>(name[index]);
    if (static_cast<char>(std::tolower(value)) != kPrefix[index]) return false;
  }
  return true;
}

int32_t observed_telephone_event_pt(
    const std::map<uint8_t, std::string> &payload_type_names) {
  for (const auto &entry : payload_type_names) {
    if (has_telephone_event_prefix(entry.second)) {
      return static_cast<int32_t>(entry.first);
    }
  }
  return -1;
}

int32_t overridden_telephone_event_pt(
    const RtpPayloadOverrides *overrides) {
  if (overrides == nullptr) return -1;
  for (const RtpPayloadOverride &entry : overrides->items()) {
    if (canonical_codec(entry.codec).id == "telephone-event") {
      return static_cast<int32_t>(entry.pt);
    }
  }
  return -1;
}

// 从 `_rtp_info` 取值、组装观察记录的薄包装（纯映射在 rtp_info_view.h）。
RtpPacketObservation view_rtp_info(const struct _rtp_info *rtp_info,
                                   packet_info *pinfo, double arrival_ms) {
  return make_rtp_observation(arrival_ms, pinfo->num, rtp_info->info_seq_num,
                              rtp_info->info_timestamp,
                              rtp_info->info_marker_set != FALSE,
                              rtp_info->info_payload_type,
                              rtp_info->info_payload_type_str,
                              rtp_info->info_payload_rate);
}

}  // namespace

// tap 回调必须是静态自由函数。TL_REQUIRES_NOTHING：树可能不存在，回调里绝不
// 取 proto_tree，也不做 I/O、不分配大缓冲、不解析负载。
static tap_packet_status rtp_tap_packet_cb(void *ctx, packet_info *pinfo,
                                           epan_dissect_t * /* edt */,
                                           const void *data,
                                           tap_flags_t /* flags */) {
  static_cast<RtpStreamCollector *>(ctx)->onPacket(
      pinfo, static_cast<const struct _rtp_info *>(data));
  return TAP_PACKET_DONT_REDRAW;
}

RtpStreamCollector::RtpStreamCollector(WiresharkSession *session,
                                       double first_frame_abs_ms)
    : session_(session), first_frame_abs_ms_(first_frame_abs_ms) {}

RtpStreamCollector::~RtpStreamCollector() {
  // 正常路径下调用方已在 dissect_mutex 下显式 removeTap()，这里 registered_
  // 已是 false，不会重复移除。提前返回等异常路径若仍处于注册状态，由本析构
  // 补齐；tap 注册表是进程全局的，补移除同样要在 mutex 下进行（因此构造/析构
  // 不得与 registerTap 处在同一个锁定作用域内）。
  if (!registered_ || !session_) return;
  std::unique_lock<std::mutex> lock(session_->dissect_mutex);
  removeTap();
}

bool RtpStreamCollector::registerTap(std::string &error) {
  // 调用方必须已持有 session->dissect_mutex（tap 注册表是进程全局的）。
  if (registered_) return true;
  GString *err = register_tap_listener("rtp", this, nullptr, TL_REQUIRES_NOTHING,
                                       nullptr /* reset */, rtp_tap_packet_cb,
                                       nullptr, nullptr);
  if (err) {
    error = err->str ? err->str : "Unable to register the rtp tap.";
    g_string_free(err, TRUE);
    return false;
  }
  registered_ = true;
  return true;
}

void RtpStreamCollector::removeTap() {
  if (!registered_) return;
  registered_ = false;
  remove_tap_listener(this);
}

void RtpStreamCollector::onPacket(packet_info *pinfo,
                                  const struct _rtp_info *rtp_info) {
  // 多会话过滤：另一个会话同时在解析时，进程全局的 tap 回调也会进来。
  if (!pinfo || !rtp_info || pinfo->epan != session_->epan) return;

  const RtpStreamKey key = make_rtp_stream_key(pinfo, rtp_info->info_sync_src);
  auto found = by_key_.find(key);
  if (found == by_key_.end()) {
    if (by_key_.size() >= kMaxStreams) {
      // 拒绝新建：只置截断标志，不记录包，避免无界增长。
      streams_truncated_ = true;
      return;
    }
    found = by_key_.emplace(key, StreamState{}).first;
    found->second.out.key = key;
  }
  StreamState &state = found->second;
  state.payload_evidence.observe(
      rtp_info->info_payload_len, rtp_info->info_all_data_present != FALSE,
      rtp_info->info_is_srtp != FALSE, rtp_info->info_padding_set != FALSE,
      rtp_info->info_padding_count);

  // 首包判断要在喂给 analysis 之前完成（analysis 的 stats 在 onPacket 后才同步）。
  const bool first_packet = !state.analysis.stats().has_first_packet;

  const double arrival_ms = nstime_to_msec(&pinfo->abs_ts) - first_frame_abs_ms_;
  state.analysis.onPacket(view_rtp_info(rtp_info, pinfo, arrival_ms));

  if (rtp_info->info_all_data_present == FALSE) state.truncated += 1;

  // 流级元数据（只在有意义时更新，避免被后续 0/空值覆盖）。
  if (first_packet) {
    state.out.first_abs_epoch_us =
        static_cast<uint64_t>(pinfo->abs_ts.secs) * 1000000ULL +
        static_cast<uint64_t>(pinfo->abs_ts.nsecs / 1000);
  }
  if (state.out.codec_name.empty() && rtp_info->info_payload_type_str) {
    state.out.codec_name = rtp_info->info_payload_type_str;
  }
  if (rtp_info->info_payload_rate != 0) {
    state.out.payload_rate = rtp_info->info_payload_rate;
  }
  if (rtp_info->info_setup_frame_num != 0) {
    state.out.setup_frame = rtp_info->info_setup_frame_num;
  }
  state.out.is_srtp = rtp_info->info_is_srtp != FALSE;
  state.out.bytes += rtp_info->info_data_len +
                     (pinfo->net_src.type == AT_IPv6 ? 48u : 28u);

  const uint32_t payload_type = rtp_info->info_payload_type;
  if (payload_type < 256) {
    const uint8_t pt = static_cast<uint8_t>(payload_type);
    std::vector<uint8_t> &seen = state.out.payload_types_seen;
    if (std::find(seen.begin(), seen.end(), pt) == seen.end()) {
      seen.insert(std::lower_bound(seen.begin(), seen.end(), pt), pt);
    }
    if (rtp_info->info_payload_type_str != nullptr &&
        state.out.payload_type_names.find(pt) ==
            state.out.payload_type_names.end()) {
      state.out.payload_type_names.emplace(pt,
                                           rtp_info->info_payload_type_str);
    }
  }
}

void RtpStreamCollector::finalize(const RtpPayloadOverrides *overrides) {
  ordered_.clear();
  ordered_.reserve(by_key_.size());
  for (auto &entry : by_key_) {
    StreamState &state = entry.second;
    // RTP-shaped probes/keepalives are not media streams. Do this after the
    // complete scan: a later payload with the same SSRC must retain the stream,
    // including its earlier empty packets. Never filter by SSRC or packet count.
    if (!state.payload_evidence.shouldKeep()) continue;
    state.analysis.finalize();  // 幂等：填 expected / lost / lost_pct
    state.out.stats = state.analysis.stats();
    state.out.stats.truncated = state.truncated;  // tap 层统计，analysis 不管这个字段
    state.out.primary_pt = state.analysis.primaryPayloadType();
    state.out.telephone_event_pt = overridden_telephone_event_pt(overrides);
    if (state.out.telephone_event_pt < 0) {
      state.out.telephone_event_pt =
          observed_telephone_event_pt(state.out.payload_type_names);
    }
    ordered_.push_back(state.out);
  }
  std::sort(ordered_.begin(), ordered_.end(),
            [](const RtpCollectedStream &a, const RtpCollectedStream &b) {
              return a.stats.first_frame < b.stats.first_frame;
            });
  LOGI("RtpStreamCollector: streams=%zu truncated=%d", ordered_.size(),
       streams_truncated_ ? 1 : 0);
}

const std::vector<RtpCollectedStream> &RtpStreamCollector::streams() const {
  return ordered_;
}

}  // namespace layanalyzer::rtp
