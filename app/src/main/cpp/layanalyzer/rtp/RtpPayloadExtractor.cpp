#include "layanalyzer/rtp/RtpPayloadExtractor.h"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <epan/dissectors/packet-rtp.h>
#include <wsutil/nstime.h>

#include "layanalyzer/rtp/RtpStreamKeyEpan.h"
#include "layanalyzer/rtp/core/RtppFile.h"
#include "layanalyzer/rtp/core/RtppIndex.h"
#include "layanalyzer/session/WiresharkSession.h"

namespace layanalyzer::rtp {
namespace {

std::string join_path(const std::string &directory, const std::string &name) {
  if (directory.empty()) return name;
  const char last = directory.back();
  if (last == '/' || last == '\\') return directory + name;
  return directory + "/" + name;
}

class ExtractionContext {
 public:
  ExtractionContext(WiresharkSession *session,
                    const RtpExtractionRequest &request,
                    double first_frame_abs_sec)
      : session_(session),
        request_(request),
        first_frame_abs_sec_(first_frame_abs_sec) {}

  ~ExtractionContext() {
    removeTap();
  }

  bool registerTap(std::string &error) {
    if (registered_) return true;
    std::unique_lock<std::mutex> lock(session_->dissect_mutex);
    GString *tap_error = register_tap_listener(
        "rtp", this, nullptr, TL_REQUIRES_NOTHING, nullptr,
        rtp_payload_tap_packet_cb, nullptr, nullptr);
    if (tap_error) {
      error = tap_error->str ? tap_error->str
                             : "Unable to register the rtp payload tap.";
      g_string_free(tap_error, TRUE);
      return false;
    }
    registered_ = true;
    return true;
  }

  void removeTap() {
    if (!registered_) return;
    std::unique_lock<std::mutex> lock(session_->dissect_mutex);
    if (registered_) {
      registered_ = false;
      remove_tap_listener(this);
    }
  }

  bool openFiles(std::string &error) {
    if (request_.out_dir.empty()) {
      error = "RTP payload output directory is empty.";
      return false;
    }

    for (const RtpStreamKey &key : request_.keys) {
      if (outputs_.find(key) != outputs_.end()) continue;
      auto id_it = request_.stream_ids.find(key);
      if (id_it == request_.stream_ids.end() || id_it->second.empty()) {
        error = "Missing stream id for an RTP payload extraction key.";
        return false;
      }

      Output output;
      output.id = id_it->second;
      output.rtpp_path = join_path(request_.out_dir, output.id + ".rtpp");
      output.index_path =
          join_path(request_.out_dir, output.id + ".rtpp.idx");
      output.writer = std::make_unique<RtppWriter>();
      if (!output.writer->open(output.rtpp_path, output.id, error)) {
        return false;
      }

      all_paths_.push_back(output.rtpp_path);
      all_paths_.push_back(output.index_path);
      outputs_.emplace(key, std::move(output));
    }
    return true;
  }

  void onPacket(packet_info *pinfo, const struct _rtp_info *rtp_info) {
    if (failed_ || !pinfo || !rtp_info || pinfo->epan != session_->epan) return;

    const RtpStreamKey key =
        make_rtp_stream_key(pinfo, rtp_info->info_sync_src);
    auto output_it = outputs_.find(key);
    if (output_it == outputs_.end()) return;

    if (rtp_info->info_all_data_present == FALSE) {
      ++truncated_packets_;
      return;
    }

    uint64_t payload_length = rtp_info->info_payload_len;
    if (rtp_info->info_padding_set != FALSE) {
      const uint64_t padding_length = rtp_info->info_padding_count;
      if (padding_length > payload_length) {
        ++truncated_packets_;
        return;
      }
      payload_length -= padding_length;
    }
    if (payload_length == 0) {
      ++zero_payload_packets_;
      return;
    }
    if (payload_length > UINT16_MAX) {
      ++truncated_packets_;
      return;
    }

    const uint64_t payload_offset = rtp_info->info_payload_offset;
    const uint64_t data_length = rtp_info->info_data_len;
    if (!rtp_info->info_data || payload_offset > data_length ||
        payload_length > data_length - payload_offset) {
      ++truncated_packets_;
      return;
    }

    RtppRecordHeader header;
    header.frame = pinfo->num;
    header.arrival_rel_sec =
        nstime_to_sec(&pinfo->abs_ts) - first_frame_abs_sec_;
    header.ext_seq = rtp_info->info_extended_seq_num;
    header.ext_ts = rtp_info->info_extended_timestamp;
    header.pt = static_cast<uint8_t>(rtp_info->info_payload_type);
    header.marker = rtp_info->info_marker_set != FALSE ? 1u : 0u;
    header.len = static_cast<uint16_t>(payload_length);

    if (!output_it->second.writer->append(
            header, rtp_info->info_data + payload_offset)) {
      failed_ = true;
      error_ = "Unable to append an RTP payload record.";
    }
  }

  bool failed() const { return failed_; }
  const std::string &error() const { return error_; }
  uint64_t truncatedPackets() const { return truncated_packets_; }
  uint64_t zeroPayloadPackets() const { return zero_payload_packets_; }

  bool finalizeOutputs(RtpExtractionResult &result, std::string &error) {
    for (auto &entry : outputs_) {
      Output &output = entry.second;
      if (!output.writer->finalize(error)) return false;

      const std::vector<RtppIndexEntry> index = build_sequence_index(
          output.writer->record_headers(), output.writer->record_offsets());
      if (!write_rtpp_index(output.index_path, index, error)) return false;

      result.rtpp_paths[output.id] = output.rtpp_path;
      result.index_paths[output.id] = output.index_path;
      result.record_counts[output.id] =
          static_cast<uint64_t>(output.writer->record_headers().size());
    }
    return true;
  }

  void cleanupFiles() {
    for (auto &entry : outputs_) {
      entry.second.writer.reset();
    }
    outputs_.clear();
    for (const std::string &path : all_paths_) {
      std::remove(path.c_str());
    }
    all_paths_.clear();
  }

 private:
  struct Output {
    std::string id;
    std::string rtpp_path;
    std::string index_path;
    std::unique_ptr<RtppWriter> writer;
  };

  static tap_packet_status rtp_payload_tap_packet_cb(
      void *context, packet_info *pinfo, epan_dissect_t * /* edt */,
      const void *data, tap_flags_t /* flags */) {
    static_cast<ExtractionContext *>(context)->onPacket(
        pinfo, static_cast<const struct _rtp_info *>(data));
    return TAP_PACKET_DONT_REDRAW;
  }

  WiresharkSession *session_ = nullptr;
  const RtpExtractionRequest &request_;
  double first_frame_abs_sec_ = 0.0;
  bool registered_ = false;
  bool failed_ = false;
  std::string error_;
  uint64_t truncated_packets_ = 0;
  uint64_t zero_payload_packets_ = 0;
  std::unordered_map<RtpStreamKey, Output, RtpStreamKeyHash> outputs_;
  std::vector<std::string> all_paths_;
};

}  // namespace

RtpExtractionResult extract_rtp_payloads(
    WiresharkSession *session, const std::vector<int> &frames,
    const RtpExtractionRequest &request,
    const std::function<bool(uint32_t, uint32_t)> &progress,
    uint64_t cancel_generation) {
  RtpExtractionResult result;
  if (!session || !session->wth || !session->epan) {
    result.error = "No capture is open.";
    return result;
  }
  if (session->closed.load(std::memory_order_acquire)) {
    result.error = "Capture was closed.";
    return result;
  }

  std::shared_ptr<const RtpScanSnapshot> snapshot;
  {
    std::lock_guard<std::mutex> lock(session->rtp_mutex);
    snapshot = session->rtp_last_scan;
  }
  std::string current_filter;
  {
    std::shared_lock<std::shared_mutex> lock(session->state_mutex);
    current_filter = session->active_filter;
  }
  if (!snapshot ||
      (snapshot->limit_to_display_filter &&
       snapshot->filter_expression != current_filter)) {
    result.error = "staleScan";
    return result;
  }

  double first_frame_abs_sec = 0.0;
  {
    std::unique_lock<std::mutex> lock(session->dissect_mutex);
    DissectedFrame first;
    if (!session->frame_offsets.empty() &&
        dissect_frame(session, 0, FALSE, FALSE, nullptr, first)) {
      first_frame_abs_sec = nstime_to_sec(&first.fd.abs_ts);
    }
  }

  ExtractionContext context(session, request, first_frame_abs_sec);
  std::string error;
  if (!context.registerTap(error)) {
    result.error = error;
    return result;
  }
  if (!context.openFiles(error)) {
    context.removeTap();
    context.cleanupFiles();
    result.error = error;
    return result;
  }

  const uint32_t total_frames = static_cast<uint32_t>(frames.size());
  bool cancelled = false;
  bool session_closed = false;
  for (size_t index = 0; index < frames.size(); ++index) {
    if (session->closed.load(std::memory_order_acquire)) {
      session_closed = true;
      break;
    }
    if (long_operation_cancelled(cancel_generation)) {
      cancelled = true;
      break;
    }

    {
      std::unique_lock<std::mutex> lock(session->dissect_mutex);
      DissectedFrame frame;
      dissect_frame_with_taps(session, frames[index], FALSE, FALSE, nullptr,
                              frame);
    }
    if (context.failed()) break;

    yield_to_interactive_reads(session);
    if (progress &&
        ((index + 1) % 256 == 0 || index + 1 == frames.size())) {
      if (!progress(static_cast<uint32_t>(index + 1), total_frames)) {
        cancelled = true;
        break;
      }
    }
  }

  context.removeTap();
  if (session_closed) {
    context.cleanupFiles();
    result.error = "Capture was closed.";
    return result;
  }
  if (cancelled) {
    context.cleanupFiles();
    result.cancelled = true;
    return result;
  }
  if (context.failed()) {
    context.cleanupFiles();
    result.error = context.error();
    return result;
  }

  if (!context.finalizeOutputs(result, error)) {
    context.cleanupFiles();
    result = RtpExtractionResult{};
    result.error = error;
    return result;
  }

  result.truncated_packets = context.truncatedPackets();
  result.zero_payload_packets = context.zeroPayloadPackets();
  LOGI("extractRtpPayloads: streams=%zu frames=%zu truncated=%llu zero=%llu",
       result.rtpp_paths.size(), frames.size(),
       static_cast<unsigned long long>(result.truncated_packets),
       static_cast<unsigned long long>(result.zero_payload_packets));
  return result;
}

}  // namespace layanalyzer::rtp
