// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Session state and the single Wireshark dissection entry point shared by all
// legacy JNI modules. The types here were file-local in the former single
// translation unit; they are exposed in this header so each module can compile
// as its own translation unit with unchanged behaviour.
#pragma once
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/rtp/RtpMediaSnapshot.h"
#include "layanalyzer/rtp/RtpScanSnapshot.h"
#include "layanalyzer/rtp/core/RtpPayloadOverrides.h"

using layanalyzer::rtp::RtpMediaSnapshot;
using layanalyzer::rtp::RtpPayloadOverrides;
using layanalyzer::rtp::RtpScanSnapshot;

struct CachedPacketSummary {
  bool valid = false;
  double timestamp = 0.0;
  std::string source;
  std::string destination;
  std::string protocol;
  int length = 0;
  int source_port = -1;
  int destination_port = -1;
  std::string info;
};

struct WiresharkSession {
  wtap *wth = nullptr;                // Wiretap handle
  // Set by closeFile before the handle is removed from the registry.
  // Active long operations retain a shared_ptr, so this is their signal
  // that no result may be published after the session was closed.
  std::atomic<bool> closed{false};
  int file_type = 0;
  int file_encap = WTAP_ENCAP_UNKNOWN;
  std::vector<int64_t> frame_offsets;
  // Frames that have already had a first-pass dissection, indexed like
  // frame_offsets.  Wireshark builds cross-frame state -- conversations,
  // reassembly tables and the TCP multi-segment PDUs behind desegmentation --
  // only while `pinfo->fd->visited` is false, and it expects each frame to go
  // through that once.  Every dissection here used to create a fresh
  // frame_data (visited == 0), so each of the app's many passes over the same
  // frames ran as another first pass and kept re-writing that state; the
  // visible damage was TCP continuations being mistaken for retransmissions
  // and multi-segment PDUs never completing (so e.g. SIP over TCP never
  // reassembled).  Marking a frame once dissected keeps later passes -- the
  // ones that actually build the protocol tree and columns -- on the
  // "revisit" path, which is also the path a real Wireshark display uses.
  //
  // Accessed only from dissect_frame_internal and invalidate_summary_cache,
  // both of which honour the dissect_mutex contract documented below.
  std::vector<uint8_t> dissected_frames;
  // Sparse, bounded cache: allocating one CachedPacketSummary per frame made
  // a million-frame capture consume hundreds of MB before the first page.
  std::unordered_map<int, CachedPacketSummary> summary_cache;
  std::list<int> summary_cache_lru;
  // Iterator index avoids list::remove()'s O(n) walk on every page hit.
  std::unordered_map<int, std::list<int>::iterator> summary_cache_lru_index;
  size_t summary_cache_bytes = 0;
  uint64_t summary_cache_hits = 0;
  uint64_t summary_cache_misses = 0;
  uint64_t summary_cache_evictions = 0;
  std::mutex summary_cache_mutex;
  static constexpr size_t kSummaryCacheMaxEntries = 8192;
  static constexpr size_t kSummaryCacheMaxBytes = 16 * 1024 * 1024;
  std::vector<int> filtered_frames;
  std::string active_filter;
  std::string filter_error;
  // One-entry scoped-query cache. Paging the same temporary display filter
  // must not re-dissect the complete capture for every requested page.
  std::string scoped_query_cache_filter;
  uint64_t scoped_query_cache_visibility_generation = 0;
  std::shared_ptr<const std::vector<int>> scoped_query_cache_matches;
  std::mutex scoped_query_cache_mutex;
  // Keep analysis offline by default. The UI exposes an explicit opt-in for
  // DNS/hostname lookups, which may consult the configured network.
  bool name_resolution_enabled = false;
  epan_t *epan = nullptr;             // Wireshark Protocol Analyzer session
  std::vector<export_object_entry_t *> http_objects;
  std::atomic<uint64_t> filter_request_generation{0};
  std::atomic<uint64_t> search_request_generation{0};
  std::atomic<int> interactive_reads{0};
  // Wireshark's wtap/epan objects are not safe for concurrent dissection.
  // Long operations take this mutex one frame at a time so paging can run
  // between frames. State that does not touch epan uses the read/write lock.
  std::mutex dissect_mutex;
  std::mutex http_objects_mutex;
  // RTP 扫描代际与快照（RTP1-NAT-04）。每次 scanRtpStreams / 后续的
  // setRtpHeuristicEnabled、Decode As 变更、setRtpPayloadOverrides 都会让
  // rtp_scan_generation 自增；M2 的入口据此拒绝过期快照。
  std::atomic<uint64_t> rtp_scan_generation{0};
  std::mutex rtp_mutex;  // 保护下面两个字段（rtp_last_scan / rtp_overrides）
  std::shared_ptr<const RtpScanSnapshot> rtp_last_scan;  // layanalyzer/rtp/RtpScanSnapshot.h
  // 会话级负载类型覆盖表（RTP1-NAT-06，定义在 layanalyzer/rtp/core/RtpPayloadOverrides.h）。
  // 由 setRtpPayloadOverrides 整体替换，scanRtpStreams 在 rtp_mutex 下取一份快照使用。
  RtpPayloadOverrides rtp_overrides;
  // M2 解码成功后的流 id -> key/media 元数据；由 NAT-06 发布。
  std::mutex rtp_media_mutex;  // 保护 rtp_last_media
  std::shared_ptr<const RtpMediaSnapshot> rtp_last_media;
  // Background scans wait here instead of polling/sleeping while an
  // interactive read is active.  The dissection mutex remains the single
  // serialization boundary for a session's epan_t.
  std::mutex interactive_mutex;
  std::condition_variable interactive_cv;
  mutable std::shared_mutex state_mutex;

  ~WiresharkSession() {
    for (export_object_entry_t *entry : http_objects) {
      eo_free_entry(entry);
    }
    http_objects.clear();
    if (epan) {
      epan_free(epan);
      epan = nullptr;
    }
    if (wth) {
      wtap_close(wth);
      wth = nullptr;
    }
  }
};

class InteractiveReadGuard {
 public:
  explicit InteractiveReadGuard(WiresharkSession *session) : session_(session) {
    session_->interactive_reads.fetch_add(1, std::memory_order_acq_rel);
  }

  ~InteractiveReadGuard() {
    session_->interactive_reads.fetch_sub(1, std::memory_order_acq_rel);
    session_->interactive_cv.notify_all();
  }

  InteractiveReadGuard(const InteractiveReadGuard &) = delete;
  InteractiveReadGuard &operator=(const InteractiveReadGuard &) = delete;

 private:
  WiresharkSession *session_;
};

// A lease keeps a session alive after it has been removed from g_sessions.
// Long-running JNI calls must not hold g_native_mutex for their entire scan:
// closeFile() should be able to detach a handle immediately while the active
// operation drains safely.  Engine cleanup uses the same counter to wait for
// all leases before calling epan_cleanup().
class SessionLease {
 public:
  SessionLease() = default;
  explicit SessionLease(std::shared_ptr<WiresharkSession> session)
      : session_(std::move(session)) {}
  SessionLease(const SessionLease &) = delete;
  SessionLease &operator=(const SessionLease &) = delete;
  SessionLease(SessionLease &&other) noexcept
      : session_(std::move(other.session_)), counted_(other.counted_) {
    other.counted_ = false;
  }
  SessionLease &operator=(SessionLease &&other) noexcept {
    if (this == &other) return *this;
    release();
    session_ = std::move(other.session_);
    counted_ = other.counted_;
    other.counted_ = false;
    return *this;
  }
  ~SessionLease() { release(); }

  WiresharkSession *get() const { return session_.get(); }
  WiresharkSession *operator->() const { return session_.get(); }
  explicit operator bool() const { return session_ != nullptr; }
  bool active() const { return counted_; }
  operator WiresharkSession *() const { return session_.get(); }
  void mark_counted() { counted_ = true; }

 private:
  void release() {
    if (!counted_) return;
    counted_ = false;
    {
      std::lock_guard<std::mutex> lock(g_lease_mutex);
      if (g_active_session_leases > 0) --g_active_session_leases;
    }
    g_lease_cv.notify_all();
  }

  std::shared_ptr<WiresharkSession> session_;
  bool counted_ = false;
};

// Process-wide Wireshark settings (name resolution and Decode As) cannot be
// changed while any session is dissecting.  This guard blocks new leases,
// waits for existing ones to finish, and serializes the update with the
// registry.  It is intentionally short-lived and must never wrap a full scan.
class RuntimeExclusiveGuard {
 public:
  RuntimeExclusiveGuard()
      : runtime_lock_(g_runtime_exclusive_mutex) {
    {
      std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
      g_engine_shutting_down = true;
    }
    std::unique_lock<std::mutex> lease_lock(g_lease_mutex);
    g_lease_cv.wait(lease_lock,
                    [] { return g_active_session_leases == 0; });
    // Acquire the registry only after all activities have drained. Taking it
    // first would deadlock with openFile's final publication step: openFile
    // still owns an activity lease while waiting to publish its Session.
    registry_lock_ = std::unique_lock<std::shared_mutex>(g_native_mutex);
  }

  RuntimeExclusiveGuard(const RuntimeExclusiveGuard &) = delete;
  RuntimeExclusiveGuard &operator=(const RuntimeExclusiveGuard &) = delete;

  ~RuntimeExclusiveGuard() {
    {
      std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
      g_engine_shutting_down = false;
    }
    registry_lock_.unlock();
  }

 private:
  std::unique_lock<std::mutex> runtime_lock_;
  std::unique_lock<std::shared_mutex> registry_lock_;
};

struct FrameRead {
  wtap_rec rec;
  Buffer buf;

  FrameRead() {
    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1500);
  }

  ~FrameRead() {
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);
  }

  void reset() {
    wtap_rec_reset(&rec);
  }
};

struct DissectedFrame {
  wtap_rec rec;
  Buffer buf;
  frame_data fd;
  column_info cinfo;
  epan_dissect_t *edt = nullptr;
  bool has_columns = false;

  DissectedFrame() {
    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1500);
    memset(&fd, 0, sizeof(frame_data));
    memset(&cinfo, 0, sizeof(column_info));
  }

  ~DissectedFrame() {
    if (has_columns) {
      col_cleanup(&cinfo);
    }
    if (edt) {
      epan_dissect_free(edt);
    }
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);
  }
};

void yield_to_interactive_reads(WiresharkSession *session);
void clear_http_objects(WiresharkSession *session);

size_t summary_cache_cost(const CachedPacketSummary &summary);
void invalidate_summary_cache(WiresharkSession *session);
void invalidate_scoped_query_cache(WiresharkSession *session);

// Drops every open session's cached dissections *and* Wireshark's process-wide
// cross-frame dissection state (conversations, reassembly tables, TCP
// multi-segment PDUs, stream and expert state), so the next pass rebuilds all
// of it under the new settings. Call this -- not invalidate_summary_cache
// alone -- whenever a setting that changes how frames are dissected is
// applied (Decode As, ESP decryption, the RTP heuristics).
//
// Only the caches go stale on their own; the cross-frame state does not, and
// re-dissecting frames on top of it leaves segments of an existing stream
// misclassified as retransmissions, which stops multi-segment PDUs from ever
// completing. This is the reset Wireshark itself performs between captures.
//
// Must be called inside a RuntimeExclusiveGuard: it frees file-scope memory no
// session may still be dissecting against.
void reset_dissection_state();
bool load_cached_packet_summary(WiresharkSession *session, int frameIdx,
                                CachedPacketSummary &summary,
                                bool record_stats = true);
void store_cached_packet_summary(WiresharkSession *session, int frameIdx,
                                 const CachedPacketSummary &summary);

void prepare_packet_record(wtap *wth, wtap_rec *rec);
guint packet_data_length(const wtap_rec *rec, Buffer *buffer);
const char *safe_col_text(column_info *cinfo, int format);
std::string infer_protocol_from_packet(int encap, Buffer *buffer,
                                       guint capturedLen);

int visible_frame_count(WiresharkSession *session);
std::vector<int> snapshot_visible_frames(WiresharkSession *session);
int visible_frame_at(WiresharkSession *session, int visibleIndex);

/**
 * The one dissection entry used by every read path. Callers that need
 * serialized access must already hold session->dissect_mutex; dissect_frame
 * itself only performs the seek/read/dissect work.
 */
bool dissect_frame(WiresharkSession *session, int frameIdx,
                   bool createTree, bool setupColumns,
                   dfilter_t *primeFilter, DissectedFrame &out,
                   int *errOut = nullptr, gchar **errInfoOut = nullptr);

/**
 * dissect_frame 的 tap 版本：先 tap_queue_init、解析后再 tap_push_tapped_queue。
 * 与 dissect_frame 一样，调用方必须已持有 session->dissect_mutex。
 * 原因：epan_dissect_run 不会触发 tap（reference/.../epan/epan.c:616-646）。
 */
bool dissect_frame_with_taps(WiresharkSession *session, int frameIdx,
                             bool createTree, bool setupColumns,
                             dfilter_t *primeFilter, DissectedFrame &out);
