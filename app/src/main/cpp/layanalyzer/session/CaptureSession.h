// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#pragma once

// CaptureSession: the WiresharkSession state object, the summary/scoped-query
// caches, and the single dissection path (dissect_frame) every JNI feature
// goes through.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/runtime/SessionRegistry.h"

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
  int file_type = 0;
  int file_encap = WTAP_ENCAP_UNKNOWN;
  std::vector<int64_t> frame_offsets;
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
  // Background scans wait here instead of polling/sleeping while an
  // interactive read is active.  The dissection mutex remains the single
  // serialization boundary for a session's epan_t.
  std::mutex interactive_mutex;
  std::condition_variable interactive_cv;
  mutable std::shared_mutex state_mutex;

  ~WiresharkSession();
};

// Marks the session as serving an interactive read so background scans can
// yield between frames.
class InteractiveReadGuard {
 public:
  explicit InteractiveReadGuard(WiresharkSession *session);
  ~InteractiveReadGuard();
  InteractiveReadGuard(const InteractiveReadGuard &) = delete;
  InteractiveReadGuard &operator=(const InteractiveReadGuard &) = delete;

 private:
  WiresharkSession *session_;
};

// Background scans wait here while an interactive read is active.
void yield_to_interactive_reads(WiresharkSession *session);

// Frees and clears the cached export_object entries.
void clear_http_objects(WiresharkSession *session);

void invalidate_summary_cache(WiresharkSession *session);
void invalidate_scoped_query_cache(WiresharkSession *session);

bool load_cached_packet_summary(WiresharkSession *session, int frameIdx,
                                CachedPacketSummary &summary,
                                bool record_stats = true);
void store_cached_packet_summary(WiresharkSession *session, int frameIdx,
                                 const CachedPacketSummary &summary);

size_t summary_cache_cost(const CachedPacketSummary &summary);

// Dissects one frame through the session's single epan executor.  Holds no
// lock itself: callers take session->dissect_mutex for the duration.
bool dissect_frame(WiresharkSession *session, int frameIdx, bool createTree,
                   bool setupColumns, dfilter_t *primeFilter,
                   DissectedFrame &out, int *errOut = nullptr,
                   gchar **errInfoOut = nullptr);

// RAII wiretap record + buffer pair for indexing and byte reads.
struct FrameRead {
  wtap_rec rec;
  Buffer buf;

  FrameRead();
  ~FrameRead();
  FrameRead(const FrameRead &) = delete;
  FrameRead &operator=(const FrameRead &) = delete;

  void reset() { wtap_rec_reset(&rec); }
};

// A frame positioned for dissection: record, buffer, frame_data, columns and
// the owned epan_dissect_t.  Destroyed before the caller releases
// dissect_mutex so packet-scope memory never outlives the executor.
struct DissectedFrame {
  wtap_rec rec;
  Buffer buf;
  frame_data fd;
  column_info cinfo;
  epan_dissect_t *edt = nullptr;
  bool has_columns = false;

  DissectedFrame();
  ~DissectedFrame();
  DissectedFrame(const DissectedFrame &) = delete;
  DissectedFrame &operator=(const DissectedFrame &) = delete;
};

void prepare_packet_record(wtap *wth, wtap_rec *rec);
void populate_frame_data(frame_data *fd, int frame_number, int64_t offset,
                         const wtap_rec *rec);
const char *safe_col_text(column_info *cinfo, int format);
tvbuff_t *new_owned_tvb_from_buffer(Buffer *buffer, guint captured_len,
                                    gint reported_len);
guint packet_data_length(const wtap_rec *rec, Buffer *buffer);

// Column setup used by summary dissection.
void setup_summary_columns(column_info *cinfo, epan_t *epan,
                           bool resolveNames);

// Wireshark dissector errors are exceptions, not C++ exceptions.  Keep the
// TRY/CATCH boundary in one place so a malformed frame is a per-frame
// failure instead of a process abort.
bool run_epan_dissect_safely(epan_dissect_t *edt, int file_type_subtype,
                             wtap_rec *rec, tvbuff_t *tvb, frame_data *fd,
                             column_info *cinfo, int frame_number,
                             const char *operation);
