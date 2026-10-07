// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// CaptureSession implementation: session state, cache bookkeeping, wiretap
// record/buffer RAII and the single per-frame dissection path.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/session/CaptureSession.h"

WiresharkSession::~WiresharkSession() {
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

InteractiveReadGuard::InteractiveReadGuard(WiresharkSession *session)
    : session_(session) {
  session_->interactive_reads.fetch_add(1, std::memory_order_acq_rel);
}

InteractiveReadGuard::~InteractiveReadGuard() {
  session_->interactive_reads.fetch_sub(1, std::memory_order_acq_rel);
  session_->interactive_cv.notify_all();
}

void yield_to_interactive_reads(WiresharkSession *session) {
  if (!session) return;
  std::unique_lock<std::mutex> wait_lock(session->interactive_mutex);
  session->interactive_cv.wait(wait_lock, [session] {
    return session->interactive_reads.load(std::memory_order_acquire) == 0;
  });
  std::this_thread::yield();
}

void clear_http_objects(WiresharkSession *session) {
  if (!session) return;
  for (export_object_entry_t *entry : session->http_objects) {
    eo_free_entry(entry);
  }
  session->http_objects.clear();
}

void invalidate_summary_cache(WiresharkSession *session) {
  if (!session) return;
  std::lock_guard<std::mutex> cache_lock(session->summary_cache_mutex);
  session->summary_cache.clear();
  session->summary_cache_lru.clear();
  session->summary_cache_lru_index.clear();
  session->summary_cache_bytes = 0;
  session->summary_cache_hits = 0;
  session->summary_cache_misses = 0;
  session->summary_cache_evictions = 0;
}

void invalidate_scoped_query_cache(WiresharkSession *session) {
  if (!session) return;
  std::lock_guard<std::mutex> lock(session->scoped_query_cache_mutex);
  session->scoped_query_cache_filter.clear();
  session->scoped_query_cache_visibility_generation = 0;
  session->scoped_query_cache_matches.reset();
}

size_t summary_cache_cost(const CachedPacketSummary &summary) {
  return sizeof(CachedPacketSummary) + summary.source.size() +
         summary.destination.size() + summary.protocol.size() +
         summary.info.size();
}

/** Cache access is independent from session state; it never holds state_mutex
 * while doing LRU work, dissection, or string copies. */
bool load_cached_packet_summary(WiresharkSession *session, int frameIdx,
                                CachedPacketSummary &summary,
                                bool record_stats) {
  if (!session || frameIdx < 0) return false;
  std::lock_guard<std::mutex> cache_lock(session->summary_cache_mutex);
  auto found = session->summary_cache.find(frameIdx);
  if (found == session->summary_cache.end() || !found->second.valid) {
    if (record_stats) session->summary_cache_misses++;
    return false;
  }
  summary = found->second;
  auto lru_it = session->summary_cache_lru_index.find(frameIdx);
  if (lru_it != session->summary_cache_lru_index.end()) {
    session->summary_cache_lru.splice(session->summary_cache_lru.end(),
                                      session->summary_cache_lru,
                                      lru_it->second);
    lru_it->second = std::prev(session->summary_cache_lru.end());
  } else {
    session->summary_cache_lru.push_back(frameIdx);
    session->summary_cache_lru_index[frameIdx] =
        std::prev(session->summary_cache_lru.end());
  }
  if (record_stats) session->summary_cache_hits++;
  return true;
}

void store_cached_packet_summary(WiresharkSession *session, int frameIdx,
                                 const CachedPacketSummary &summary) {
  if (!session || frameIdx < 0 || !summary.valid) return;
  std::lock_guard<std::mutex> cache_lock(session->summary_cache_mutex);

  auto found = session->summary_cache.find(frameIdx);
  if (found != session->summary_cache.end()) {
    session->summary_cache_bytes -= summary_cache_cost(found->second);
    auto lru_it = session->summary_cache_lru_index.find(frameIdx);
    if (lru_it != session->summary_cache_lru_index.end()) {
      session->summary_cache_lru.erase(lru_it->second);
      session->summary_cache_lru_index.erase(lru_it);
    }
    session->summary_cache.erase(found);
  }
  session->summary_cache.emplace(frameIdx, summary);
  session->summary_cache_lru.push_back(frameIdx);
  session->summary_cache_lru_index[frameIdx] =
      std::prev(session->summary_cache_lru.end());
  session->summary_cache_bytes += summary_cache_cost(summary);

  while (session->summary_cache.size() > WiresharkSession::kSummaryCacheMaxEntries ||
         session->summary_cache_bytes > WiresharkSession::kSummaryCacheMaxBytes) {
    if (session->summary_cache_lru.empty()) break;
    const int evict_index = session->summary_cache_lru.front();
    session->summary_cache_lru.pop_front();
    session->summary_cache_lru_index.erase(evict_index);
    auto evicted = session->summary_cache.find(evict_index);
    if (evicted != session->summary_cache.end()) {
      session->summary_cache_bytes -= summary_cache_cost(evicted->second);
      session->summary_cache.erase(evicted);
      ++session->summary_cache_evictions;
    }
  }
}

void prepare_packet_record(wtap *wth, wtap_rec *rec) {
  if (!wth || !rec || rec->rec_type != REC_TYPE_PACKET) {
    return;
  }

  int file_encap = wtap_file_encap(wth);
  int &pkt_encap = rec->rec_header.packet_header.pkt_encap;
  if ((pkt_encap == WTAP_ENCAP_UNKNOWN || pkt_encap == WTAP_ENCAP_PER_PACKET) &&
      file_encap != WTAP_ENCAP_PER_PACKET) {
    pkt_encap = file_encap;
  }

  guint32 &len = rec->rec_header.packet_header.len;
  guint32 caplen = rec->rec_header.packet_header.caplen;
  if (len < caplen) {
    LOGW("Packet reported length %u is smaller than captured length %u; using captured length",
         len, caplen);
    len = caplen;
  }
}

void populate_frame_data(frame_data *fd, int frame_number, int64_t offset,
                         const wtap_rec *rec) {
  memset(fd, 0, sizeof(frame_data));
  fd->num = frame_number;
  fd->pkt_len = rec->rec_header.packet_header.len;
  fd->cap_len = rec->rec_header.packet_header.caplen;
  fd->file_off = offset;
  if (rec->presence_flags & WTAP_HAS_TS) {
    fd->abs_ts.secs = rec->ts.secs;
    fd->abs_ts.nsecs = static_cast<int>(rec->ts.nsecs);
  }
}

const char *safe_col_text(column_info *cinfo, int format) {
  if (!cinfo || format < 0 || format >= NUM_COL_FMTS) return "";
  const gchar *text = col_get_text(cinfo, format);
  return text ? text : "";
}

FrameRead::FrameRead() {
  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1500);
}

FrameRead::~FrameRead() {
  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
}

tvbuff_t *new_owned_tvb_from_buffer(Buffer *buffer, guint captured_len,
                                    gint reported_len) {
  guint available = 0;
  if (buffer && buffer->data && buffer->allocated >= buffer->start) {
    available = static_cast<guint>(buffer->allocated - buffer->start);
  }
  guint length = std::min(captured_len, available);
  if (captured_len > available) {
    LOGW("Packet captured length %u exceeds buffer capacity %u; using capacity",
         captured_len, available);
  }

  guint8 *data = nullptr;
  if (length > 0) {
    data = static_cast<guint8 *>(g_malloc(length));
    memcpy(data, ws_buffer_start_ptr(buffer), length);
  }

  tvbuff_t *tvb = tvb_new_real_data(data, length, reported_len);
  tvb_set_free_cb(tvb, g_free);
  return tvb;
}

guint packet_data_length(const wtap_rec *rec, Buffer *buffer) {
  if (!rec || rec->rec_type != REC_TYPE_PACKET) {
    return buffer ? static_cast<guint>(ws_buffer_length(buffer)) : 0;
  }
  guint captured_len = rec->rec_header.packet_header.caplen;
  guint available = 0;
  if (buffer && buffer->data && buffer->allocated >= buffer->start) {
    available = static_cast<guint>(buffer->allocated - buffer->start);
  }
  if (captured_len > available) {
    LOGW("Packet captured length %u exceeds buffer capacity %u; using capacity",
         captured_len, available);
  }
  return std::min(captured_len, available);
}

void setup_summary_columns(column_info *cinfo, epan_t *epan,
                           bool resolveNames) {
  memset(cinfo, 0, sizeof(column_info));
  col_setup(cinfo, 7);
  cinfo->columns[0].col_fmt = COL_NUMBER;
  cinfo->columns[1].col_fmt = COL_REL_TIME;
  cinfo->columns[2].col_fmt = resolveNames ? COL_RES_SRC : COL_UNRES_SRC;
  cinfo->columns[3].col_fmt = resolveNames ? COL_RES_DST : COL_UNRES_DST;
  cinfo->columns[4].col_fmt = COL_PROTOCOL;
  cinfo->columns[5].col_fmt = COL_PACKET_LENGTH;
  cinfo->columns[6].col_fmt = COL_INFO;
  for (int i = 0; i < cinfo->num_cols; ++i) {
    cinfo->columns[i].col_title = g_strdup("");
    cinfo->columns[i].col_custom_fields = nullptr;
    cinfo->columns[i].col_custom_occurrence = 0;
    cinfo->columns[i].col_custom_dfilter = nullptr;
    cinfo->columns[i].col_fence = 0;
  }
  col_finalize(cinfo);
  cinfo->epan = epan;
}

/**
 * Dissector errors are Wireshark exceptions, not C++ exceptions. A caller
 * that reaches epan_dissect_run without a TRY/ENDTRY boundary invokes
 * Wireshark's unhandled catcher, which aborts the process. Keep that boundary
 * in one place so every JNI read path can treat a malformed frame as a
 * per-frame failure instead of a process failure.
 */
bool run_epan_dissect_safely(epan_dissect_t *edt,
                             int file_type_subtype, wtap_rec *rec,
                             tvbuff_t *tvb, frame_data *fd,
                             column_info *cinfo, int frame_number,
                             const char *operation) {
  if (!edt || !rec || !tvb || !fd) return false;

  bool succeeded = false;
  TRY {
    epan_dissect_run(edt, file_type_subtype, rec, tvb, fd, cinfo);
    succeeded = true;
  }
  CATCH_BOUNDS_AND_DISSECTOR_ERRORS {
    const unsigned long code = EXCEPT_CODE;
    const char *message = GET_MESSAGE;
    LOGW("Wireshark rejected frame %d in %s: code=%lu message=%s",
         frame_number, operation ? operation : "dissection", code,
         message ? message : "none");
  }
  CATCH_ALL {
    const unsigned long code = EXCEPT_CODE;
    const char *message = GET_MESSAGE;
    LOGW("Wireshark exception while dissecting frame %d in %s: code=%lu message=%s",
         frame_number, operation ? operation : "dissection", code,
         message ? message : "none");
  }
  ENDTRY;

  return succeeded;
}

DissectedFrame::DissectedFrame() {
  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1500);
  memset(&fd, 0, sizeof(frame_data));
  memset(&cinfo, 0, sizeof(column_info));
}

DissectedFrame::~DissectedFrame() {
  if (has_columns) {
    col_cleanup(&cinfo);
  }
  if (edt) {
    epan_dissect_free(edt);
  }
  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
}

bool dissect_frame(WiresharkSession *session, int frameIdx,
                   bool createTree, bool setupColumns,
                   dfilter_t *primeFilter, DissectedFrame &out,
                   int *errOut, gchar **errInfoOut) {
  if (!session || !session->wth || !session->epan || frameIdx < 0 ||
      frameIdx >= (int)session->frame_offsets.size()) {
    return false;
  }

  int err = 0;
  gchar *err_info = nullptr;
  int64_t offset = session->frame_offsets[frameIdx];
  if (!wtap_seek_read(session->wth, offset, &out.rec, &out.buf, &err, &err_info)) {
    if (errOut) *errOut = err;
    if (errInfoOut) {
      *errInfoOut = err_info;
    } else {
      g_free(err_info);
    }
    return false;
  }

  prepare_packet_record(session->wth, &out.rec);
  populate_frame_data(&out.fd, frameIdx + 1, offset, &out.rec);
  tvbuff_t *tvb = new_owned_tvb_from_buffer(&out.buf, out.fd.cap_len,
                                            out.fd.pkt_len);
  out.edt = epan_dissect_new(session->epan, createTree, createTree);
  if (!out.edt) {
    return false;
  }
  if (primeFilter) {
    epan_dissect_prime_with_dfilter(out.edt, primeFilter);
  }
  if (setupColumns) {
    setup_summary_columns(&out.cinfo, session->epan,
                          session->name_resolution_enabled);
    out.has_columns = true;
  }
  if (!run_epan_dissect_safely(
          out.edt, session->file_type, &out.rec, tvb, &out.fd,
          setupColumns ? &out.cinfo : nullptr, frameIdx + 1, "dissect_frame")) {
    return false;
  }
  if (setupColumns) {
    col_fill_in(&out.edt->pi, FALSE, TRUE);
  }
  return true;
}
