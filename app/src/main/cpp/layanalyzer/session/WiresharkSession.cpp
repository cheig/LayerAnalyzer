// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Session core implementation: summary cache, wiretap record helpers, the
// protocol-inference fallback and the single Wireshark dissection entry point.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/session/WiresharkSession.h"

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

size_t summary_cache_cost(const CachedPacketSummary &summary) {
  return sizeof(CachedPacketSummary) + summary.source.size() +
         summary.destination.size() + summary.protocol.size() +
         summary.info.size();
}

void invalidate_summary_cache(WiresharkSession *session) {
  if (!session) return;
  // Dropping the summaries means the next pass dissects every frame again, so
  // the first-pass bookkeeping has to go with them: otherwise
  // dissect_frame_internal would treat the redissection as a revisit and the
  // cross-frame state (conversations, TCP multi-segment PDUs) that the new
  // settings call for would never be rebuilt. Callers must not already hold
  // dissect_mutex -- every current one runs inside a RuntimeExclusiveGuard or
  // before the session is published, so nothing is dissecting here.
  {
    std::lock_guard<std::mutex> dissect_lock(session->dissect_mutex);
    session->dissected_frames.clear();
  }
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

void reset_dissection_state() {
  // Wireshark keeps conversations, reassembly tables, TCP multi-segment PDUs,
  // stream and expert state in a process-wide "file scope". Only epan_new() and
  // epan_free() set that scope up and tear it down -- the init_dissection() /
  // cleanup_dissection() pair that does the actual work is not exported from the
  // prebuilt library -- so rebuilding the epan handle is the supported way to
  // get the reset. It is the same sequence openFile/closeFile already drive.
  //
  // The scope is entered once and shared, so this only holds together for the
  // single session this app ever has open; with more, one epan_free() too many
  // would leave a scope that was never entered.
  if (g_sessions.size() == 1) {
    WiresharkSession *session = g_sessions.begin()->second.get();
    if (session && session->epan) {
      // Export-object entries point into the file scope, so release them before
      // the scope that backs them goes away.
      {
        std::lock_guard<std::mutex> lock(session->http_objects_mutex);
        clear_http_objects(session);
      }
      // Order matters: epan_free() leaves the scope and epan_new() asserts it is
      // not already entered.
      epan_free(session->epan);
      session->epan = epan_new((struct packet_provider_data *)session,
                               &layanalyzer_provider_funcs);
      if (!session->epan) {
        LOGE("reset_dissection_state: epan_new failed after epan_free");
      }
    }
  }

  for (const auto &entry : g_sessions) {
    WiresharkSession *session = entry.second.get();
    invalidate_summary_cache(session);
    invalidate_scoped_query_cache(session);
    session->rtp_scan_generation.fetch_add(1);
  }
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

static void populate_frame_data(frame_data *fd, int frame_number, int64_t offset,
                                const wtap_rec *rec) {
  memset(fd, 0, sizeof(frame_data));
  fd->num = frame_number;
  fd->pkt_len = rec->rec_header.packet_header.len;
  fd->cap_len = rec->rec_header.packet_header.caplen;
  fd->file_off = offset;
  if (rec->presence_flags & WTAP_HAS_TS) {
    fd->has_ts = 1;
    fd->abs_ts.secs = rec->ts.secs;
    fd->abs_ts.nsecs = static_cast<int>(rec->ts.nsecs);
  }
}

const char *safe_col_text(column_info *cinfo, int format) {
  if (!cinfo || format < 0 || format >= NUM_COL_FMTS) return "";
  const gchar *text = col_get_text(cinfo, format);
  return text ? text : "";
}

static tvbuff_t *new_owned_tvb_from_buffer(Buffer *buffer, guint captured_len,
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

static guint16 read_be16(const guint8 *data, guint offset, guint length) {
  if (!data || offset + 1 >= length) return 0;
  return static_cast<guint16>((data[offset] << 8) | data[offset + 1]);
}

static std::string protocol_from_ip_header(const guint8 *data, guint length,
                                           guint offset) {
  if (!data || offset >= length) return "";
  guint8 version = static_cast<guint8>(data[offset] >> 4);
  if (version == 4) {
    if (offset + 20 > length) return "IPv4";
    switch (data[offset + 9]) {
      case 1: return "ICMP";
      case 6: return "TCP";
      case 17: return "UDP";
      case 132: return "SCTP";
      default: return "IPv4";
    }
  }
  if (version == 6) {
    if (offset + 40 > length) return "IPv6";
    switch (data[offset + 6]) {
      case 6: return "TCP";
      case 17: return "UDP";
      case 58: return "ICMPv6";
      case 132: return "SCTP";
      default: return "IPv6";
    }
  }
  return "";
}

static std::string protocol_from_ethertype(guint16 ethertype, const guint8 *data,
                                           guint length, guint payloadOffset) {
  switch (ethertype) {
    case 0x0800: return protocol_from_ip_header(data, length, payloadOffset);
    case 0x86DD: return protocol_from_ip_header(data, length, payloadOffset);
    case 0x0806: return "ARP";
    case 0x8035: return "RARP";
    case 0x8100:
    case 0x88A8:
    case 0x9100:
      if (payloadOffset + 4 <= length) {
        guint16 innerType = read_be16(data, payloadOffset + 2, length);
        return protocol_from_ethertype(innerType, data, length, payloadOffset + 4);
      }
      return "VLAN";
    default:
      return "";
  }
}

std::string infer_protocol_from_packet(int encap, Buffer *buffer,
                                       guint capturedLen) {
  if (!buffer || !buffer->data || buffer->allocated < buffer->start) return "";
  guint available = static_cast<guint>(buffer->allocated - buffer->start);
  guint length = std::min(capturedLen, available);
  const guint8 *data = ws_buffer_start_ptr(buffer);
  if (!data || length == 0) return "";

  switch (encap) {
    case WTAP_ENCAP_ETHERNET:
      if (length >= 14) {
        return protocol_from_ethertype(read_be16(data, 12, length), data, length, 14);
      }
      break;
    case WTAP_ENCAP_SLL:
      if (length >= 16) {
        guint16 protocol = read_be16(data, 14, length);
        if (protocol == 0x0003 && length >= 30) {
          return protocol_from_ethertype(read_be16(data, 28, length), data, length, 30);
        }
        return protocol_from_ethertype(protocol, data, length, 16);
      }
      break;
    case WTAP_ENCAP_RAW_IP:
      return protocol_from_ip_header(data, length, 0);
    default:
      return protocol_from_ip_header(data, length, 0);
  }
  return "";
}

static void setup_summary_columns(column_info *cinfo, epan_t *epan,
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
static bool run_epan_dissect_safely(epan_dissect_t *edt,
                                    int file_type_subtype, wtap_rec *rec,
                                    tvbuff_t *tvb, frame_data *fd,
                                    column_info *cinfo, int frame_number,
                                    const char *operation, bool with_taps) {
  if (!edt || !rec || !tvb || !fd) return false;

  bool succeeded = false;
  TRY {
    if (with_taps) {
      // epan_dissect_run() 不会触发 tap（reference/.../epan/epan.c:616-646），必须
      // 走 with_taps 变体。epan_dissect_run_with_taps() 内部就是
      // tap_queue_init() + dissect_record() + tap_push_tapped_queue()（同文件
      // 632-646 行），所以这里不能再手写那两个调用：
      // prebuilt libwireshark.so 只导出 epan_dissect_run_with_taps，
      // tap_queue_init / tap_push_tapped_queue 在 4.0.10 里是 extern（非
      // WS_DLL_PUBLIC），链接会失败。异常路径由 TRY 边界包住，不会推队列。
      epan_dissect_run_with_taps(edt, file_type_subtype, rec, tvb, fd, cinfo);
    } else {
      epan_dissect_run(edt, file_type_subtype, rec, tvb, fd, cinfo);
    }
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

int visible_frame_count(WiresharkSession *session) {
  if (!session) {
    return 0;
  }
  std::shared_lock<std::shared_mutex> state_lock(session->state_mutex);
  return session->active_filter.empty()
             ? static_cast<int>(session->frame_offsets.size())
             : static_cast<int>(session->filtered_frames.size());
}

static int visible_frame_count_locked(WiresharkSession *session) {
  if (!session) return 0;
  return session->active_filter.empty()
             ? static_cast<int>(session->frame_offsets.size())
             : static_cast<int>(session->filtered_frames.size());
}

static int resolve_visible_frame_index(WiresharkSession *session, int visibleIndex) {
  if (!session) {
    return -1;
  }
  std::shared_lock<std::shared_mutex> state_lock(session->state_mutex);
  if (!session->active_filter.empty()) {
    if (visibleIndex < 0 || visibleIndex >= (int)session->filtered_frames.size()) {
      return -1;
    }
    return session->filtered_frames[visibleIndex];
  }
  if (visibleIndex < 0 || visibleIndex >= (int)session->frame_offsets.size()) {
    return -1;
  }
  return visibleIndex;
}

std::vector<int> snapshot_visible_frames(WiresharkSession *session) {
  std::vector<int> frames;
  if (!session) return frames;
  std::shared_lock<std::shared_mutex> state_lock(session->state_mutex);
  if (!session->active_filter.empty()) return session->filtered_frames;
  frames.reserve(session->frame_offsets.size());
  for (int i = 0; i < static_cast<int>(session->frame_offsets.size()); ++i) {
    frames.push_back(i);
  }
  return frames;
}

// Return one visible frame without materialising the complete visible set.
// This is the hot path for PagingSource requests: an unfiltered capture can
// contain millions of frames while a page usually contains fewer than 100.
int visible_frame_at(WiresharkSession *session, int visibleIndex) {
  if (!session || visibleIndex < 0) return -1;
  std::shared_lock<std::shared_mutex> state_lock(session->state_mutex);
  if (session->active_filter.empty()) {
    return visibleIndex < static_cast<int>(session->frame_offsets.size())
               ? visibleIndex
               : -1;
  }
  return visibleIndex < static_cast<int>(session->filtered_frames.size())
             ? session->filtered_frames[visibleIndex]
             : -1;
}

// dissect_frame 与 dissect_frame_with_taps 共用的实现。with_taps 决定是否走
// tap（tap_queue_init + epan_dissect_run_with_taps + tap_push_tapped_queue）；
// 其余步骤（wtap_seek_read、prepare_packet_record、populate_frame_data、
// new_owned_tvb_from_buffer、epan_dissect_new、prime filter、列）完全一致。
// 拆成带参数的静态实现而不是复制两份：with_taps == false 时执行的是与改动前
// 逐字相同的代码，保证 dissect_frame 的对外行为不变。
static bool dissect_frame_internal(WiresharkSession *session, int frameIdx,
                                   bool createTree, bool setupColumns,
                                   dfilter_t *primeFilter, DissectedFrame &out,
                                   bool with_taps, int *errOut,
                                   gchar **errInfoOut) {
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
  // Size the first-pass bookkeeping on first use; invalidate_summary_cache
  // empties it again whenever the dissection settings change.
  if (session->dissected_frames.size() != session->frame_offsets.size()) {
    session->dissected_frames.assign(session->frame_offsets.size(), 0);
  }
  out.fd.visited = session->dissected_frames[frameIdx] ? 1 : 0;
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
  const bool dissected = run_epan_dissect_safely(
      out.edt, session->file_type, &out.rec, tvb, &out.fd,
      setupColumns ? &out.cinfo : nullptr, frameIdx + 1,
      with_taps ? "dissect_frame_with_taps" : "dissect_frame", with_taps);
  // Recorded even when the dissection was rejected: the frame has been through
  // the dissectors once, so later attempts belong on the revisit path rather
  // than rebuilding cross-frame state on top of a half-written pass.
  session->dissected_frames[frameIdx] = 1;
  if (!dissected) return false;
  if (setupColumns) {
    col_fill_in(&out.edt->pi, FALSE, TRUE);
  }
  return true;
}

bool dissect_frame(WiresharkSession *session, int frameIdx,
                   bool createTree, bool setupColumns,
                   dfilter_t *primeFilter, DissectedFrame &out,
                   int *errOut, gchar **errInfoOut) {
  return dissect_frame_internal(session, frameIdx, createTree, setupColumns,
                                primeFilter, out, /*with_taps=*/false, errOut,
                                errInfoOut);
}

bool dissect_frame_with_taps(WiresharkSession *session, int frameIdx,
                             bool createTree, bool setupColumns,
                             dfilter_t *primeFilter, DissectedFrame &out) {
  return dissect_frame_internal(session, frameIdx, createTree, setupColumns,
                                primeFilter, out, /*with_taps=*/true, nullptr,
                                nullptr);
}
