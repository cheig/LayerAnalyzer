// Display filter service: scoped temporary queries, filter validation and
// committing a filter to the session's visible set.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/runtime/EngineRuntime.h"
#include "layanalyzer/runtime/SessionRegistry.h"
#include "layanalyzer/session/CaptureSession.h"
#include "layanalyzer/projection/FieldReader.h"
#include "layanalyzer/query/QuerySupport.h"

/**
 * Query summaries against a temporary filter without touching the session's
 * active_filter, filtered_frames or filter_request_generation.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_queryPacketSummaries(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring jFilter,
    jint start, jint count) {
  auto session = acquire_session(sessionPtr);
  json result = {
      {"success", false},
      {"error", ""},
      {"items", json::array()},
      {"offset", start},
      {"returned", 0},
      {"total", 0},
      {"truncated", false},
      {"cancelled", false},
      {"queryVersion", kScopedQueryVersion},
  };

  if (!session || !session->wth || !session->epan) {
    result["error"] = "No capture is open.";
    return new_java_string(env, result.dump());
  }
  if (start < 0 || count <= 0) {
    result["error"] = "Invalid pagination.";
    return new_java_string(env, result.dump());
  }

  const int boundedCount = std::min(static_cast<int>(count), 100);
  result["offset"] = start;

  const char *filterChars = env->GetStringUTFChars(jFilter, nullptr);
  std::string filter = filterChars ? filterChars : "";
  if (filterChars) env->ReleaseStringUTFChars(jFilter, filterChars);
  filter = trim_copy(filter);

  dfilter_t *compiled = nullptr;
  ScopedGFree errorMessage;
  bool compiledOk = true;
  if (!filter.empty()) {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    compiledOk = dfilter_compile(filter.c_str(), &compiled, &errorMessage.value);
  }
  ScopedDFilter scopedFilter(session);
  scopedFilter.reset(compiled);
  if (!compiledOk) {
    result["error"] = std::string(
        errorMessage.value ? errorMessage.value : "Invalid display filter.");
    return new_java_string(env, result.dump());
  }

  const int frameCount = static_cast<int>(session->frame_offsets.size());
  const uint64_t cancelGeneration = current_cancel_generation();
  const int64_t pageEnd = static_cast<int64_t>(start) + boundedCount;
  json items = json::array();

  // An unfiltered query is an index lookup, not a full-capture scan.  The old
  // implementation walked every frame merely to calculate totalMatches.
  if (!scopedFilter.get()) {
    const int first = std::min(start, frameCount);
    const int last = std::min(frameCount, static_cast<int>(pageEnd));
    for (int frameIdx = first; frameIdx < last; ++frameIdx) {
      if (long_operation_cancelled(cancelGeneration)) {
        result["error"] = "Operation cancelled.";
        result["cancelled"] = true;
        return new_java_string(env, result.dump());
      }
      CachedPacketSummary summary =
          get_or_build_packet_summary(session, frameIdx);
      append_packet_summary_json(items, frameIdx, summary);
      yield_to_interactive_reads(session);
    }
    result["success"] = true;
    result["total"] = frameCount;
    result["returned"] = static_cast<int>(items.size());
    result["truncated"] = static_cast<int64_t>(start) +
                           static_cast<int64_t>(items.size()) < frameCount;
    result["items"] = std::move(items);
    return new_java_string(env, result.dump());
  }

  const uint64_t visibilityGeneration =
      session->filter_request_generation.load(std::memory_order_relaxed);
  std::shared_ptr<const std::vector<int>> cachedMatches;
  {
    std::lock_guard<std::mutex> query_cache_lock(
        session->scoped_query_cache_mutex);
    if (session->scoped_query_cache_filter == filter &&
        session->scoped_query_cache_visibility_generation ==
            visibilityGeneration) {
      cachedMatches = session->scoped_query_cache_matches;
    }
  }
  if (cachedMatches) {
    // The expensive filter traversal was already completed by an earlier
    // page request. Only materialize the requested summaries now.
    const int totalMatches = static_cast<int>(cachedMatches->size());
    const int first = std::min(start, totalMatches);
    const int last = std::min(totalMatches, static_cast<int>(pageEnd));
    for (int position = first; position < last; ++position) {
      if (long_operation_cancelled(cancelGeneration)) {
        result["error"] = "Operation cancelled.";
        result["cancelled"] = true;
        return new_java_string(env, result.dump());
      }
      const int frameIdx = (*cachedMatches)[position];
      CachedPacketSummary summary =
          get_or_build_packet_summary(session, frameIdx);
      append_packet_summary_json(items, frameIdx, summary);
      yield_to_interactive_reads(session);
    }
    result["success"] = true;
    result["total"] = totalMatches;
    result["returned"] = static_cast<int>(items.size());
    result["truncated"] = static_cast<int64_t>(start) +
                           static_cast<int64_t>(items.size()) < totalMatches;
    result["items"] = std::move(items);
    return new_java_string(env, result.dump());
  }

  const std::vector<int> visibleFrames = snapshot_visible_frames(session);
  int totalMatches = 0;
  auto matchedFrames = std::make_shared<std::vector<int>>();
  matchedFrames->reserve(std::min<size_t>(visibleFrames.size(), 4096));
  for (int frameIdx : visibleFrames) {
    if (long_operation_cancelled(cancelGeneration)) {
      result["error"] = "Operation cancelled.";
      result["cancelled"] = true;
      return new_java_string(env, result.dump());
    }

    const bool maybeInPage = totalMatches >= start &&
                             static_cast<int64_t>(totalMatches) < pageEnd;
    bool matched = false;
    CachedPacketSummary summary;
    bool cached = maybeInPage && load_cached_packet_summary(session, frameIdx, summary);
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      const bool setupColumns = maybeInPage && !cached;
      if (dissect_frame(session, frameIdx, TRUE, setupColumns,
                        scopedFilter.get(), frame) &&
          dfilter_apply_edt(scopedFilter.get(), frame.edt)) {
        matched = true;
        if (maybeInPage && !cached &&
            populate_packet_summary(session, frameIdx, frame, summary)) {
          store_cached_packet_summary(session, frameIdx, summary);
        }
      }
    }
    if (matched) {
      matchedFrames->push_back(frameIdx);
      if (totalMatches >= start &&
          static_cast<int64_t>(totalMatches) < pageEnd &&
          summary.valid) {
        items.push_back({
            {"frameNumber", frameIdx + 1},
            {"time", summary.timestamp},
            {"source", summary.source},
            {"destination", summary.destination},
            {"protocol", summary.protocol},
            {"length", summary.length},
            {"sourcePort", summary.source_port},
            {"destinationPort", summary.destination_port},
            {"info", summary.info},
        });
      }
      totalMatches++;
    }
    yield_to_interactive_reads(session);
  }

  result["success"] = true;
  result["total"] = totalMatches;
  result["returned"] = static_cast<int>(items.size());
  result["truncated"] = static_cast<int64_t>(start) +
                         static_cast<int64_t>(items.size()) < totalMatches;
  result["items"] = std::move(items);
  if (!long_operation_cancelled(cancelGeneration) &&
      session->filter_request_generation.load(std::memory_order_relaxed) ==
          visibilityGeneration) {
    std::lock_guard<std::mutex> query_cache_lock(
        session->scoped_query_cache_mutex);
    session->scoped_query_cache_filter = filter;
    session->scoped_query_cache_visibility_generation = visibilityGeneration;
    session->scoped_query_cache_matches = std::move(matchedFrames);
  }
  return new_java_string(env, result.dump());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getSummaryCacheStats(JNIEnv *env,
                                                               jobject /* this */,
                                                               jlong sessionPtr) {
  auto session = acquire_session(sessionPtr);
  json result;
  if (!session) {
    result["frames"] = 0;
    result["valid"] = 0;
    result["hits"] = 0;
    result["misses"] = 0;
    result["evictions"] = 0;
    return new_java_string(env, result.dump());
  }

  std::lock_guard<std::mutex> cache_lock(session->summary_cache_mutex);
  int valid = 0;
  for (const auto &entry : session->summary_cache) {
    if (entry.second.valid) valid++;
  }
  result["frames"] = static_cast<int>(session->frame_offsets.size());
  result["valid"] = valid;
  result["hits"] = session->summary_cache_hits;
  result["misses"] = session->summary_cache_misses;
  result["evictions"] = session->summary_cache_evictions;
  result["entries"] = static_cast<int>(session->summary_cache.size());
  result["bytes"] = static_cast<uint64_t>(session->summary_cache_bytes);
  return new_java_string(env, result.dump());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_validateDisplayFilter(JNIEnv *env,
                                                                jobject /* this */,
                                                                jlong sessionPtr,
                                                                jstring jFilter) {
  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    json result = {{"success", false}, {"error", "No capture is open."}};
    return new_java_string(env, result.dump());
  }

  const char *filter_chars = env->GetStringUTFChars(jFilter, nullptr);
  std::string filter = filter_chars ? filter_chars : "";
  if (filter_chars) env->ReleaseStringUTFChars(jFilter, filter_chars);
  if (filter.empty()) {
    json result = {{"success", true}, {"error", ""}};
    return new_java_string(env, result.dump());
  }

  dfilter_t *compiled_filter = nullptr;
  gchar *error_message = nullptr;
  bool compiled = false;
  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    compiled = dfilter_compile(filter.c_str(), &compiled_filter, &error_message);
    if (compiled_filter) dfilter_free(compiled_filter);
  }
  std::string error = compiled ? "" : (error_message ? error_message : "Invalid display filter.");
  g_free(error_message);
  json result = {{"success", compiled}, {"error", error}};
  return new_java_string(env, result.dump());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_applyDisplayFilter(JNIEnv *env,
                                                             jobject /* this */,
                                                             jlong sessionPtr,
                                                             jstring jFilter) {
  PERF_SCAN_START();
  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    json result = {{"success", false}, {"error", "No capture is open."}, {"count", 0}};
    return new_java_string(env, result.dump());
  }

  const char *filterChars = env->GetStringUTFChars(jFilter, nullptr);
  std::string filter = filterChars ? filterChars : "";
  env->ReleaseStringUTFChars(jFilter, filterChars);

  uint64_t filter_request_generation = 0;
  {
    std::unique_lock<std::shared_mutex> state_lock(session->state_mutex);
    filter_request_generation =
        session->filter_request_generation.fetch_add(1, std::memory_order_relaxed) + 1;
  }
  // A new visibility generation invalidates any previously materialized
  // scoped-query result, even if the temporary filter text is unchanged.
  invalidate_scoped_query_cache(session);

  if (filter.empty()) {
    std::unique_lock<std::shared_mutex> state_lock(session->state_mutex);
    if (session->filter_request_generation.load(std::memory_order_relaxed) !=
        filter_request_generation) {
      int current_count = session->active_filter.empty()
                              ? static_cast<int>(session->frame_offsets.size())
                              : static_cast<int>(session->filtered_frames.size());
      json result = {{"success", false}, {"error", "Operation cancelled."},
                     {"count", current_count}};
      PERF_SCAN_LOG("applyDisplayFilter filter=<empty> frames=%d ms=%lld cancelled=1",
                    static_cast<int>(session->frame_offsets.size()), __perf_ms);
      return new_java_string(env, result.dump());
    }
    session->active_filter.clear();
    session->filter_error.clear();
    session->filtered_frames.clear();
    json result = {{"success", true}, {"error", ""},
                   {"count", static_cast<int>(session->frame_offsets.size())}};
    PERF_SCAN_LOG("applyDisplayFilter filter=<empty> frames=%d ms=%lld matches=%d",
                  static_cast<int>(session->frame_offsets.size()), __perf_ms,
                  static_cast<int>(session->frame_offsets.size()));
    return new_java_string(env, result.dump());
  }

  dfilter_t *df = nullptr;
  gchar *err_msg = nullptr;
  bool compiled = false;
  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    compiled = dfilter_compile(filter.c_str(), &df, &err_msg);
  }
  if (!compiled) {
    std::string error = err_msg ? err_msg : "Invalid display filter.";
    int current_count = 0;
    {
      std::unique_lock<std::shared_mutex> state_lock(session->state_mutex);
      if (session->filter_request_generation.load(std::memory_order_relaxed) ==
          filter_request_generation) {
        session->filter_error = error;
      }
      current_count = session->active_filter.empty()
                          ? static_cast<int>(session->frame_offsets.size())
                          : static_cast<int>(session->filtered_frames.size());
    }
    json result = {{"success", false}, {"error", error},
                   {"count", current_count}};
    g_free(err_msg);
    return new_java_string(env, result.dump());
  }

  uint64_t cancel_generation = current_cancel_generation();
  std::vector<int> matches;
  const int total_frames = static_cast<int>(session->frame_offsets.size());
  for (int i = 0; i < total_frames; ++i) {
    if (long_operation_cancelled(cancel_generation) ||
        session->filter_request_generation.load(std::memory_order_relaxed) !=
            filter_request_generation) {
      {
        std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
        dfilter_free(df);
      }
      json result = {{"success", false}, {"error", "Operation cancelled."},
                     {"count", visible_frame_count(session)}};
      PERF_SCAN_LOG("applyDisplayFilter filter=%s frames=%d ms=%lld cancelled=1",
                    filter.c_str(), total_frames, __perf_ms);
      return new_java_string(env, result.dump());
    }
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      if (dissect_frame(session, i, TRUE, FALSE, df, frame) &&
          (!df || dfilter_apply_edt(df, frame.edt))) {
        matches.push_back(i);
      }
    }
    yield_to_interactive_reads(session);
  }

  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    dfilter_free(df);
  }
  int match_count = static_cast<int>(matches.size());
  int current_count = 0;
  bool cancelled = false;
  {
    std::unique_lock<std::shared_mutex> state_lock(session->state_mutex);
    cancelled = long_operation_cancelled(cancel_generation) ||
                session->filter_request_generation.load(std::memory_order_relaxed) !=
                    filter_request_generation;
    if (cancelled) {
      current_count = session->active_filter.empty()
                          ? static_cast<int>(session->frame_offsets.size())
                          : static_cast<int>(session->filtered_frames.size());
    } else {
      session->active_filter = filter;
      session->filter_error.clear();
      session->filtered_frames = std::move(matches);
    }
  }
  if (cancelled) {
    json result = {{"success", false}, {"error", "Operation cancelled."},
                   {"count", current_count}};
    PERF_SCAN_LOG("applyDisplayFilter filter=%s frames=%d ms=%lld cancelled=1",
                  filter.c_str(), total_frames, __perf_ms);
    return new_java_string(env, result.dump());
  }
  json result = {{"success", true}, {"error", ""},
                  {"count", match_count}};
  PERF_SCAN_LOG("applyDisplayFilter filter=%s frames=%d ms=%lld matches=%d",
                filter.c_str(), total_frames, __perf_ms, match_count);
  return new_java_string(env, result.dump());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_layanalyzer_NativeEngine_getFilteredFrameCount(JNIEnv *env,
                                                                jobject /* this */,
                                                                jlong sessionPtr) {
  (void)env;
  auto session = acquire_session(sessionPtr);
  return visible_frame_count(session);
}
