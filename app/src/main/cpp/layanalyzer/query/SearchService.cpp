// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Search service: number / hex / field / text packet search over the visible
// frame set.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/runtime/EngineRuntime.h"
#include "layanalyzer/runtime/SessionRegistry.h"
#include "layanalyzer/session/CaptureSession.h"
#include "layanalyzer/projection/FieldReader.h"
#include "layanalyzer/query/QuerySupport.h"

extern "C" JNIEXPORT jintArray JNICALL
Java_com_example_layanalyzer_NativeEngine_searchPackets(JNIEnv *env,
                                                        jobject /* this */,
                                                        jlong sessionPtr,
                                                        jstring jMode,
                                                        jstring jQuery) {
  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) return env->NewIntArray(0);
  const char *modeChars = env->GetStringUTFChars(jMode, nullptr);
  const char *queryChars = env->GetStringUTFChars(jQuery, nullptr);
  std::string mode = modeChars ? modeChars : "text";
  std::string query = queryChars ? queryChars : "";
  env->ReleaseStringUTFChars(jMode, modeChars);
  env->ReleaseStringUTFChars(jQuery, queryChars);

  uint64_t search_request_generation =
      session->search_request_generation.fetch_add(1, std::memory_order_relaxed) + 1;
  uint64_t cancel_generation = current_cancel_generation();
  std::vector<int> results;
  std::vector<int> visible_frames = snapshot_visible_frames(session);
  if (!query.empty() && mode == "number") {
    const int frame_number = atoi(query.c_str());
    const int physical_index = frame_number - 1;
    bool visible = false;
    if (frame_number > 0 &&
        physical_index < static_cast<int>(session->frame_offsets.size())) {
      std::shared_lock<std::shared_mutex> state_lock(session->state_mutex);
      visible = session->active_filter.empty() ||
                std::binary_search(session->filtered_frames.begin(),
                                   session->filtered_frames.end(),
                                   physical_index);
    }
    if (visible) results.push_back(frame_number);
  } else if (!query.empty()) {
    std::vector<guint8> hexNeedle = mode == "hex" ? parse_hex_query(query) : std::vector<guint8>();
    for (int frameIdx : visible_frames) {
      if (long_operation_cancelled(cancel_generation) ||
          session->search_request_generation.load(std::memory_order_relaxed) !=
              search_request_generation) {
        break;
      }
      bool createTree = mode == "field";
      bool matched = false;
      {
        std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
        DissectedFrame frame;
        if (!dissect_frame(session, frameIdx, createTree, TRUE, nullptr, frame)) {
          continue;
        }
        if (mode == "hex") {
          matched = bytes_contain(ws_buffer_start_ptr(&frame.buf),
                                  packet_data_length(&frame.rec, &frame.buf),
                                  hexNeedle);
        } else if (mode == "field") {
          matched = tree_contains_text(frame.edt->tree, query);
        } else {
          matched = contains_case_insensitive(
              frame_search_text(session, frameIdx, frame), query);
        }
      }
      if (matched) results.push_back(frameIdx + 1);
      yield_to_interactive_reads(session);
    }
  }

  if (long_operation_cancelled(cancel_generation) ||
      session->search_request_generation.load(std::memory_order_relaxed) !=
          search_request_generation) {
    results.clear();
  }
  jintArray array = env->NewIntArray(static_cast<jsize>(results.size()));
  if (array && !results.empty()) {
    env->SetIntArrayRegion(array, 0, static_cast<jsize>(results.size()), results.data());
  }
  return array;
}
