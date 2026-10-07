// Expert Info service: scans the visible frames for Wireshark expert items.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/runtime/EngineRuntime.h"
#include "layanalyzer/runtime/SessionRegistry.h"
#include "layanalyzer/session/CaptureSession.h"
#include "layanalyzer/projection/FieldReader.h"
#include "layanalyzer/query/QuerySupport.h"

static bool collect_expert_nodes(proto_node *node, json &items,
                                 std::string &highest) {
  bool found = false;
  if (!node) return false;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo) {
      std::string severity = severity_from_flags(finfo->flags);
      if (severity != "none") {
        std::string label = finfo->rep ? finfo->rep->representation : "";
        if (label.empty() && finfo->hfinfo && finfo->hfinfo->name) label = finfo->hfinfo->name;
        json item;
        item["label"] = label;
        item["filter"] = (finfo->hfinfo && finfo->hfinfo->abbrev) ? finfo->hfinfo->abbrev : "";
        item["severity"] = severity;
        item["start"] = finfo->start < 0 ? 0 : finfo->start;
        item["length"] = finfo->length < 0 ? 0 : finfo->length;
        items.push_back(item);
        if (severity_rank(severity) > severity_rank(highest)) highest = severity;
        found = true;
      }
    }
    if (collect_expert_nodes(current, items, highest)) found = true;
  }
  return found;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getExpertInfoSummary(JNIEnv *env,
                                                               jobject /* this */,
                                                               jlong sessionPtr) {
  PERF_SCAN_START();
  auto session = acquire_session(sessionPtr);
  json root;
  root["items"] = json::array();
  if (!session || !session->wth || !session->epan) {
    root["warnings"] = 0;
    root["errors"] = 0;
    return new_java_string(env, root.dump());
  }

  uint64_t cancel_generation = current_cancel_generation();
  int warnings = 0;
  int errors = 0;
  int total_items = 0;
  std::vector<int> visible_frames = snapshot_visible_frames(session);
  for (int frameIdx : visible_frames) {
    if (long_operation_cancelled(cancel_generation)) {
      root["cancelled"] = true;
      break;
    }
    json items = json::array();
    std::string highest = "none";
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      if (!dissect_frame(session, frameIdx, TRUE, FALSE, nullptr, frame)) continue;
      if (collect_expert_nodes(frame.edt->tree, items, highest)) {
        if (highest == "error") errors++; else if (highest == "warn") warnings++;
        for (auto &item : items) {
          item["frameNumber"] = frameIdx + 1;
          total_items++;
          if (root["items"].size() < 5000) root["items"].push_back(item);
        }
      }
    }
    yield_to_interactive_reads(session);
  }
  root["warnings"] = warnings;
  root["errors"] = errors;
  root["totalItems"] = total_items;
  root["truncated"] = total_items > static_cast<int>(root["items"].size());
  PERF_SCAN_LOG("getExpertInfoSummary frames=%d ms=%lld items=%d warnings=%d errors=%d%s",
                static_cast<int>(visible_frames.size()), __perf_ms, total_items,
                warnings, errors,
                root.contains("cancelled") ? " cancelled=1" : "");
  return new_java_string(env, root.dump());
}
