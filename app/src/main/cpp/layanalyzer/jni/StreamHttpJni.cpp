// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Follow Stream and HTTP object JNI endpoints.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/internal/TextUtils.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/ProtocolProjection.h"
#include "layanalyzer/stream/HttpObjectCallbacks.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_followStream(JNIEnv *env,
                                                       jobject /* this */,
                                                       jlong sessionPtr,
                                                       jint packetIndex,
                                                       jstring jProtocol) {
  auto session = acquire_session(sessionPtr);
  json root;
  root["records"] = json::array();
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, dump_json(root));
  }
  const char *protocolChars = env->GetStringUTFChars(jProtocol, nullptr);
  std::string protocol = lowercase_copy(protocolChars ? protocolChars : "tcp");
  env->ReleaseStringUTFChars(jProtocol, protocolChars);
  std::string streamField = protocol == "udp" ? "udp.stream" : "tcp.stream";
  std::string payloadField = protocol == "udp" ? "udp.payload" : "tcp.payload";

  int streamId = -1;
  std::string client;
  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    DissectedFrame selected;
    if (!dissect_frame(session, packetIndex, TRUE, FALSE, nullptr, selected)) {
      root["error"] = "Unable to dissect selected packet.";
      return new_java_string(env, dump_json(root));
    }
    streamId = find_stream_id(selected.edt->tree, streamField);
    if (streamId < 0) {
      root["error"] = "Selected packet does not expose a " + protocol + " stream.";
      return new_java_string(env, dump_json(root));
    }
    client = address_text(&selected.edt->pi.src,
                          session->name_resolution_enabled) + ":" +
             std::to_string(selected.edt->pi.srcport);
  }

  root["protocol"] = protocol;
  root["streamId"] = streamId;
  root["error"] = "";
  root["scope"] = "current filtered packet set";

  uint64_t cancel_generation = current_cancel_generation();
  std::vector<int> visible_frames = snapshot_visible_frames(session);
  bool direction_known = false;
  if (protocol == "tcp") {
    for (int frame_idx : visible_frames) {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      if (!dissect_frame(session, frame_idx, TRUE, FALSE, nullptr, frame) ||
          find_stream_id(frame.edt->tree, streamField) != streamId) continue;
      if (find_boolean_field(frame.edt->tree, "tcp.flags.syn") &&
          !find_boolean_field(frame.edt->tree, "tcp.flags.ack")) {
        packet_info *pinfo = &frame.edt->pi;
        client = address_text(&pinfo->src, session->name_resolution_enabled) + ":" +
                 std::to_string(pinfo->srcport);
        direction_known = true;
        break;
      }
    }
  }
  root["directionKnown"] = direction_known;
  for (int i : visible_frames) {
    if (long_operation_cancelled(cancel_generation)) {
      root["error"] = "Operation cancelled.";
      break;
    }
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      if (!dissect_frame(session, i, TRUE, FALSE, nullptr, frame)) continue;
      if (find_stream_id(frame.edt->tree, streamField) != streamId) continue;
      packet_info *pinfo = &frame.edt->pi;
      std::string source = address_text(&pinfo->src, session->name_resolution_enabled) + ":" + std::to_string(pinfo->srcport);
      std::string dest = address_text(&pinfo->dst, session->name_resolution_enabled) + ":" + std::to_string(pinfo->destport);
      std::vector<guint8> bytes;
      bool hasPayload = append_payload_bytes(frame.edt->tree, payloadField, bytes);
      if (!hasPayload) {
        const guint8 *data = ws_buffer_start_ptr(&frame.buf);
        size_t length = packet_data_length(&frame.rec, &frame.buf);
        if (data && length > 0) bytes.assign(data, data + length);
      }
      json record;
      record["frameNumber"] = i + 1;
      record["direction"] = direction_known ? (source == client ? "client" : "server") : "unknown";
      record["source"] = source;
      record["destination"] = dest;
      record["length"] = static_cast<int>(bytes.size());
      record["payload"] = hasPayload;
      record["ascii"] = bytes_to_ascii(bytes);
      record["text"] = bytes_to_utf8_text(bytes);
      record["hex"] = bytes_to_hex(bytes);
      root["records"].push_back(record);
    }
    yield_to_interactive_reads(session);
  }
  return new_java_string(env, dump_json(root));
}

void http_object_list_add_entry(void *gui_data,
                                export_object_entry_t *entry) {
  auto *session = static_cast<WiresharkSession *>(gui_data);
  if (!session || !entry) {
    if (entry) eo_free_entry(entry);
    return;
  }
  session->http_objects.push_back(entry);
}

export_object_entry_t *http_object_list_get_entry(void *gui_data, int row) {
  auto *session = static_cast<WiresharkSession *>(gui_data);
  if (!session || row < 0 ||
      row >= static_cast<int>(session->http_objects.size())) {
    return nullptr;
  }
  return session->http_objects[row];
}

namespace {

// True when the frame's protocol tree contains `abbrev` as the protocol item
// itself or as the prefix of one of its fields ("http2" or "http2.*"). Lets the
// scan tell an HTTP/2 capture from an HTTP/1 one without a second dissection.
bool tree_has_protocol(proto_node *node, const char *abbrev) {
  if (!node || !abbrev) return false;
  const size_t length = strlen(abbrev);
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    const char *name = (finfo && finfo->hfinfo) ? finfo->hfinfo->abbrev : nullptr;
    if (name) {
      if (strcmp(name, abbrev) == 0) return true;
      if (strncmp(name, abbrev, length) == 0 && name[length] == '.') return true;
    }
    if (tree_has_protocol(current, abbrev)) return true;
  }
  return false;
}

/**
 * Registers one Wireshark export-object tap for the duration of a scan and
 * removes it on every exit path, including exceptions and early returns.
 * register_tap_listener()/remove_tap_listener() take session->dissect_mutex the
 * same way the RTP payload extractor does, so a concurrent dissection cannot
 * race tap teardown. The export-object reset callback runs before registration
 * so a rescan never inherits the previous scan's intermediate state and cannot
 * duplicate entries.
 *
 * The export-object tap only fires from epan_dissect_run_with_taps(); the scan
 * below must use dissect_frame_with_taps(), never plain dissect_frame().
 */
class ExportObjectTap {
 public:
  ExportObjectTap(WiresharkSession *session, register_eo_t *export_eo,
                  export_object_list_t *list)
      : session_(session), list_(list) {
    export_object_gui_reset_cb reset = get_eo_reset_func(export_eo);
    if (reset) reset();
    std::unique_lock<std::mutex> lock(session_->dissect_mutex);
    GString *error = register_tap_listener(
        get_eo_tap_listener_name(export_eo), list_, nullptr, 0, nullptr,
        get_eo_packet_func(export_eo), nullptr, nullptr);
    if (error) {
      error_ = (error->str && error->str[0])
                   ? error->str
                   : "Unable to register the HTTP export tap.";
      g_string_free(error, TRUE);
      return;
    }
    registered_ = true;
  }
  ~ExportObjectTap() { remove(); }
  ExportObjectTap(const ExportObjectTap &) = delete;
  ExportObjectTap &operator=(const ExportObjectTap &) = delete;

  bool registered() const { return registered_; }
  const std::string &error() const { return error_; }
  void remove() {
    if (!registered_) return;
    std::unique_lock<std::mutex> lock(session_->dissect_mutex);
    if (registered_) {
      registered_ = false;
      remove_tap_listener(list_);
    }
  }

 private:
  WiresharkSession *session_;
  export_object_list_t *list_;
  bool registered_ = false;
  std::string error_;
};

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getHttpObjects(JNIEnv *env,
                                                         jobject /* this */,
                                                         jlong sessionPtr) {
  auto session = acquire_session(sessionPtr);
  json root = {{"schemaVersion", 1},
               {"success", false},
               {"errorCode", nullptr},
               {"error", ""},
               {"scope", "complete_capture"},
               {"objects", json::array()},
               {"http2Present", false},
               {"http2Supported", false},
               {"incomplete", false},
               {"unavailableReason", nullptr}};
  if (!session || !session->wth || !session->epan) {
    root["errorCode"] = "NOT_READY";
    root["error"] = "No capture is open.";
    return new_java_string(env, dump_json(root));
  }

  register_eo_t *http_export = get_eo_by_name("http");
  if (!http_export) {
    root["errorCode"] = "UNSUPPORTED";
    root["error"] =
        "HTTP object export is not available in this Wireshark build.";
    return new_java_string(env, dump_json(root));
  }
  // Wireshark 4.0.10 registers an export-object tap for HTTP/1 only. Without an
  // HTTP/2 exporter an h2-only capture would otherwise look like a real
  // "zero objects" success; record the capability so the result is honest.
  const bool http2_supported = get_eo_by_name("http2") != nullptr;
  root["http2Supported"] = http2_supported;

  std::unique_lock<std::mutex> object_lock(session->http_objects_mutex);
  clear_http_objects(session);

  export_object_list_t object_list;
  object_list.add_entry = http_object_list_add_entry;
  object_list.get_entry = http_object_list_get_entry;
  object_list.gui_data = session;

  ExportObjectTap tap(session, http_export, &object_list);
  if (!tap.registered()) {
    root["errorCode"] = "UNSUPPORTED";
    root["error"] = tap.error();
    return new_java_string(env, dump_json(root));
  }

  // The scan always feeds the complete capture, in frame order, so TCP/TLS and
  // HTTP reassembly see every segment even when a display filter hides some.
  // The response declares scope=complete_capture so a filtered view is never
  // presented as if it were the whole result, nor the reverse.
  const uint64_t cancel_generation = current_cancel_generation();
  bool http2_present = false;
  bool cancelled = false;
  for (size_t frame_idx = 0; frame_idx < session->frame_offsets.size();
       ++frame_idx) {
    if (session->closed.load() || long_operation_cancelled(cancel_generation)) {
      cancelled = true;
      break;
    }
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      // Must be the with_taps entry: plain dissect_frame() never pushes the tap
      // queue, so the export-object callback would silently never fire.
      if (!dissect_frame_with_taps(session, static_cast<int>(frame_idx), TRUE,
                                   FALSE, nullptr, frame)) {
        continue;
      }
      if (!http2_present)
        http2_present = tree_has_protocol(frame.edt->tree, "http2");
    }
    yield_to_interactive_reads(session);
  }
  tap.remove();

  if (cancelled) {
    // Never publish a partial object set: a later getHttpObjectPayload() by
    // index would then read entries the caller never saw completed.
    clear_http_objects(session);
    root["errorCode"] = "CANCELLED";
    root["error"] = "Operation cancelled.";
    return new_java_string(env, dump_json(root));
  }
  root["http2Present"] = http2_present;

  for (int index = 0; index < static_cast<int>(session->http_objects.size());
       ++index) {
    export_object_entry_t *entry = session->http_objects[index];
    if (!entry) continue;
    std::string filename = entry->filename ? entry->filename : "";
    if (filename.empty()) {
      filename = "http-object-" + std::to_string(entry->pkt_num) + "-" +
                 std::to_string(index + 1);
    }
    root["objects"].push_back({
        {"id", index},
        {"frameNumber", entry->pkt_num},
        {"hostname", entry->hostname ? entry->hostname : ""},
        {"contentType", entry->content_type ? entry->content_type : ""},
        {"filename", filename},
        {"size", entry->payload_len},
    });
  }

  if (root["objects"].empty()) {
    if (http2_present) {
      // No fake empty success: the capture carries HTTP/2, but this scan only
      // registers the HTTP/1 export tap. Whatever the runtime exporter probe
      // reports, an HTTP/2 capture is not a real "zero objects" result.
      root["errorCode"] = "UNSUPPORTED";
      root["error"] = http2_supported
                           ? "HTTP/2 objects need a dedicated HTTP/2 export "
                             "scan, which this build does not run."
                           : "HTTP/2 export objects are not supported by this "
                             "Wireshark build.";
      root["unavailableReason"] = "HTTP2_UNSUPPORTED";
    } else {
      root["success"] = true;
      root["error"] = "";
    }
  } else {
    root["success"] = true;
    root["error"] = "";
    if (http2_present) {
      // HTTP/1 objects were extracted, but any HTTP/2 objects in the same
      // capture are missing; surface that without hiding the HTTP/1 result.
      root["incomplete"] = true;
      root["unavailableReason"] = "HTTP2_UNSUPPORTED";
    }
  }
  return new_java_string(env, dump_json(root));
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_layanalyzer_NativeEngine_getHttpObjectPayload(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jint objectIndex) {
  auto session = acquire_session(sessionPtr);
  if (!session) return env->NewByteArray(0);

  std::unique_lock<std::mutex> object_lock(session->http_objects_mutex);
  if (objectIndex < 0 ||
      objectIndex >= static_cast<int>(session->http_objects.size())) {
    return env->NewByteArray(0);
  }
  export_object_entry_t *entry = session->http_objects[objectIndex];
  if (!entry || !entry->payload_data || entry->payload_len == 0 ||
      entry->payload_len > static_cast<size_t>(std::numeric_limits<jsize>::max())) {
    return env->NewByteArray(0);
  }
  jsize length = static_cast<jsize>(entry->payload_len);
  jbyteArray result = env->NewByteArray(length);
  if (result) {
    env->SetByteArrayRegion(result, 0, length,
                            reinterpret_cast<const jbyte *>(entry->payload_data));
  }
  return result;
}
