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
    return new_java_string(env, root.dump());
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
      return new_java_string(env, root.dump());
    }
    streamId = find_stream_id(selected.edt->tree, streamField);
    if (streamId < 0) {
      root["error"] = "Selected packet does not expose a " + protocol + " stream.";
      return new_java_string(env, root.dump());
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
  return new_java_string(env, root.dump());
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

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getHttpObjects(JNIEnv *env,
                                                         jobject /* this */,
                                                         jlong sessionPtr) {
  auto session = acquire_session(sessionPtr);
  json root = {{"objects", json::array()}, {"error", ""}};
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }

  std::unique_lock<std::mutex> object_lock(session->http_objects_mutex);
  clear_http_objects(session);
  register_eo_t *http_export = get_eo_by_name("http");
  if (!http_export) {
    root["error"] =
        "HTTP object export is not available in this Wireshark build.";
    return new_java_string(env, root.dump());
  }

  export_object_gui_reset_cb export_reset = get_eo_reset_func(http_export);
  if (export_reset) export_reset();

  export_object_list_t object_list;
  object_list.add_entry = http_object_list_add_entry;
  object_list.get_entry = http_object_list_get_entry;
  object_list.gui_data = session;

  GString *tap_error = register_tap_listener(
      get_eo_tap_listener_name(http_export), &object_list, nullptr, 0, nullptr,
      get_eo_packet_func(http_export), nullptr, nullptr);
  if (tap_error) {
    root["error"] = tap_error->str ? tap_error->str
                                   : "Unable to register the HTTP export tap.";
    g_string_free(tap_error, TRUE);
    return new_java_string(env, root.dump());
  }

  uint64_t cancel_generation = current_cancel_generation();
  std::vector<int> visible_frames = snapshot_visible_frames(session);
  for (int frame_idx : visible_frames) {
    if (long_operation_cancelled(cancel_generation)) {
      root["error"] = "Operation cancelled.";
      break;
    }
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      dissect_frame(session, frame_idx, TRUE, FALSE, nullptr, frame);
    }
    yield_to_interactive_reads(session);
  }
  remove_tap_listener(&object_list);

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
  return new_java_string(env, root.dump());
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
