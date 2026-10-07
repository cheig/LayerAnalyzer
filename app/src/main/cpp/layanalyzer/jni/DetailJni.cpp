// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Packet detail JNI endpoints: protocol-tree JSON serialization and raw
// packet bytes.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/ProtocolProjection.h"
#include "layanalyzer/projection/TreeFieldReader.h"

static std::string recursive_tree_walk(proto_node *node, json &jMsg) {
  std::string highest = "none";
  if (!node)
    return highest;

  for (proto_node *current = node->first_child; current;
       current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (!finfo)
      continue;

    json jItem;
    std::string itemSeverity = severity_from_flags(finfo->flags);

    // Basic info
    if (finfo->hfinfo) {
      jItem["id"] = finfo->hfinfo->abbrev ? finfo->hfinfo->abbrev : "";
      jItem["filter"] = finfo->hfinfo->abbrev ? finfo->hfinfo->abbrev : "";
      jItem["name"] = finfo->hfinfo->name ? finfo->hfinfo->name : "";
      jItem["type"] = ftype_name(finfo->hfinfo->type);
      std::string filterValue = get_filter_value(finfo);
      if (!filterValue.empty()) {
        jItem["filterValue"] = filterValue;
      }
    }

    // Label
    std::string label = get_node_text(finfo);
    if (label.empty() && finfo->hfinfo) {
      label = finfo->hfinfo->name;
    }
    jItem["label"] = label;
    jItem["start"] = finfo->start < 0 ? 0 : finfo->start;
    jItem["length"] = finfo->length < 0 ? 0 : finfo->length;
    jItem["generated"] = FI_GET_FLAG(finfo, FI_GENERATED) != 0;
    jItem["hidden"] = FI_GET_FLAG(finfo, FI_HIDDEN) != 0;
    if (severity_rank(itemSeverity) > severity_rank(highest)) {
      highest = itemSeverity;
    }

    // Children
    if (current->first_child) {
      json jChildren = json::array();          // Create array for children
      std::string childSeverity = recursive_tree_walk(current, jChildren); // Fill it
      if (severity_rank(childSeverity) > severity_rank(itemSeverity)) {
        itemSeverity = childSeverity;
      }
      if (severity_rank(childSeverity) > severity_rank(highest)) {
        highest = childSeverity;
      }
      if (!jChildren.empty()) {
        jItem["children"] = jChildren;
      }
    }
    jItem["severity"] = itemSeverity;

    jMsg.push_back(jItem); // Add this item to parent array
  }

  return highest;
}

// JNI to get detailed JSON for a packet
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getPacketDetails(JNIEnv *env,
                                                           jobject /* this */,
                                                           jlong sessionPtr,
                                                           jint packetIndex) {
  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    LOGE("getPacketDetails: Invalid session");
    return new_java_string(env, "{}");
  }
  InteractiveReadGuard interactive_guard(session);
  std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);

  if (packetIndex < 0 || packetIndex >= (int)session->frame_offsets.size()) {
    LOGE("getPacketDetails: Invalid index %d", packetIndex);
    return new_java_string(env, "{}");
  }

  json jRoot = json::object();
  {
    DissectedFrame frame;
    if (!dissect_frame(session, packetIndex, TRUE, FALSE, nullptr, frame)) {
      LOGE("getPacketDetails: Failed to dissect frame %d", packetIndex);
      return new_java_string(env, "{}");
    }

    // Convert Protocol Tree to JSON while packet-scope Wireshark memory is
    // valid. The DissectedFrame is destroyed before releasing dissect_mutex.
    json jChildren = json::array();
    std::string rootSeverity = recursive_tree_walk(frame.edt->tree, jChildren);
    jRoot["label"] = "Packet " + std::to_string(packetIndex + 1);
    jRoot["severity"] = rootSeverity;
    jRoot["children"] = std::move(jChildren);
  }

  // All Wireshark pointers have been consumed into value-based JSON. Release
  // the dissection mutex before serializing/allocating the Java string so a
  // large protocol tree does not block paging requests.
  dissect_lock.unlock();
  std::string jsonStr = jRoot.dump();
  return new_java_string(env, jsonStr);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_layanalyzer_NativeEngine_getPacketBytes(JNIEnv *env,
                                                         jobject /* this */,
                                                         jlong sessionPtr,
                                                         jint packetIndex) {
  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth) {
    LOGE("getPacketBytes: Invalid session");
    return env->NewByteArray(0);
  }
  InteractiveReadGuard interactive_guard(session);
  std::vector<guint8> packet_bytes;
  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    if (packetIndex < 0 || packetIndex >= (int)session->frame_offsets.size()) {
      LOGE("getPacketBytes: Invalid index %d", packetIndex);
      return env->NewByteArray(0);
    }

    int64_t offset = session->frame_offsets[packetIndex];
    int err = 0;
    gchar *err_info = nullptr;
    FrameRead packet_frame;
    if (!wtap_seek_read(session->wth, offset, &packet_frame.rec,
                        &packet_frame.buf, &err, &err_info)) {
      LOGE("Failed to read bytes for frame %d: %s", packetIndex,
           err_info ? err_info : "unknown");
      g_free(err_info);
      return env->NewByteArray(0);
    }

    prepare_packet_record(session->wth, &packet_frame.rec);
    const size_t length = packet_data_length(&packet_frame.rec,
                                             &packet_frame.buf);
    if (length > static_cast<size_t>(std::numeric_limits<jsize>::max())) {
      LOGE("Frame %d is too large for a Java byte array: %zu bytes", packetIndex,
           length);
      return env->NewByteArray(0);
    }
    const guint8 *data = ws_buffer_start_ptr(&packet_frame.buf);
    if (data && length > 0) packet_bytes.assign(data, data + length);
  }

  const jsize length = static_cast<jsize>(packet_bytes.size());
  jbyteArray result = env->NewByteArray(length);
  if (result && length > 0) {
    env->SetByteArrayRegion(result, 0, length,
                            reinterpret_cast<const jbyte *>(packet_bytes.data()));
  }
  return result;
}
