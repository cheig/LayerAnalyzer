// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Packet detail JNI endpoints: protocol-tree JSON serialization and raw
// packet bytes.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/internal/TextUtils.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/ProtocolProjection.h"
#include "layanalyzer/projection/TextEncoding.h"
#include "layanalyzer/projection/TreeFieldReader.h"

namespace {

/**
 * Fields that carry a declared charset. HTTP/1.1 exposes the parsed
 * Content-Type directly; HTTP/2 keeps header names and values in separate
 * fields, but "charset=" only ever appears in a content-type value, so a
 * header value that mentions it is one.
 */
const char *const kCharsetHintFields[] = {
    "http.content_type",
    "http.header.value",
    "http2.header.value",
    "mime.multipart.content_type",
};

/**
 * Field types whose label is the field's own captured text. Only these may be
 * rebuilt from raw bytes: for anything else the label is a formatted value
 * (hex dump, number, composed sentence) and replacing it would lose meaning.
 */
bool is_text_type(ftenum_t type) {
  return type == FT_STRING || type == FT_STRINGZ || type == FT_STRINGZPAD;
}

layanalyzer::projection::TextCharset sniff_declared_charset(proto_node *node) {
  if (!node) return layanalyzer::projection::TextCharset::kAuto;
  for (proto_node *current = node->first_child; current;
       current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo && finfo->hfinfo && finfo->hfinfo->abbrev) {
      const std::string abbrev = lowercase_copy(finfo->hfinfo->abbrev);
      for (const char *candidate : kCharsetHintFields) {
        if (abbrev != candidate) continue;
        const layanalyzer::projection::TextCharset parsed =
            layanalyzer::projection::charset_from_content_type(
                get_filter_value(finfo));
        if (parsed != layanalyzer::projection::TextCharset::kAuto) {
          return parsed;
        }
      }
    }
    const layanalyzer::projection::TextCharset nested =
        sniff_declared_charset(current);
    if (nested != layanalyzer::projection::TextCharset::kAuto) return nested;
  }
  return layanalyzer::projection::TextCharset::kAuto;
}

/**
 * Per-packet declared charset, resolved on first use.
 *
 * Sniffing walks the protocol tree, and the P2-1 conversion only needs an
 * answer when a label is not UTF-8 in the first place -- rare per packet. A
 * lazily resolved value keeps the common path at one g_utf8_validate().
 */
class LazyCharsetHint {
 public:
  explicit LazyCharsetHint(proto_node *root) : root_(root) {}

  layanalyzer::projection::TextCharset get() {
    if (!resolved_) {
      resolved_ = true;
      charset_ = sniff_declared_charset(root_);
    }
    return charset_;
  }

 private:
  proto_node *root_;
  bool resolved_ = false;
  layanalyzer::projection::TextCharset charset_ =
      layanalyzer::projection::TextCharset::kAuto;
};

}  // namespace

static std::string recursive_tree_walk(
    proto_node *node, json &jMsg,
    const layanalyzer::tls::PacketDataSnapshot& snapshot,
    const layanalyzer::tls::PacketSourceBindings& bindings,
    const layanalyzer::projection::CharsetProvider& charset_hint) {
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

    // Data source mapping. Resolved before the label because P2-1 may need the
    // field's raw bytes to rebuild text the dissector has already sanitised.
    jItem["start"] = finfo->start < 0 ? 0 : finfo->start;
    jItem["length"] = finfo->length < 0 ? 0 : finfo->length;
    jItem["generated"] = FI_GET_FLAG(finfo, FI_GENERATED) != 0;
    jItem["dataSourceId"] = nullptr;
    jItem["offsetValid"] = false;
    const layanalyzer::tls::PacketDataSource* source_data = nullptr;
    auto source = bindings.find(finfo->ds_tvb);
    if (source != bindings.end()) {
      const auto& data = snapshot.sources[source->second];
      jItem["dataSourceId"] = data.id;
      jItem["offsetValid"] = !FI_GET_FLAG(finfo, FI_GENERATED) &&
          finfo->start >= 0 && finfo->length > 0 &&
          static_cast<size_t>(finfo->start) <= data.bytes.size() &&
          static_cast<size_t>(finfo->length) <= data.bytes.size() - finfo->start;
      if (jItem["offsetValid"].get<bool>()) source_data = &data;
    }

    // Label
    // P2-1: a GBK page or a GBK header value makes this label non-UTF-8, and
    // several dissectors (HTTP request/response line, COL_INFO) replace those
    // bytes with U+FFFD before the label exists at all. Decode the label when
    // it still carries the bytes, and otherwise rebuild it from the field's
    // data source. filterValue is deliberately left byte-exact: it is pasted
    // back into a display filter, where a transcoded value would look valid
    // while never matching the captured bytes.
    std::string label = get_node_text(finfo);
    if (label.empty() && finfo->hfinfo) {
      label = finfo->hfinfo->name;
    }
    if (source_data && finfo->hfinfo && is_text_type(finfo->hfinfo->type)) {
      label = layanalyzer::projection::recover_text_from_source(
          std::move(label), reinterpret_cast<const char*>(source_data->bytes.data()) + finfo->start,
          static_cast<size_t>(finfo->length), charset_hint);
    }
    jItem["label"] =
        layanalyzer::projection::to_display_utf8(std::move(label), charset_hint);
    jItem["hidden"] = FI_GET_FLAG(finfo, FI_HIDDEN) != 0;
    if (severity_rank(itemSeverity) > severity_rank(highest)) {
      highest = itemSeverity;
    }

    // Children
    if (current->first_child) {
      json jChildren = json::array();          // Create array for children
      std::string childSeverity = recursive_tree_walk(current, jChildren, snapshot, bindings, charset_hint);
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
  try {
    DissectedFrame frame;
    if (!dissect_frame(session, packetIndex, TRUE, FALSE, nullptr, frame)) {
      LOGE("getPacketDetails: Failed to dissect frame %d", packetIndex);
      return new_java_string(env, "{}");
    }

    // Convert Protocol Tree to JSON while packet-scope Wireshark memory is
    // valid. The DissectedFrame is destroyed before releasing dissect_mutex.
    layanalyzer::tls::PacketSourceBindings bindings;
    auto snapshot = layanalyzer::tls::buildDataSnapshot(*session.get(), frame, bindings);
    // P2-1: the declared charset lives in the tree, so the hint is resolved
    // lazily against the tree being serialized.
    LazyCharsetHint charset_state(frame.edt->tree);
    const layanalyzer::projection::CharsetProvider charset_hint =
        [&charset_state] { return charset_state.get(); };
    json jChildren = json::array();
    std::string rootSeverity = recursive_tree_walk(frame.edt->tree, jChildren, snapshot, bindings, charset_hint);
    jRoot["schemaVersion"] = 1;
    jRoot["success"] = true;
    jRoot["errorCode"] = nullptr;
    jRoot["error"] = nullptr;
    jRoot["snapshotId"] = snapshot.id;
    jRoot["dissectionGeneration"] = snapshot.generation;
    jRoot["frameNumber"] = snapshot.frame_number;
    jRoot["dataSourceId"] = nullptr;
    jRoot["offsetValid"] = false;
    jRoot["label"] = "Packet " + std::to_string(packetIndex + 1);
    jRoot["severity"] = rootSeverity;
    jRoot["children"] = std::move(jChildren);
    if (session->closed.load()) return new_java_string(env, "{}");
    layanalyzer::tls::retainDataSnapshot(*session.get(), std::move(snapshot));
  } catch (...) {
    // Keep legacy detail failure semantics for existing callers; the source
    // APIs use structured failures. Never publish a tree without its snapshot.
    LOGE("getPacketDetails: Cannot create packet data snapshot");
    return new_java_string(env, "{}");
  }

  // All Wireshark pointers have been consumed into value-based JSON. Release
  // the dissection mutex before serializing/allocating the Java string so a
  // large protocol tree does not block paging requests.
  dissect_lock.unlock();
  std::string jsonStr = dump_json(jRoot);
  return new_java_string(env, jsonStr);
}

/**
 * One frame of the TLS priming scan.
 *
 * The scan has to dissect every frame in capture order: that in-order pass is
 * what rebuilds Wireshark's cross-frame reassembly state, which a later
 * single-frame read needs before it can decrypt a record that spans segments.
 * The rest of getPacketDetails is not part of that job -- serialising the whole
 * protocol tree, retaining a data snapshot and its byte copy, then a second JNI
 * call to ask what sources it produced. On a few thousand frames that made the
 * scan long enough to freeze the packet list for the whole reconfiguration.
 *
 * Every frame is classified, including the ones after the first plaintext was
 * seen: P2-2 stopped classifying there to save work, which also made the counts
 * "first hit" rather than totals, and left the scan unable to say how many
 * connections decrypted. A data source is two node visits per frame, next to a
 * dissection that already happened, so the totals are affordable.
 *
 * The reply is counts and identity only: never a source label, offset or byte.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_probeTlsPlaintext(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jint packetIndex) {
  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    LOGE("probeTlsPlaintext: Invalid session");
    return new_java_string(env, "{}");
  }
  InteractiveReadGuard interactive_guard(session);
  std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);

  if (packetIndex < 0 || packetIndex >= (int)session->frame_offsets.size()) {
    LOGE("probeTlsPlaintext: Invalid index %d", packetIndex);
    return new_java_string(env, "{}");
  }

  json jResult;
  try {
    DissectedFrame frame;
    // Same dissection shape as getPacketDetails: the tree exists (data sources
    // and label state hang off it) but its columns are not built.
    if (!dissect_frame(session, packetIndex, true, false, nullptr, frame)) {
      LOGE("probeTlsPlaintext: Failed to dissect frame %d", packetIndex);
      return new_java_string(env, "{}");
    }
    const auto probe = layanalyzer::tls::probeDecryptedSources(frame);
    jResult = {{"schemaVersion", 1}, {"success", true}, {"errorCode", nullptr},
               {"decryptedSources", probe.sources}, {"decryptedBytes", probe.bytes},
               {"observed", probe.observed}, {"streamId", probe.stream},
               {"tlsVersion", probe.tls_version}};
    if (session->closed.load()) return new_java_string(env, "{}");
  } catch (...) {
    // A frame the dissectors reject is a scan failure, not "no plaintext".
    LOGE("probeTlsPlaintext: Cannot inspect frame %d", packetIndex);
    return new_java_string(env, "{}");
  }

  dissect_lock.unlock();
  return new_java_string(env, dump_json(jResult));
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
