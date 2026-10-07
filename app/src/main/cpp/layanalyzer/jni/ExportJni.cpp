// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Visible-capture pcap export JNI endpoint.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/session/WiresharkSession.h"

// A display filter can match only the final frame of a reassembled PDU.
// Export its dependencies too, otherwise reopening the capture loses that
// PDU (and protocol state such as the SDP which identifies subsequent RTP).
// Work on an export-local snapshot so the UI filter and statistics stay intact.
static bool include_reassembly_dependencies(WiresharkSession *session,
                                            std::vector<int> &frames,
                                            uint64_t cancel_generation,
                                            std::string &error) {
  const size_t total_frames = session->frame_offsets.size();
  if (frames.size() == total_frames) return true;

  std::vector<uint8_t> included(total_frames, 0);
  for (int index : frames) included[index] = 1;

  // Walk newly discovered frames as well: a TCP segment may itself have been
  // reassembled from IP fragments. The bitmap also prevents duplicates/cycles.
  for (size_t cursor = 0; cursor < frames.size(); ++cursor) {
    if (session->closed.load() || long_operation_cancelled(cancel_generation)) {
      error = "Operation cancelled.";
      return false;
    }
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      // Filtering has already dissected the capture. Revisit with a visible
      // tree so Wireshark emits its protocol-independent dependent_frames list.
      if (!dissect_frame(session, frames[cursor], TRUE, FALSE, nullptr, frame)) {
        error = "Unable to read packet reassembly dependencies.";
        return false;
      }
      for (GSList *item = frame.edt->pi.dependent_frames; item; item = item->next) {
        const guint32 number = GPOINTER_TO_UINT(item->data);
        if (number == 0 || number > total_frames) continue;
        const int index = static_cast<int>(number - 1);
        if (!included[index]) {
          included[index] = 1;
          frames.push_back(index);
        }
      }
    }
    yield_to_interactive_reads(session);
  }
  std::sort(frames.begin(), frames.end());
  return true;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_exportVisibleCapture(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring jOutputPath) {
  auto session = acquire_session(sessionPtr);
  json result = {{"success", false}, {"count", 0}, {"error", ""}};
  if (!session || !session->wth) {
    result["error"] = "No capture is open.";
    return new_java_string(env, result.dump());
  }
  std::vector<int> export_frames = snapshot_visible_frames(session);
  const int count = static_cast<int>(export_frames.size());
  if (count <= 0) {
    result["error"] = "No packets are available to export.";
    return new_java_string(env, result.dump());
  }

  const char *path_chars = env->GetStringUTFChars(jOutputPath, nullptr);
  std::string output_path = path_chars ? path_chars : "";
  env->ReleaseStringUTFChars(jOutputPath, path_chars);
  if (output_path.empty()) {
    result["error"] = "An output path is required.";
    return new_java_string(env, result.dump());
  }

  const uint64_t cancel_generation = current_cancel_generation();
  std::string dependency_error;
  if (!include_reassembly_dependencies(session, export_frames, cancel_generation,
                                       dependency_error)) {
    result["error"] = dependency_error;
    return new_java_string(env, result.dump());
  }

  int first_index = export_frames.front();
  int err = 0;
  gchar *err_info = nullptr;
  int first_encap = WTAP_ENCAP_UNKNOWN;
  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    FrameRead first;
    if (!wtap_seek_read(session->wth, session->frame_offsets[first_index],
                        &first.rec, &first.buf, &err, &err_info)) {
      result["error"] = err_info ? err_info : "Unable to read the first packet.";
      g_free(err_info);
      return new_java_string(env, result.dump());
    }
    prepare_packet_record(session->wth, &first.rec);
    first_encap = first.rec.rec_header.packet_header.pkt_encap;
  }
  int link_type = link_type_for_encapsulation(first_encap);
  if (link_type < 0) {
    result["error"] =
        "The capture encapsulation cannot be represented as classic pcap.";
    return new_java_string(env, result.dump());
  }
  uint32_t snapshot_length = wtap_snapshot_length(session->wth);
  if (snapshot_length == 0) snapshot_length = 65535;

  FILE *output = fopen(output_path.c_str(), "wb");
  if (!output) {
    result["error"] = "Unable to open the output file.";
    return new_java_string(env, result.dump());
  }
  bool ok = write_le32(output, 0xa1b2c3d4u) && write_le16(output, 2) &&
            write_le16(output, 4) && write_le32(output, 0) &&
            write_le32(output, 0) && write_le32(output, snapshot_length) &&
            write_le32(output, static_cast<uint32_t>(link_type));
  int exported = 0;
  for (int frame_index : export_frames) {
    if (!ok) break;
    if (session->closed.load() || long_operation_cancelled(cancel_generation)) {
      result["error"] = "Operation cancelled.";
      ok = false;
      break;
    }
    std::vector<guint8> packet_bytes;
    guint captured_length = 0;
    guint original_length = 0;
    int64_t seconds = 0;
    int32_t micros = 0;
    err = 0;
    err_info = nullptr;
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      FrameRead frame;
      if (!wtap_seek_read(session->wth, session->frame_offsets[frame_index],
                          &frame.rec, &frame.buf, &err, &err_info)) {
        result["error"] = err_info ? err_info : "Unable to read a packet.";
        g_free(err_info);
        ok = false;
      } else {
        prepare_packet_record(session->wth, &frame.rec);
        int frame_encap = frame.rec.rec_header.packet_header.pkt_encap;
        if (frame_encap != first_encap) {
          result["error"] =
              "Mixed link-layer encapsulations cannot be exported as classic pcap.";
          ok = false;
        }
        captured_length = packet_data_length(&frame.rec, &frame.buf);
        original_length = frame.rec.rec_header.packet_header.len;
        const guint8 *data = ws_buffer_start_ptr(&frame.buf);
        if (data && captured_length > 0) {
          packet_bytes.assign(data, data + captured_length);
        }
        if (frame.rec.presence_flags & WTAP_HAS_TS) {
          seconds = std::max<int64_t>(0, frame.rec.ts.secs);
          micros = std::max<int32_t>(0, frame.rec.ts.nsecs / 1000);
        }
      }
    }
    if (!ok) break;
    ok = write_le32(output, static_cast<uint32_t>(seconds)) &&
         write_le32(output, static_cast<uint32_t>(micros)) &&
         write_le32(output, captured_length) &&
         write_le32(output, original_length) &&
         (captured_length == 0 ||
          fwrite(packet_bytes.data(), 1, captured_length, output) ==
              captured_length);
    if (ok) exported++;
    yield_to_interactive_reads(session);
  }
  if (fflush(output) != 0 || ferror(output)) ok = false;
  if (fclose(output) != 0) ok = false;
  if (!ok) {
    if (result["error"].get<std::string>().empty()) {
      result["error"] = "Unable to write the output capture.";
    }
    remove(output_path.c_str());
  } else {
    result["success"] = true;
    result["count"] = exported;
  }
  return new_java_string(env, result.dump());
}
