// Process-wide Wireshark configuration JNI endpoints: name resolution,
// Decode As and ESP NULL-encryption decryption. All serialize through
// RuntimeExclusiveGuard because the underlying Wireshark state is
// process-global.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/projection/ProtocolProjection.h"
#include "layanalyzer/session/WiresharkSession.h"
#include <epan/prefs.h>

extern "C" JNIEXPORT void JNICALL
Java_com_example_layanalyzer_NativeEngine_setNameResolutionEnabled(JNIEnv *env,
                                                                   jobject /* this */,
                                                                   jlong sessionPtr,
                                                                   jboolean enabled) {
  (void)env;
  RuntimeExclusiveGuard runtime_guard;
  auto *session = find_session_locked(sessionPtr);
  if (session) {
    bool next_enabled = enabled == JNI_TRUE;
    for (const auto &entry : g_sessions) {
      WiresharkSession *open_session = entry.second.get();
      if (open_session->name_resolution_enabled != next_enabled) {
        open_session->name_resolution_enabled = next_enabled;
        invalidate_summary_cache(open_session);
        invalidate_scoped_query_cache(open_session);
      }
    }
    apply_name_resolution_flags(next_enabled);
  }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_applyDecodeAs(JNIEnv *env,
                                                        jobject /* this */,
                                                        jlong sessionPtr,
                                                        jstring jTableName,
                                                        jint port,
                                                        jstring jDissectorName) {
  RuntimeExclusiveGuard runtime_guard;
  auto *session = find_session_locked(sessionPtr);
  json result = {{"success", false}, {"error", ""}};
  if (!session || !session->epan) {
    result["error"] = "No capture is open.";
    return new_java_string(env, result.dump());
  }
  if (port < 0 || port > 65535) {
    result["error"] = "Port must be between 0 and 65535.";
    return new_java_string(env, result.dump());
  }

  const char *tableChars = env->GetStringUTFChars(jTableName, nullptr);
  const char *dissectorChars = env->GetStringUTFChars(jDissectorName, nullptr);
  std::string tableName = tableChars ? tableChars : "";
  std::string dissectorName = dissectorChars ? dissectorChars : "";
  env->ReleaseStringUTFChars(jTableName, tableChars);
  env->ReleaseStringUTFChars(jDissectorName, dissectorChars);

  if (tableName.empty() || dissectorName.empty()) {
    result["error"] = "Decode As table and protocol are required.";
    return new_java_string(env, result.dump());
  }

  dissector_handle_t handle = find_dissector(dissectorName.c_str());
  if (!handle) {
    result["error"] = "Unknown dissector: " + dissectorName;
    return new_java_string(env, result.dump());
  }

  dissector_change_uint(tableName.c_str(), static_cast<guint32>(port), handle);
  reset_dissection_state();
  result["success"] = true;
  result["error"] = "";
  return new_java_string(env, result.dump());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_resetDecodeAs(JNIEnv *env,
                                                        jobject /* this */,
                                                        jlong sessionPtr,
                                                        jstring jTableName,
                                                        jint port) {
  RuntimeExclusiveGuard runtime_guard;
  auto *session = find_session_locked(sessionPtr);
  json result = {{"success", false}, {"error", ""}};
  if (!session || !session->epan) {
    result["error"] = "No capture is open.";
    return new_java_string(env, result.dump());
  }
  const char *tableChars = env->GetStringUTFChars(jTableName, nullptr);
  std::string tableName = tableChars ? tableChars : "";
  env->ReleaseStringUTFChars(jTableName, tableChars);
  if (tableName.empty()) {
    result["error"] = "Decode As table is required.";
    return new_java_string(env, result.dump());
  }

  dissector_reset_uint(tableName.c_str(), static_cast<guint32>(port));
  reset_dissection_state();
  result["success"] = true;
  return new_java_string(env, result.dump());
}

// ---------------------------------------------------------------------------
// ESP NULL-encryption decryption
//
// Wireshark ships the whole mechanism: the
// `esp.enable_null_encryption_decode_heuristic` preference. When it is on,
// packet-esp.c tries ICV lengths 12/16/24/32, validates the ESP padding and
// only accepts a decode when the derived next-header dissector accepts the
// inner packet. Enabling it is therefore a one-preference change; nothing
// here reimplements ESP.
//
// The preference is process-global, so every write happens inside a
// RuntimeExclusiveGuard and every open session's caches are dropped.
// ---------------------------------------------------------------------------

namespace {

constexpr const char *kEspNullDecryptionPref =
    "esp.enable_null_encryption_decode_heuristic";

// Upper bound on how many frames `probe` dissects while looking for a decodable
// ESP payload. The probe has to decode frames, so it cannot run inside a
// RuntimeExclusiveGuard; the cap keeps an ESP-free megacapture from paying a
// full-capture scan before the first page is shown.
constexpr int kEspProbeMaxFrames = 5000;

// Flips the Wireshark preference and resets the cached and cross-frame
// dissection state so the next pass runs under the new setting. Callers must
// hold the runtime exclusively: the preference is global epan state, and no
// session may be dissecting while it changes.
bool apply_esp_null_decryption_locked(bool enabled, std::string &error) {
  std::string argument =
      std::string(kEspNullDecryptionPref) + (enabled ? ":TRUE" : ":FALSE");
  // prefs_set_pref() splits the string on ':' in place, so it needs a mutable
  // buffer that outlives the call.
  std::vector<char> buffer(argument.begin(), argument.end());
  buffer.push_back('\0');

  char *error_message = nullptr;
  const prefs_set_pref_e outcome = prefs_set_pref(buffer.data(), &error_message);
  if (outcome != PREFS_SET_OK) {
    error = error_message ? error_message
                          : "Unable to set the ESP decryption preference.";
    if (error_message) g_free(error_message);
    return false;
  }
  if (error_message) g_free(error_message);

  set_esp_null_decryption_enabled(enabled);
  reset_dissection_state();
  return true;
}

// True when at least one of the first kEspProbeMaxFrames frames of the capture
// holds an ESP payload the heuristic decoded. `esp.protocol` is added to the
// tree only by a successful decode (packet-esp.c), so its presence is the
// signal and it also implies the frame carried ESP in the first place.
//
// Walks the physical frame list, deliberately *not* the display-filtered view:
// the answer is a property of the capture ("does it carry null-encrypted
// ESP?"), so it must not change when the user edits the display filter. A
// filtered sample would also make the outcome depend on which frames happened
// to be visible when the preference was applied.
bool probe_esp_null_decryption(WiresharkSession *session, int &frames_scanned,
                               uint64_t cancel_generation) {
  frames_scanned = 0;
  const int frame_count = static_cast<int>(session->frame_offsets.size());
  const int limit = std::min(frame_count, kEspProbeMaxFrames);
  for (int frame_index = 0; frame_index < limit; ++frame_index) {
    if (long_operation_cancelled(cancel_generation)) break;

    bool decoded = false;
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      if (!dissect_frame(session, frame_index, TRUE, TRUE, nullptr, frame)) {
        continue;
      }
      FieldIndex fields(frame.edt->tree);
      std::string next_header;
      decoded = fields.find({"esp.protocol"}, next_header);
    }
    frames_scanned++;
    if (decoded) return true;
    yield_to_interactive_reads(session);
  }
  return false;
}

}  // namespace

// Applies one of {"off", "probe", "all"} and reports what happened as
// {"schemaVersion":1,"mode":<m>,"enabled":<b>,"decoded":<b>,
//  "framesScanned":<n>,"error":""}.
//
// "probe" is the default: the preference is switched on, the capture is
// sampled for a decodable ESP frame, and it is switched back off when nothing
// decodes -- fail-closed, so a capture of genuinely encrypted ESP keeps its
// opaque dissection.
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_setEspDecryptionMode(JNIEnv *env,
                                                               jobject /* this */,
                                                               jlong sessionPtr,
                                                               jstring jMode) {
  const char *mode_chars = env->GetStringUTFChars(jMode, nullptr);
  const std::string mode = mode_chars ? mode_chars : "";
  if (mode_chars) env->ReleaseStringUTFChars(jMode, mode_chars);

  json root = {{"schemaVersion", 1},
               {"mode", mode},
               {"enabled", false},
               {"decoded", false},
               {"framesScanned", 0},
               {"error", ""}};

  const bool valid_mode = mode == "off" || mode == "probe" || mode == "all";
  if (!valid_mode) {
    root["error"] = "Unknown ESP decryption mode: " + mode;
    return new_java_string(env, root.dump());
  }

  if (mode != "probe") {
    const bool enabled = mode == "all";
    std::string error;
    {
      RuntimeExclusiveGuard runtime_guard;
      if (!apply_esp_null_decryption_locked(enabled, error)) {
        root["error"] = error;
        return new_java_string(env, root.dump());
      }
    }
    root["enabled"] = enabled;
    root["decoded"] = enabled;
    return new_java_string(env, root.dump());
  }

  // "probe": turn the preference on, sample the capture, keep it only if the
  // sample decoded. The two preference writes are guarded; the sampling
  // between them takes the session lease instead, because the guard blocks
  // exactly the dissection the probe needs.
  std::string error;
  {
    RuntimeExclusiveGuard runtime_guard;
    if (!apply_esp_null_decryption_locked(true, error)) {
      root["error"] = error;
      return new_java_string(env, root.dump());
    }
  }

  bool decoded = false;
  int frames_scanned = 0;
  const uint64_t cancel_generation = current_cancel_generation();
  {
    SessionLease session = acquire_session(sessionPtr);
    if (session && session->wth && session->epan) {
      decoded = probe_esp_null_decryption(session.get(), frames_scanned,
                                          cancel_generation);
    }
  }

  if (!decoded) {
    std::string revert_error;
    RuntimeExclusiveGuard runtime_guard;
    if (!apply_esp_null_decryption_locked(false, revert_error)) {
      root["error"] = revert_error;
      return new_java_string(env, root.dump());
    }
  }

  root["enabled"] = decoded;
  root["decoded"] = decoded;
  root["framesScanned"] = frames_scanned;
  LOGI("setEspDecryptionMode: probe decoded=%d framesScanned=%d", decoded ? 1 : 0,
       frames_scanned);
  return new_java_string(env, root.dump());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_layanalyzer_NativeEngine_isEspNullDecryptionEnabled(
    JNIEnv * /* env */, jobject /* this */) {
  return esp_null_decryption_enabled() ? JNI_TRUE : JNI_FALSE;
}
