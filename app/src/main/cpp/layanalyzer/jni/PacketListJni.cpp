// Packet list JNI endpoints: file opening/indexing, session handles, the
// PacketSummary paging path and cancel/error accessors.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/ProtocolProjection.h"

extern "C" JNIEXPORT jlong JNICALL
Java_com_example_layanalyzer_NativeEngine_openFile(JNIEnv *env,
                                                   jobject /* this */,
                                                   jstring jPath,
                                                   jobject progressCallback) {
  auto engine_activity = acquire_engine_activity();
  if (!engine_activity.active()) {
    set_last_error("Wireshark engine is shutting down.");
    return 0;
  }
  const char *path = env->GetStringUTFChars(jPath, nullptr);
  std::string path_str(path ? path : "");
  int err = 0;
  gchar *err_info = nullptr;
  clear_last_error();

  LOGI("Opening pcap file: %s", path);

  wtap *wth = wtap_open_offline(path, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
  env->ReleaseStringUTFChars(jPath, path);

  if (!wth) {
    set_last_error("Failed to open file: " +
                   std::string(err_info ? err_info : "unknown") +
                   " (err=" + std::to_string(err) + ")");
    g_free(err_info);
    return 0;
  }

  auto *session = new WiresharkSession();
  session->wth = wth;
  session->file_type = wtap_file_type_subtype(wth);
  session->file_encap = wtap_file_encap(wth);

  // Initialize epan session
  session->epan = epan_new((struct packet_provider_data *)session,
                           &layanalyzer_provider_funcs);
  if (!session->epan) {
    set_last_error("Failed to create epan session");
    delete session;
    return 0;
  }

  FrameRead index_frame;

  struct stat file_stat {};
  jlong total_bytes = 0;
  if (stat(path_str.c_str(), &file_stat) == 0) {
    total_bytes = static_cast<jlong>(file_stat.st_size);
  }

  jmethodID progress_method = nullptr;
  if (progressCallback) {
    jclass callback_cls = env->GetObjectClass(progressCallback);
    progress_method = env->GetMethodID(callback_cls, "onProgress", "(IJJ)Z");
  }

  int64_t data_offset = 0;
  while (wtap_read(wth, &index_frame.rec, &index_frame.buf, &err, &err_info, &data_offset)) {
    session->frame_offsets.push_back(data_offset);
    if (progressCallback && progress_method &&
        (session->frame_offsets.size() == 1 ||
         session->frame_offsets.size() % 512 == 0)) {
      jboolean keep_going = env->CallBooleanMethod(
          progressCallback, progress_method,
          static_cast<jint>(session->frame_offsets.size()),
          static_cast<jlong>(std::max<int64_t>(0, data_offset)), total_bytes);
      if (env->ExceptionCheck()) {
        env->ExceptionClear();
        keep_going = JNI_FALSE;
      }
      if (keep_going == JNI_FALSE) {
        set_last_error("Capture indexing was cancelled.");
        delete session;
        return 0;
      }
    }
    index_frame.reset();
  }
  if (err != 0) {
    set_last_error("Stopped scanning capture after " +
                   std::to_string(session->frame_offsets.size()) +
                   " frames: " + std::string(err_info ? err_info : "unknown"));
    g_free(err_info);
    delete session;
    return 0;
  }

  invalidate_summary_cache(session);

  if (progressCallback && progress_method) {
    env->CallBooleanMethod(
        progressCallback, progress_method,
        static_cast<jint>(session->frame_offsets.size()), total_bytes,
        total_bytes);
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
    }
  }

  LOGI("Opened file with %zu frames", session->frame_offsets.size());

  std::unique_lock<std::shared_mutex> registry_lock(g_native_mutex);
  {
    std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
    // cleanup may have started while a large capture was being indexed. Never
    // publish a Session after cleanup detached the registry.
    if (g_engine_shutting_down) {
      delete session;
      set_last_error("Capture indexing completed after engine shutdown began.");
      return 0;
    }
  }
  return register_session_locked(session);
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_layanalyzer_NativeEngine_cancelLongRunningOperations(JNIEnv *env,
                                                                      jobject /* this */) {
  (void)env;
  g_cancel_generation.fetch_add(1, std::memory_order_relaxed);
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_layanalyzer_NativeEngine_cancelSearch(JNIEnv *env,
                                                       jobject /* this */,
                                                       jlong sessionPtr) {
  (void)env;
  if (auto session = acquire_session(sessionPtr)) {
    session->search_request_generation.fetch_add(1, std::memory_order_relaxed);
  }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getLastError(JNIEnv *env,
                                                       jobject /* this */) {
  std::shared_lock<std::shared_mutex> lifetime_lock(g_native_mutex);
  return new_java_string(env, copy_last_error());
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_layanalyzer_NativeEngine_closeFile(JNIEnv *env,
                                                    jobject /* this */,
                                                    jlong sessionPtr) {
  (void)env;
  std::unique_lock<std::shared_mutex> lifetime_lock(g_native_mutex);
  if (auto session = remove_session_locked(sessionPtr)) {
    LOGI("Closing session with %zu frames", session->frame_offsets.size());
  }
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_layanalyzer_NativeEngine_getFrameCount(JNIEnv *env,
                                                        jobject /* this */,
                                                        jlong sessionPtr) {
  (void)env;
  auto session = acquire_session(sessionPtr);
  if (!session) return 0;
  std::shared_lock<std::shared_mutex> state_lock(session->state_mutex);
  return static_cast<jint>(session->frame_offsets.size());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getCaptureEncapsulation(
    JNIEnv *env, jobject /* this */, jlong sessionPtr) {
  auto session = acquire_session(sessionPtr);
  if (!session) return new_java_string(env, "unknown");
  const char *name = wtap_encap_name(session->file_encap);
  return new_java_string(env, name ? name : "unknown");
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_example_layanalyzer_NativeEngine_getPacketSummaries(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jint startIndex,
    jint count) {
  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth) {
    LOGE("getPacketSummaries: Invalid session");
    return nullptr;
  }

  InteractiveReadGuard interactive_guard(session);
  const int total_frames = visible_frame_count(session);
  const int actual_count =
      startIndex >= 0 && startIndex < total_frames && count > 0
          ? std::min(count, total_frames - startIndex)
          : 0;

  if (!ensure_packet_summary_refs(env)) return nullptr;
  jobjectArray result =
      env->NewObjectArray(actual_count, g_packet_summary_class, nullptr);
  if (!result) {
    LOGE("Failed to create packet summary result array");
    return nullptr;
  }

  int result_index = 0;
  for (int page_index = 0; page_index < actual_count; ++page_index) {
    const int frame_index = visible_frame_at(session, startIndex + page_index);
    if (frame_index < 0) continue;

    CachedPacketSummary summary =
        get_or_build_packet_summary(session, frame_index);

    jstring source = new_java_string(env, summary.source);
    jstring destination = new_java_string(env, summary.destination);
    jstring protocol = new_java_string(env, summary.protocol);
    jstring info = new_java_string(env, summary.info);
    jobject summary_object = env->NewObject(
        g_packet_summary_class, g_packet_summary_ctor, frame_index + 1,
        summary.timestamp, source, destination, protocol, summary.length,
        summary.source_port, summary.destination_port, info);
    if (summary_object) {
      env->SetObjectArrayElement(result, result_index++, summary_object);
      env->DeleteLocalRef(summary_object);
    }
    env->DeleteLocalRef(source);
    env->DeleteLocalRef(destination);
    env->DeleteLocalRef(protocol);
    env->DeleteLocalRef(info);
  }
  return result;
}
