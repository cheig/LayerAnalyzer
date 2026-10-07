// Packet query service: paging summaries over the visible frame set.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/runtime/EngineRuntime.h"
#include "layanalyzer/runtime/SessionRegistry.h"
#include "layanalyzer/session/CaptureSession.h"
#include "layanalyzer/projection/FieldReader.h"
#include "layanalyzer/query/QuerySupport.h"

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
      env->NewObjectArray(actual_count, packet_summary_class(), nullptr);
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
        packet_summary_class(), packet_summary_ctor(), frame_index + 1,
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
