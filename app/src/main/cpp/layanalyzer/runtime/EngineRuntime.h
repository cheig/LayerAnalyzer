#pragma once

// Process-wide engine runtime: last-error store, JNI string and PacketSummary
// reference helpers, the global cancellation token, and the packet provider
// callbacks that epan sessions borrow for out-of-frame context queries.

#include <jni.h>
#include <atomic>
#include <string>

struct packet_provider_funcs;

// Bumped by cancelLongRunningOperations(); long scans capture the current
// generation before starting and abort when it no longer matches.
extern std::atomic<uint64_t> g_cancel_generation;

inline uint64_t current_cancel_generation() {
  return g_cancel_generation.load(std::memory_order_relaxed);
}

inline bool long_operation_cancelled(uint64_t generation) {
  return g_cancel_generation.load(std::memory_order_relaxed) != generation;
}

// Records the most recent engine error for getLastError().
void set_last_error(const std::string &message);
// Clears the recorded error; openFile calls this before a new open attempt.
void clear_last_error();

jstring new_java_string(JNIEnv *env, const std::string &value);
jstring new_java_string(JNIEnv *env, const char *value);

// Caches the PacketSummary class and constructor used by getPacketSummaries.
// The accessors below are valid only after ensure_packet_summary_refs()
// returned true for the calling thread's JNIEnv.
bool ensure_packet_summary_refs(JNIEnv *env);
jclass packet_summary_class();
jmethodID packet_summary_ctor();

// Schema marker reported by queryPacketSummaries.
extern const char kScopedQueryVersion[];

// epan sessions receive this provider so Wireshark can query frame timing and
// interface names outside the indexed frame set.
extern const struct packet_provider_funcs layanalyzer_provider_funcs;

// Applies `enabled` to Wireshark's process-global gbl_resolv_flags.
void apply_name_resolution_flags(bool enabled);
