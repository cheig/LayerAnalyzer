// Engine-wide state shared across the LayerAnalyzer JNI modules.
//
// These symbols were file-local inside the former single translation unit.
// They are declared here only so the legacy modules can compile as separate
// translation units with unchanged behaviour; new code must go through the
// runtime/session services instead of touching these globals directly.
#pragma once
#include "layanalyzer/internal/Common.h"

struct WiresharkSession;
class SessionLease;

// ---- Lifetime, lease and registry state -------------------------------
// Protects engine lifetime and opaque session handles. Session work takes a
// shared lifetime lock; open/close/cleanup update the handle registry under
// the exclusive lock so a queued call can reject a handle closed before it
// acquired the lock.
extern std::shared_mutex g_native_mutex;
// Session leases are counted separately from the registry lock.  This lets
// closeFile detach a handle without waiting for a background scan, while
// cleanup can still quiesce all Wireshark users before epan_cleanup().
extern std::mutex g_lease_mutex;
extern std::condition_variable g_lease_cv;
// Serializes process-wide Wireshark configuration transitions (Decode As,
// name resolution and cleanup-adjacent guards).
extern std::mutex g_runtime_exclusive_mutex;
extern size_t g_active_session_leases;
extern bool g_engine_shutting_down;
extern std::map<jlong, std::shared_ptr<WiresharkSession>> g_sessions;
extern std::atomic<uint64_t> g_cancel_generation;
// Process-wide RTP heuristic toggle (RTP1-NAT-05). It mirrors the state of the
// four `rtp_*` Wireshark heuristics; writes happen inside a
// RuntimeExclusiveGuard, reads never lock.
extern std::atomic<bool> g_rtp_heuristic_enabled;
// Process-wide ESP NULL-encryption decryption toggle. It mirrors Wireshark's
// `esp.enable_null_encryption_decode_heuristic` preference, which is global
// epan state: writes happen under RuntimeExclusiveGuard, reads never lock.
extern std::atomic<bool> g_esp_null_decryption_enabled;

// ---- PacketSummary JNI class refs (created lazily, released on unload) --
extern jclass g_packet_summary_class;
extern jmethodID g_packet_summary_ctor;
// Guards the refs above in both ensure (EngineState.cpp) and release
// (jni/EngineLifecycle.cpp) paths.
extern std::mutex g_jni_ref_mutex;
bool ensure_packet_summary_refs(JNIEnv *env);

// ---- Process-global error store ----------------------------------------
void set_last_error(const std::string &message);
void clear_last_error();
std::string copy_last_error();

// ---- Cancellation -------------------------------------------------------
uint64_t current_cancel_generation();
bool long_operation_cancelled(uint64_t generation);

// ---- Process-wide RTP heuristic toggle (RTP1-NAT-05) --------------------
// Setting the toggle is only half the job: callers must serialize the epan
// transition through RuntimeExclusiveGuard and invalidate every open
// session's caches.  The reader is a plain atomic load (no lock).
void set_rtp_heuristic_enabled(bool enabled);
bool rtp_heuristic_enabled();

// ---- Process-wide ESP NULL-encryption decryption toggle -------------------
// Same contract as the RTP heuristic toggle above: the setter must run inside
// a RuntimeExclusiveGuard and callers must invalidate every open session's
// caches. The reader is a plain atomic load (no lock).
void set_esp_null_decryption_enabled(bool enabled);
bool esp_null_decryption_enabled();

// ---- Shared JNI helpers -------------------------------------------------
jstring new_java_string(JNIEnv *env, const std::string &value);
jstring new_java_string(JNIEnv *env, const char *value);

// ---- Wireshark process configuration and session registry ---------------
void apply_name_resolution_flags(bool enabled);
void close_all_sessions_locked();
jlong register_session_locked(WiresharkSession *session);
WiresharkSession *find_session_locked(jlong handle);
std::shared_ptr<WiresharkSession> remove_session_locked(jlong handle);
SessionLease acquire_session(jlong handle);
SessionLease acquire_engine_activity();

// Provider callbacks installed into every epan session (defined in
// jni/EngineLifecycle.cpp; openFile needs the object's address).
extern const struct packet_provider_funcs layanalyzer_provider_funcs;
