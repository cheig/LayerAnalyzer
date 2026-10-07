// Engine-wide state definitions: lifetime/lease registry, the process-global
// error store, shared JNI string helpers and Wireshark process configuration.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/session/WiresharkSession.h"

std::shared_mutex g_native_mutex;
std::mutex g_lease_mutex;
std::condition_variable g_lease_cv;
std::mutex g_runtime_exclusive_mutex;
size_t g_active_session_leases = 0;
bool g_engine_shutting_down = false;
std::map<jlong, std::shared_ptr<WiresharkSession>> g_sessions;
static jlong g_next_session_handle = 1;
std::atomic<uint64_t> g_cancel_generation{0};
std::atomic<bool> g_rtp_heuristic_enabled{false};
std::atomic<bool> g_esp_null_decryption_enabled{false};

jclass g_packet_summary_class = nullptr;
jmethodID g_packet_summary_ctor = nullptr;

static std::string g_last_error;
static std::mutex g_last_error_mutex;
std::mutex g_jni_ref_mutex;

uint64_t current_cancel_generation() {
  return g_cancel_generation.load(std::memory_order_relaxed);
}

bool long_operation_cancelled(uint64_t generation) {
  return g_cancel_generation.load(std::memory_order_relaxed) != generation;
}

void set_rtp_heuristic_enabled(bool enabled) {
  g_rtp_heuristic_enabled.store(enabled, std::memory_order_relaxed);
}

bool rtp_heuristic_enabled() {
  return g_rtp_heuristic_enabled.load(std::memory_order_relaxed);
}

void set_esp_null_decryption_enabled(bool enabled) {
  g_esp_null_decryption_enabled.store(enabled, std::memory_order_relaxed);
}

bool esp_null_decryption_enabled() {
  return g_esp_null_decryption_enabled.load(std::memory_order_relaxed);
}

void set_last_error(const std::string &message) {
  {
    std::lock_guard<std::mutex> lock(g_last_error_mutex);
    g_last_error = message;
  }
  if (!message.empty()) {
    LOGE("%s", message.c_str());
  }
}

void clear_last_error() {
  std::lock_guard<std::mutex> lock(g_last_error_mutex);
  g_last_error.clear();
}

std::string copy_last_error() {
  std::lock_guard<std::mutex> lock(g_last_error_mutex);
  return g_last_error;
}

jstring new_java_string(JNIEnv *env, const std::string &value) {
  if (value.empty()) {
    return env->NewStringUTF("");
  }

  gchar *valid = g_utf8_make_valid(value.data(), static_cast<gssize>(value.size()));
  if (!valid) {
    return env->NewStringUTF("");
  }

  GError *error = nullptr;
  glong items_written = 0;
  gunichar2 *utf16 = g_utf8_to_utf16(valid, -1, nullptr, &items_written, &error);
  g_free(valid);

  if (!utf16) {
    if (error) {
      LOGW("Failed to convert native UTF-8 string for JNI: %s", error->message);
      g_error_free(error);
    }
    return env->NewStringUTF("");
  }

  jstring result = env->NewString(reinterpret_cast<const jchar *>(utf16),
                                  static_cast<jsize>(items_written));
  g_free(utf16);
  return result;
}

jstring new_java_string(JNIEnv *env, const char *value) {
  return new_java_string(env, std::string(value ? value : ""));
}

bool ensure_packet_summary_refs(JNIEnv *env) {
  if (!env) return false;
  std::lock_guard<std::mutex> lock(g_jni_ref_mutex);
  if (g_packet_summary_class && g_packet_summary_ctor) return true;

  jclass local = env->FindClass("com/example/layanalyzer/core/PacketSummary");
  if (!local) {
    LOGE("Failed to find PacketSummary class");
    return false;
  }
  jmethodID ctor = env->GetMethodID(
      local, "<init>",
      "(IDLjava/lang/String;Ljava/lang/String;Ljava/lang/String;IIILjava/lang/"
      "String;)V");
  if (!ctor) {
    env->DeleteLocalRef(local);
    LOGE("Failed to get PacketSummary constructor");
    return false;
  }
  jclass global = static_cast<jclass>(env->NewGlobalRef(local));
  env->DeleteLocalRef(local);
  if (!global) return false;
  g_packet_summary_class = global;
  g_packet_summary_ctor = ctor;
  return true;
}

void apply_name_resolution_flags(bool enabled) {
  gbl_resolv_flags.mac_name = enabled ? TRUE : FALSE;
  gbl_resolv_flags.transport_name = enabled ? TRUE : FALSE;
  gbl_resolv_flags.network_name = enabled ? TRUE : FALSE;
  gbl_resolv_flags.dns_pkt_addr_resolution = enabled ? TRUE : FALSE;
  gbl_resolv_flags.use_external_net_name_resolver = FALSE;
}

void close_all_sessions_locked() {
  g_sessions.clear();
}

static void advance_session_handle_locked() {
  g_next_session_handle =
      g_next_session_handle == std::numeric_limits<jlong>::max()
          ? 1
          : g_next_session_handle + 1;
}

jlong register_session_locked(WiresharkSession *session) {
  if (!session) return 0;
  while (g_next_session_handle == 0 ||
         g_sessions.find(g_next_session_handle) != g_sessions.end()) {
    advance_session_handle_locked();
  }
  jlong handle = g_next_session_handle;
  advance_session_handle_locked();
  g_sessions.emplace(handle, std::shared_ptr<WiresharkSession>(session));
  return handle;
}

WiresharkSession *find_session_locked(jlong handle) {
  if (handle == 0) return nullptr;
  auto found = g_sessions.find(handle);
  return found == g_sessions.end() ? nullptr : found->second.get();
}

std::shared_ptr<WiresharkSession> remove_session_locked(jlong handle) {
  auto found = g_sessions.find(handle);
  if (found == g_sessions.end()) return nullptr;
  std::shared_ptr<WiresharkSession> session = std::move(found->second);
  session->closed.store(true, std::memory_order_release);
  g_sessions.erase(found);
  return session;
}

SessionLease acquire_session(jlong handle) {
  if (handle == 0) return {};
  std::shared_lock<std::shared_mutex> registry_lock(g_native_mutex);
  auto found = g_sessions.find(handle);
  if (found == g_sessions.end()) return {};
  std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
  if (g_engine_shutting_down) return {};
  ++g_active_session_leases;
  SessionLease lease(found->second);
  lease.mark_counted();
  return lease;
}

SessionLease acquire_engine_activity() {
  std::shared_lock<std::shared_mutex> registry_lock(g_native_mutex);
  std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
  if (g_engine_shutting_down) return {};
  ++g_active_session_leases;
  SessionLease lease;
  lease.mark_counted();
  return lease;
}
