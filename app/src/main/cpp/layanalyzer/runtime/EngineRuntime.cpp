// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Process-wide engine runtime: logging, report callbacks, last-error store,
// JNI string/PacketSummary helpers, cancellation token, packet provider and
// the initEngine/getVersion/cleanup/initCaresAndroid JNI entry points.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/runtime/EngineRuntime.h"
#include "layanalyzer/runtime/SessionRegistry.h"

std::atomic<uint64_t> g_cancel_generation{0};
static const char *kNativeBuildMarker = "core-correlation-20260804-01";
const char kScopedQueryVersion[] = "native-scoped-v1";

static std::string g_last_error;
static std::mutex g_last_error_mutex;

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

static void wslog_writer(const char *domain, enum ws_log_level level,
                         struct timespec timestamp, const char *file, long line,
                         const char *func, const char *user_format,
                         va_list user_ap, void *user_data) {
  (void)timestamp;
  (void)file;
  (void)line;
  (void)func;
  (void)user_data;

  int android_level = 4; // INFO
  if (level >= LOG_LEVEL_ERROR) {
    android_level = 6; // ERROR
  } else if (level >= LOG_LEVEL_WARNING) {
    android_level = 5; // WARN
  } else if (level >= LOG_LEVEL_DEBUG) {
    android_level = 3; // DEBUG
  }
  __android_log_vprint(android_level, domain ? domain : "Wireshark",
                       user_format, user_ap);
}

static void wslog_vcmdarg_err(const char *format, va_list ap) {
  __android_log_vprint(6, "Wireshark-Init", format, ap);
}

static void glib_log_handler(const gchar *log_domain, GLogLevelFlags log_level,
                             const gchar *message, gpointer user_data) {
  (void)user_data;
  int android_level = 3; // DEBUG
  if (log_level & (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL)) {
    android_level = 6; // ERROR
  } else if (log_level & G_LOG_LEVEL_WARNING) {
    android_level = 5; // WARN
  } else if (log_level & G_LOG_LEVEL_INFO) {
    android_level = 4; // INFO
  }
  __android_log_print(android_level, log_domain ? log_domain : "GLib", "%s",
                      message);
}

// Global JavaVM reference
JavaVM *gJvm = nullptr;
static std::mutex g_jni_ref_mutex;
static jclass g_packet_summary_class = nullptr;
static jmethodID g_packet_summary_ctor = nullptr;

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

jclass packet_summary_class() { return g_packet_summary_class; }
jmethodID packet_summary_ctor() { return g_packet_summary_ctor; }

static void release_jni_refs(JavaVM *vm) {
  if (!vm) return;
  JNIEnv *env = nullptr;
  if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK ||
      !env) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_jni_ref_mutex);
  if (g_packet_summary_class) {
    env->DeleteGlobalRef(g_packet_summary_class);
    g_packet_summary_class = nullptr;
    g_packet_summary_ctor = nullptr;
  }
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)reserved;
  gJvm = vm;
  LOGI("Native build marker: %s", kNativeBuildMarker);

#if defined(ANDROID) || defined(__ANDROID__)
  ares_library_init_jvm(vm);
  LOGI("ares_library_init_jvm called");
#else
  LOGW("c-ares Android JVM init not available - DNS resolution may fail");
#endif

  return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
  (void)reserved;
  release_jni_refs(vm);
  gJvm = nullptr;
}

// Wireshark reporting callbacks
static void vreport_failure_cb(const char *msg_format, va_list ap) {
  __android_log_vprint(6, TAG, msg_format, ap);
}

static void vreport_warning_cb(const char *msg_format, va_list ap) {
  __android_log_vprint(5, TAG, msg_format, ap);
}

static void report_open_failure_cb(const char *filename, int err,
                                   gboolean for_writing) {
  LOGE("Wireshark Open Failure: %s (error %d, writing %d)", filename, err,
       (int)for_writing);
}

static void report_read_failure_cb(const char *filename, int err) {
  LOGE("Wireshark Read Failure: %s (error %d)", filename, err);
}

static void report_write_failure_cb(const char *filename, int err) {
  LOGE("Wireshark Write Failure: %s (error %d)", filename, err);
}

static void report_cfile_open_failure_cb(const char *filename, int err,
                                         gchar *err_info) {
  LOGE("Wireshark Capture Open Failure: %s (error %d, info: %s)", filename, err,
       err_info ? err_info : "none");
}

static void report_cfile_dump_open_failure_cb(const char *filename, int err,
                                              gchar *err_info,
                                              int file_type_subtype) {
  LOGE("Wireshark Capture Dump Open Failure: %s (error %d)", filename, err);
}

static void report_cfile_read_failure_cb(const char *filename, int err,
                                         gchar *err_info) {
  LOGE("Wireshark Capture Read Failure: %s (error %d)", filename, err);
}

static void report_cfile_write_failure_cb(const char *in_filename,
                                          const char *out_filename, int err,
                                          gchar *err_info, uint32_t framenum,
                                          int file_type_subtype) {
  LOGE("Wireshark Capture Write Failure");
}

static void report_cfile_close_failure_cb(const char *filename, int err,
                                          gchar *err_info) {
  LOGE("Wireshark Capture Close Failure: %s", filename);
}

static const report_message_routines layanalyzer_report_routines = {
    vreport_failure_cb,
    vreport_warning_cb,
    report_open_failure_cb,
    report_read_failure_cb,
    report_write_failure_cb,
    report_cfile_open_failure_cb,
    report_cfile_dump_open_failure_cb,
    report_cfile_read_failure_cb,
    report_cfile_write_failure_cb,
    report_cfile_close_failure_cb};

// Helper function to create directory
static void make_dir(const char *path) { mkdir(path, 0755); }

// Helper to set environment variable
static void set_env_var(const char *key, const char *value) {
  if (setenv(key, value, 1) != 0) {
    LOGE("Failed to set env var: %s=%s", key, value);
  }
}

static bool local_file_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_layanalyzer_NativeEngine_initEngine(JNIEnv *env,
                                                     jobject /* this */,
                                                     jstring jAppDataDir) {
  std::unique_lock<std::shared_mutex> lifetime_lock(g_native_mutex);

  {
    std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
    g_engine_shutting_down = false;
  }

  const char *appDataDir = env->GetStringUTFChars(jAppDataDir, 0);
  std::string dataPath(appDataDir);

  LOGI("Initializing Wireshark engine");

  std::string wsDataPath = dataPath + "/wireshark-data";
  std::string cachePath = dataPath + "/cache";
  std::string configPath = dataPath + "/config";

  make_dir(wsDataPath.c_str());
  make_dir(cachePath.c_str());
  make_dir(configPath.c_str());

  std::string diameterDictionary = wsDataPath + "/diameter/dictionary.xml";

  set_env_var("WIRESHARK_DATA_DIR", wsDataPath.c_str());
  set_env_var("WIRESHARK_PLUGIN_DIR", (wsDataPath + "/plugins").c_str());
  set_env_var("XDG_CACHE_HOME", cachePath.c_str());
  set_env_var("XDG_CONFIG_HOME", configPath.c_str());
  set_env_var("HOME", dataPath.c_str());

  // configuration_init() queries started_with_special_privs(), whose state is
  // established by init_process_policies(). Reversing these calls makes
  // wsutil deliberately abort the process.
  init_process_policies();

  char *configError = configuration_init("LayerAnalyzer", "Wireshark");
  if (configError) {
    LOGW("Wireshark configuration_init failed: %s", configError);
    g_free(configError);
  }
  set_persconffile_dir(configPath.c_str());
  set_persdatafile_dir(dataPath.c_str());
  LOGI("Wireshark data dir: %s (diameter dictionary: %s)",
       get_datafile_dir() ? get_datafile_dir() : "unknown",
       local_file_exists(diameterDictionary.c_str()) ? "present" : "missing");

  init_report_message("LayerAnalyzer", &layanalyzer_report_routines);

  ws_log_init_with_writer("LayerAnalyzer", wslog_writer, wslog_vcmdarg_err);
  ws_log_set_level(LOG_LEVEL_WARNING);

  bool init_success = true;

  g_log_set_default_handler(glib_log_handler, nullptr);

  wtap_init(FALSE);

  gboolean result = epan_init(nullptr, nullptr, FALSE);
  if (!result) {
    LOGE("epan_init returned FALSE");
    init_success = false;
  } else {
    epan_load_settings();
    apply_name_resolution_flags(true);
  }

  LOGI("Wireshark engine initialization %s",
       init_success ? "SUCCESS" : "FAILED");

  env->ReleaseStringUTFChars(jAppDataDir, appDataDir);
  return static_cast<jboolean>(init_success);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getVersion(JNIEnv *env,
                                                     jobject /* this */) {
  std::shared_lock<std::shared_mutex> lifetime_lock(g_native_mutex);
  const char *version = epan_get_version();
  return new_java_string(env, version ? version : "Unknown");
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_layanalyzer_NativeEngine_cleanup(JNIEnv *env,
                                                  jobject /* this */) {
  (void)env;
  // Serialize cleanup with process-wide Decode As/name-resolution updates.
  // epan_cleanup must never run concurrently with those Wireshark mutations.
  std::unique_lock<std::mutex> runtime_lock(g_runtime_exclusive_mutex);
  {
    std::unique_lock<std::shared_mutex> lifetime_lock(g_native_mutex);
    {
      std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
      g_engine_shutting_down = true;
    }
    close_all_sessions_locked();
  }
  // Do not hold the registry lock while waiting: a lease destructor may need
  // to publish its decrement and notify this condition variable.
  {
    std::unique_lock<std::mutex> lease_lock(g_lease_mutex);
    g_lease_cv.wait(lease_lock, [] { return g_active_session_leases == 0; });
  }
  epan_cleanup();
  LOGI("epan_cleanup called");
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_layanalyzer_NativeEngine_initCaresAndroid(
    JNIEnv *env, jobject /* this */, jobject connectivityManager) {
  (void)env;

#if defined(ANDROID) || defined(__ANDROID__)
  if (connectivityManager == nullptr) {
    LOGE("initCaresAndroid: ConnectivityManager is null");
    return JNI_FALSE;
  }

  LOGI("Calling ares_library_init_android...");
  int status = ares_library_init_android(connectivityManager);
  if (status != ARES_SUCCESS) {
    LOGE("ares_library_init_android failed: %s", ares_strerror(status));
    return JNI_FALSE;
  }
  LOGI("ares_library_init_android succeeded");
  return JNI_TRUE;
#else
  (void)connectivityManager;
  LOGW("c-ares Android init not available in this build");
  return JNI_FALSE;
#endif
}

// ========== packet_provider_funcs implementation ==========

static const nstime_t *provider_get_frame_ts(struct packet_provider_data *prov,
                                             guint32 frame_num) {
  return nullptr;
}

static const char *
provider_get_interface_name(struct packet_provider_data *prov,
                            guint32 interface_id) {
  return "unknown";
}

static const char *
provider_get_interface_description(struct packet_provider_data *prov,
                                   guint32 interface_id) {
  return "Unknown Interface";
}

static wtap_block_t
provider_get_modified_block(struct packet_provider_data *prov,
                            const frame_data *fd) {
  return nullptr;
}

const struct packet_provider_funcs layanalyzer_provider_funcs = {
    provider_get_frame_ts, provider_get_interface_name,
    provider_get_interface_description, provider_get_modified_block};
