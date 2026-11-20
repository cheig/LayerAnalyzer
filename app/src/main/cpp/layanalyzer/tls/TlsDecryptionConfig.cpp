// Copyright (c) 2026 cheig; GPL-3.0.
#include "TlsDecryptionConfig.h"
#include "layanalyzer/session/WiresharkSession.h"
#include <epan/prefs.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>

namespace layanalyzer::tls {
namespace {
struct Failure : std::runtime_error {
    const char* code;
    Failure(const char* code, const char* message) : std::runtime_error(message), code(code) {}
};

std::string preference(const char* moduleName, const char* name) {
    auto* module = prefs_find_module(moduleName);
    auto* pref = module ? prefs_find_preference(module, name) : nullptr;
    if (!pref) throw Failure("UNSUPPORTED", "Required TLS preference is unavailable");
    gchar* value = prefs_pref_to_str(pref, pref_current);
    if (!value) throw Failure("UNSUPPORTED", "Cannot read TLS preference");
    std::string result(value);
    g_free(value);
    return result;
}

void setPreference(const char* name, const std::string& value) {
    std::string argument = std::string(name) + ":" + value;
    gchar* error = nullptr;
    auto status = prefs_set_pref(argument.data(), &error);
    g_free(error); // Preference errors can contain the private path.
    if (status != PREFS_SET_OK) throw Failure("UNSUPPORTED", "TLS preference was rejected");
}

std::string readPath(JNIEnv* env, jstring input) {
    if (!input) return {};
    const auto length = env->GetStringLength(input);
    if (length == 0 || length > 4096)
        throw Failure("INVALID_ARGUMENT", "Invalid keylog path");
    const jchar* chars = env->GetStringChars(input, nullptr);
    if (!chars) throw Failure("IO_ERROR", "Cannot read keylog path");
    bool valid = chars[0] == '/';
    for (jsize i = 0; i < length; ++i) valid = valid && chars[i] >= 32 && chars[i] != 127;
    env->ReleaseStringChars(input, chars);
    if (!valid) throw Failure("INVALID_ARGUMENT", "Invalid keylog path");
    const char* utf = env->GetStringUTFChars(input, nullptr);
    if (!utf) throw Failure("IO_ERROR", "Cannot read keylog path");
    std::string path(utf);
    env->ReleaseStringUTFChars(input, utf);
    if (path.size() > 4096) throw Failure("INVALID_ARGUMENT", "Invalid keylog path");
    return path;
}

void checkFile(const std::string& path) {
    if (path.empty()) return;
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) throw Failure("IO_ERROR", "Cannot open keylog lease");
    struct stat info {};
    const bool regular = fstat(fd, &info) == 0 && S_ISREG(info.st_mode);
    close(fd);
    if (!regular || info.st_size <= 0)
        throw Failure("INVALID_ARGUMENT", "Keylog lease must be a nonempty regular file");
    // TLS-104 may append the missing final LF to a 16 MiB parser input.
    if (info.st_size > 16 * 1024 * 1024 + 1)
        throw Failure("CAPACITY_EXCEEDED", "Keylog lease exceeds the byte limit");
}

void describe(json& result, const WiresharkSession* session) {
    result["dissectionGeneration"] = session->dissection_generation.load();
    result["secretsGeneration"] = session->tls_secrets_generation;
    result["configured"] = !session->tls_keylog_path.empty();
}
}

bool clearSecretsPreference() noexcept {
    try {
        setPreference("tls.keylog_file", "");
        setPreference("tls.debug_file", "");
        prefs_apply(prefs_find_module("tls"));
        return preference("tls", "keylog_file").empty();
    } catch (...) {
        // No path, key material, or library error string may reach Logcat.
        return false;
    }
}

jstring configureSecrets(JNIEnv* env, jlong sessionHandle, jstring keyLogPath,
                         jlong secretsGeneration) {
    json result = {{"schemaVersion", 1}, {"success", false}, {"errorCode", nullptr},
                   {"error", nullptr}, {"sessionClosed", false}};
    try {
        if (secretsGeneration < 0)
            throw Failure("INVALID_ARGUMENT", "Secrets revision must be nonnegative");
        const std::string path = readPath(env, keyLogPath);
        // Never acquire our own SessionLease before this guard: it waits for
        // every lease to drain, and then obtains the registry for locked lookup.
        RuntimeExclusiveGuard guard;
        auto* session = find_session_locked(sessionHandle);
        if (!session || session->closed.load() || !session->epan)
            throw Failure("NOT_READY", "Capture session is unavailable");
        describe(result, session);
        if (g_sessions.size() != 1)
            throw Failure("NOT_READY", "TLS configuration requires one active capture");
        const auto revision = static_cast<uint64_t>(secretsGeneration);
        if (revision < session->tls_secrets_generation ||
            (revision == session->tls_secrets_generation && path != session->tls_keylog_path))
            throw Failure("STALE_GENERATION", "Secrets revision is stale or already used");
        if (preference("tls", "keylog_file") != session->tls_keylog_path)
            throw Failure("NOT_READY", "A different TLS configuration owns the engine");
        checkFile(path);
        if (revision != session->tls_secrets_generation) {
            if (session->dissection_generation.load() >= static_cast<uint64_t>(INT64_MAX))
                throw Failure("CAPACITY_EXCEEDED", "Dissection generation is exhausted");
            // Validate every required preference before the first mutation.
            preference("tls", "debug_file");
            preference("tls", "desegment_ssl_records");
            preference("tls", "desegment_ssl_application_data");
            preference("tcp", "desegment_tcp_streams");
            try {
                setPreference("tls.debug_file", "");
                setPreference("tls.keylog_file", path);
                setPreference("tls.desegment_ssl_records", "TRUE");
                setPreference("tls.desegment_ssl_application_data", "TRUE");
                setPreference("tcp.desegment_tcp_streams", "TRUE");
                prefs_apply(prefs_find_module("tls"));
                prefs_apply(prefs_find_module("tcp"));
                if (preference("tls", "keylog_file") != path)
                    throw Failure("IO_ERROR", "TLS preference did not apply");
                if (!reset_dissection_state())
                    throw Failure("IO_ERROR", "Cannot rebuild capture dissection");
                session->tls_keylog_path = path;
                session->tls_secrets_generation = revision;
                // The old filtered index cannot survive changed dissections.
                // TLS-106 reapplies the user's filter after sequential priming.
                session->filter_request_generation.fetch_add(1);
                session->search_request_generation.fetch_add(1);
                {
                    std::unique_lock<std::shared_mutex> state(session->state_mutex);
                    session->filtered_frames.clear();
                    session->active_filter.clear();
                    session->filter_error.clear();
                }
            } catch (...) {
                // Once mutation starts, no mixed old/new analysis may escape.
                // The destructor clears prefs and epan (including TLS maps)
                // before the exclusive guard admits another session/query.
                remove_session_locked(sessionHandle).reset();
                result["sessionClosed"] = true;
                result["configured"] = false;
                throw;
            }
        }
        describe(result, session);
        result["success"] = true;
    } catch (const Failure& error) {
        result["errorCode"] = error.code;
        result["error"] = error.what();
    } catch (...) {
        result["errorCode"] = "IO_ERROR";
        result["error"] = "TLS configuration failed";
    }
    if (env->ExceptionCheck()) return nullptr;
    return new_java_string(env, dump_json(result));
}
}
