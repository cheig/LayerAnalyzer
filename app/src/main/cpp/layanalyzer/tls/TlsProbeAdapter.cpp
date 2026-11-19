#include "TlsProxyAdapter.h"
#include "tls_probe.h"

#include <dlfcn.h>
#include <atomic>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <nlohmann/json.hpp>

namespace layanalyzer::tls {
namespace {
using Json = nlohmann::json;
std::atomic<int> globalRefs{0};
std::atomic<int> attachedThreads{0};
std::atomic<uint64_t> callbacksStarted{0};
std::atomic<uint64_t> callbacksCompleted{0};

// GetJavaVM returns the VM registered by the existing JNI_OnLoad. Never retain
// JNIEnv: it belongs to the calling thread. Only detach threads we attached.
class ScopedEnv {
public:
    explicit ScopedEnv(JavaVM* vm) : vm_(vm) {
        if (!vm_) return;
        const jint status = vm_->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
            if (vm_->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached_ = true;
                ++attachedThreads;
            } else {
                env = nullptr;
            }
        } else if (status != JNI_OK) {
            env = nullptr;
        }
    }
    ~ScopedEnv() {
        if (attached_) {
            vm_->DetachCurrentThread();
            --attachedThreads;
        }
    }
    JNIEnv* env = nullptr;
private:
    JavaVM* vm_;
    bool attached_ = false;
};

struct CallbackRef {
    JavaVM* vm = nullptr;
    jobject object = nullptr;
    jmethodID method = nullptr;
    ~CallbackRef() {
        if (!object) return;
        ScopedEnv scope(vm);
        if (scope.env) {
            scope.env->DeleteGlobalRef(object);
            --globalRefs;
        }
    }
};

struct State {
    std::mutex mutex;
    void* library = nullptr; // Go runtime remains resident for process lifetime.
    decltype(&la_tls_probe_abi_version) version = nullptr;
    decltype(&la_tls_probe_start) start = nullptr;
    decltype(&la_tls_probe_stop) stop = nullptr;
    decltype(&la_tls_probe_active_handles) active = nullptr;
    uint32_t abiVersion = 0;
    bool ready = false;
    bool starting = false;
    uint64_t handle = 0;
    std::unique_ptr<CallbackRef> callback;
};

State& state() {
    // No static destructor calling into a VM or Go runtime during teardown.
    static auto* value = new State;
    return *value;
}

Json result(const char* errorCode = nullptr, const char* error = nullptr) {
    return {{"schemaVersion", 1}, {"success", errorCode == nullptr},
            {"errorCode", errorCode ? Json(errorCode) : Json(nullptr)},
            {"error", error ? Json(error) : Json(nullptr)}};
}

Json smokeResult(int32_t code) {
    switch (code) {
        case LA_TLS_PROBE_OK: return result();
        case LA_TLS_PROBE_INVALID_ARGUMENT: return result("INVALID_ARGUMENT", "Invalid probe handle");
        case LA_TLS_PROBE_NOT_READY: return result("NOT_READY", "Probe already active");
        case LA_TLS_PROBE_CAPACITY_EXCEEDED: return result("CAPACITY_EXCEEDED", "Probe handle capacity reached");
        default: return result("IO_ERROR", "Unknown probe status");
    }
}

template<typename Operation>
jstring guarded(JNIEnv* env, Operation operation) {
    try {
        const auto json = operation().dump();
        return env->NewStringUTF(json.c_str());
    } catch (...) {
        // Never publish dlerror(), exception.what() or Java exception text.
        if (env->ExceptionCheck()) env->ExceptionClear();
        return env->NewStringUTF("{\"schemaVersion\":1,\"success\":false,\"errorCode\":\"IO_ERROR\",\"error\":\"Probe operation failed\"}");
    }
}

bool clearException(JNIEnv* env) {
    if (!env->ExceptionCheck()) return false;
    env->ExceptionClear();
    return true;
}

Json load(bool missingLibrary, int expectedVersion) {
    if (expectedVersion <= 0) return result("INVALID_ARGUMENT", "Invalid probe ABI version");
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    if (s.starting || s.handle) return result("NOT_READY", "Stop the probe before loading");
    // Only these fixed basenames are accepted; callers cannot load arbitrary paths.
    if (missingLibrary) {
        void* missing = dlopen("liblayanalyzer_tls_probe_intentionally_missing.so", RTLD_NOW | RTLD_LOCAL);
        (void)missing; // Never unload an unexpectedly installed Go runtime either.
        return result("NOT_READY", "Probe library unavailable");
    }
    if (!s.library) s.library = dlopen("liblayanalyzer_tls_probe.so", RTLD_NOW | RTLD_LOCAL);
    if (!s.library) return result("NOT_READY", "Probe library unavailable");
    s.ready = false;
    s.version = reinterpret_cast<decltype(s.version)>(dlsym(s.library, "la_tls_probe_abi_version"));
    s.start = reinterpret_cast<decltype(s.start)>(dlsym(s.library, "la_tls_probe_start"));
    s.stop = reinterpret_cast<decltype(s.stop)>(dlsym(s.library, "la_tls_probe_stop"));
    s.active = reinterpret_cast<decltype(s.active)>(dlsym(s.library, "la_tls_probe_active_handles"));
    if (!s.version || !s.start || !s.stop || !s.active) {
        return result("UNSUPPORTED", "Probe ABI symbols unavailable");
    }
    s.abiVersion = s.version();
    if (s.abiVersion != LA_TLS_PROBE_ABI_VERSION || s.abiVersion != static_cast<uint32_t>(expectedVersion)) {
        return result("UNSUPPORTED", "Probe ABI version mismatch");
    }
    s.ready = true;
    auto reply = result();
    reply["abiVersion"] = s.abiVersion;
    return reply;
}

Json start(JNIEnv* env, jobject callback) {
    if (!callback) return result("INVALID_ARGUMENT", "Probe callback required");
    auto& s = state();
    std::unique_lock<std::mutex> lock(s.mutex);
    if (!s.ready) return result("NOT_READY", "Load a compatible probe first");
    if (s.starting || s.handle) return result("NOT_READY", "Probe already active");
    auto ref = std::make_unique<CallbackRef>();
    if (env->GetJavaVM(&ref->vm) != JNI_OK) return result("NOT_READY", "Java VM unavailable");
    jclass cls = env->GetObjectClass(callback);
    if (cls) {
        ref->method = env->GetMethodID(cls, "onProbeStarted", "(J)Z");
        env->DeleteLocalRef(cls);
    }
    if (clearException(env) || !ref->method) return result("INVALID_ARGUMENT", "Invalid probe callback");
    ref->object = env->NewGlobalRef(callback);
    if (ref->object) ++globalRefs;
    if (clearException(env) || !ref->object) return result("IO_ERROR", "Cannot retain probe callback");
    uint64_t handle = 0;
    const auto code = s.start(&handle);
    if (code != LA_TLS_PROBE_OK) return smokeResult(code);
    if (!handle || handle > static_cast<uint64_t>(std::numeric_limits<jlong>::max())) {
        if (handle) s.stop(handle);
        return result("CAPACITY_EXCEEDED", "Invalid probe handle range");
    }
    s.starting = true;
    lock.unlock(); // Callback may re-enter state/stop. No adapter or Wireshark lock held.
    enum class CallbackStatus { Failed, Rejected, Accepted } status = CallbackStatus::Failed;
    try {
        std::thread worker([&] {
            ++callbacksStarted;
            {
                ScopedEnv scope(ref->vm);
                if (scope.env) {
                    const auto accepted = scope.env->CallBooleanMethod(ref->object, ref->method, static_cast<jlong>(handle));
                    if (!clearException(scope.env)) {
                        status = accepted ? CallbackStatus::Accepted : CallbackStatus::Rejected;
                    }
                }
            }
            ++callbacksCompleted;
        });
        worker.join(); // No callbacks remain in flight when start returns or stop releases the ref.
    } catch (...) {
        status = CallbackStatus::Failed;
    }
    lock.lock();
    s.starting = false;
    if (status != CallbackStatus::Accepted) {
        s.stop(handle);
        return status == CallbackStatus::Rejected
            ? result("CANCELLED", "Probe callback rejected start")
            : result("IO_ERROR", "Probe callback failed");
    }
    // Allocate the reply before transferring ownership, so allocation failure cannot
    // hide a newly active handle from the caller.
    Json reply;
    try {
        reply = result();
        reply["engineHandle"] = handle;
    } catch (...) {
        s.stop(handle);
        throw;
    }
    s.handle = handle;
    s.callback = std::move(ref);
    return reply;
}

int32_t prepareSocket(uintptr_t context, int32_t fd, int64_t generation) {
    auto* ref = reinterpret_cast<CallbackRef*>(context);
    ++callbacksStarted;
    struct Complete { ~Complete() { ++callbacksCompleted; } } complete;
    try {
        ScopedEnv scope(ref->vm);
        auto* env = scope.env;
        if (!env) return LA_TLS_PROBE_IO_ERROR;
        auto text = static_cast<jstring>(env->CallObjectMethod(ref->object, ref->method,
            static_cast<jint>(fd), static_cast<jlong>(generation)));
        if (clearException(env) || !text) return LA_TLS_PROBE_IO_ERROR;
        if (env->GetStringUTFLength(text) > 1024) {
            env->DeleteLocalRef(text);
            return LA_TLS_PROBE_IO_ERROR;
        }
        const char* utf = env->GetStringUTFChars(text, nullptr);
        if (!utf) { clearException(env); env->DeleteLocalRef(text); return LA_TLS_PROBE_IO_ERROR; }
        const auto value = Json::parse(utf, nullptr, false);
        env->ReleaseStringUTFChars(text, utf);
        env->DeleteLocalRef(text);
        if (value.is_discarded() || value.value("schemaVersion", 0) != 1) return LA_TLS_PROBE_IO_ERROR;
        if (value.value("success", false)) {
            return value.contains("errorCode") && value["errorCode"].is_null() &&
                value.contains("error") && value["error"].is_null() ? LA_TLS_PROBE_OK : LA_TLS_PROBE_IO_ERROR;
        }
        const auto code = value.value("errorCode", std::string());
        if (code == "PROTECT_FAILED") return LA_TLS_PROBE_PROTECT_FAILED;
        if (code == "NETWORK_CHANGED") return LA_TLS_PROBE_NETWORK_CHANGED;
        if (code == "STALE_GENERATION") return LA_TLS_PROBE_STALE_GENERATION;
        if (code == "INVALID_ARGUMENT") return LA_TLS_PROBE_INVALID_ARGUMENT;
        return LA_TLS_PROBE_IO_ERROR;
    } catch (...) { return LA_TLS_PROBE_IO_ERROR; }
}
int32_t prepareTun(uintptr_t context, uint16_t port, uint8_t* token, uint32_t size) {
    auto* ref = reinterpret_cast<CallbackRef*>(context);
    ++callbacksStarted;
    struct Complete { ~Complete() { ++callbacksCompleted; } } complete;
    ScopedEnv scope(ref->vm);
    auto* env = scope.env;
    if (!env || size != 32 || !token) return LA_TLS_PROBE_IO_ERROR;
    auto cls = env->GetObjectClass(ref->object);
    if (!cls) { clearException(env); return LA_TLS_PROBE_IO_ERROR; }
    auto method = env->GetMethodID(cls, "prepareTun", "(I[B)Z");
    env->DeleteLocalRef(cls);
    if (clearException(env) || !method) return LA_TLS_PROBE_IO_ERROR;
    auto bytes = env->NewByteArray(32);
    if (!bytes) { clearException(env); return LA_TLS_PROBE_IO_ERROR; }
    env->SetByteArrayRegion(bytes, 0, 32, reinterpret_cast<jbyte*>(token));
    if (clearException(env)) { env->DeleteLocalRef(bytes); return LA_TLS_PROBE_IO_ERROR; }
    const auto ok = env->CallBooleanMethod(ref->object, method, static_cast<jint>(port), bytes);
    const bool exception = clearException(env);
    const jbyte zero[32]{};
    env->SetByteArrayRegion(bytes, 0, 32, zero);
    env->DeleteLocalRef(bytes);
    if (clearException(env) || exception) return LA_TLS_PROBE_IO_ERROR;
    return ok ? LA_TLS_PROBE_OK : LA_TLS_PROBE_CANCELLED;
}
} // namespace

jobjectArray probeTlsPair(JNIEnv* env, jint protocol, jboolean rejectRoot, jobject callback, bool tun) {
    const auto pack = [&](const la_tls_probe_pair_result& data) -> jobjectArray {
        const la_tls_probe_bytes buffers[] = {data.metadata, data.downstream_keys, data.upstream_keys};
        for (const auto& buffer : buffers) {
            if (buffer.len > 16384 || (buffer.len && !buffer.data)) throw std::runtime_error("Invalid probe buffer");
        }
        auto cls = env->FindClass("[B");
        if (!cls) return nullptr;
        auto array = env->NewObjectArray(3, cls, nullptr);
        env->DeleteLocalRef(cls);
        if (!array) return nullptr;
        for (int i = 0; i < 3; ++i) {
            auto bytes = env->NewByteArray(static_cast<jsize>(buffers[i].len));
            if (!bytes) return nullptr;
            if (buffers[i].len) env->SetByteArrayRegion(bytes, 0, buffers[i].len,
                reinterpret_cast<const jbyte*>(buffers[i].data));
            env->SetObjectArrayElement(array, i, bytes);
            env->DeleteLocalRef(bytes);
            if (env->ExceptionCheck()) return nullptr;
        }
        return array;
    };
    const auto failure = [&](const char* code) {
        auto json = result(code, "TLS pair probe unavailable").dump();
        la_tls_probe_pair_result data{};
        data.metadata = {reinterpret_cast<uint8_t*>(json.data()), static_cast<uint32_t>(json.size())};
        return pack(data);
    };
    try {
        if (protocol < 0 || protocol > 2 || !callback) return failure("INVALID_ARGUMENT");
        decltype(&la_tls_probe_pair_run) run = nullptr;
        decltype(&la_tls_probe_tun_run) tunRun = nullptr;
        decltype(&la_tls_probe_pair_free) release = nullptr;
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            if (!s.ready) return failure("NOT_READY");
            const auto version = reinterpret_cast<decltype(&la_tls_probe_pair_abi_version)>(dlsym(s.library, "la_tls_probe_pair_abi_version"));
            run = reinterpret_cast<decltype(run)>(dlsym(s.library, "la_tls_probe_pair_run"));
            release = reinterpret_cast<decltype(release)>(dlsym(s.library, "la_tls_probe_pair_free"));
            if (!version || !run || !release || version() != LA_TLS_PAIR_PROBE_ABI_VERSION) return failure("UNSUPPORTED");
            if (tun) {
                const auto tunVersion = reinterpret_cast<decltype(&la_tls_probe_tun_abi_version)>(dlsym(s.library, "la_tls_probe_tun_abi_version"));
                tunRun = reinterpret_cast<decltype(tunRun)>(dlsym(s.library, "la_tls_probe_tun_run"));
                if (!tunVersion || !tunRun || tunVersion() != LA_TLS_TUN_PROBE_ABI_VERSION) return failure("UNSUPPORTED");
            }
        }
        auto ref = std::make_unique<CallbackRef>();
        if (env->GetJavaVM(&ref->vm) != JNI_OK) return failure("NOT_READY");
        auto cls = env->GetObjectClass(callback);
        if (cls) {
            ref->method = env->GetMethodID(cls, "prepareSocket", "(IJ)Ljava/lang/String;");
            env->DeleteLocalRef(cls);
        }
        if (clearException(env) || !ref->method) return failure("INVALID_ARGUMENT");
        ref->object = env->NewGlobalRef(callback);
        if (ref->object) ++globalRefs;
        if (clearException(env) || !ref->object) return failure("IO_ERROR");
        la_tls_probe_pair_result data{};
        struct Cleanup {
            decltype(release) fn;
            la_tls_probe_pair_result* data;
            ~Cleanup() { fn(data); }
        } cleanup{release, &data};
        const auto code = tun ? tunRun(protocol, &prepareSocket, &prepareTun,
            reinterpret_cast<uintptr_t>(ref.get()), &data) :
            run(protocol, rejectRoot ? 1 : 0, &prepareSocket, reinterpret_cast<uintptr_t>(ref.get()), &data);
        if (code != LA_TLS_PROBE_OK) return failure(code == LA_TLS_PROBE_CAPACITY_EXCEEDED ? "CAPACITY_EXCEEDED" : "IO_ERROR");
        return pack(data); // Copies dedicated secret buffers, then zeroes/frees C memory.
    } catch (...) {
        clearException(env);
        return failure("IO_ERROR");
    }
}

jstring probeSocket(JNIEnv* env, jstring ip, jint port, jlong generation,
                    jint timeoutMillis, jobject callback) {
    return guarded(env, [&] {
        if (!ip || !callback || port < 1 || port > 65535 || generation < 0 ||
            timeoutMillis < 1 || timeoutMillis > 10000 || env->GetStringUTFLength(ip) > 45) {
            return result("INVALID_ARGUMENT", "Invalid socket probe arguments");
        }
        decltype(&la_tls_probe_socket_dial) dial = nullptr;
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            if (!s.ready) return result("NOT_READY", "Load a compatible probe first");
            const auto version = reinterpret_cast<decltype(&la_tls_probe_socket_abi_version)>(
                dlsym(s.library, "la_tls_probe_socket_abi_version"));
            dial = reinterpret_cast<decltype(dial)>(dlsym(s.library, "la_tls_probe_socket_dial"));
            if (!version || !dial || version() != LA_TLS_SOCKET_PROBE_ABI_VERSION) {
                return result("UNSUPPORTED", "Socket probe extension unavailable");
            }
        }
        auto ref = std::make_unique<CallbackRef>();
        if (env->GetJavaVM(&ref->vm) != JNI_OK) return result("NOT_READY", "Java VM unavailable");
        jclass cls = env->GetObjectClass(callback);
        if (cls) {
            ref->method = env->GetMethodID(cls, "prepareSocket", "(IJ)Ljava/lang/String;");
            env->DeleteLocalRef(cls);
        }
        if (clearException(env) || !ref->method) return result("INVALID_ARGUMENT", "Invalid socket callback");
        ref->object = env->NewGlobalRef(callback);
        if (ref->object) ++globalRefs;
        if (clearException(env) || !ref->object) return result("IO_ERROR", "Cannot retain socket callback");
        const char* utf = env->GetStringUTFChars(ip, nullptr);
        if (!utf) { clearException(env); return result("IO_ERROR", "Cannot read probe destination"); }
        // Copy/release Java memory before calling Go or re-entering the VM.
        std::string address;
        try { address = utf; } catch (...) { env->ReleaseStringUTFChars(ip, utf); throw; }
        env->ReleaseStringUTFChars(ip, utf);
        la_tls_probe_socket_result diagnostics{};
        const auto status = dial(reinterpret_cast<uint8_t*>(address.data()), address.size(), port,
            generation, timeoutMillis, &prepareSocket, reinterpret_cast<uintptr_t>(ref.get()), &diagnostics);
        // The synchronous ABI closes the FD and completes every callback before
        // returning. Only now may ref be released; no Wireshark lock was acquired.
        const char* code = nullptr;
        switch (status) {
            case LA_TLS_PROBE_OK: break;
            case LA_TLS_PROBE_INVALID_ARGUMENT: code = "INVALID_ARGUMENT"; break;
            case LA_TLS_PROBE_PROTECT_FAILED: code = "PROTECT_FAILED"; break;
            case LA_TLS_PROBE_NETWORK_CHANGED: code = "NETWORK_CHANGED"; break;
            case LA_TLS_PROBE_STALE_GENERATION: code = "STALE_GENERATION"; break;
            case LA_TLS_PROBE_CAPACITY_EXCEEDED: code = "CAPACITY_EXCEEDED"; break;
            case LA_TLS_PROBE_CANCELLED: code = "CANCELLED"; break;
            default: code = "IO_ERROR";
        }
        auto reply = result(code, code ? "Socket probe failed" : nullptr);
        reply["controlCalls"] = diagnostics.control_calls;
        reply["connected"] = diagnostics.connected != 0;
        reply["serverAcceptSequence"] = diagnostics.server_accept_sequence;
        return reply;
    });
}

jstring probeState(JNIEnv* env) {
    return guarded(env, [] {
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        auto reply = result();
        reply["libraryLoaded"] = s.library != nullptr;
        reply["abiVersion"] = s.abiVersion;
        reply["ready"] = s.ready;
        // Do not invoke any ABI function on an incompatible library.
        reply["activeHandles"] = s.ready ? Json(s.active()) : Json(nullptr);
        reply["globalRefs"] = globalRefs.load();
        reply["attachedThreads"] = attachedThreads.load();
        reply["callbacksStarted"] = callbacksStarted.load();
        reply["callbacksCompleted"] = callbacksCompleted.load();
        return reply;
    });
}

jstring probeLoad(JNIEnv* env, jboolean missingLibrary, jint expectedAbiVersion) {
    return guarded(env, [&] { return load(missingLibrary, expectedAbiVersion); });
}

jstring probeStart(JNIEnv* env, jobject callback) {
    return guarded(env, [&] { return start(env, callback); });
}

jstring probeStop(JNIEnv* env, jlong handle) {
    return guarded(env, [&] {
        if (handle <= 0) return result("INVALID_ARGUMENT", "Invalid probe handle");
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        if (!s.ready) return result("NOT_READY", "Load a compatible probe first");
        if (s.starting) return result("NOT_READY", "Probe callback in progress");
        const auto code = s.stop(static_cast<uint64_t>(handle));
        if (code == LA_TLS_PROBE_OK && s.handle == static_cast<uint64_t>(handle)) {
            s.callback.reset();
            s.handle = 0;
        }
        return smokeResult(code);
    });
}
} // namespace layanalyzer::tls
