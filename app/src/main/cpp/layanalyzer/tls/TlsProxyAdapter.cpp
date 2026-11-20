#include "TlsProxyAdapter.h"
#include <nlohmann/json.hpp>
#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>
#ifdef LAYANALYZER_ENABLE_TLS
#include "la_tls_bridge.h"
#include <dlfcn.h>
#endif

namespace layanalyzer::tls {
namespace {
using Json = nlohmann::json;
Json envelope(const char* code = nullptr) {
    return {{"schemaVersion", 1}, {"success", !code}, {"errorCode", code ? Json(code) : Json(nullptr)},
        {"error", code ? Json("TLS operation unavailable or rejected") : Json(nullptr)}};
}
template<class F> jstring guarded(JNIEnv* env, F operation) {
    try { return env->NewStringUTF(operation().dump().c_str()); }
    catch (...) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return env->NewStringUTF("{\"schemaVersion\":1,\"success\":false,\"errorCode\":\"IO_ERROR\",\"error\":\"TLS operation failed\"}");
    }
}
// CA material cannot travel in a JSON envelope (C05): a failure is a redacted
// typed exception whose message is one fixed code name. Only the code name
// crosses, so a provider or filesystem message can never leak a key or a path.
void throwCertificateStatus(JNIEnv* env, const char* code) {
    if (env->ExceptionCheck()) env->ExceptionClear();
    jclass cls = env->FindClass("com/example/layanalyzer/capture/tls/TlsCertificateException");
    if (!cls) {
        env->ExceptionClear();
        cls = env->FindClass("java/lang/IllegalStateException");
        if (!cls) { env->ExceptionClear(); return; }
    }
    env->ThrowNew(cls, code);
    env->DeleteLocalRef(cls);
}
// The gateway token is not certificate material, so it does not reuse the
// certificate exception. It never travels in a JSON envelope either (C05: the
// start result carries engineHandle and port only), so a failure is one fixed
// code name in an IllegalStateException and never a returned empty array, a
// token byte, or a platform message.
void throwTokenStatus(JNIEnv* env, const char* code) {
    if (env->ExceptionCheck()) env->ExceptionClear();
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    if (!cls) { env->ExceptionClear(); return; }
    env->ThrowNew(cls, code);
    env->DeleteLocalRef(cls);
}
#ifdef LAYANALYZER_ENABLE_TLS
const char* statusName(int32_t status) {
    switch (status) {
        case LA_TLS_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case LA_TLS_NOT_READY: return "NOT_READY";
        case LA_TLS_UNSUPPORTED: return "UNSUPPORTED";
        case LA_TLS_CAPACITY_EXCEEDED: return "CAPACITY_EXCEEDED";
        default: return "IO_ERROR";
    }
}

std::atomic<uint64_t> refs{0}, attached{0}, calls{0}, completed{0};
thread_local unsigned callbackDepth = 0;
bool clearException(JNIEnv* env) {
    if (!env->ExceptionCheck()) return false;
    env->ExceptionClear(); return true;
}
class ScopedEnv {
    JavaVM* vm;
    bool owns = false;
public:
    JNIEnv* env = nullptr;
    explicit ScopedEnv(JavaVM* value) : vm(value) {
        const auto status = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
            owns = vm->AttachCurrentThread(&env, nullptr) == JNI_OK;
            if (owns) ++attached; else env = nullptr;
        } else if (status != JNI_OK) env = nullptr;
    }
    ~ScopedEnv() { if (owns) { vm->DetachCurrentThread(); --attached; } }
};
struct CallbackRef {
    JavaVM* vm = nullptr;
    jobject object = nullptr;
    jmethodID prepare = nullptr, resolve = nullptr, verify = nullptr, offer = nullptr;
    ~CallbackRef() {
        if (!object) return;
        ScopedEnv scope(vm);
        if (scope.env) { scope.env->DeleteGlobalRef(object); --refs; }
    }
};
struct State {
    std::mutex mutex;
    void* library = nullptr; // Go runtime stays resident; never dlclose it.
    bool compatible = false, starting = false;
    uint64_t handle = 0;
    std::shared_ptr<CallbackRef> callback;
    std::vector<uint8_t> token;
    decltype(&la_tls_abi_version) version = nullptr;
    decltype(&la_tls_capabilities) capabilities = nullptr;
    decltype(&la_tls_start) start = nullptr;
    decltype(&la_tls_stop) stop = nullptr;
    decltype(&la_tls_poll) poll = nullptr;
    decltype(&la_tls_stats) stats = nullptr;
    decltype(&la_tls_generate_ca) generate = nullptr;
    decltype(&la_tls_free_buffer) release = nullptr;
};
State& state() { static auto* s = new State; return *s; }
bool load(State& s) {
    if (s.compatible) return true;
    if (!s.library) s.library = dlopen("liblayanalyzer_tls.so", RTLD_NOW | RTLD_LOCAL);
    if (!s.library) return false;
#define LOAD(field, symbol) s.field = reinterpret_cast<decltype(s.field)>(dlsym(s.library, #symbol))
    LOAD(version, la_tls_abi_version); LOAD(capabilities, la_tls_capabilities);
    LOAD(start, la_tls_start); LOAD(stop, la_tls_stop); LOAD(poll, la_tls_poll);
    LOAD(stats, la_tls_stats); LOAD(generate, la_tls_generate_ca); LOAD(release, la_tls_free_buffer);
#undef LOAD
    s.compatible = s.version && s.capabilities && s.start && s.stop && s.poll && s.stats && s.generate && s.release && s.version() == LA_TLS_ABI_VERSION;
    return s.compatible;
}
struct Buffer {
    la_tls_buffer value{};
    decltype(&la_tls_free_buffer) release;
    explicit Buffer(decltype(release) fn) : release(fn) {}
    ~Buffer() { release(&value); }
    Json json(int32_t status) const {
        if (!value.data || !value.len || value.len > LA_TLS_MAX_JSON) return envelope("IO_ERROR");
        auto r = Json::parse(value.data, value.data + value.len, nullptr, false);
        if (!r.is_object() || r.value("schemaVersion", 0) != 1 || !r.contains("success") ||
            !r["success"].is_boolean() || r["success"] != (status == LA_TLS_OK) ||
            !r.contains("errorCode") || !r.contains("error")) return envelope("IO_ERROR");
        return r;
    }
};
int32_t code(const Json& r) {
    if (!r.is_object() || r.value("schemaVersion", 0) != 1 || !r.contains("success") || !r["success"].is_boolean()) return LA_TLS_IO_ERROR;
    if (r["success"] == true) return r.contains("errorCode") && r["errorCode"].is_null() && r.contains("error") && r["error"].is_null() ? LA_TLS_OK : LA_TLS_IO_ERROR;
    const auto name = r.value("errorCode", std::string());
    static const char* names[] = {"", "INVALID_ARGUMENT", "NOT_READY", "UNSUPPORTED", "STALE_GENERATION", "CANCELLED", "IO_ERROR", "CAPACITY_EXCEEDED", "PROTECT_FAILED", "NETWORK_CHANGED", "UPSTREAM_CERT_INVALID", "DOWNSTREAM_TLS_REJECTED", "SECRETS_INCOMPLETE", "CAPTURE_CONTEXT_MISSING"};
    for (int i = 1; i <= LA_TLS_CAPTURE_CONTEXT_MISSING; ++i) if (name == names[i]) return i;
    return LA_TLS_IO_ERROR;
}
Json readJson(JNIEnv* env, jstring text, size_t limit) {
    if (clearException(env) || !text || env->GetStringUTFLength(text) > static_cast<jsize>(limit)) return Json();
    const char* chars = env->GetStringUTFChars(text, nullptr);
    if (!chars) { clearException(env); return Json(); }
    auto result = Json::parse(chars, nullptr, false);
    env->ReleaseStringUTFChars(text, chars);
    return result;
}
// Only normalized ASCII names/IDs cross these string callbacks.
jstring string(JNIEnv* env, la_tls_bytes value, size_t limit) {
    if (!value.data || !value.len || value.len > limit) return nullptr;
    for (uint32_t i = 0; i < value.len; ++i) if (value.data[i] < 0x20 || value.data[i] > 0x7e) return nullptr;
    return env->NewStringUTF(std::string(reinterpret_cast<const char*>(value.data), value.len).c_str());
}
jbyteArray bytes(JNIEnv* env, la_tls_bytes value, size_t limit) {
    if (!value.data || !value.len || value.len > limit) return nullptr;
    auto result = env->NewByteArray(value.len);
    if (result) env->SetByteArrayRegion(result, 0, value.len, reinterpret_cast<const jbyte*>(value.data));
    return result;
}
template<class F> int32_t callback(uintptr_t context, F f) {
    ++calls; ++callbackDepth;
    struct Done { ~Done() { ++completed; --callbackDepth; } } done;
    auto* ref = reinterpret_cast<CallbackRef*>(context);
    if (!ref) return LA_TLS_IO_ERROR;
    ScopedEnv scope(ref->vm);
    auto* env = scope.env;
    if (!env || env->PushLocalFrame(32) != JNI_OK) { if (env) clearException(env); return LA_TLS_IO_ERROR; }
    struct Frame { JNIEnv* env; ~Frame() { env->PopLocalFrame(nullptr); } } frame{env};
    try { const auto result = f(env, *ref); return clearException(env) ? LA_TLS_IO_ERROR : result; }
    catch (...) { clearException(env); return LA_TLS_IO_ERROR; }
}
int32_t prepare(uintptr_t c, int32_t fd, int64_t generation) {
    return callback(c, [&](JNIEnv* env, CallbackRef& r) {
        return code(readJson(env, static_cast<jstring>(env->CallObjectMethod(r.object, r.prepare, fd, static_cast<jlong>(generation))), 1024));
    });
}
int32_t resolve(uintptr_t c, la_tls_bytes host, int64_t generation, uint8_t* out, uint32_t capacity, uint32_t* size) {
    if (!out || !size) return LA_TLS_INVALID_ARGUMENT;
    *size = 0;
    return callback(c, [&](JNIEnv* env, CallbackRef& r) -> int32_t {
        auto name = string(env, host, 253); if (!name) return LA_TLS_INVALID_ARGUMENT;
        auto parsed = readJson(env, static_cast<jstring>(env->CallObjectMethod(r.object, r.resolve, name, static_cast<jlong>(generation))), 16384);
        auto status = code(parsed); if (status != LA_TLS_OK) return status;
        if (!parsed.contains("addresses") || !parsed["addresses"].is_array()) return LA_TLS_IO_ERROR;
        auto json = parsed.dump(); if (json.size() > capacity) return LA_TLS_CAPACITY_EXCEEDED;
        std::memcpy(out, json.data(), json.size()); *size = json.size(); return LA_TLS_OK;
    });
}
int32_t verify(uintptr_t c, const la_tls_bytes* chain, uint32_t count, la_tls_bytes identity, la_tls_bytes auth, la_tls_bytes version) {
    if (!chain || count < 1 || count > 16) return LA_TLS_INVALID_ARGUMENT;
    return callback(c, [&](JNIEnv* env, CallbackRef& r) -> int32_t {
        auto id = string(env, identity, 253), at = string(env, auth, 32), tls = string(env, version, 16);
        if (!id || !at || !tls || clearException(env)) return LA_TLS_INVALID_ARGUMENT;
        auto cls = env->FindClass("[B"); if (!cls) return LA_TLS_IO_ERROR;
        auto certs = env->NewObjectArray(count, cls, nullptr); if (!certs) return LA_TLS_IO_ERROR;
        for (uint32_t i = 0; i < count; ++i) {
            auto der = bytes(env, chain[i], 65536); if (!der || clearException(env)) return LA_TLS_INVALID_ARGUMENT;
            env->SetObjectArrayElement(certs, i, der); env->DeleteLocalRef(der);
            if (clearException(env)) return LA_TLS_IO_ERROR;
        }
        return code(readJson(env, static_cast<jstring>(env->CallObjectMethod(r.object, r.verify, certs, id, at, tls)), 1024));
    });
}
int32_t offer(uintptr_t c, la_tls_bytes capture, la_tls_bytes connection, la_tls_bytes line) {
    return callback(c, [&](JNIEnv* env, CallbackRef& r) -> int32_t {
        auto cid = string(env, capture, 128), coid = string(env, connection, 128);
        auto record = bytes(env, line, 8192);
        if (!cid || !coid || !record || clearException(env)) return LA_TLS_INVALID_ARGUMENT;
        const auto accepted = env->CallBooleanMethod(r.object, r.offer, cid, coid, record);
        const bool failed = clearException(env);
        std::vector<jbyte> zero(line.len, 0); env->SetByteArrayRegion(record, 0, line.len, zero.data());
        return failed ? LA_TLS_IO_ERROR : accepted ? LA_TLS_OK : LA_TLS_SECRETS_INCOMPLETE;
    });
}
std::shared_ptr<CallbackRef> retain(JNIEnv* env, jobject object) {
    if (!object) return {};
    auto ref = std::make_shared<CallbackRef>();
    if (env->GetJavaVM(&ref->vm) != JNI_OK) return {};
    auto cls = env->GetObjectClass(object); if (!cls) return {};
    struct Local { JNIEnv* e; jclass c; ~Local() { e->DeleteLocalRef(c); } } local{env, cls};
    ref->prepare = env->GetMethodID(cls, "prepareSocket", "(IJ)Ljava/lang/String;"); if (clearException(env)) return {};
    ref->resolve = env->GetMethodID(cls, "resolveHost", "(Ljava/lang/String;J)Ljava/lang/String;"); if (clearException(env)) return {};
    ref->verify = env->GetMethodID(cls, "verifyUpstream", "([[BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"); if (clearException(env)) return {};
    ref->offer = env->GetMethodID(cls, "offerSecret", "(Ljava/lang/String;Ljava/lang/String;[B)Z");
    if (clearException(env) || !ref->prepare || !ref->resolve || !ref->verify || !ref->offer) return {};
    ref->object = env->NewGlobalRef(object); if (!ref->object || clearException(env)) return {};
    ++refs; return ref;
}
struct MaterialBytes {
    std::vector<uint8_t> value;
    ~MaterialBytes() { volatile uint8_t* p = value.data(); for (size_t i = 0; i < value.size(); ++i) p[i] = 0; }
    bool read(JNIEnv* env, jbyteArray input, size_t limit) {
        if (!input) return false;
        auto size = env->GetArrayLength(input); if (size <= 0 || size > static_cast<jsize>(limit)) return false;
        value.resize(size); env->GetByteArrayRegion(input, 0, size, reinterpret_cast<jbyte*>(value.data())); return !clearException(env);
    }
    la_tls_bytes view() const { return {value.data(), static_cast<uint32_t>(value.size())}; }
};
#endif
} // namespace

jstring capabilities(JNIEnv* env) {
    return guarded(env, [] {
#ifdef LAYANALYZER_ENABLE_TLS
        auto& s = state(); std::lock_guard<std::mutex> lock(s.mutex);
        Json r;
        if (s.compatible) { Buffer b(s.release); auto status = s.capabilities(&b.value); r = b.json(status); }
        else { r = envelope(); r["abiVersion"] = 1; r["engineReady"] = false; }
        r["buildEnabled"] = true; r["libraryLoaded"] = s.library != nullptr;
        // CA generation is a property of the build, not of whether this process
        // has dlopen'd the Go library yet: a capability query must not load Go
        // (TLS-201), so deriving it from load state made it unobservable before
        // the first start and left a caller unable to tell a CA-capable build
        // from one without it. libraryLoaded/engineReady stay dynamic.
        r["caGenerationReady"] = true;
        r["globalRefs"] = refs.load(); r["attachedThreads"] = attached.load();
        r["callbacksStarted"] = calls.load(); r["callbacksCompleted"] = completed.load(); return r;
#else
        auto r = envelope("UNSUPPORTED"); r["buildEnabled"] = false; r["libraryLoaded"] = false; r["engineReady"] = false; return r;
#endif
    });
}
jstring start(JNIEnv* env, jstring config, jbyteArray certificate, jbyteArray privateKey, jobject callbacks) {
    return guarded(env, [&] {
#ifdef LAYANALYZER_ENABLE_TLS
        if (callbackDepth) return envelope("NOT_READY");
        auto parsed = readJson(env, config, 65536); if (!parsed.is_object()) return envelope("INVALID_ARGUMENT");
        auto json = parsed.dump(); MaterialBytes cert, key;
        if (!cert.read(env, certificate, 65536) || !key.read(env, privateKey, 16384)) return envelope("INVALID_ARGUMENT");
        auto ref = retain(env, callbacks); if (!ref) return envelope("INVALID_ARGUMENT");
        auto& s = state();
        { std::lock_guard<std::mutex> lock(s.mutex);
          if (s.starting || s.handle) return envelope("NOT_READY");
          if (!load(s)) return envelope(s.library ? "UNSUPPORTED" : "NOT_READY"); s.starting = true; }
        struct Starting { State& s; ~Starting() { std::lock_guard<std::mutex> lock(s.mutex); s.starting = false; } } starting{s};
        la_tls_callbacks table{sizeof(la_tls_callbacks), LA_TLS_ABI_VERSION, reinterpret_cast<uintptr_t>(ref.get()), prepare, resolve, verify, offer};
        Buffer output(s.release), token(s.release);
        auto status = s.start({reinterpret_cast<const uint8_t*>(json.data()), static_cast<uint32_t>(json.size())}, cert.view(), key.view(), &table, &output.value, &token.value);
        auto result = output.json(status);
        if (status == LA_TLS_OK) {
            const auto handle = result.value("engineHandle", uint64_t{0});
            if (!handle || token.value.len != 43 || !token.value.data) {
                if (handle) { Buffer stopped(s.release); s.stop(handle, 5000, &stopped.value); }
                return envelope("IO_ERROR");
            }
            std::lock_guard<std::mutex> lock(s.mutex);
            s.handle = handle; s.callback = std::move(ref); s.token.assign(token.value.data, token.value.data + token.value.len);
        }
        return result;
#else
        return envelope("UNSUPPORTED");
#endif
    });
}
jstring stop(JNIEnv* env, jlong handle, jint timeoutMillis) {
    return guarded(env, [&] {
#ifdef LAYANALYZER_ENABLE_TLS
        if (handle <= 0 || timeoutMillis < 1 || timeoutMillis > 5000) return envelope("INVALID_ARGUMENT");
        if (callbackDepth) return envelope("NOT_READY");
        auto& s = state();
        { std::lock_guard<std::mutex> lock(s.mutex); if (!s.compatible || s.starting) return envelope("NOT_READY"); }
        Buffer output(s.release); auto status = s.stop(handle, timeoutMillis, &output.value); auto r = output.json(status);
        if (status == LA_TLS_OK) {
            std::lock_guard<std::mutex> lock(s.mutex);
            if (s.handle == static_cast<uint64_t>(handle)) { s.callback.reset(); std::fill(s.token.begin(), s.token.end(), 0); s.token.clear(); s.handle = 0; }
        }
        return r;
#else
        return envelope("UNSUPPORTED");
#endif
    });
}
// The current run's gateway token, as the 43 ASCII characters of C05's base64url
// form. This is a dedicated byte buffer for exactly one caller — the SOCKS hop
// that writes the LAT1 frame (TLS-215) — never an ordinary JSON field, never a
// log line, and cleared by stop. The array returned is a copy, so the engine's
// own bytes are not handed out and the caller can wipe its copy.
jbyteArray gatewayToken(JNIEnv* env, jlong handle) {
#ifdef LAYANALYZER_ENABLE_TLS
    if (callbackDepth) { throwTokenStatus(env, "NOT_READY"); return nullptr; }
    if (handle <= 0) { throwTokenStatus(env, "INVALID_ARGUMENT"); return nullptr; }
    auto& s = state();
    std::vector<uint8_t> token;
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        // A handle that does not name the running run is the same stale handle
        // stop and poll reject: there is no token to hand out for it.
        if (s.handle != static_cast<uint64_t>(handle) || s.token.empty()) {
            throwTokenStatus(env, "STALE_GENERATION");
            return nullptr;
        }
        token = s.token;
    }
    struct Wipe { std::vector<uint8_t>& value; ~Wipe() { volatile uint8_t* p = value.data(); for (size_t i = 0; i < value.size(); ++i) p[i] = 0; } } wipe{token};
    auto result = env->NewByteArray(static_cast<jsize>(token.size()));
    if (result) {
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(token.size()), reinterpret_cast<const jbyte*>(token.data()));
    }
    if (!result || env->ExceptionCheck()) {
        if (result) env->DeleteLocalRef(result);
        clearException(env);
        throwTokenStatus(env, "IO_ERROR");
        return nullptr;
    }
    return result;
#else
    (void)handle;
    throwTokenStatus(env, "UNSUPPORTED");
    return nullptr;
#endif
}
jstring poll(JNIEnv* env, jlong handle, jint maxEvents) {
    return guarded(env, [&] {
#ifdef LAYANALYZER_ENABLE_TLS
        if (handle <= 0 || maxEvents < 1 || maxEvents > 128) return envelope("INVALID_ARGUMENT");
        auto& s = state(); { std::lock_guard<std::mutex> lock(s.mutex); if (!s.compatible) return envelope("NOT_READY"); }
        Buffer b(s.release); auto status = s.poll(handle, maxEvents, &b.value); return b.json(status);
#else
        return envelope("UNSUPPORTED");
#endif
    });
}
jstring stats(JNIEnv* env, jlong handle) {
    return guarded(env, [&] {
#ifdef LAYANALYZER_ENABLE_TLS
        if (handle <= 0) return envelope("INVALID_ARGUMENT");
        auto& s = state(); { std::lock_guard<std::mutex> lock(s.mutex); if (!s.compatible) return envelope("NOT_READY"); }
        Buffer b(s.release); auto status = s.stats(handle, &b.value); return b.json(status);
#else
        return envelope("UNSUPPORTED");
#endif
    });
}
jobjectArray generateCaMaterial(JNIEnv* env) {
#ifdef LAYANALYZER_ENABLE_TLS
    // Go owns the generation and the two allocations; this function only copies
    // them into JVM arrays and releases the originals. Generation spends real CPU
    // on RSA, so a Go callback thread must not be the one asking for it.
    if (callbackDepth) { throwCertificateStatus(env, "NOT_READY"); return nullptr; }
    auto& s = state();
    { std::lock_guard<std::mutex> lock(s.mutex);
      if (!load(s)) { throwCertificateStatus(env, s.library ? "UNSUPPORTED" : "NOT_READY"); return nullptr; } }
    Buffer certificate(s.release), privateKey(s.release);
    const auto status = s.generate(&certificate.value, &privateKey.value);
    if (status != LA_TLS_OK || !certificate.value.data || !certificate.value.len ||
        !privateKey.value.data || !privateKey.value.len) {
        throwCertificateStatus(env, status == LA_TLS_OK ? "IO_ERROR" : statusName(status));
        return nullptr;
    }
    auto copy = [&](const la_tls_buffer& buffer, uint32_t limit) -> jbyteArray {
        if (buffer.len > limit) return nullptr;
        auto result = env->NewByteArray(static_cast<jsize>(buffer.len));
        if (result) env->SetByteArrayRegion(result, 0, static_cast<jsize>(buffer.len),
                                           reinterpret_cast<const jbyte*>(buffer.data));
        return result;
    };
    auto cert = copy(certificate.value, 65536);
    auto key = copy(privateKey.value, 16384);
    jobjectArray result = nullptr;
    auto cls = env->FindClass("[B");
    if (cert && key && cls) {
        result = env->NewObjectArray(2, cls, nullptr);
        if (result) {
            env->SetObjectArrayElement(result, 0, cert);
            env->SetObjectArrayElement(result, 1, key);
        }
    }
    if (cls) env->DeleteLocalRef(cls);
    if (cert) env->DeleteLocalRef(cert);
    if (key) env->DeleteLocalRef(key);
    if (env->ExceptionCheck()) { if (result) env->DeleteLocalRef(result); result = nullptr; }
    if (!result) { throwCertificateStatus(env, "IO_ERROR"); return nullptr; }
    // Both la_tls_buffer RAII members are cleared and freed by Go on return.
    return result;
#else
    throwCertificateStatus(env, "UNSUPPORTED");
    return nullptr;
#endif
}
} // namespace layanalyzer::tls
