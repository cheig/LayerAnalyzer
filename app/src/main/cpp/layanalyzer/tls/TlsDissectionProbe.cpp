// Copyright (c) 2026 cheig; GPL-3.0. P0 experiment, excluded from release.
#include "TlsDissectionProbe.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/TreeFieldReader.h"
#include <epan/follow.h>
#include <epan/prefs.h>
#include <set>
#include <stdexcept>

namespace layanalyzer::tls {
namespace {
constexpr size_t kMaxBytes = 1024 * 1024;
constexpr size_t kMaxFrames = 4096;
std::mutex probeMutex;

struct Failure : std::runtime_error {
    std::string code;
    Failure(const char* code, const char* message) : std::runtime_error(message), code(code) {}
};

std::string sha256(const guint8* bytes, size_t size) {
    gchar* value = g_compute_checksum_for_data(G_CHECKSUM_SHA256, bytes, size);
    std::string result(value);
    g_free(value);
    return result;
}

std::string base64(const guint8* bytes, size_t size) {
    gchar* value = g_base64_encode(bytes, size);
    std::string result(value);
    g_free(value);
    return result;
}

std::string preference(const char* moduleName, const char* name) {
    auto* module = prefs_find_module(moduleName);
    auto* pref = module ? prefs_find_preference(module, name) : nullptr;
    if (!pref) throw Failure("UNSUPPORTED", "Required Wireshark preference is absent");
    gchar* text = prefs_pref_to_str(pref, pref_current);
    if (!text) throw Failure("UNSUPPORTED", "Cannot read Wireshark preference");
    std::string result(text);
    g_free(text);
    return result;
}

void setPreference(const std::string& name, const std::string& value) {
    std::string argument = name + ":" + value;
    gchar* error = nullptr;
    auto status = prefs_set_pref(argument.data(), &error);
    g_free(error); // Never expose a key path or TLS debug contents in an error.
    if (status != PREFS_SET_OK) throw Failure("UNSUPPORTED", "Wireshark rejected probe preference");
}

WiresharkSession* checkedSession(jlong handle) {
    auto* session = find_session_locked(handle);
    if (!session || !session->epan || g_sessions.size() != 1)
        throw Failure("NOT_READY", "Probe requires one active capture");
    return session;
}

// Transactions never acquire their own SessionLease. Scans run outside the
// exclusive guard, with a lease plus per-frame dissect_mutex instead.
struct Configuration {
    jlong handle;
    guint port;
    bool changed = false;
    bool portChanged = false;
    dissector_handle_t oldDissector = nullptr;
    std::vector<std::pair<std::string, std::string>> saved;

    Configuration(jlong handle, guint port) : handle(handle), port(port) {}

    void apply(const std::string& keyPath) {
        RuntimeExclusiveGuard guard;
        auto* session = checkedSession(handle);
        if (session->frame_offsets.empty() || session->frame_offsets.size() > kMaxFrames)
            throw Failure("CAPACITY_EXCEEDED", "Probe capture must contain 1..4096 frames");
        if (!preference("tls", "keylog_file").empty())
            throw Failure("NOT_READY", "An existing TLS secrets context must be closed first");
        for (const auto& item : std::vector<std::pair<const char*, const char*>>{
                {"tls", "debug_file"}, {"tls", "desegment_ssl_records"},
                {"tls", "desegment_ssl_application_data"}, {"tcp", "desegment_tcp_streams"}}) {
            saved.emplace_back(std::string(item.first) + "." + item.second,
                               preference(item.first, item.second));
        }
        auto table = find_dissector_table("tcp.port");
        auto tls = find_dissector("tls");
        if (!table || !tls) throw Failure("UNSUPPORTED", "TLS Decode As is unavailable");
        oldDissector = dissector_get_uint_handle(table, port);
        portChanged = dissector_is_uint_changed(table, port);
        changed = true; // Cleanup also covers partial preference application.
        setPreference("tls.debug_file", "");
        setPreference("tls.keylog_file", keyPath);
        for (size_t i = 1; i < saved.size(); ++i) setPreference(saved[i].first, "TRUE");
        prefs_apply(prefs_find_module("tls"));
        prefs_apply(prefs_find_module("tcp"));
        dissector_change_uint("tcp.port", port, tls);
        reset_dissection_state();
        if (!session->epan) throw Failure("IO_ERROR", "Cannot rebuild capture dissection");
    }

    void clear() {
        if (!changed) return;
        RuntimeExclusiveGuard guard;
        setPreference("tls.keylog_file", "");
        for (const auto& item : saved) setPreference(item.first, item.second);
        prefs_apply(prefs_find_module("tls"));
        prefs_apply(prefs_find_module("tcp"));
        if (portChanged) dissector_change_uint("tcp.port", port, oldDissector);
        else dissector_reset_uint("tcp.port", port);
        // All frame/tap owners have already died before file-scope teardown.
        reset_dissection_state();
        if (!preference("tls", "keylog_file").empty())
            throw Failure("IO_ERROR", "TLS keylog preference did not clear");
        auto* session = find_session_locked(handle);
        if (session && !session->epan) throw Failure("IO_ERROR", "Cannot rebuild cleared capture");
        changed = false;
    }
};

struct Follower {
    follow_info_t* info = g_new0(follow_info_t, 1);
    bool registered = false;
    ~Follower() {
        if (registered) remove_tap_listener(info);
        // This is a heap object, and follow_info_free frees both it and records.
        follow_info_free(info);
    }
};

struct Source {
    std::string id;
    std::string name;
    std::vector<guint8> bytes;
};

void bodyFields(proto_node* node, const char* fieldName,
                const std::map<tvbuff_t*, Source>& sources, json& fields,
                std::vector<guint8>& body, guint frameNumber, unsigned depth = 0) {
    if (!node || depth > 128) return;
    for (auto* child = node->first_child; child; child = child->next) {
        auto* field = PITEM_FINFO(child);
        if (field && field->hfinfo && field->hfinfo->abbrev &&
                strcmp(field->hfinfo->abbrev, fieldName) == 0) {
            auto source = sources.find(field->ds_tvb);
            bool valid = source != sources.end() && !FI_GET_FLAG(field, FI_GENERATED) &&
                field->start >= 0 && field->length > 0 &&
                static_cast<size_t>(field->start) <= source->second.bytes.size() &&
                static_cast<size_t>(field->length) <= source->second.bytes.size() - field->start;
            json entry = {{"field", fieldName}, {"frameNumber", frameNumber},
                          {"start", field->start}, {"length", field->length},
                          {"offsetValid", valid}, {"dataSourceId", nullptr}};
            if (source != sources.end()) entry["dataSourceId"] = source->second.id;
            if (valid) {
                const auto* bytes = source->second.bytes.data() + field->start;
                entry["sha256"] = sha256(bytes, field->length);
                if (body.size() + field->length > kMaxBytes)
                    throw Failure("CAPACITY_EXCEEDED", "Probe body exceeds 1 MiB");
                body.insert(body.end(), bytes, bytes + field->length);
            }
            fields.push_back(entry);
        }
        bodyFields(child, fieldName, sources, fields, body, frameNumber, depth + 1);
    }
}

json scan(jlong handle, guint port, bool http2, bool withTaps) {
    auto lease = acquire_session(handle);
    if (!lease || !lease->epan) throw Failure("NOT_READY", "Capture closed before probe scan");
    auto* follower = get_follow_by_name("TLS"); // Protocol short name, not filter name.
    if (!follower || !get_follow_tap_handler(follower))
        throw Failure("UNSUPPORTED", "TLS follower is not registered");
    Follower tap;
    follow_reset_stream(tap.info);
    tap.info->show_stream = BOTH_HOSTS;
    const char* tapName = get_follow_tap_string(follower);
    if (!tapName) throw Failure("UNSUPPORTED", "TLS tap name is absent");
    const std::string filter = "tcp.port == " + std::to_string(port);
    auto* tapError = register_tap_listener(tapName, tap.info, filter.c_str(),
        TL_REQUIRES_PROTO_TREE, nullptr, get_follow_tap_handler(follower), nullptr, nullptr);
    if (tapError) {
        g_string_free(tapError, TRUE);
        throw Failure("UNSUPPORTED", "Cannot register TLS follower tap");
    }
    tap.registered = true; // Also registered for the ordinary-path negative control.
    json result = {{"withTaps", withTaps}, {"tapName", tapName},
                   {"sources", json::array()}, {"bodyFields", json::array()},
                   {"records", json::array()}, {"frames", 0}};
    std::vector<guint8> body;
    std::set<int> streams;
    size_t sourceBytes = 0, captureBytes = 0;
    std::map<guint, bool> serverFrames;
    const auto cancel = current_cancel_generation();
    for (size_t i = 0; i < lease->frame_offsets.size(); ++i) {
        if (long_operation_cancelled(cancel)) throw Failure("CANCELLED", "Probe scan cancelled");
        std::lock_guard<std::mutex> lock(lease->dissect_mutex);
        DissectedFrame frame;
        bool ok = withTaps ? dissect_frame_with_taps(lease.get(), i, TRUE, FALSE, nullptr, frame)
                          : dissect_frame(lease.get(), i, TRUE, FALSE, nullptr, frame);
        if (!ok) throw Failure("IO_ERROR", "Fixture dissection failed");
        captureBytes += frame.fd->cap_len;
        if (frame.fd->cap_len > 65536 || captureBytes > 16 * kMaxBytes)
            throw Failure("CAPACITY_EXCEEDED", "Probe capture exceeds frame/byte budget");
        ++result["frames"].get_ref<json::number_integer_t&>();
        auto& pi = frame.edt->pi;
        if (pi.ptype != PT_TCP || (pi.srcport != port && pi.destport != port)) continue;
        const int stream = parse_tree_integer(frame.edt->tree, {"tcp.stream"}, -1);
        if (stream >= 0) streams.insert(stream);
        if (streams.size() > 1) throw Failure("INVALID_ARGUMENT", "Probe expects one target TCP stream");
        serverFrames[frame.fd->num] = pi.srcport == port;
        // Seed direction from the first client TCP packet (normally SYN), before
        // encrypted server handshake records can make TLS infer the wrong side.
        if (!tap.info->client_port && pi.destport == port) {
            tap.info->client_port = pi.srcport;
            copy_address(&tap.info->client_ip, &pi.src);
        }
        if (static_cast<size_t>(tap.info->bytes_written[0]) + tap.info->bytes_written[1] > kMaxBytes)
            throw Failure("CAPACITY_EXCEEDED", "TLS follower exceeds 1 MiB");
        std::map<tvbuff_t*, Source> sources;
        size_t index = 0;
        for (auto* item = pi.data_src; item; item = item->next, ++index) {
            auto* ds = static_cast<data_source*>(item->data);
            auto* tvb = get_data_source_tvb(ds);
            if (!tvb) continue;
            const guint size = tvb_captured_length(tvb);
            sourceBytes += size;
            if (sourceBytes > 4 * kMaxBytes || result["sources"].size() >= 8192)
                throw Failure("CAPACITY_EXCEEDED", "Probe source copies exceed 4 MiB");
            char* allocatedName = get_data_source_name(ds);
            Source source{index == 0 ? "raw" : "derived-" + std::to_string(index),
                          allocatedName ? allocatedName : "", std::vector<guint8>(size)};
            wmem_free(nullptr, allocatedName);
            if (size) tvb_memcpy(tvb, source.bytes.data(), 0, size);
            result["sources"].push_back({{"frameNumber", frame.fd->num}, {"id", source.id},
                {"name", source.name}, {"byteLength", size},
                {"sha256", sha256(source.bytes.data(), size)}});
            sources.emplace(tvb, std::move(source));
        }
        if (pi.srcport == port) {
            bodyFields(frame.edt->tree, http2 ? "http2.data.data" : "http.file_data",
                       sources, result["bodyFields"], body, frame.fd->num);
        }
        // All ds_tvb keys die here, before DissectedFrame; only JSON values escape.
    }
    result["tcpStreams"] = streams.size();
    result["bodyBytes"] = body.size();
    result["bodySha256"] = sha256(body.data(), body.size());
    bool directionKnown = true;
    // Library payload is reverse chronological order, as documented by follow.h.
    for (auto* item = g_list_last(tap.info->payload); item; item = item->prev) {
        auto* record = static_cast<follow_record_t*>(item->data);
        if (!record || !record->data) throw Failure("IO_ERROR", "Invalid TLS follower record");
        auto found = serverFrames.find(record->packet_num);
        directionKnown &= found != serverFrames.end() && found->second == bool(record->is_server);
        result["records"].push_back({{"frameNumber", record->packet_num},
            {"fromServer", bool(record->is_server)}, {"byteLength", record->data->len},
            {"bytesBase64", base64(record->data->data, record->data->len)}});
    }
    result["directionKnown"] = !result["records"].empty() && directionKnown;
    return result; // tap removes listener/free records before lease release.
}
} // namespace

jstring probeDissection(JNIEnv* env, jlong handle, jstring keyLogPath,
                        jint serverPort, jboolean http2, jboolean withTaps) {
    std::lock_guard<std::mutex> serialize(probeMutex);
    json result = {{"schemaVersion", 1}, {"success", false}, {"errorCode", nullptr}, {"error", nullptr}};
    Configuration config(handle, serverPort);
    try {
        if (serverPort < 1 || serverPort > 65535)
            throw Failure("INVALID_ARGUMENT", "Invalid fixture server port");
        std::string keyPath;
        if (keyLogPath) {
            const char* chars = env->GetStringUTFChars(keyLogPath, nullptr);
            if (!chars) return nullptr;
            keyPath = chars;
            env->ReleaseStringUTFChars(keyLogPath, chars);
            struct stat info{};
            if (keyPath.empty() || keyPath.size() > 4096 || keyPath.find('\n') != std::string::npos ||
                    keyPath.find('\r') != std::string::npos || stat(keyPath.c_str(), &info) != 0 ||
                    !S_ISREG(info.st_mode) || info.st_size > 16 * kMaxBytes)
                throw Failure("INVALID_ARGUMENT", "Invalid test keylog file");
        }
        config.apply(keyPath);
        result["scan"] = scan(handle, serverPort, http2 == JNI_TRUE, withTaps == JNI_TRUE);
        config.clear();
        result["preferenceCleared"] = true;
        result["epanRebuilt"] = true;
        result["success"] = true;
    } catch (const Failure& failure) {
        result["errorCode"] = failure.code;
        result["error"] = failure.what();
    } catch (...) {
        result["errorCode"] = "IO_ERROR";
        result["error"] = "TLS dissection probe failed";
    }
    try { config.clear(); }
    catch (...) {
        result = {{"schemaVersion", 1}, {"success", false}, {"errorCode", "IO_ERROR"},
                  {"error", "TLS probe cleanup failed; close capture before continuing"}};
    }
    return new_java_string(env, dump_json(result));
}
} // namespace layanalyzer::tls
