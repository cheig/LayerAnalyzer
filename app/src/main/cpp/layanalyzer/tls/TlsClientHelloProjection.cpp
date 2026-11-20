// Copyright (c) 2026 cheig; GPL-3.0.
#include "TlsClientHelloProjection.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/TreeFieldReader.h"
#include <wsutil/nstime.h>
#include <stdexcept>

namespace layanalyzer::tls {
namespace {
// A capture rarely holds more than a few thousand handshakes. The projection is a
// bounded read (C07), so a larger capture stops at the limit and reports truncated
// instead of allocating an unbounded array.
constexpr int kDefaultMaxFrames = 4096;
constexpr int kMaxFrames = 65536;

// RFC 8446: the ClientHello.random is 32 bytes. A field of another length is not a
// client_random, so it is skipped rather than truncated into a wrong key.
constexpr guint kClientRandomBytes = 32;

struct Failure : std::runtime_error {
    const char* code;
    Failure(const char* code, const char* message) : std::runtime_error(message), code(code) {}
};

json envelope() {
    return {{"schemaVersion", 1}, {"success", false}, {"errorCode", nullptr}, {"error", nullptr}};
}

// The ClientHello random of one dissected frame, as lowercase hex. Only called for a
// frame whose tls.handshake.type is 1, so this never reads a ServerHello random. Uses
// the field's own data source range, exactly like the other field readers.
bool clientRandomHex(const FieldIndex& fields, std::string& out) {
    auto found = fields.values.find("tls.handshake.random");
    if (found == fields.values.end()) return false;
    for (field_info* field : found->second) {
        if (!field || !field->ds_tvb || field->start < 0 ||
            static_cast<guint>(field->length) != kClientRandomBytes) {
            continue;
        }
        const guint8* data = tvb_get_ptr(field->ds_tvb, field->start, field->length);
        if (!data) continue;
        static const char* kHex = "0123456789abcdef";
        out.clear();
        out.reserve(kClientRandomBytes * 2);
        for (guint i = 0; i < kClientRandomBytes; ++i) {
            out.push_back(kHex[data[i] >> 4]);
            out.push_back(kHex[data[i] & 0x0f]);
        }
        return true;
    }
    return false;
}

bool hasHandshakeType(const FieldIndex& fields, guint type) {
    auto found = fields.values.find("tls.handshake.type");
    if (found == fields.values.end()) return false;
    for (field_info* field : found->second) {
        if (field && fvalue_get_uinteger(&field->value) == type) return true;
    }
    return false;
}
} // namespace

jstring projectClientHellos(JNIEnv* env, jlong session, jlong expectedGeneration, jint maxFrames) {
    json result = envelope();
    result["dissectionGeneration"] = expectedGeneration;
    result["observations"] = json::array();
    result["truncated"] = false;
    try {
        if (expectedGeneration < 0)
            throw Failure("INVALID_ARGUMENT", "Generation must be nonnegative");
        const int limit = maxFrames <= 0 ? kDefaultMaxFrames : maxFrames;
        if (limit < 1 || limit > kMaxFrames)
            throw Failure("INVALID_ARGUMENT", "Frame budget is out of range");

        auto handle = acquire_session(session);
        if (!handle || !handle->wth || !handle->epan || handle->closed.load())
            throw Failure("NOT_READY", "Capture session is unavailable");
        const uint64_t generation = static_cast<uint64_t>(expectedGeneration);
        const auto cancel = current_cancel_generation();

        const size_t total = handle->frame_offsets.size();
        for (size_t index = 0; index < total; ++index) {
            if (handle->closed.load() || long_operation_cancelled(cancel))
                throw Failure("CANCELLED", "ClientHello projection cancelled");
            if (handle->dissection_generation.load() != generation)
                throw Failure("STALE_GENERATION", "Capture analysis changed");
            if (static_cast<int>(result["observations"].size()) >= limit) {
                result["truncated"] = true;
                break;
            }
            {
                // Wireshark's epan is not thread-safe: one frame under the dissection
                // mutex, released before the next so paging can make progress.
                std::lock_guard<std::mutex> lock(handle->dissect_mutex);
                DissectedFrame frame;
                if (!dissect_frame(handle.get(), static_cast<int>(index), TRUE, FALSE, nullptr, frame))
                    throw Failure("IO_ERROR", "Cannot dissect capture frame");
                FieldIndex fields(frame.edt->tree);
                if (!hasHandshakeType(fields, 1)) continue; // 1 == ClientHello
                std::string random;
                if (!clientRandomHex(fields, random)) continue;
                char address[256] = {0};
                address_to_str_buf(&frame.edt->pi.net_dst, address, sizeof(address));
                result["observations"].push_back({
                    {"frameNumber", static_cast<int64_t>(frame.fd->num)},
                    {"frameTimeMillis", static_cast<int64_t>(nstime_to_msec(&frame.fd->abs_ts))},
                    {"clientRandom", random},
                    {"destinationIp", std::string(address)},
                    {"destinationPort", static_cast<int>(frame.edt->pi.destport)}
                });
            }
            yield_to_interactive_reads(handle.get());
        }
        if (handle->closed.load())
            throw Failure("NOT_READY", "Capture session is unavailable");
        if (handle->dissection_generation.load() != generation)
            throw Failure("STALE_GENERATION", "Capture analysis changed");
        result["success"] = true;
    } catch (const Failure& failure) {
        result = envelope(); // Never retain partial observations on a failed response.
        result["errorCode"] = failure.code;
        result["error"] = failure.what();
    } catch (const std::bad_alloc&) {
        result = envelope();
        result["errorCode"] = "CAPACITY_EXCEEDED";
        result["error"] = "Cannot allocate ClientHello projection";
    } catch (...) {
        result = envelope();
        result["errorCode"] = "IO_ERROR";
        result["error"] = "ClientHello projection failed";
    }
    if (env->ExceptionCheck()) return nullptr;
    return new_java_string(env, dump_json(result));
}
}
