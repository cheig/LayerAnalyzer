// Copyright (c) 2026 cheig; GPL-3.0.
#include "TlsFollowStream.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/TreeFieldReader.h"
#include <epan/follow.h>
#include <epan/dissectors/packet-tls-utils.h>
#include <cstdio>
#include <functional>
#include <memory>
#include <stdexcept>

namespace layanalyzer::tls {
namespace {
constexpr size_t kMaxBytes = 1024 * 1024;
// Full-stream export cap. The preview stays at kMaxBytes; this only bounds one connection's
// streamed-to-file export, which never holds the stream in memory.
constexpr size_t kMaxExportBytes = 64 * 1024 * 1024;
// Also bound JSON/record overhead when a peer sends tiny application records.
constexpr size_t kMaxRecords = 8192;

struct Failure : std::runtime_error {
    const char* code;
    Failure(const char* code, const char* message) : std::runtime_error(message), code(code) {}
};

void checkCurrent(WiresharkSession* session, uint64_t generation, uint64_t cancel) {
    if (session->closed.load() || long_operation_cancelled(cancel))
        throw Failure("CANCELLED", "TLS follow cancelled");
    if (session->dissection_generation.load() != generation)
        throw Failure("STALE_GENERATION", "Capture analysis changed");
}

struct Follower {
    follow_info_t* info = nullptr;
    tap_packet_cb handler;
    // When set, application records are streamed to the export sink (bounded chunks) instead of
    // being accumulated as follow records. It owns hashing/writing and returns false on write error.
    std::function<bool(const guint8*, size_t)> sink;
    size_t limit, bytes = 0, records = 0;
    bool truncated = false, gap = false, invalid = false, sinkFailed = false;

    Follower(tap_packet_cb handler, size_t limit) : handler(handler), limit(limit) {
        // Optimized GLib uses a statement expression, invalid in a member initializer.
        info = g_new0(follow_info_t, 1);
        follow_reset_stream(info);
        info->show_stream = BOTH_HOSTS;
    }
    ~Follower() { follow_info_free(info); }

    // These are the bundled 4.0.10 public tap structs, not private symbols.
    // Dispatch one bounded application record to the REGISTERED handler. It
    // owns copying/ordering/deduplication. Never modify the dissector's record.
    static tap_packet_status packet(void* data, packet_info* pi, epan_dissect_t* edt,
                                    const void* payload, tap_flags_t flags) noexcept {
        auto& self = *static_cast<Follower*>(data);
        auto* packet = static_cast<const SslPacketInfo*>(payload);
        if (!packet || self.truncated || self.invalid || self.sinkFailed) return TAP_PACKET_DONT_REDRAW;
        const bool server = self.info->client_port != pi->srcport ||
            !addresses_equal(&self.info->client_ip, &pi->src);
        const auto from = server ? FROM_SERVER : FROM_CLIENT;
        for (auto* record = packet->records; record; record = record->next) {
            if (record->type != SSL_ID_APP_DATA || record->data_len == 0) continue;
            if (!record->plain_data) { self.invalid = true; break; }
            // The TLS handler uses bytes_written as the next application seq.
            // A gap must not permit duplicate records on subsequent callbacks.
            if (record->seq < self.info->bytes_written[from]) continue;
            if (record->seq > self.info->bytes_written[from]) {
                self.gap = true;
                self.info->bytes_written[from] = record->seq;
            }
            // The export streams to a file, so it is bounded only by bytes, not by a record count.
            if (self.bytes == self.limit || (!self.sink && self.records == kMaxRecords)) {
                self.truncated = true;
                break;
            }
            auto bounded = *record;
            bounded.next = nullptr;
            bounded.data_len = static_cast<guint>(std::min<size_t>(record->data_len, self.limit - self.bytes));
            // Avoid wrapping the handler's guint sequence counter.
            if (bounded.data_len > G_MAXUINT - record->seq) { self.invalid = true; break; }
            if (self.sink) {
                if (!self.sink(record->plain_data, bounded.data_len)) { self.sinkFailed = true; break; }
                // The registered handler advances this cursor for the preview.
                // Streaming bypasses that handler, so it must advance explicitly
                // for contiguous records and duplicate callbacks to behave alike.
                self.info->bytes_written[from] = record->seq + bounded.data_len;
            } else {
                auto boundedPacket = *packet;
                boundedPacket.records = &bounded;
                self.handler(self.info, pi, edt, &boundedPacket, flags);
            }
            self.bytes += bounded.data_len;
            ++self.records;
            if (bounded.data_len != record->data_len) { self.truncated = true; break; }
        }
        return TAP_PACKET_DONT_REDRAW;
    }
};

// Registration, with-taps dissection, removal and frame destruction all take
// place under the SAME dissect_mutex. No listener exists between scan frames,
// so unrelated HTTP/RTP scans cannot feed our accumulator or race tap teardown.
struct TapRegistration {
    Follower& follower;
    TapRegistration(Follower& follower, const char* name, const std::string& filter) : follower(follower) {
        auto* error = register_tap_listener(name, &follower, filter.c_str(), TL_REQUIRES_PROTO_TREE,
                                           nullptr, Follower::packet, nullptr, nullptr);
        if (error) {
            g_string_free(error, TRUE);
            throw Failure("UNSUPPORTED", "TLS follower tap is unavailable");
        }
    }
    ~TapRegistration() { remove_tap_listener(&follower); }
};

bool hasValue(const FieldIndex& fields, const char* name, guint value) {
    const auto found = fields.values.find(name);
    if (found == fields.values.end()) return false;
    return std::any_of(found->second.begin(), found->second.end(), [value](field_info* field) {
        return fvalue_get_uinteger(&field->value) == value;
    });
}

json scan(jlong handle, int selectedIndex, uint64_t generation, size_t maxBytes,
          const std::string& exportPath) {
    const auto cancel = current_cancel_generation();
    auto session = acquire_session(handle);
    if (!session || !session->wth || !session->epan)
        throw Failure("NOT_READY", "No capture is open");
    checkCurrent(session, generation, cancel);
    if (selectedIndex < 0 || static_cast<size_t>(selectedIndex) >= session->frame_offsets.size())
        throw Failure("INVALID_ARGUMENT", "Invalid packet index");
    auto* registration = get_follow_by_name("TLS");
    auto handler = registration ? get_follow_tap_handler(registration) : nullptr;
    const char* tapName = registration ? get_follow_tap_string(registration) : nullptr;
    if (!handler || !tapName) throw Failure("UNSUPPORTED", "TLS follower is not registered");

    const bool streaming = !exportPath.empty();
    // RAII so a mid-scan failure never leaks the file or checksum.
    struct FileCloser { void operator()(FILE* file) const { if (file) fclose(file); } };
    struct ChecksumFree { void operator()(GChecksum* checksum) const { if (checksum) g_checksum_free(checksum); } };
    std::unique_ptr<FILE, FileCloser> exportFile;
    std::unique_ptr<GChecksum, ChecksumFree> checksum;
    if (streaming) {
        FILE* raw = std::fopen(exportPath.c_str(), "wb");
        if (!raw) throw Failure("IO_ERROR", "Cannot open TLS stream export file");
        exportFile.reset(raw);
        checksum.reset(g_checksum_new(G_CHECKSUM_SHA256));
        if (!checksum) throw Failure("IO_ERROR", "Cannot initialise the stream export digest");
    }

    int stream = -1;
    // TLS-106 performs the first sequential pass after configuration. Complete
    // that context for native callers too, BEFORE inspecting the selected frame.
    // Preserve visited bookkeeping: resetting it without epan_free corrupts TCP
    // reassembly. A read must not reset epan or silently change its generation.
    for (size_t index = 0; index < session->frame_offsets.size(); ++index) {
        checkCurrent(session, generation, cancel);
        {
            std::lock_guard<std::mutex> lock(session->dissect_mutex);
            DissectedFrame frame;
            if (!dissect_frame(session, index, TRUE, FALSE, nullptr, frame))
                throw Failure("IO_ERROR", "Cannot prepare TLS capture context");
            if (index == static_cast<size_t>(selectedIndex))
                stream = parse_tree_integer(frame.edt->tree, {"tcp.stream"}, -1);
        }
        yield_to_interactive_reads(session);
    }
    if (stream < 0) throw Failure("INVALID_ARGUMENT", "Selected packet has no TCP connection");
    Follower follower(handler, maxBytes);
    if (streaming) {
        FILE* out = exportFile.get();
        GChecksum* sum = checksum.get();
        // Bounded chunks: one application record at a time, hashed as it is written.
        follower.sink = [out, sum](const guint8* data, size_t len) -> bool {
            if (len && std::fwrite(data, 1, len, out) != len) return false;
            g_checksum_update(sum, data, static_cast<gssize>(len));
            return true;
        };
    }
    const std::string filter = "tcp.stream == " + std::to_string(stream);
    bool directionKnown = false, sawTls = false, clientHello = false, serverHello = false;
    bool syn = false, clientFin = false, serverFin = false, reset = false, missing = false;
    size_t frames = 0;
    for (size_t index = 0; index < session->frame_offsets.size(); ++index) {
        checkCurrent(session, generation, cancel);
        {
            std::lock_guard<std::mutex> lock(session->dissect_mutex);
            DissectedFrame context;
            if (!dissect_frame(session, index, TRUE, FALSE, nullptr, context))
                throw Failure("IO_ERROR", "Cannot inspect TLS connection");
            FieldIndex fields(context.edt->tree);
            if (fields.integer({"tcp.stream"}) != stream) continue;
            ++frames;
            auto& pi = context.edt->pi;
            const bool isSyn = fields.boolean("tcp.flags.syn");
            const bool isAck = fields.boolean("tcp.flags.ack");
            const bool hello = hasValue(fields, "tls.handshake.type", 1);
            if (!follower.info->client_port || (!directionKnown && hello && !follower.bytes)) {
                // The first SYN (including SYN/ACK) or ClientHello gives roles.
                // Otherwise keep a stable first endpoint but label UNKNOWN.
                const bool reverse = isSyn && isAck;
                free_address(&follower.info->client_ip);
                free_address(&follower.info->server_ip);
                follower.info->client_port = reverse ? pi.destport : pi.srcport;
                follower.info->server_port = reverse ? pi.srcport : pi.destport;
                copy_address(&follower.info->client_ip, reverse ? &pi.dst : &pi.src);
                copy_address(&follower.info->server_ip, reverse ? &pi.src : &pi.dst);
                directionKnown = isSyn || hello;
            }
            const bool server = pi.srcport != follower.info->client_port ||
                !addresses_equal(&follower.info->client_ip, &pi.src);
            syn |= isSyn && !isAck;
            clientHello |= hello;
            serverHello |= hasValue(fields, "tls.handshake.type", 2);
            sawTls |= fields.values.count("tls") != 0;
            reset |= fields.boolean("tcp.flags.reset");
            if (fields.boolean("tcp.flags.fin")) (server ? serverFin : clientFin) = true;
            missing |= context.fd->cap_len < context.fd->pkt_len ||
                fields.boolean("tcp.analysis.lost_segment") ||
                fields.boolean("tcp.analysis.ack_lost_segment");
            // A partly decryptable connection must not look complete merely
            // because another frame/direction produced some application bytes.
            if (fields.values.count("tls.app_data")) {
                bool decrypted = false;
                for (auto* item = pi.data_src; item; item = item->next) {
                    auto* source = static_cast<data_source*>(item->data);
                    char* name = get_data_source_name(source);
                    decrypted |= name && g_str_has_prefix(name, "Decrypted TLS");
                    wmem_free(nullptr, name);
                }
                missing |= !decrypted;
            }
            if (!follower.truncated) {
                DissectedFrame replay;
                TapRegistration tap(follower, tapName, filter);
                if (!dissect_frame_with_taps(session, index, TRUE, FALSE, nullptr, replay))
                    throw Failure("IO_ERROR", "Cannot replay TLS connection");
            }
        }
        yield_to_interactive_reads(session);
    }
    checkCurrent(session, generation, cancel);
    if (follower.invalid) throw Failure("IO_ERROR", "Invalid TLS application record");
    if (follower.sinkFailed) throw Failure("IO_ERROR", "Cannot write TLS stream export");
    json result = {{"streamId", stream}, {"directionKnown", directionKnown},
        {"truncated", follower.truncated},
        {"incomplete", missing || follower.gap || !directionKnown || !syn || !clientHello || !serverHello ||
            !(reset || (clientFin && serverFin)) || follower.truncated},
        {"connectionFrames", frames}, {"byteLength", follower.bytes},
        {"unavailableReason", nullptr}};
    if (!sawTls) result["unavailableReason"] = "NOT_TLS";
    else if (!follower.bytes) result["unavailableReason"] =
        session->tls_keylog_path.empty() ? "SECRETS_NOT_CONFIGURED" :
        (!clientHello || !serverHello) ? "HANDSHAKE_INCOMPLETE" : "NO_DECRYPTED_APPLICATION_DATA";
    if (streaming) {
        // Digest of exactly the bytes written; the export carries no bytes in the envelope.
        const gchar* digest = g_checksum_get_string(checksum.get());
        result["sha256"] = digest ? std::string(digest) : std::string();
    } else {
        result["records"] = json::array();
        for (auto* node = g_list_last(follower.info->payload); node; node = node->prev) {
            auto* record = static_cast<follow_record_t*>(node->data);
            if (!record || !record->data) throw Failure("IO_ERROR", "Invalid TLS follower result");
            gchar* encoded = g_base64_encode(record->data->data, record->data->len);
            const std::string bytes(encoded);
            g_free(encoded);
            result["records"].push_back({{"frameNumber", record->packet_num},
                {"direction", directionKnown ? (record->is_server ? "server" : "client") : "unknown"},
                {"fromServer", directionKnown ? json(bool(record->is_server)) : json(nullptr)},
                {"byteLength", record->data->len}, {"bytesBase64", bytes}});
        }
    }
    checkCurrent(session, generation, cancel);
    if (streaming) {
        // Buffered fwrite may succeed while the final flush fails (e.g. ENOSPC).
        // Close explicitly before publishing length/digest, and leave the outer
        // export failure path responsible for removing the partial file.
        FILE* out = exportFile.release();
        const bool flushed = std::fflush(out) == 0;
        const bool closed = std::fclose(out) == 0;
        if (!flushed || !closed) throw Failure("IO_ERROR", "Cannot finish TLS stream export");
    }
    return result;
}
} // namespace

jstring followStream(JNIEnv* env, jlong session, jint packetIndex,
                     jlong expectedGeneration, jint maxBytes) {
    json result = {{"schemaVersion", 1}, {"success", false}, {"errorCode", nullptr}, {"error", nullptr},
        {"protocol", "tls"}, {"scope", "complete_connection"}, {"dissectionGeneration", expectedGeneration},
        {"directionKnown", false}, {"records", json::array()}, {"truncated", false}, {"incomplete", true},
        {"unavailableReason", nullptr}};
    try {
        if (expectedGeneration < 0 || maxBytes <= 0 || static_cast<size_t>(maxBytes) > kMaxBytes)
            throw Failure("INVALID_ARGUMENT", "Invalid TLS follow generation or byte budget");
        result.update(scan(session, packetIndex, expectedGeneration, maxBytes, std::string()));
        if (!result["unavailableReason"].is_null()) {
            result["incomplete"] = true;
            throw Failure("NOT_READY", "No decrypted TLS application data is available");
        }
        result["success"] = true;
    } catch (const Failure& failure) {
        result["errorCode"] = failure.code;
        result["error"] = failure.what();
    } catch (...) {
        result["errorCode"] = "IO_ERROR";
        result["error"] = "TLS follow failed";
    }
    if (env->ExceptionCheck()) return nullptr;
    return new_java_string(env, dump_json(result));
}

// TLS-308 bounded full-stream export. Same session/generation lease and scan as the preview, but
// the plaintext is streamed to `outputPath` in bounded chunks and only the digest is returned. The
// preview's 1 MiB budget is unchanged and is never used to fake a full export. On any failure or
// cancellation the partial file is removed, so a half file is never reported as a success.
jstring exportStream(JNIEnv* env, jlong session, jint packetIndex,
                     jlong expectedGeneration, jstring outputPath, jint maxBytes) {
    json result = {{"schemaVersion", 1}, {"success", false}, {"errorCode", nullptr}, {"error", nullptr},
        {"protocol", "tls"}, {"scope", "complete_connection"}, {"dissectionGeneration", expectedGeneration},
        {"directionKnown", false}, {"truncated", false}, {"incomplete", true},
        {"unavailableReason", nullptr}, {"sha256", nullptr}, {"byteLength", 0}};

    std::string path;
    if (outputPath) {
        const char* chars = env->GetStringUTFChars(outputPath, nullptr);
        if (chars) path = chars;
        env->ReleaseStringUTFChars(outputPath, chars);
    }
    bool wrote = false;
    try {
        if (expectedGeneration < 0 || maxBytes <= 0 || static_cast<size_t>(maxBytes) > kMaxExportBytes)
            throw Failure("INVALID_ARGUMENT", "Invalid TLS export generation or byte budget");
        if (path.empty()) throw Failure("INVALID_ARGUMENT", "An output path is required");
        json scanned = scan(session, packetIndex, expectedGeneration, maxBytes, path);
        if (!scanned["unavailableReason"].is_null()) {
            throw Failure("NOT_READY", "No decrypted TLS application data is available");
        }
        const std::string digest = scanned["sha256"].get<std::string>();
        if (digest.empty()) throw Failure("IO_ERROR", "TLS stream export produced no digest");
        result.update(scanned);
        result["success"] = true;
        wrote = true;
    } catch (const Failure& failure) {
        result["errorCode"] = failure.code;
        result["error"] = failure.what();
    } catch (...) {
        result["errorCode"] = "IO_ERROR";
        result["error"] = "TLS stream export failed";
    }
    if (!wrote && !path.empty()) std::remove(path.c_str());
    if (env->ExceptionCheck()) return nullptr;
    return new_java_string(env, dump_json(result));
}
}
