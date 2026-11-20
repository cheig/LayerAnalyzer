// Copyright (c) 2026 cheig; GPL-3.0.
#include "TlsDataSources.h"
#include "layanalyzer/session/WiresharkSession.h"
#include <algorithm>
#include <stdexcept>
#include <unordered_set>

namespace layanalyzer::tls {
namespace {
std::atomic<uint64_t> next_snapshot_id{1};

struct Failure : std::runtime_error {
    const char* code;
    Failure(const char* code, const char* message) : std::runtime_error(message), code(code) {}
};

std::string readId(JNIEnv* env, jstring input) {
    if (!input) throw Failure("INVALID_ARGUMENT", "Data source identity is required");
    const jsize size = env->GetStringLength(input);
    if (size <= 0 || size > 96)
        throw Failure("INVALID_ARGUMENT", "Invalid data source identity");
    const jchar* chars = env->GetStringChars(input, nullptr);
    if (!chars) throw Failure("IO_ERROR", "Cannot read data source identity");
    std::string value;
    bool valid = true;
    for (jsize i = 0; i < size; ++i) {
        const auto c = chars[i];
        valid &= (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        value.push_back(static_cast<char>(c));
    }
    env->ReleaseStringChars(input, chars);
    if (!valid) throw Failure("INVALID_ARGUMENT", "Invalid data source identity");
    return value;
}

std::string sourceKind(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // Labels are Wireshark's data-source labels, not packet protocol guesses.
    if (lower.find("decrypted tls") != std::string::npos) return "decrypted_tls";
    if (lower.find("reassembled") != std::string::npos) return "reassembled";
    return "derived";
}

// Protocol field ids resolved once. -1 means this build does not register the
// field, and the corresponding fact is then simply not reported.
struct TlsProbeFieldIds {
    int stream;
    int opaque_type;
    int record_version;
};

const TlsProbeFieldIds& probeFieldIds() {
    static const TlsProbeFieldIds ids{
        proto_registrar_get_id_byname("tcp.stream"),
        proto_registrar_get_id_byname("tls.record.opaque_type"),
        proto_registrar_get_id_byname("tls.record.version")};
    return ids;
}

// Same value rule as FieldReader: FT_BOOLEAN lives in the 64-bit slot and the
// 32-bit accessor aborts, so the type decides which accessor may be used.
uint32_t unsignedFieldValue(field_info* field) {
    if (!field) return 0;
    switch (fvalue_type_ftenum(&field->value)) {
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
            return static_cast<uint32_t>(fvalue_get_uinteger(&field->value));
        case FT_UINT64:
            return static_cast<uint32_t>(fvalue_get_uinteger64(&field->value));
        default:
            return 0;
    }
}

/**
 * Reads this frame's connection and record version from the dissected tree.
 *
 * Only ever called for a frame that already produced decrypted data, so the
 * extra walk is proportional to the plaintext frames of a capture, not to all of
 * them. `tls.record.opaque_type` is decisive when present (1.3); otherwise the
 * record header version is the legacy answer. The walk may stop early once both
 * answers are known -- but only once the 1.3 marker has been seen, because its
 * absence can only be established by reaching the end.
 */
void readTlsIdentity(proto_node* node, DecryptedSourceProbe& probe) {
    const TlsProbeFieldIds& ids = probeFieldIds();
    for (proto_node* current = node ? node->first_child : nullptr; current;
         current = current->next) {
        field_info* field = PITEM_FINFO(current);
        if (field && field->hfinfo) {
            const int id = field->hfinfo->id;
            if (ids.stream >= 0 && id == ids.stream && probe.stream < 0) {
                probe.stream = static_cast<int32_t>(unsignedFieldValue(field));
            } else if (ids.opaque_type >= 0 && id == ids.opaque_type) {
                probe.tls_version = 0x0304;
            } else if (ids.record_version >= 0 && id == ids.record_version &&
                       probe.tls_version == 0) {
                probe.tls_version = static_cast<uint16_t>(unsignedFieldValue(field));
            }
        }
        // A 1.3 record proves 1.3 regardless of what its legacy header says, so
        // the marker must not be overwritten by a later record-version field;
        // the branch above only fills an empty slot.
        if (probe.stream >= 0 && probe.tls_version == 0x0304) return;
        readTlsIdentity(current, probe);
        if (probe.stream >= 0 && probe.tls_version == 0x0304) return;
    }
}

json envelope() {
    return {{"schemaVersion", 1}, {"success", false}, {"errorCode", nullptr}, {"error", nullptr}};
}

json sourceDescription(const PacketDataSource& source) {
    return {{"id", source.id}, {"name", source.name}, {"kind", source.kind},
            {"byteLength", source.byte_length}, {"availableLength", source.bytes.size()},
            {"truncated", source.bytes.size() < source.byte_length}};
}

json query(JNIEnv* env, jlong handle, jstring snapshotId, jlong expectedGeneration,
           bool read, jstring sourceId, jint offset, jint length) {
    json result = envelope();
    try {
        if (expectedGeneration < 0)
            throw Failure("INVALID_ARGUMENT", "Generation must be nonnegative");
        const std::string id = readId(env, snapshotId);
        const std::string source_id = read ? readId(env, sourceId) : std::string();
        if (read && (offset < 0 || length < 0 || static_cast<size_t>(length) > kDataSourceRangeLimit))
            throw Failure("INVALID_ARGUMENT", "Range must be nonnegative and at most 256 KiB");
        auto session = acquire_session(handle);
        if (!session || session->closed.load() || !session->epan)
            throw Failure("NOT_READY", "Capture session is unavailable");
        std::lock_guard<std::mutex> lock(session->dissect_mutex);
        if (session->dissection_generation.load() != static_cast<uint64_t>(expectedGeneration))
            throw Failure("STALE_GENERATION", "Packet dissection has changed");
        const auto& entries = session->data_snapshots.entries;
        const auto snapshot = std::find_if(entries.begin(), entries.end(),
                                         [&](const auto& entry) { return entry.id == id; });
        if (snapshot == entries.end() || snapshot->generation != static_cast<uint64_t>(expectedGeneration))
            throw Failure("STALE_GENERATION", "Packet data snapshot has expired");
        result["snapshotId"] = snapshot->id;
        result["dissectionGeneration"] = snapshot->generation;
        result["frameNumber"] = snapshot->frame_number;
        if (!read) {
            result["sources"] = json::array();
            for (const auto& source : snapshot->sources)
                result["sources"].push_back(sourceDescription(source));
        } else {
            const auto source = std::find_if(snapshot->sources.begin(), snapshot->sources.end(),
                                            [&](const auto& entry) { return entry.id == source_id; });
            if (source == snapshot->sources.end())
                throw Failure("INVALID_ARGUMENT", "Data source does not belong to this snapshot");
            const size_t start = static_cast<size_t>(offset);
            const size_t count = static_cast<size_t>(length);
            // Subtraction avoids signed offset+length overflow. Do not silently
            // serve another source or turn a truncated range into empty success.
            if (start > source->bytes.size() || count > source->bytes.size() - start)
                throw Failure("INVALID_ARGUMENT", "Range exceeds available source bytes");
            result["sourceId"] = source->id;
            result["offset"] = offset;
            result["length"] = length;
            result["byteLength"] = source->byte_length;
            result["availableLength"] = source->bytes.size();
            result["truncated"] = source->bytes.size() < source->byte_length;
            gchar* encoded = g_base64_encode(count ? source->bytes.data() + start : nullptr, count);
            result["bytesBase64"] = encoded ? encoded : "";
            g_free(encoded);
        }
        if (session->closed.load())
            throw Failure("NOT_READY", "Capture session is unavailable");
        result["success"] = true;
    } catch (const Failure& failure) {
        result = envelope(); // Never retain partial bytes on a failed response.
        result["errorCode"] = failure.code;
        result["error"] = failure.what();
    } catch (const std::bad_alloc&) {
        result = envelope();
        result["errorCode"] = "CAPACITY_EXCEEDED";
        result["error"] = "Cannot allocate packet data response";
    } catch (...) {
        result = envelope();
        result["errorCode"] = "IO_ERROR";
        result["error"] = "Cannot read packet data snapshot";
    }
    return result;
}
}

PacketDataSnapshots::~PacketDataSnapshots() { clear(); }

void PacketDataSnapshots::evictOldest() {
    if (entries.empty()) return;
    auto& snapshot = entries.front();
    byte_size -= snapshot.byte_size;
    for (auto& source : snapshot.sources) {
        // Best-effort erasure of owned plaintext on eviction/reset/close.
        volatile uint8_t* data = source.bytes.data();
        for (size_t i = 0; i < source.bytes.size(); ++i) data[i] = 0;
    }
    entries.pop_front();
}

void PacketDataSnapshots::clear() {
    while (!entries.empty()) evictOldest();
}

PacketDataSnapshot buildDataSnapshot(WiresharkSession& session, DissectedFrame& frame,
                                    PacketSourceBindings& bindings) {
    auto& cache = session.data_snapshots;
    // Evict before allocating: even the in-progress copy counts toward 8 MiB.
    while (cache.entries.size() >= kDetailSnapshotLimit) cache.evictOldest();
    PacketDataSnapshot snapshot;
    const auto sequence = next_snapshot_id.fetch_add(1);
    if (sequence == 0 || sequence > static_cast<uint64_t>(INT64_MAX))
        throw Failure("CAPACITY_EXCEEDED", "Packet snapshot identity limit reached");
    snapshot.id = "detail-" + std::to_string(sequence);
    snapshot.generation = session.dissection_generation.load();
    snapshot.frame_number = frame.fd->num;

    auto addSource = [&](tvbuff_t* tvb, const std::string& name, bool raw) {
        if (!tvb || bindings.find(tvb) != bindings.end()) return;
        // Metadata is bounded too; never silently omit an unknown source and
        // accidentally map its fields onto raw bytes.
        if (snapshot.sources.size() >= 4096 || name.size() > 4096)
            throw Failure("CAPACITY_EXCEEDED", "Packet source metadata exceeds limits");
        PacketDataSource source;
        source.id = raw ? "raw" : "derived-" + std::to_string(snapshot.sources.size());
        source.name = name;
        source.kind = raw ? "raw_frame" : sourceKind(name);
        const size_t captured = tvb_captured_length(tvb);
        source.byte_length = std::max<uint64_t>(captured, tvb_reported_length(tvb));
        while (!cache.entries.empty() && captured > kDetailBytesLimit - cache.byte_size - snapshot.byte_size)
            cache.evictOldest();
        const size_t count = std::min(captured, kDetailBytesLimit - cache.byte_size - snapshot.byte_size);
        source.bytes.resize(count);
        if (count) tvb_memcpy(tvb, source.bytes.data(), 0, count);
        bindings.emplace(tvb, snapshot.sources.size());
        snapshot.byte_size += count;
        snapshot.sources.push_back(std::move(source));
    };
    // Raw identity comes from the actual frame tvb, never the position/name of
    // an arbitrary data source. field_info.ds_tvb is already source-relative.
    addSource(frame.edt->tvb, "Frame", true);
    for (auto* item = frame.edt->pi.data_src; item; item = item->next) {
        auto* source = static_cast<data_source*>(item->data);
        auto* tvb = get_data_source_tvb(source);
        char* allocated = get_data_source_name(source);
        std::string name = allocated ? allocated : "";
        wmem_free(nullptr, allocated);
        addSource(tvb, name, false);
    }
    return snapshot;
}

void retainDataSnapshot(WiresharkSession& session, PacketDataSnapshot&& snapshot) {
    const size_t count = snapshot.byte_size;
    session.data_snapshots.entries.push_back(std::move(snapshot));
    session.data_snapshots.byte_size += count;
}

DecryptedSourceProbe probeDecryptedSources(DissectedFrame& frame) {
    DecryptedSourceProbe probe;
    if (!frame.edt) return probe;
    // buildDataSnapshot() registers the frame's own tvb first and then ignores any
    // data source bound to a tvbuff it has already taken, so the same tvb must not
    // be counted twice here either.
    std::unordered_set<tvbuff_t*> seen;
    seen.insert(frame.edt->tvb);
    for (auto* item = frame.edt->pi.data_src; item; item = item->next) {
        auto* source = static_cast<data_source*>(item->data);
        auto* tvb = get_data_source_tvb(source);
        if (!tvb || !seen.insert(tvb).second) continue;
        char* allocated = get_data_source_name(source);
        const std::string name = allocated ? allocated : "";
        wmem_free(nullptr, allocated);
        if (sourceKind(name) != "decrypted_tls") continue;
        // Same length rule as buildDataSnapshot(): a truncated capture still
        // reports the plaintext it carried, so the verdict is not silently lost.
        const uint64_t length =
            std::max<uint64_t>(tvb_captured_length(tvb), tvb_reported_length(tvb));
        ++probe.sources;
        probe.bytes += length;
        if (length > 0) probe.observed = true;
    }
    // Identity is only worth a tree walk when the frame actually carried
    // plaintext; a frame without any keeps stream = -1 / version = 0.
    if (probe.sources > 0) readTlsIdentity(frame.edt->tree, probe);
    return probe;
}

jstring describeDataSources(JNIEnv* env, jlong session, jstring snapshotId, jlong generation) {
    return new_java_string(env, dump_json(query(env, session, snapshotId, generation, false, nullptr, 0, 0)));
}

jstring readDataSource(JNIEnv* env, jlong session, jstring snapshotId, jstring sourceId,
                       jint offset, jint length, jlong generation) {
    return new_java_string(env, dump_json(query(env, session, snapshotId, generation, true, sourceId, offset, length)));
}
}
