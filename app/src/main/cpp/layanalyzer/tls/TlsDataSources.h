// Copyright (c) 2026 cheig; GPL-3.0.
#pragma once

#include <jni.h>
#include <cstdint>
#include <list>
#include <string>
#include <unordered_map>
#include <vector>
#include <epan/tvbuff.h>

struct WiresharkSession;
struct DissectedFrame;

namespace layanalyzer::tls {
inline constexpr size_t kDetailSnapshotLimit = 2;
inline constexpr size_t kDetailBytesLimit = 8 * 1024 * 1024;
inline constexpr size_t kDataSourceRangeLimit = 256 * 1024;

struct PacketDataSource {
    std::string id;
    std::string name;
    std::string kind;
    uint64_t byte_length = 0;
    std::vector<uint8_t> bytes;
};

// Value ownership only. No Wireshark or packet-scope pointers may be added here.
struct PacketDataSnapshot {
    std::string id;
    uint64_t generation = 0;
    uint32_t frame_number = 0;
    size_t byte_size = 0;
    std::vector<PacketDataSource> sources;
};

struct PacketDataSnapshots {
    std::list<PacketDataSnapshot> entries; // Oldest creation first; reads do not pin.
    size_t byte_size = 0;
    ~PacketDataSnapshots();
    void evictOldest();
    void clear();
};

// This mapping exists ONLY inside the current DissectedFrame lifetime.
using PacketSourceBindings = std::unordered_map<tvbuff_t*, size_t>;
PacketDataSnapshot buildDataSnapshot(WiresharkSession& session, DissectedFrame& frame,
                                    PacketSourceBindings& bindings);

/**
 * How much decrypted TLS plaintext one already-dissected frame carries, and
 * which connection it belongs to.
 *
 * The TLS priming scan visits every frame in capture order, and once the verdict
 * is known it still has to dissect the rest: that in-order pass is what rebuilds
 * the cross-frame reassembly state a later single-frame read depends on. What it
 * does not need is the rest of the detail path -- the protocol tree as JSON, a
 * retained data snapshot and its byte copy. This reports the same classification
 * `buildDataSnapshot()` produces (`sourceKind()` on the data-source name, length
 * `max(captured, reported)`, one entry per distinct tvbuff) without materialising
 * any of it, so the scan costs one dissection per frame and nothing else.
 */
struct DecryptedSourceProbe {
    uint32_t sources = 0;
    uint64_t bytes = 0;
    bool observed = false;
    /**
     * `tcp.stream` of the frame that carried this plaintext, or -1 when the
     * frame has no TCP layer. The caller aggregates per stream, because one
     * connection is one decryption verdict and a per-frame count is not.
     */
    int32_t stream = -1;
    /**
     * Version of the records that carried this plaintext, on the TLS wire scale
     * (0x0303 TLS 1.2, 0x0304 TLS 1.3), or 0 when it cannot be told.
     *
     * TLS 1.3 does not put its version in the record header -- every 1.3 record
     * header says 0x0303 -- so `tls.record.version` alone reports 1.2 for a 1.3
     * connection. `tls.record.opaque_type` is the disambiguator: packet-tls.c
     * adds it (instead of `tls.record.content_type`) exactly when
     * `session->version == TLSV1DOT3_VERSION && content_type == SSL_ID_APP_DATA`,
     * i.e. when the record the frame decrypted is a 1.3 record. That field is
     * authoritative where the record header is not, so it is checked first.
     */
    uint16_t tls_version = 0;
};
DecryptedSourceProbe probeDecryptedSources(DissectedFrame& frame);

void retainDataSnapshot(WiresharkSession& session, PacketDataSnapshot&& snapshot);

jstring describeDataSources(JNIEnv* env, jlong session, jstring snapshotId,
                            jlong expectedGeneration);
jstring readDataSource(JNIEnv* env, jlong session, jstring snapshotId, jstring sourceId,
                       jint offset, jint length, jlong expectedGeneration);
}
