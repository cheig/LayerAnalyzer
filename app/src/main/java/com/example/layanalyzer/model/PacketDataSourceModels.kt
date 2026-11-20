// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.model

const val PACKET_DATA_RANGE_LIMIT = 256 * 1024
const val PACKET_DATA_SNAPSHOT_LIMIT = 8 * 1024 * 1024

enum class PacketDataSourceKind(val wireValue: String) {
    RawFrame("raw_frame"), Reassembled("reassembled"), DecryptedTls("decrypted_tls"),
    Derived("derived"), Unknown("unknown");

    companion object {
        fun fromWire(value: String) = entries.firstOrNull { it.wireValue == value } ?: Unknown
    }
}

data class PacketDataSourceDescriptor(
    val id: String,
    val name: String,
    val kind: PacketDataSourceKind,
    val byteLength: Long,
    val availableLength: Int,
    val truncated: Boolean
)

data class PacketDataSnapshotRef(
    val snapshotId: String,
    val dissectionGeneration: Long,
    val frameNumber: Long
)

data class PacketDetailSnapshot(
    val frameNumber: Long,
    val root: ProtocolNode,
    /** Null only for legacy details; those cannot address native derived bytes. */
    val snapshot: PacketDataSnapshotRef?,
    val sources: List<PacketDataSourceDescriptor> = emptyList()
)

data class PacketDataSourceChunk(
    val snapshot: PacketDataSnapshotRef,
    val sourceId: String,
    val offset: Int,
    val bytes: ByteArray,
    val byteLength: Long,
    val availableLength: Int,
    val truncated: Boolean
) {
    // Never include decoded plaintext in diagnostics.
    override fun toString() = "PacketDataSourceChunk(offset=$offset, length=${bytes.size})"
}

class PacketDataSourceException(val errorCode: String) :
    IllegalStateException("Packet data unavailable ($errorCode).")
