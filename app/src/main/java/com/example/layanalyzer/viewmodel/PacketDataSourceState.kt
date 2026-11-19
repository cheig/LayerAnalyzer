// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.data.CaptureAnalysisRevision
import com.example.layanalyzer.data.PacketDataSourceParser
import com.example.layanalyzer.model.*

/** Request identity includes the capture open/revision, frame, snapshot, source AND range serial. */
data class PacketDataSourceRequest(
    val analysis: CaptureAnalysisRevision,
    val snapshot: PacketDataSnapshotRef,
    val source: PacketDataSourceDescriptor,
    val serial: Long,
    val offset: Int,
    val length: Int
)

/** Plain values owned by the ViewModel; no UI state or decoded bytes live in the repository. */
data class PacketDataSourceState(
    val analysis: CaptureAnalysisRevision? = null,
    val detail: PacketDetailSnapshot? = null,
    val sourceId: String? = null,
    val serial: Long = 0,
    val request: PacketDataSourceRequest? = null,
    val offset: Int = 0,
    val bytes: ByteArray = ByteArray(0),
    val selection: IntRange? = null,
    val errorCode: String? = null
) {
    val sources: List<PacketDataSourceDescriptor> get() = detail?.sources.orEmpty()
    val source: PacketDataSourceDescriptor? get() = sources.firstOrNull { it.id == sourceId }
    val isLoading: Boolean get() = request != null

    fun open(analysis: CaptureAnalysisRevision, detail: PacketDetailSnapshot) = PacketDataSourceState(
        analysis = analysis, detail = detail, sourceId = detail.sources.firstOrNull { it.id == "raw" }?.id,
        serial = serial + 1
    )

    fun switchSource(id: String): PacketDataSourceState {
        require(sources.any { it.id == id }) { "Unknown data source." }
        return copy(sourceId = id, serial = serial + 1, request = null, offset = 0,
            bytes = ByteArray(0), selection = null, errorCode = null)
    }

    fun beginRange(offset: Int, length: Int): PacketDataSourceState {
        val source = source ?: throw PacketDataSourceException("NOT_READY")
        val snapshot = detail?.snapshot ?: throw PacketDataSourceException("UNSUPPORTED")
        val analysis = analysis ?: throw PacketDataSourceException("NOT_READY")
        PacketDataSourceParser.validateRange(source, offset, length)
        val next = serial + 1
        return copy(serial = next, request = PacketDataSourceRequest(analysis, snapshot, source, next, offset, length),
            offset = offset, bytes = ByteArray(0), selection = null, errorCode = null)
    }

    fun accepts(token: PacketDataSourceRequest): Boolean = request == token && serial == token.serial &&
        analysis == token.analysis && detail?.snapshot == token.snapshot && sourceId == token.source.id

    fun complete(token: PacketDataSourceRequest, chunk: PacketDataSourceChunk): PacketDataSourceState {
        if (!accepts(token)) return this
        if (chunk.snapshot != token.snapshot || chunk.sourceId != token.source.id ||
            chunk.offset != token.offset || chunk.bytes.size != token.length ||
            chunk.availableLength != token.source.availableLength || chunk.byteLength != token.source.byteLength ||
            chunk.truncated != token.source.truncated
        ) return fail(token, "INVALID_RESPONSE")
        return copy(request = null, bytes = chunk.bytes, errorCode = null)
    }

    fun fail(token: PacketDataSourceRequest, code: String): PacketDataSourceState =
        if (accepts(token)) copy(request = null, bytes = ByteArray(0), selection = null, errorCode = code) else this

    /** Derived IDs are only snapshot-local. Even the same ID/name in a new tree is not a field match. */
    fun refreshed(token: PacketDataSourceRequest, fresh: PacketDetailSnapshot): PacketDataSourceState {
        if (!accepts(token)) return this
        require(fresh.frameNumber == token.snapshot.frameNumber)
        require(fresh.snapshot?.dissectionGeneration == token.analysis.dissectionGeneration)
        return open(token.analysis, fresh).copy(
            sourceId = if (token.source.id == "raw") "raw" else null,
            errorCode = "STALE_GENERATION"
        )
    }

    /** Drop only the highlight; bytes and source identity are untouched. */
    fun clearSelection(): PacketDataSourceState = copy(selection = null)

    /** Offset is relative to the source, not the currently loaded window. */
    fun selectRange(range: IntRange?): PacketDataSourceState {
        val valid = range?.takeIf {
            !it.isEmpty() && it.first >= offset && it.last.toLong() < offset.toLong() + bytes.size &&
                it.last < (source?.availableLength ?: 0) && request == null
        }
        return copy(selection = valid)
    }

    fun selectField(node: ProtocolNode): PacketDataSourceState {
        // Reject a node retained by a previous snapshot, even if its values/ID happen to match.
        fun contains(root: ProtocolNode): Boolean = root === node || root.children.any(::contains)
        val source = source
        val range = if (source != null && detail?.root?.let(::contains) == true) {
            node.byteRange(source.id, source.availableLength)
        } else null
        return selectRange(range)
    }

    override fun toString() = "PacketDataSourceState(sourceId=$sourceId, offset=$offset, length=${bytes.size})"
}
