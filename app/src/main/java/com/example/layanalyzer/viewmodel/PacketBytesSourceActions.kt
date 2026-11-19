// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.model.PACKET_DATA_RANGE_LIMIT
import com.example.layanalyzer.model.PacketDataSourceDescriptor
import com.example.layanalyzer.model.ProtocolNode

/**
 * TLS-307 pure decisions behind the byte window: which data source a clicked field lives in, the
 * bounded read that renders it, and the source bytes copy/format/export must use.
 *
 * Everything here operates on plain values (no `android.*`), so the whole surface runs in the host
 * JVM test `PacketBytesSourceActionsTest` without a device. The decrypted bytes themselves only
 * come from the native data source; this object never falls back to `getPacketBytes(raw)`.
 */
object PacketBytesSourceActions {

    /**
     * The source a node's bytes live in, plus its source-relative range, or null when the node must
     * not be selectable. Generated fields, `offsetValid=false`, a missing/unknown `dataSourceId` and
     * any out-of-window or out-of-available range are all rejected rather than silently mapped to raw.
     */
    fun fieldTarget(
        state: PacketDataSourceState,
        node: ProtocolNode
    ): Pair<PacketDataSourceDescriptor, IntRange>? {
        if (node.generated || !node.offsetValid || node.start < 0 || node.length <= 0) return null
        val id = node.dataSourceId ?: return null
        val source = state.sources.firstOrNull { it.id == id } ?: return null
        val range = node.byteRange(source.id, source.availableLength) ?: return null
        return source to range
    }

    /**
     * A bounded, source-relative window read that fully covers [range]. Reads start at the field so a
     * field past the 256 KiB prefix still renders; a field longer than the per-read limit is clipped
     * to the limit and no further. Null when nothing legal can be read.
     */
    fun windowRead(
        range: IntRange,
        source: PacketDataSourceDescriptor,
        limit: Int = PACKET_DATA_RANGE_LIMIT
    ): IntRange? {
        if (range.isEmpty() || range.first < 0 || range.last.toLong() >= source.availableLength) return null
        val span = range.last.toLong() - range.first + 1
        val length = minOf(span, limit.toLong(), source.availableLength.toLong() - range.first)
        return if (length <= 0) null else range.first until (range.first + length).toInt()
    }

    /**
     * Source-relative range the byte window acts on: the current selection when it is inside the
     * loaded window, otherwise the whole loaded window when browsing. Null closes the selection
     * actions (a field with no addressable range, while loading, or an empty window).
     */
    fun actionRange(state: PacketDataSourceState, selectionAvailable: Boolean): IntRange? {
        state.selection?.let { selection ->
            val coversWindow = selection.first >= state.offset &&
                selection.last < state.offset.toLong() + state.bytes.size &&
                selection.last < (state.source?.availableLength ?: 0)
            return if (coversWindow && state.request == null) selection else null
        }
        if (!selectionAvailable || state.isLoading || state.bytes.isEmpty()) return null
        return state.offset until (state.offset + state.bytes.size)
    }

    /**
     * The source bytes to copy/format/export: sliced from the currently loaded source window. Null
     * when the range does not lie inside the window, so no action can read a partial or foreign slice.
     */
    fun actionBytes(state: PacketDataSourceState, range: IntRange?): ByteArray? {
        range ?: return null
        val from = range.first - state.offset
        val to = range.last - state.offset + 1
        if (from < 0 || to > state.bytes.size || to <= from) return null
        return state.bytes.copyOfRange(from, to)
    }

    /** What is actually loaded for [range]; a truncated (larger than one read) field highlights the prefix. */
    fun loadedSelection(range: IntRange, window: IntRange): IntRange =
        range.first..minOf(range.last, window.last)
}
