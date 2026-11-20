// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.data.CaptureAnalysisRevision
import com.example.layanalyzer.model.*
import org.junit.Assert.*
import org.junit.Test

class PacketDataSourceStateTest {
    private val analysis = CaptureAnalysisRevision(12, 4, 8, 2, true, true)
    private val raw = PacketDataSourceDescriptor("raw", "Frame", PacketDataSourceKind.RawFrame, 20, 20, false)
    private val decrypted = PacketDataSourceDescriptor("source-1", "Decrypted TLS", PacketDataSourceKind.DecryptedTls, 30, 10, true)
    private val field = ProtocolNode("body", start = 2, length = 3, dataSourceId = "source-1", offsetValid = true)
    private val detail = PacketDetailSnapshot(3, ProtocolNode("root", children = listOf(field)),
        PacketDataSnapshotRef("snapshot-1", 8, 3), listOf(raw, decrypted))
    private fun opened() = PacketDataSourceState().open(analysis, detail)
    private fun response(request: PacketDataSourceRequest) = PacketDataSourceChunk(request.snapshot, request.source.id,
        request.offset, ByteArray(request.length) { it.toByte() }, request.source.byteLength,
        request.source.availableLength, request.source.truncated)
    private fun loaded(source: String = "source-1", offset: Int = 0, length: Int = 10): PacketDataSourceState {
        val pending = opened().switchSource(source).beginRange(offset, length)
        val token = pending.request!!
        return pending.complete(token, response(token))
    }

    @Test fun switchingSourcesClearsBytesSelectionAndInFlightRequest() {
        val first = loaded().selectField(field)
        assertEquals(2..4, first.selection)
        val switched = first.switchSource("raw")
        assertTrue(switched.bytes.isEmpty())
        assertNull(switched.selection)
        assertNull(switched.request)
        assertEquals(0, switched.offset)
        assertEquals("raw", switched.sourceId)
    }

    @Test fun delayedDecodeCannotOverwriteDifferentSourceOrNewerRange() {
        val old = opened().beginRange(0, 3)
        val token = old.request!!
        val switched = old.switchSource("source-1").beginRange(0, 3)
        assertSame(switched, switched.complete(token, response(token)))
        val newer = old.beginRange(4, 3)
        assertSame(newer, newer.complete(token, response(token)))
        assertSame(newer, newer.fail(token, "IO_ERROR"))
        val backToRaw = switched.switchSource("raw").beginRange(0, 3)
        assertSame(backToRaw, backToRaw.complete(token, response(token)))
    }

    @Test fun delayedResultsCannotCrossCaptureFrameOrGeneration() {
        val old = opened().beginRange(0, 3)
        val token = old.request!!
        listOf(
            old.open(analysis.copy(sessionHandle = 13), detail),
            old.open(analysis.copy(revision = 5), detail),
            old.open(analysis.copy(dissectionGeneration = 9), detail.copy(snapshot = detail.snapshot!!.copy(dissectionGeneration = 9))),
            old.open(analysis, detail.copy(frameNumber = 4, snapshot = detail.snapshot!!.copy(frameNumber = 4))),
            old.open(analysis, detail.copy(snapshot = detail.snapshot!!.copy(snapshotId = "snapshot-2"))),
            PacketDataSourceState(serial = old.serial + 1)
        ).forEach { assertSame(it, it.complete(token, response(token))) }
    }

    @Test fun responseMustMatchEntirePendingRequest() {
        val pending = opened().beginRange(0, 3)
        val token = pending.request!!
        val response = response(token)
        listOf(response.copy(sourceId = "source-1"), response.copy(offset = 1), response.copy(bytes = byteArrayOf()),
            response.copy(snapshot = response.snapshot.copy(frameNumber = 4)), response.copy(truncated = true)
        ).forEach {
            val failed = pending.complete(token, it)
            assertEquals("INVALID_RESPONSE", failed.errorCode)
            assertTrue(failed.bytes.isEmpty())
            assertNull(failed.selection)
        }
    }

    @Test fun unavailableAndOutOfWindowFieldsCannotBeSelected() {
        val state = loaded(offset = 4, length = 6)
        assertNull(state.selectField(field).selection)
        assertNull(loaded("raw").selectField(field).selection)
        assertNull(loaded().selectField(field.copy()).selection) // stale tree, equal value
        assertNull(loaded().selectRange(8..10).selection) // beyond available prefix
        assertNull(loaded().selectRange(-1..2).selection)
        assertNull(loaded().selectRange(3..2).selection)
        assertEquals(4..9, state.selectRange(4..9).selection)
    }

    @Test fun generatedUnmappedOrMissingOffsetNodesCannotHighlight() {
        listOf(field.copy(generated = true), field.copy(dataSourceId = null), field.copy(offsetValid = false),
            field.copy(start = -1), field.copy(length = Int.MAX_VALUE), field.copy(length = 0)
        ).forEach { invalid ->
            val state = loaded().copy(detail = detail.copy(root = ProtocolNode("root", children = listOf(invalid))))
            assertNull(state.selectField(invalid).selection)
        }
    }

    @Test fun staleDerivedSnapshotReplacesWholeTreeAndRequiresFreshSourceChoice() {
        val pending = opened().switchSource("source-1").beginRange(0, 10)
        val freshField = field.copy(start = 5)
        val fresh = detail.copy(snapshot = detail.snapshot!!.copy(snapshotId = "snapshot-2"),
            root = ProtocolNode("new root", children = listOf(freshField)))
        val token = pending.request!!
        val refreshed = pending.refreshed(token, fresh)
        assertSame(fresh, refreshed.detail)
        assertNull(refreshed.sourceId)
        assertNull(refreshed.selection)
        assertTrue(refreshed.bytes.isEmpty())
        assertFalse(refreshed.accepts(token))
        val next = refreshed.switchSource("source-1").beginRange(0, 10)
        val nextToken = next.request!!
        val loaded = next.complete(nextToken, response(nextToken))
        assertNull(loaded.selectField(field).selection)
        assertEquals(5..7, loaded.selectField(freshField).selection)
    }

    @Test fun staleRawSnapshotResetsToLegalPrefixWithoutRetainingOldOffset() {
        val pending = opened().beginRange(10, 10)
        val fresh = detail.copy(snapshot = detail.snapshot!!.copy(snapshotId = "snapshot-2"),
            sources = listOf(raw.copy(availableLength = 5, truncated = true)))
        val refreshed = pending.refreshed(pending.request!!, fresh)
        assertEquals("raw", refreshed.sourceId)
        assertEquals(0, refreshed.offset)
        assertNull(refreshed.selection)
        assertNotNull(refreshed.beginRange(0, 5).request)
        assertThrows(PacketDataSourceException::class.java) { refreshed.beginRange(10, 10) }
    }

    @Test fun delayedStaleRefreshDoesNotReplaceNewSelection() {
        val pending = opened().beginRange(0, 3)
        val switched = pending.switchSource("source-1")
        assertSame(switched, switched.refreshed(pending.request!!, detail))
    }

    @Test fun failedOrPendingReadClearsSelectionAndBytes() {
        val pending = loaded().selectField(field).beginRange(0, 3)
        assertTrue(pending.bytes.isEmpty())
        assertNull(pending.selection)
        assertTrue(pending.isLoading)
        val failed = pending.fail(pending.request!!, "INVALID_RESPONSE")
        assertEquals("INVALID_RESPONSE", failed.errorCode)
        assertFalse(failed.isLoading)
        assertTrue(failed.bytes.isEmpty())
    }

    @Test fun legacyDetailsRemainReadableWithoutInventingNativeSnapshot() {
        val state = PacketDataSourceState().open(analysis, detail.copy(snapshot = null))
        assertEquals("raw", state.sourceId)
        assertThrows(PacketDataSourceException::class.java) { state.beginRange(0, 1) }
    }
}
