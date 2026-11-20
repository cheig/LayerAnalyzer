// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.data.CaptureAnalysisRevision
import com.example.layanalyzer.model.*
import org.junit.Assert.*
import org.junit.Test

/**
 * Host tests for the TLS-307 byte-window action layer. Everything here is a plain value transition;
 * the decrypted bytes are synthetic, so this proves the source/range plumbing, not native decryption.
 */
class PacketBytesSourceActionsTest {
    private val analysis = CaptureAnalysisRevision(12, 4, 8, 2, true, true)
    private val raw = PacketDataSourceDescriptor("raw", "Frame", PacketDataSourceKind.RawFrame, 40, 40, false)
    private val decrypted = PacketDataSourceDescriptor("source-1", "Decrypted TLS", PacketDataSourceKind.DecryptedTls, 24, 24, false)
    private val rawField = ProtocolNode("record", start = 4, length = 3, dataSourceId = "raw", offsetValid = true)
    private val bodyField = ProtocolNode("http.file_data", start = 6, length = 4, dataSourceId = "source-1", offsetValid = true)
    private val detail = PacketDetailSnapshot(
        3, ProtocolNode("root", children = listOf(rawField, bodyField)),
        PacketDataSnapshotRef("snapshot-1", 8, 3), listOf(raw, decrypted)
    )

    private fun opened() = PacketDataSourceState().open(analysis, detail)

    private fun response(request: PacketDataSourceRequest, fill: (Int) -> Byte) = PacketDataSourceChunk(
        request.snapshot, request.source.id, request.offset, ByteArray(request.length, fill),
        request.source.byteLength, request.source.availableLength, request.source.truncated
    )

    /** Loads a window of the current source and returns the settled state. */
    private fun loaded(sourceId: String, offset: Int, length: Int, fill: (Int) -> Byte): PacketDataSourceState {
        val pending = opened().switchSource(sourceId).beginRange(offset, length)
        val token = pending.request!!
        return pending.complete(token, response(token, fill))
    }

    @Test fun fieldTargetPicksTheFieldsOwnSourceNotRaw() {
        val state = opened()
        val bodyTarget = PacketBytesSourceActions.fieldTarget(state, bodyField)
        assertNotNull(bodyTarget)
        assertEquals("source-1", bodyTarget!!.first.id)
        assertEquals(6..9, bodyTarget.second)

        val rawTarget = PacketBytesSourceActions.fieldTarget(state, rawField)
        assertEquals("raw", rawTarget!!.first.id)
        assertEquals(4..6, rawTarget.second)
    }

    @Test fun generatedMissingOffsetOrUnknownNodesHaveNoTarget() {
        val state = opened()
        listOf(
            bodyField.copy(generated = true),
            bodyField.copy(offsetValid = false),
            bodyField.copy(dataSourceId = null),
            bodyField.copy(dataSourceId = "missing"),
            bodyField.copy(start = -1),
            bodyField.copy(length = 0),
            bodyField.copy(length = Int.MAX_VALUE)
        ).forEach { assertNull(PacketBytesSourceActions.fieldTarget(state, it)) }
    }

    @Test fun windowReadIsBoundedAndCoversFieldsPastThePrefix() {
        val large = decrypted.copy(availableLength = PACKET_DATA_RANGE_LIMIT + 500)
        assertEquals(5 until 8, PacketBytesSourceActions.windowRead(5..7, large))
        // A field longer than one read is clipped to the range limit, not to the whole source.
        assertEquals(0 until PACKET_DATA_RANGE_LIMIT,
            PacketBytesSourceActions.windowRead(0..(large.availableLength - 1), large))
        // A field shorter than the limit keeps its own length.
        assertEquals(10 until 14, PacketBytesSourceActions.windowRead(10..13, large))
        // A range outside availableLength is rejected instead of being silently clamped to it.
        assertNull(PacketBytesSourceActions.windowRead((large.availableLength - 2)..(large.availableLength + 1), large))
        assertNull(PacketBytesSourceActions.windowRead(-1..2, large))
        assertNull(PacketBytesSourceActions.windowRead(3..2, large))
    }

    @Test fun actionBytesComeFromTheCurrentSourceWindow() {
        val decryptedBytes = loaded("source-1", 0, 24) { (it + 0x40).toByte() }
        val range = PacketBytesSourceActions.fieldTarget(decryptedBytes, bodyField)!!.second
        val selected = decryptedBytes.selectRange(range)
        val bytes = PacketBytesSourceActions.actionBytes(selected, PacketBytesSourceActions.actionRange(selected, true))
        assertArrayEquals(decryptedBytes.bytes.copyOfRange(6, 10), bytes)
        // The decrypted selection is never the raw ciphertext at the same offsets.
        val rawBytes = loaded("raw", 0, 40) { it.toByte() }
        val rawSelected = rawBytes.selectRange(range)
        assertNotEquals(
            PacketBytesSourceActions.actionBytes(selected, range)!!.toList(),
            PacketBytesSourceActions.actionBytes(rawSelected, range)!!.toList()
        )
    }

    @Test fun actionRangeFallsBackToWholeWindowWhenBrowsingAndClosesWhenUnavailable() {
        val loadedWindow = loaded("raw", 0, 12) { it.toByte() }
        assertEquals(0..11, PacketBytesSourceActions.actionRange(loadedWindow, selectionAvailable = true))
        assertNull(PacketBytesSourceActions.actionRange(loadedWindow, selectionAvailable = false))
        val selected = loadedWindow.selectRange(2..5)
        assertEquals(2..5, PacketBytesSourceActions.actionRange(selected, selectionAvailable = true))
        assertEquals(2..5, PacketBytesSourceActions.actionRange(selected, selectionAvailable = false))
    }

    @Test fun actionRangeAndBytesCloseWhenTheWindowIsEmptyOrLoading() {
        val switched = opened().switchSource("source-1")
        assertNull(PacketBytesSourceActions.actionRange(switched, selectionAvailable = true))
        val pending = switched.beginRange(0, 4)
        assertNull(PacketBytesSourceActions.actionRange(pending, selectionAvailable = true))
        assertNull(PacketBytesSourceActions.actionBytes(pending, 0..3))
    }

    @Test fun truncatedSelectionCannotExceedAvailableLength() {
        val truncated = decrypted.copy(byteLength = 100, availableLength = 10, truncated = true)
        val state = PacketDataSourceState().open(analysis,
            detail.copy(sources = listOf(raw, truncated)))
        val loaded = state.switchSource("source-1").let { s ->
            val pending = s.beginRange(0, 10)
            pending.complete(pending.request!!, response(pending.request!!) { it.toByte() })
        }
        assertNull(loaded.selectRange(8..12).selection)
        assertNull(PacketBytesSourceActions.actionBytes(loaded, 8..12))
        assertEquals(8..9, loaded.selectRange(8..9).selection)
    }

    @Test fun loadedSelectionClipsLongFieldsToTheLoadedWindow() {
        assertEquals(5..20, PacketBytesSourceActions.loadedSelection(5..300, 5..20))
        assertEquals(5..7, PacketBytesSourceActions.loadedSelection(5..7, 5..20))
    }

    @Test fun fastFrameSwitchDropsThePreviousWindowsAction() {
        val first = opened().beginRange(0, 4)
        val token = first.request!!
        // The user switches frames; the ViewModel replaces the whole state (new serial, new analysis).
        val second = PacketDataSourceState().open(analysis.copy(revision = 5), detail)
        val settled = second.complete(token, response(token) { it.toByte() })
        assertSame(second, settled)
        assertNull(PacketBytesSourceActions.actionRange(settled, selectionAvailable = true))
    }
}
