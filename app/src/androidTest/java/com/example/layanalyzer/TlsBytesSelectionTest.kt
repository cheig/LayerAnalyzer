// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.data.CaptureAnalysisRevision
import com.example.layanalyzer.data.PacketDataSourceParser
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.model.PacketDataSnapshotRef
import com.example.layanalyzer.model.PacketDataSourceDescriptor
import com.example.layanalyzer.model.PacketDetailSnapshot
import com.example.layanalyzer.model.ProtocolNode
import com.example.layanalyzer.viewmodel.PacketBytesSourceActions
import com.example.layanalyzer.viewmodel.PacketDataSourceState
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream

/**
 * TLS-307 device acceptance for the source-aware byte window. Runs the real production JNI data
 * sources plus the production [PacketBytesSourceActions] / [PacketDataSourceState] layer; the
 * Compose pixels (light/dark, 360dp) are the separate `U` walkthrough, not this test.
 *
 * Requires a device and the synthetic TLS fixtures (`TA/tls/fixtures`); there is no probe.
 */
@RunWith(AndroidJUnit4::class)
class TlsBytesSelectionTest {
    @Before fun engineReady() { NativeTestSupport.awaitApplicationEngine() }

    @Test fun decryptedBodyFieldSelectsItsOwnSourceWhileRawStaysCiphertext() =
        bodySelection("tls12-h1")

    @Test fun http2BodyFieldSelectsItsOwnSourceWhileRawStaysCiphertext() =
        bodySelection("tls13-h2")

    /**
     * Click a body field -> the byte window acts on that field's own source. Copying the selection
     * yields exactly the golden plaintext, the raw window at the same offsets does not match it, and
     * the original capture never contains the plaintext.
     */
    private fun bodySelection(id: String) = TlsPassiveFixture(id).use { fixture ->
        val handle = fixture.open()
        try {
            NativeEngine.configureTlsSecrets(handle, fixture.file("keylog").path, 1)
            val repository = PacketRepository()
            val filter = if (fixture.http2) "http2.data.data" else "http.file_data"
            val copiedPlaintext = ByteArrayOutputStream()
            var clicked = 0
            for (index in 0 until NativeEngine.getFrameCount(handle)) {
                val frame = snapshot(handle, repository, index)
                forEachNode(frame.detail.root) { node ->
                    if (node.filter != filter) return@forEachNode
                    assertTrue("Body field must have a real source", node.offsetValid)
                    val target = PacketBytesSourceActions.fieldTarget(frame.state, node)
                    assertNotNull("Body field must map to its own source", target)
                    val (source, range) = target!!
                    assertNotEquals("Body bytes are not raw ciphertext offsets", "raw", source.id)
                    val window = PacketBytesSourceActions.windowRead(range, source)
                    assertNotNull(window)
                    // Exactly what a field click does: switch to the field's source, load its window,
                    // then highlight. Copy then reads the selection from that source window.
                    val selected = load(handle, frame.ref, frame.state, source, window!!).selectField(node)
                    val bytes = PacketBytesSourceActions.actionBytes(
                        selected, PacketBytesSourceActions.actionRange(selected, selectionAvailable = true)
                    )
                    assertNotNull("Copied selection must come from the loaded source window", bytes)
                    copiedPlaintext.write(bytes)
                    // The raw source at the same range is a different byte sequence (ciphertext).
                    val rawCopy = rawAt(handle, frame.ref, frame.state, range)
                    assertFalse("Raw ciphertext must differ from the decrypted body", rawCopy.contentEquals(bytes))
                    ++clicked
                }
            }
            assertTrue("At least one decrypted body field must be clickable", clicked > 0)
            assertArrayEquals(fixture.body, copiedPlaintext.toByteArray())
            assertFalse("Original capture must not contain the golden plaintext",
                contains(fixture.file("pcap").readBytes(), fixture.body))
        } finally { fixture.closeCapture(handle) }
    }

    /** A frame switched mid-read must not publish the previous frame's bytes. */
    @Test fun fastFrameSwitchAndSlowReadDoNotPublishThePreviousFrame() = TlsPassiveFixture("tls13-h1").use { fixture ->
        val handle = fixture.open()
        try {
            NativeEngine.configureTlsSecrets(handle, fixture.file("keylog").path, 1)
            val repository = PacketRepository()
            val first = snapshot(handle, repository, 0)
            val pending = first.state.beginRange(0, 4)
            val stale = pending.request!!
            val raw = first.detail.sources.single { it.id == "raw" }
            // The user switches to another frame; the ViewModel replaces the whole state.
            val second = snapshot(handle, repository, 1)
            val chunk = PacketDataSourceParser.chunk(
                NativeEngine.readPacketDataSource(handle, first.ref.snapshotId, "raw", 0, 4,
                    first.ref.dissectionGeneration),
                first.ref, raw, 0, 4
            )
            assertSame(second.state, second.state.complete(stale, chunk))
            assertNull(PacketBytesSourceActions.actionRange(second.state, selectionAvailable = true))
        } finally { fixture.closeCapture(handle) }
    }

    /** A truncated source cannot highlight or copy past its available length. */
    @Test fun truncatedRangeCannotExceedAvailableLength() = TlsPassiveFixture("tls12-h1").use { fixture ->
        val handle = fixture.open()
        try {
            val repository = PacketRepository()
            val frame = snapshot(handle, repository, 0)
            val raw = frame.detail.sources.single { it.id == "raw" }
            val window = PacketBytesSourceActions.windowRead(0..0, raw)
            assertNotNull(window)
            val loaded = load(handle, frame.ref, frame.state, raw, window!!)
            val past = raw.availableLength
            assertNull("A range past availableLength must not highlight", loaded.selectRange((past - 1)..past).selection)
            assertNull(PacketBytesSourceActions.windowRead((past - 1)..past, raw))
            assertNull(PacketBytesSourceActions.actionBytes(loaded, (past - 1)..past))
        } finally { fixture.closeCapture(handle) }
    }

    private data class Frame(
        val state: PacketDataSourceState,
        val ref: PacketDataSnapshotRef,
        val detail: PacketDetailSnapshot
    )

    private fun snapshot(handle: Long, repository: PacketRepository, index: Int): Frame {
        val json = JSONObject(NativeEngine.getPacketDetails(handle, index))
        val frameNumber = json.getLong("frameNumber")
        val ref = PacketDataSourceParser.detailRef(json, frameNumber, json.getLong("dissectionGeneration"))!!
        val sources = PacketDataSourceParser.sources(
            NativeEngine.getPacketDataSources(handle, ref.snapshotId, ref.dissectionGeneration), ref
        )
        val detail = PacketDetailSnapshot(frameNumber, repository.parseProtocolNode(json), ref, sources)
        val analysis = CaptureAnalysisRevision(sessionHandle = handle, dissectionGeneration = ref.dissectionGeneration)
        return Frame(PacketDataSourceState().open(analysis, detail), ref, detail)
    }

    private fun load(
        handle: Long,
        ref: PacketDataSnapshotRef,
        state: PacketDataSourceState,
        source: PacketDataSourceDescriptor,
        window: IntRange
    ): PacketDataSourceState {
        val switched = if (state.sourceId == source.id) state else state.switchSource(source.id)
        val pending = switched.beginRange(window.first, window.count())
        val token = pending.request!!
        val chunk = PacketDataSourceParser.chunk(
            NativeEngine.readPacketDataSource(handle, ref.snapshotId, source.id, window.first, window.count(),
                ref.dissectionGeneration),
            ref, source, window.first, window.count()
        )
        return pending.complete(token, chunk)
    }

    /** Reads a source-relative range out of the raw source for the same snapshot. */
    private fun rawAt(handle: Long, ref: PacketDataSnapshotRef, state: PacketDataSourceState, range: IntRange): ByteArray {
        val raw = state.sources.single { it.id == "raw" }
        val window = PacketBytesSourceActions.windowRead(range, raw) ?: return ByteArray(0)
        val loaded = load(handle, ref, state, raw, window)
        return PacketBytesSourceActions.actionBytes(loaded, PacketBytesSourceActions.actionRange(loaded, true))
            ?: ByteArray(0)
    }

    private fun forEachNode(root: ProtocolNode, action: (ProtocolNode) -> Unit) {
        action(root)
        root.children.forEach { forEachNode(it, action) }
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean =
        needle.isNotEmpty() && (0..haystack.size - needle.size).any { offset ->
            needle.indices.all { haystack[offset + it] == needle[it] }
        }
}
