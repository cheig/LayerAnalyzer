// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.TlsConnectionJournal
import com.example.layanalyzer.capture.tls.TlsConnectionStore
import com.example.layanalyzer.data.CaptureAnalysisSource
import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.data.ClientHelloObservation
import com.example.layanalyzer.data.TlsAssociationReason
import com.example.layanalyzer.data.TlsAssociationState
import com.example.layanalyzer.data.TlsConnectionCorrelator
import com.example.layanalyzer.data.TlsFrameMapping
import com.example.layanalyzer.model.CaptureArtifactManifest
import com.example.layanalyzer.model.CaptureSegmentRef
import com.example.layanalyzer.model.TlsConnectionEvent
import com.example.layanalyzer.model.TlsConnectionPhase
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * TLS-303 ARM64 acceptance through the production JNI dissector, repository and journal.
 * Expected ClientHellos are read independently from hash-verified synthetic PCAP bytes;
 * no proxy, network traffic, configured secrets or native substitute is used.
 * Commands and actual device results are recorded in evidence/TLS-303.md.
 */
@RunWith(AndroidJUnit4::class)
class TlsConnectionAssociationTest {
    @Before fun ready() { NativeTestSupport.awaitApplicationEngine() }

    @Test fun aRealClientHelloIsProjectedAndAssociatedToItsFrame() = verify("tls12-h1", 1)

    @Test fun tls13ClientHelloIsProjectedAndAssociatedToItsFrame() = verify("tls13-h1", 1)

    @Test fun helloRetryRequestAcrossSegmentsKeepsOneConnectionAndRealFrames() = verify("tls13-hrr-h1", 2)

    private fun verify(fixtureId: String, helloCount: Int) {
        TlsPassiveFixture(fixtureId).use { fixture ->
            val captureId = "tls-assoc-${UUID.randomUUID().toString().replace("-", "")}"
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val repository = CaptureArtifactRepository(File(context.filesDir, "captures"))
            val directory = File(context.filesDir, "captures/$captureId").apply { check(mkdirs()) }
            try {
                val pcap = readRawPcap(fixture.file("pcap").readBytes())
                val expected = pcap.hellos
                assertEquals(helloCount, expected.size)
                assertEquals(1, expected.map { it.clientRandom }.distinct().size)
                assertEquals(helloCount == 2, pcap.hasHelloRetryRequest)
                val first = expected.first()
                assertEquals(fixture.port, first.destinationPort)

                // Split after the first ClientHello; HRR's second hello is in the next
                // segment, whose local numbering differs from the global frame numbers.
                val boundary = first.frameNumber.toInt()
                val partitions = listOf(pcap.records.take(boundary), pcap.records.drop(boundary))
                var nextFrame = 1L
                val refs = partitions.mapIndexed { index, records ->
                    val name = "packets-%04d.pcap".format(index + 1)
                    File(directory, name).writeBytes(pcap.bytes(records))
                    CaptureSegmentRef(name, nextFrame, records.size.toLong()).also { nextFrame += records.size }
                }
                repository.commit(CaptureArtifactManifest(
                    captureId = captureId, segments = refs, finalized = true, complete = true
                ))
                val merged = repository.openForAnalysis(captureId) as CaptureAnalysisSource.Merged
                assertFalse(merged.contextIncomplete)
                assertTrue(merged.captureIsComplete)
                assertArrayEquals(pcap.bytes(), merged.analysisFile.readBytes())
                val observations = project(merged.analysisFile, fixture.port)
                // Exact equality checks all five fields, including epoch ms, random,
                // destination and the actual 1-based source frame.
                assertEquals(expected, observations)

                val event = TlsConnectionEvent(
                    captureId = captureId, connectionId = "connection-1", eventSequence = 1,
                    monotonicNanos = 1, wallTimeMillis = first.frameTimeMillis,
                    destinationIp = first.destinationIp, destinationPort = first.destinationPort,
                    networkGeneration = 1, phase = TlsConnectionPhase.RELAYING,
                    downstreamClientRandom = first.clientRandom
                )
                val journalFile = repository.connectionEventsFile(captureId)
                val journal = TlsConnectionJournal(journalFile)
                val history = TlsConnectionStore(captureId, journal = journal).use { store ->
                    assertTrue(store.append(event))
                    assertFalse(store.append(event))
                    assertFalse(store.append(event.copy(captureId = "other-capture", eventSequence = 2)))
                    assertTrue(store.append(event.copy(eventSequence = 2, phase = TlsConnectionPhase.CLOSED)))
                    journal.close() // Drain before checking durable, on-demand history.
                    store.history()
                }
                assertEquals(listOf(1L, 2L), history.map { it.eventSequence })
                assertEquals(0L, journal.droppedLines)
                assertEquals(2, journalFile.readLines().size)
                assertNoSecrets(journalFile.readText())

                val correlator = TlsConnectionCorrelator(captureId)
                val mapping = TlsFrameMapping.of(merged)
                val matched = correlator.associate(history, observations, mapping).single()
                assertEquals(TlsAssociationState.MATCHED, matched.state)
                assertEquals(TlsAssociationReason.MATCHED, matched.reason)
                assertEquals(first.frameNumber, matched.globalFrameNumber)
                assertEquals(helloCount, matched.clientHelloFrames)
                assertEquals(helloCount == 2, matched.helloRetryRequest)
                assertFalse(matched.originalApplicationKnown)

                val orphan = event.copy(connectionId = "orphan", downstreamClientRandom = "ff".repeat(32))
                val unmatched = correlator.associate(listOf(orphan), observations, mapping).single()
                assertEquals(TlsAssociationReason.NO_CLIENT_HELLO, unmatched.reason)
                assertEquals(TlsAssociationState.UNMATCHED, unmatched.state)
                assertNull(unmatched.globalFrameNumber)
                assertTrue(correlator.associate(listOf(event.copy(captureId = "other-capture")), observations, mapping).isEmpty())

                val single = repository.openSingleSegmentForAnalysis(captureId, refs[1].file) as CaptureAnalysisSource.Merged
                assertTrue(single.contextIncomplete)
                assertFalse(single.captureIsComplete)
                val later = project(single.analysisFile, fixture.port)
                assertEquals(expected.drop(1).map { it.copy(frameNumber = it.frameNumber - boundary) }, later)
                val laterMatch = correlator.associate(listOf(event), later, TlsFrameMapping.of(single)).single()
                if (helloCount == 2) {
                    assertEquals(TlsAssociationState.MATCHED, laterMatch.state)
                    assertEquals(expected.last().frameNumber, laterMatch.globalFrameNumber)
                    assertEquals(1, laterMatch.clientHelloFrames)
                    assertFalse(laterMatch.helloRetryRequest)
                } else {
                    assertEquals(TlsAssociationReason.NO_CLIENT_HELLO, laterMatch.reason)
                    assertNull(laterMatch.globalFrameNumber)
                }

                // No ClientHello remains in the pinned negative capture, including
                // HRR's second one. A previous native session must not supply a frame.
                val missing = project(fixture.file("missing-handshake"), fixture.port)
                assertTrue(missing.isEmpty())
                val missingMatch = correlator.associate(listOf(event), missing, mapping).single()
                assertEquals(TlsAssociationReason.NO_CLIENT_HELLO, missingMatch.reason)
                assertNull(missingMatch.globalFrameNumber)
                Log.i("TLS-303", "fixture=$fixtureId linkType=101 hellos=${expected.size} " +
                    "globalFrames=${expected.joinToString(",") { it.frameNumber.toString() }} " +
                    "projectionEqualsPcap=true journalSequences=1,2 duplicateRejected=true " +
                    "hrr=${matched.helloRetryRequest} singleContextIncomplete=true " +
                    "singleGlobalFrame=${laterMatch.globalFrameNumber} missingHandshakeUnmatched=true uidKnown=false")
            } finally {
                check(directory.deleteRecursively()) { "Failed to remove this test's capture" }
            }
        }
    }

    private fun project(file: File, port: Int): List<ClientHelloObservation> {
        val handle = NativeEngine.openFile(file.path, null)
        assertTrue("Synthetic capture must open", handle != 0L)
        try {
            assertTrue(JSONObject(NativeEngine.applyDecodeAs(handle, "tcp.port", port, "tls")).getBoolean("success"))
            val generation = JSONObject(NativeEngine.getPacketDetails(handle, 0)).getLong("dissectionGeneration")
            val envelope = JSONObject(NativeEngine.projectTlsClientHellos(handle, generation, 0))
            assertTrue(envelope.optString("errorCode"), envelope.getBoolean("success"))
            assertEquals(1, envelope.getInt("schemaVersion"))
            assertEquals(generation, envelope.getLong("dissectionGeneration"))
            assertFalse(envelope.getBoolean("truncated"))
            assertNoSecrets(envelope.toString())
            val array = envelope.getJSONArray("observations")
            return (0 until array.length()).map { index ->
                val item = array.getJSONObject(index)
                ClientHelloObservation(item.getLong("frameNumber"), item.getLong("frameTimeMillis"),
                    item.getString("clientRandom"), item.getString("destinationIp"), item.getInt("destinationPort"))
            }
        } finally {
            try { NativeEngine.resetDecodeAs(handle, "tcp.port", port) }
            finally { NativeEngine.closeFile(handle) }
        }
    }

    private fun assertNoSecrets(text: String) {
        listOf("PRIVATE KEY", "CLIENT_RANDOM", "TRAFFIC_SECRET", "token", "keylog").forEach {
            assertFalse("Ordinary metadata contains forbidden secret shape: $it", text.contains(it))
        }
    }

    private data class RawPcap(
        val header: ByteArray,
        val records: List<ByteArray>,
        val hellos: List<ClientHelloObservation>,
        val hasHelloRetryRequest: Boolean
    ) {
        fun bytes(selected: List<ByteArray> = records): ByteArray = ByteArrayOutputStream().apply {
            write(header)
            selected.forEach { write(it) }
        }.toByteArray()
    }

    /**
     * Independent reader for the pinned IPv4/TCP fixtures. Their ClientHello and HRR
     * records fit in one packet; later certificate/application records may span TCP
     * packets and are irrelevant here. Expected hello counts are asserted by the caller.
     */
    private fun readRawPcap(bytes: ByteArray): RawPcap {
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        check(buffer.getInt(0) == 0xa1b2c3d4.toInt()) // microsecond PCAP
        val linkType = buffer.getInt(20)
        check(linkType == 0 || linkType == 101)
        val linkBytes = if (linkType == 0) 4 else 0
        val header = bytes.copyOfRange(0, 24)
        ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).putInt(20, 101)
        val records = mutableListOf<ByteArray>()
        val hellos = mutableListOf<ClientHelloObservation>()
        var hrr = false
        var offset = 24
        fun u8(at: Int) = bytes[at].toInt() and 255
        fun u16(at: Int) = (u8(at) shl 8) or u8(at + 1)
        while (offset < bytes.size) {
            check(offset + 16 <= bytes.size)
            val length = buffer.getInt(offset + 8)
            check(length >= linkBytes + 40 && offset + 16L + length <= bytes.size)
            check(buffer.getInt(offset + 12) == length)
            if (linkBytes == 4) check(buffer.getInt(offset + 16) == 2)
            val ip = offset + 16 + linkBytes
            check(u8(ip) shr 4 == 4 && u8(ip + 9) == 6)
            check(u16(ip + 6) and 0x3fff == 0)
            val end = ip + u16(ip + 2)
            check(end == offset + 16 + length)
            val tcp = ip + (u8(ip) and 15) * 4
            var tls = tcp + (u8(tcp + 12) shr 4) * 4
            while (tls + 5 <= end) {
                if (u8(tls) !in 20..23 || u8(tls + 1) != 3) break
                val recordEnd = tls + 5 + u16(tls + 3)
                if (recordEnd > end) break
                if (u8(tls) == 22 && tls + 43 <= recordEnd) {
                    val random = bytes.copyOfRange(tls + 11, tls + 43).joinToString("") { "%02x".format(it) }
                    if (u8(tls + 5) == 1) {
                        val seconds = buffer.getInt(offset).toLong() and 0xffffffffL
                        val micros = buffer.getInt(offset + 4).toLong() and 0xffffffffL
                        hellos += ClientHelloObservation(records.size + 1L, seconds * 1000 + micros / 1000,
                            random, (16..19).joinToString(".") { u8(ip + it).toString() }, u16(tcp + 2))
                    } else if (u8(tls + 5) == 2 &&
                        random == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c") {
                        hrr = true
                    }
                }
                tls = recordEnd
            }
            val recordHeader = bytes.copyOfRange(offset, offset + 16)
            ByteBuffer.wrap(recordHeader).order(ByteOrder.LITTLE_ENDIAN).apply {
                putInt(8, length - linkBytes)
                putInt(12, length - linkBytes)
            }
            records += recordHeader + bytes.copyOfRange(ip, end)
            offset += 16 + length
        }
        return RawPcap(header, records, hellos, hrr)
    }
}
