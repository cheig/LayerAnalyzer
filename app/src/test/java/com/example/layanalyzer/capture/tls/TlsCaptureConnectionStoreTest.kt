// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsConnectionEvent
import com.example.layanalyzer.model.TlsConnectionPhase
import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Tests the same journal factory used by LiveCaptureVpnService, without Android or traffic. */
class TlsCaptureConnectionStoreTest {
    @get:Rule val temporary = TemporaryFolder()
    private val enabled = TlsCaptureSettings(enabled = true)

    @Test fun disabledCaptureDoesNotAllocateAJournalOrCreateADirectory() {
        val root = File(temporary.root, "captures")
        assertNull(createTlsCaptureConnectionStore(root, "capture-off", TlsCaptureSettings()))
        assertFalse(root.exists())
    }

    @Test fun invalidCaptureIdIsRejectedBeforeStartingTheWriter() {
        val root = File(temporary.root, "captures")
        try {
            createTlsCaptureConnectionStore(root, "../outside", enabled)?.close()
            throw AssertionError("unsafe capture id was accepted")
        } catch (error: TlsAssetException) {
            assertEquals(TlsAssetErrorCode.INVALID_ARGUMENT, error.code)
        }
        assertFalse(root.exists())
        assertFalse(File(temporary.root, "outside").exists())
    }

    @Test fun eachCapturePersistsOnlyItsOwnOrdinaryEventsAtTheRepositoryPath() {
        val root = File(temporary.root, "captures")
        val repository = CaptureArtifactRepository(root)
        for (id in listOf("capture-a", "capture-b")) {
            val store = requireNotNull(createTlsCaptureConnectionStore(root, id, enabled))
            store.use {
                it.begin()
                assertTrue(it.append(event(id, 1, TlsConnectionPhase.RELAYING)))
                assertFalse(it.append(event("capture-foreign", 2, TlsConnectionPhase.CLOSED)))
                assertTrue(it.append(event(id, 2, TlsConnectionPhase.CLOSED)))
            }
            val lines = repository.connectionEventsFile(id).readLines().map(::JSONObject)
            assertEquals(listOf("RELAYING", "CLOSED"), lines.map { it.getString("phase") })
            assertTrue(lines.all { it.getString("captureId") == id })
            assertEquals(2L, store.journalMetrics()!!.persisted)
            assertFalse(store.journalMetrics()!!.workerAlive)
            // History is read from disk, not the old store's in-memory window.
            TlsConnectionStore(id, journal = TlsConnectionJournal(repository.connectionEventsFile(id))).use {
                assertEquals(listOf(1L, 2L), it.history().map { event -> event.eventSequence })
            }
        }
        assertFalse(repository.connectionEventsFile("capture-foreign").exists())
        val text = repository.connectionEventsFile("capture-a").readText()
        for (shape in listOf("PRIVATE KEY", "CLIENT_RANDOM", "TRAFFIC_SECRET", "token", "keylog")) {
            assertFalse("ordinary journal leaked $shape", text.contains(shape))
        }
    }

    @Test fun journalIoFailureDoesNotRejectEventsAndReportsTheirLoss() {
        // A regular file in place of the root deterministically prevents journal creation.
        val root = File(temporary.root, "captures").apply { writeText("not a directory") }
        val store = requireNotNull(createTlsCaptureConnectionStore(root, "capture-failed", enabled))
        store.use {
            it.begin()
            assertTrue(it.append(event("capture-failed", 1, TlsConnectionPhase.CLOSED)))
        }
        assertEquals(1L, store.journalMetrics()!!.notPersisted)
        assertEquals(1L, store.journalMetrics()!!.writeFailures)
        assertEquals(0L, store.journalMetrics()!!.persisted)
        assertFalse(store.journalMetrics()!!.workerAlive)
        assertEquals(1L, store.snapshot().counts.eventsNotPersisted)
        assertEquals("not a directory", root.readText())
    }

    private fun event(captureId: String, sequence: Long, phase: TlsConnectionPhase) = TlsConnectionEvent(
        captureId = captureId,
        connectionId = "connection-1",
        eventSequence = sequence,
        monotonicNanos = sequence,
        wallTimeMillis = 1_700_000_000_000 + sequence,
        destinationIp = "203.0.113.7",
        destinationPort = 443,
        networkGeneration = 1,
        phase = phase
    )
}
