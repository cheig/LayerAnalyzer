// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.model.TlsCaptureStatus
import com.example.layanalyzer.model.TlsConnectionEvent
import com.example.layanalyzer.model.TlsConnectionPhase
import com.example.layanalyzer.model.TlsErrorCode
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Synthetic connection events: real destination addresses, no traffic, no key
 * material. These cases cover the reader half of TLS-212 — the bounded window,
 * the retained per-connection state, the monotonic sequence and the separated
 * counters — and none of them claims a device, a TUN capture or a decrypted
 * payload.
 */
class TlsConnectionStoreTest {
    private val captureId = "capture-store"
    private val otherCapture = "capture-other"
    private val address = "203.0.113.7"

    @Test fun runtimeCountersRemainSeparateFromPersistenceAndRejectMissingValues() {
        val store = store()
        val response = JSONObject().put("success", true)
            .put("events", JSONObject().put("bytesToUpstream", 0).put("bytesToDownstream", 0).put("eventsDropped", 0))
            .put("runtimeMetrics", JSONObject().put("certificateCacheEntries", 1).put("certificateCacheHits", 4)
                .put("goSecretsQueueBytes", 173))
        assertTrue(store.recordEngineStats(response.toString(), 197))
        assertEquals(TlsRuntimeMetrics(1, 4, 173, 197), store.snapshot().runtimeMetrics)
        assertEquals(0L, store.snapshot().counts.secretRecordsPersisted)
        response.getJSONObject("runtimeMetrics").remove("certificateCacheHits")
        assertTrue(store.recordEngineStats(response.toString(), 197))
        assertNull(store.snapshot().runtimeMetrics)
    }

    private fun store(limits: TlsConnectionStoreLimits = TlsConnectionStoreLimits()) =
        TlsConnectionStore(captureId, limits)

    private fun event(
        connection: String,
        sequence: Long,
        phase: TlsConnectionPhase,
        accepted: Long = 0,
        persisted: Long = 0,
        complete: Boolean = false,
        capture: String = captureId
    ) = TlsConnectionEvent(
        captureId = capture,
        connectionId = connection,
        eventSequence = sequence,
        monotonicNanos = sequence,
        wallTimeMillis = 1_700_000_000_000 + sequence,
        destinationIp = address,
        destinationPort = 443,
        networkGeneration = 3,
        phase = phase,
        secretRecordsAccepted = accepted,
        secretRecordsPersisted = persisted,
        secretsComplete = complete
    )

    /**
     * One engine event as the ABI writes it, so the parser is exercised on the
     * real wire shape. Every field is emitted once: the engine marshals a Go
     * struct, which cannot produce a repeated key, and a reader that quietly
     * accepted one would be reading a document the engine never sends.
     */
    private fun eventJson(
        connection: String,
        sequence: Long,
        phase: String,
        capture: String = captureId,
        port: Int = 443,
        accepted: Long = 0,
        persisted: Long = 0,
        complete: Boolean = false,
        errorCode: String? = null,
        sni: String? = null,
        alpn: String? = null
    ): String {
        val fields = mutableListOf(
            "\"captureId\":\"$capture\"",
            "\"connectionId\":\"$connection\"",
            "\"eventSequence\":$sequence",
            "\"monotonicNanos\":$sequence",
            "\"wallTimeMillis\":1700000000000",
            "\"destinationIp\":\"$address\"",
            "\"destinationPort\":$port",
            "\"networkGeneration\":3",
            "\"phase\":\"$phase\"",
            "\"secretRecordsAccepted\":$accepted",
            "\"secretRecordsPersisted\":$persisted",
            "\"secretsComplete\":$complete"
        )
        errorCode?.let { fields += "\"errorCode\":\"$it\"" }
        sni?.let { fields += "\"sni\":\"$it\"" }
        alpn?.let { fields += "\"alpn\":\"$it\"" }
        return "{${fields.joinToString(",")}}"
    }

    private fun poll(vararg events: String, success: Boolean = true, state: String = "RUNNING") =
        "{\"schemaVersion\":1,\"success\":$success,\"errorCode\":null,\"error\":null," +
            "\"state\":\"$state\",\"events\":[${events.joinToString(",")}]}"

    private fun engineStats(up: Long, down: Long, dropped: Long, success: Boolean = true) =
        "{\"schemaVersion\":1,\"success\":$success,\"errorCode\":null,\"error\":null,\"state\":\"RUNNING\"," +
            "\"budget\":{\"connections\":1},\"events\":{\"bytesToUpstream\":$up,\"bytesToDownstream\":$down," +
            "\"eventsDropped\":$dropped}}"

    @Test
    fun pollEnvelopeIsParsedIntoEventsAndAStaleDeliveryIsRefused() {
        val store = store()
        store.begin()
        assertEquals(
            2,
            store.recordPoll(
                poll(
                    eventJson("connection-1", 1, "ACCEPTED", sni = "example.test"),
                    eventJson("connection-1", 2, "RELAYING", alpn = "h2")
                )
            )
        )
        val snapshot = store.snapshot()
        assertEquals(2L, snapshot.sequence)
        assertEquals(TlsCaptureStatus.RUNNING, snapshot.status)
        assertEquals(1L, snapshot.counts.accepted)
        assertEquals(1L, snapshot.counts.proxied)
        val retained = snapshot.connections.single()
        assertEquals("connection-1", retained.connectionId)
        assertEquals(TlsConnectionPhase.RELAYING, retained.phase)
        assertEquals("example.test", store.eventsAfter(0L).first { it.eventSequence == 1L }.sni)
        assertEquals("h2", retained.alpn)

        // Re-reading the same window is what a slow reader does: nothing is
        // applied twice, so no counter can be inflated by re-delivery.
        assertEquals(0, store.recordPoll(poll(eventJson("connection-1", 2, "RELAYING"))))
        assertEquals(1L, store.snapshot().counts.proxied)
        assertEquals(1L, store.snapshot().counts.eventsRejected)
        assertTrue(store.eventsAfter(2L).isEmpty())
    }

    @Test
    fun malformedEnvelopesAndEventsAreRejectedWithoutChangingTheCounters() {
        val store = store()
        store.begin()
        assertEquals(0, store.recordPoll(""))
        assertEquals(0, store.recordPoll("not json"))
        assertEquals(0, store.recordPoll("""{"success":false,"events":[]}"""))
        assertEquals(0, store.recordPoll("""{"success":true}"""))
        assertEquals(0, store.recordPoll(poll(eventJson("connection-1", 1, "ACCEPTED")) + "{}"))
        assertEquals(0L, store.snapshot().counts.accepted)

        // Each of these is one unusable event inside an otherwise valid batch.
        val broken = listOf(
            "{\"connectionId\":\"c\"}", // no phase
            eventJson("connection-1", 2, "DECRYPTED"), // unknown phase
            eventJson("", 3, "ACCEPTED"), // no connection
            eventJson("connection-1", 0, "ACCEPTED"), // no sequence
            eventJson("connection-1", 4, "ACCEPTED", port = 0),
            eventJson("connection-1", 5, "ACCEPTED", accepted = 1, persisted = 2), // more persisted than accepted
            "{\"captureId\":\"$captureId\",\"connectionId\":\"c\",\"eventSequence\":6,\"phase\":\"ACCEPTED\"," +
                "\"destinationPort\":443,\"secretRecordsAccepted\":0,\"secretRecordsPersisted\":0}" // no destination
        )
        assertEquals(1, store.recordPoll(poll(eventJson("connection-1", 1, "ACCEPTED"), *broken.toTypedArray())))
        val counts = store.snapshot().counts
        assertEquals(1L, counts.accepted)
        assertEquals(broken.size.toLong(), counts.eventsRejected)

        // An event belonging to another capture is not this store's to apply and
        // not this store's error to report: it is refused, and nothing moves.
        assertEquals(0, store.recordPoll(poll(eventJson("connection-9", 9, "ACCEPTED", capture = otherCapture))))
        val unchanged = store.snapshot().counts
        assertEquals(counts.accepted, unchanged.accepted)
        assertEquals(counts.eventsRejected, unchanged.eventsRejected)
        assertEquals(1L, store.snapshot().sequence)
    }

    @Test
    fun aConnectionsOutcomeIsCountedOnceAndCoversEveryCategorySeparately() {
        val store = store()
        store.begin()
        // Intercepted, both handshakes succeeded, secrets persisted.
        store.recordPoll(
            poll(
                eventJson("clean", 1, "ACCEPTED"), eventJson("clean", 2, "SNIFFING"),
                eventJson("clean", 3, "UPSTREAM_HANDSHAKE"), eventJson("clean", 4, "DOWNSTREAM_HANDSHAKE"),
                eventJson("clean", 5, "RELAYING"),
                eventJson("clean", 6, "CLOSED", accepted = 3, persisted = 3, complete = true)
            )
        )
        // Bypassed by a rule, then closed.
        store.recordPoll(poll(eventJson("bypassed", 7, "ACCEPTED"), eventJson("bypassed", 8, "PASSTHROUGH"), eventJson("bypassed", 9, "CLOSED")))
        // Failed before relaying.
        store.recordPoll(poll(eventJson("failed", 10, "UPSTREAM_HANDSHAKE"), eventJson("failed", 11, "FAILED", errorCode = "UPSTREAM_CERT_INVALID")))
        // Intercepted, then failed with a secret that never reached the disk.
        store.recordPoll(
            poll(
                eventJson("lossy", 12, "RELAYING"),
                eventJson("lossy", 13, "FAILED", accepted = 2, persisted = 1)
            )
        )
        // Bypassed and then failed: a forwarding failure, not a handshake failure.
        store.recordPoll(poll(eventJson("bypassed-failed", 14, "PASSTHROUGH"), eventJson("bypassed-failed", 15, "FAILED")))

        val counts = store.snapshot().counts
        assertEquals(5L, counts.accepted)
        assertEquals(2L, counts.proxied)
        assertEquals(2L, counts.passthrough)
        assertEquals(2L, counts.closed)
        assertEquals(3L, counts.failed)
        assertEquals(1L, counts.handshakeFailed)
        assertEquals(1L, counts.secretsIncomplete)
        assertEquals(1L, counts.secretsSaved)
        assertEquals(5L, counts.secretRecordsAccepted)
        assertEquals(4L, counts.secretRecordsPersisted)

        val failed = store.snapshot().connections.single { it.connectionId == "failed" }
        assertEquals(TlsErrorCode.UPSTREAM_CERT_INVALID, failed.error?.code)
        assertNull(failed.error?.safeDescription)
    }

    @Test
    fun aSecondTerminalStateForTheSameConnectionCannotRewriteTheFirst() {
        val store = store()
        store.begin()
        assertTrue(store.append(event("connection-1", 1, TlsConnectionPhase.RELAYING)))
        assertTrue(store.append(event("connection-1", 2, TlsConnectionPhase.FAILED)))
        // Both a second terminal and an ordinary phase after it are refused.
        assertFalse(store.append(event("connection-1", 3, TlsConnectionPhase.CLOSED)))
        assertFalse(store.append(event("connection-1", 4, TlsConnectionPhase.RELAYING)))
        val snapshot = store.snapshot()
        assertEquals(TlsConnectionPhase.FAILED, snapshot.connections.single().phase)
        assertEquals(1L, snapshot.counts.failed)
        assertEquals(0L, snapshot.counts.closed)
        assertEquals(2L, snapshot.counts.eventsRejected)
        // Another connection is unaffected by the rule.
        assertTrue(store.append(event("connection-2", 5, TlsConnectionPhase.ACCEPTED)))
        assertEquals(2L, store.snapshot().counts.accepted)
    }

    @Test
    fun cumulativeSecretCountsAreFoldedAsDeltas() {
        val store = store()
        store.begin()
        store.append(event("connection-1", 1, TlsConnectionPhase.RELAYING, accepted = 1, persisted = 0))
        store.append(event("connection-1", 2, TlsConnectionPhase.RELAYING, accepted = 3, persisted = 1))
        store.append(event("connection-1", 3, TlsConnectionPhase.CLOSED, accepted = 4, persisted = 3))
        val counts = store.snapshot().counts
        assertEquals(4L, counts.secretRecordsAccepted)
        assertEquals(3L, counts.secretRecordsPersisted)
        // Four records were accepted and three reached the disk, so the
        // connection was intercepted and ended incomplete rather than saved.
        assertEquals(1L, counts.secretsIncomplete)
        assertEquals(0L, counts.secretsSaved)
    }

    @Test
    fun theEventWindowIsBoundedWhileEveryConnectionSummarySurvives() {
        val store = store(TlsConnectionStoreLimits(maxEvents = 8, maxConnections = 16))
        store.begin()
        for (sequence in 1L..200L) {
            val connection = "connection-${sequence % 12}"
            assertTrue(
                store.append(
                    event(
                        connection, sequence,
                        if (sequence % 3 == 0L) TlsConnectionPhase.RELAYING else TlsConnectionPhase.SNIFFING
                    )
                )
            )
        }
        val snapshot = store.snapshot()
        // The window is bounded; the flood cost window entries, nothing else.
        assertEquals(8, store.eventsAfter(0L).size)
        assertEquals(192L, snapshot.counts.eventHistoryEvicted)
        assertEquals(0L, snapshot.counts.eventsDropped)
        assertEquals(200L, snapshot.sequence)
        // Counters are not derived from the window, so they still describe all
        // twelve connections that were seen, one state each.
        assertEquals(12, snapshot.connections.size)
        assertEquals(12L, snapshot.counts.accepted)
    }

    @Test
    fun theRetainedConnectionSummaryIsBoundedToo() {
        val store = store(TlsConnectionStoreLimits(maxConnections = 2))
        store.begin()
        for (index in 1L..6L) {
            // Each connection is seen once and ends, so nothing is counted twice
            // even though only two of their states can be retained.
            assertTrue(store.append(event("connection-$index", index, TlsConnectionPhase.FAILED)))
        }
        val snapshot = store.snapshot()
        assertEquals(6L, snapshot.counts.accepted)
        assertEquals(6L, snapshot.counts.failed)
        assertTrue("the retained summary grew past its budget: ${snapshot.connections.size}", snapshot.connections.size <= 2)
    }

    @Test
    fun terminalStatesSurviveAFloodOfNewerEvents() {
        val store = store(TlsConnectionStoreLimits(maxEvents = 4, maxConnections = 16))
        store.begin()
        // The first connection ends immediately, then 500 events arrive for a
        // connection that is still running.
        assertTrue(store.append(event("finished", 1, TlsConnectionPhase.FAILED)))
        for (sequence in 2L..501L) {
            assertTrue(store.append(event("running", sequence, TlsConnectionPhase.RELAYING)))
        }
        val snapshot = store.snapshot()
        assertEquals("finished", snapshot.connections.last().connectionId)
        assertEquals(TlsConnectionPhase.FAILED, snapshot.connections.last().phase)
        assertEquals(1L, snapshot.counts.failed)
        assertEquals(1L, snapshot.counts.proxied)
        // The window itself holds only the newest events, which is the point:
        // the summary is retained independently of the feed.
        assertEquals(4, store.eventsAfter(0L).size)
        assertEquals(501L, store.eventsAfter(0L).last().eventSequence)
    }

    @Test
    fun engineStatsReplaceTheTrafficCountersInsteadOfAccumulatingThem() {
        val store = store()
        store.begin()
        assertTrue(store.recordEngineStats(engineStats(1_048_576, 4_194_304, 7)))
        assertEquals(1_048_576L, store.snapshot().traffic.bytesToUpstream)
        assertEquals(4_194_304L, store.snapshot().traffic.bytesToDownstream)
        // Reading the same numbers again is a re-read, not a second hop: the
        // Kotlin side must never add its own view to the engine's.
        assertTrue(store.recordEngineStats(engineStats(1_048_576, 4_194_304, 7)))
        val snapshot = store.snapshot()
        assertEquals(1_048_576L, snapshot.traffic.bytesToUpstream)
        assertEquals(4_194_304L, snapshot.traffic.bytesToDownstream)
        assertEquals(7L, snapshot.counts.eventsDropped)
        // A failed or truncated stats response changes nothing.
        assertFalse(store.recordEngineStats(engineStats(9, 9, 9, success = false)))
        assertFalse(store.recordEngineStats("""{"success":true}"""))
        assertFalse(store.recordEngineStats("{"))
        assertEquals(1_048_576L, store.snapshot().traffic.bytesToUpstream)
    }

    @Test
    fun historyRetirementIsSeparateFromActualEngineLoss() {
        val store = store(TlsConnectionStoreLimits(maxEvents = 2))
        store.begin()
        for (sequence in 1L..5L) {
            store.append(event("connection-1", sequence, TlsConnectionPhase.RELAYING))
        }
        assertEquals(3L, store.snapshot().counts.eventHistoryEvicted)
        assertEquals(0L, store.snapshot().counts.eventsDropped)
        store.recordEngineStats(engineStats(0, 0, 11))
        // The same engine snapshot does not add a second loss or erase history.
        store.recordEngineStats(engineStats(0, 0, 11))
        assertEquals(11L, store.snapshot().counts.eventsDropped)
        assertEquals(3L, store.snapshot().counts.eventHistoryEvicted)
    }

    @Test
    fun theRefreshGatePublishesAtMostOncePerInterval() {
        var now = 1_000_000_000L
        val store = TlsConnectionStore(captureId, TlsConnectionStoreLimits(), nanoTime = { now })
        store.begin()
        assertTrue("the first paint is never delayed", store.dueForPublish())
        now += 249_000_000
        assertFalse("faster than the C10 interval is refused", store.dueForPublish())
        now += 1_000_000
        assertTrue(store.dueForPublish())
        now += 10_000
        assertFalse(store.dueForPublish())
        now += 249_990_000
        assertTrue(store.dueForPublish())
        store.close()
        assertFalse("a stopped capture has nothing to repaint", store.dueForPublish(now + 1_000_000_000))
    }

    @Test
    fun theSnapshotMapsToTheUiModelWithoutClaimingDecryption() {
        val store = store()
        store.begin()
        store.recordPoll(
            poll(
                eventJson("clean", 1, "RELAYING"),
                eventJson("clean", 2, "CLOSED", accepted = 2, persisted = 2, complete = true),
                eventJson("bypassed", 3, "PASSTHROUGH")
            )
        )
        val stats = store.snapshot().toCaptureStats()
        assertEquals(TlsCaptureStatus.RUNNING, stats.status)
        assertEquals(2L, stats.acceptedConnections)
        assertEquals(1L, stats.proxiedConnections)
        assertEquals(1L, stats.secretsSavedConnections)
        assertEquals(1L, stats.passthroughConnections)
        assertEquals(0L, stats.failedConnections)
        assertEquals(2L, stats.secretRecordsAccepted)
        assertEquals(2L, stats.secretRecordsPersisted)
        // The proxy proving it carried bytes is not the analyser proving it can
        // decrypt them (C03 7).
        assertEquals(0L, stats.decryptedConnections)
        assertEquals(0L, stats.quicUndecryptedConnections)
        store.close()
        assertEquals(TlsCaptureStatus.STOPPED, store.snapshot().status)
        // A stopped capture still reports what happened, and still accepts the
        // events that were already in flight.
        assertTrue(store.append(event("late", 4, TlsConnectionPhase.CLOSED)))
        assertEquals(3L, store.snapshot().counts.accepted)
    }

    @Test
    fun limitsAndIdentifiersAreValidatedRatherThanClamped() {
        // Each of these is refused where it is built, so nothing downstream ever
        // sees a budget larger than the capture allows.
        val refusals = listOf(
            { TlsConnectionStoreLimits(maxEvents = 0) },
            { TlsConnectionStoreLimits(maxEvents = TlsConnectionStoreLimits.MAX_EVENTS + 1) },
            { TlsConnectionStoreLimits(maxConnections = 0) },
            { TlsConnectionStoreLimits(maxConnections = TlsConnectionStoreLimits.MAX_CONNECTIONS + 1) },
            { TlsConnectionStoreLimits(uiRefreshIntervalMillis = 1) },
            { TlsConnectionStoreLimits(uiRefreshIntervalMillis = 60_001) }
        )
        for (refused in refusals) {
            val failure = runCatching { refused() }.exceptionOrNull()
            assertEquals(TlsAssetErrorCode.INVALID_ARGUMENT, (failure as? TlsAssetException)?.code)
        }
        // The floor is the C10 refresh budget itself, not an arbitrary number.
        assertEquals(250L, TlsConnectionStoreLimits.MIN_UI_REFRESH_MILLIS)
        assertNotNull(TlsConnectionStore(captureId, TlsConnectionStoreLimits(uiRefreshIntervalMillis = 250)))
        for (identifier in listOf("", "../capture", "-capture", "cap ture", "a".repeat(129))) {
            assertTrue(runCatching { TlsConnectionStore(identifier) }.exceptionOrNull() is TlsAssetException)
        }
    }

    @Test
    fun aSlowReaderNeverBlocksTheProducerAndConcurrentReadersStayConsistent() {
        val store = store(TlsConnectionStoreLimits(maxEvents = 64, maxConnections = 16))
        store.begin()
        val threads = 8
        val perThread = 250
        val applied = AtomicInteger()
        val rejected = AtomicInteger()
        val started = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(threads)
        try {
            repeat(threads) { worker ->
                pool.execute {
                    started.await()
                    for (index in 1..perThread) {
                        // Each worker owns one connection, so the sequences it
                        // publishes are the ones the engine would assign them.
                        val sequence = (index * threads + worker).toLong()
                        if (store.append(event("connection-$worker", sequence, TlsConnectionPhase.RELAYING))) {
                            applied.incrementAndGet()
                        } else {
                            rejected.incrementAndGet()
                        }
                    }
                }
            }
            started.countDown()
            pool.shutdown()
            assertTrue("appends must never block waiting for a reader", pool.awaitTermination(30, TimeUnit.SECONDS))
        } finally {
            pool.shutdownNow()
        }
        // A rejected append is a counted rejection, not a lost update: every
        // call is accounted for exactly once.
        assertEquals(threads * perThread, applied.get() + rejected.get())
        val snapshot = store.snapshot()
        assertEquals(rejected.get().toLong(), snapshot.counts.eventsRejected)
        assertTrue(snapshot.connections.size <= 16)
        assertTrue(store.eventsAfter(0L).size <= 64)
        assertTrue("at least one event must have been applied", snapshot.counts.accepted in 1..threads.toLong())
    }

    // ---- TLS-303: persistence of ordinary events (C04, design §8.3) ----

    /** A fresh journal file under a private temp directory, as C08 lays it out. */
    private fun journalFile(): File =
        File(Files.createTempDirectory("tls-connections").toFile(), "tls-connections.jsonl")

    private val c04Keys = setOf(
        "captureId", "connectionId", "eventSequence", "monotonicNanos", "wallTimeMillis",
        "destinationIp", "destinationPort", "networkGeneration", "sni", "downstreamClientRandom",
        "downstreamTls", "upstreamTls", "alpn", "phase", "decisionReason", "errorCode",
        "upstreamCertificateSha256", "secretRecordsAccepted", "secretRecordsPersisted", "secretsComplete"
    )

    @Test
    fun persistedEventsCarryOnlyTheC04FieldsAndNoSecretShape() {
        val file = journalFile()
        TlsConnectionStore(captureId, TlsConnectionStoreLimits(), journal = TlsConnectionJournal(file)).use { store ->
            store.begin()
            store.recordPoll(
                poll(
                    eventJson("connection-1", 1, "ACCEPTED", sni = "example.test"),
                    eventJson("connection-1", 2, "RELAYING", alpn = "h2")
                )
            )
            store.append(event("connection-1", 3, TlsConnectionPhase.CLOSED, accepted = 2, persisted = 2, complete = true))
        }
        val text = file.readText()
        // None of these shapes may ever appear in an ordinary-event journal (C03 6).
        for (shape in listOf(
            "PRIVATE KEY", "CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0",
            "token", "keylog"
        )) {
            assertFalse("journal leaked a forbidden shape: $shape", text.contains(shape))
        }
        val lines = file.readLines().filter { it.isNotBlank() }
        assertEquals(3, lines.size)
        for (line in lines) {
            val keys = JSONObject(line).keys().asSequence().toList()
            assertTrue("unexpected field in $keys", c04Keys.containsAll(keys))
        }
        assertEquals("example.test", JSONObject(lines.first()).getString("sni"))
    }

    @Test
    fun aRejectedEventIsNotPersistedAndAStaleSequenceIsWrittenOnce() {
        val file = journalFile()
        TlsConnectionStore(captureId, TlsConnectionStoreLimits(), journal = TlsConnectionJournal(file)).use { store ->
            store.begin()
            assertTrue(store.append(event("connection-1", 1, TlsConnectionPhase.RELAYING)))
            // A duplicate sequence, a foreign capture and a second terminal are all refused.
            assertFalse(store.append(event("connection-1", 1, TlsConnectionPhase.RELAYING)))
            assertFalse(store.append(event("foreign", 1, TlsConnectionPhase.RELAYING, capture = otherCapture)))
            assertTrue(store.append(event("connection-1", 2, TlsConnectionPhase.CLOSED)))
            assertFalse(store.append(event("connection-1", 3, TlsConnectionPhase.FAILED)))
            assertEquals(2L, store.snapshot().counts.eventsRejected)
        }
        val sequences = file.readLines().filter { it.isNotBlank() }.map { JSONObject(it).getLong("eventSequence") }
        // Only the two applied events were written; the rejected ones were not resurrected,
        // and the duplicate sequence was written exactly once.
        assertEquals(listOf(1L, 2L), sequences)
        assertEquals(1, sequences.count { it == 1L })
    }

    @Test
    fun historyReloadsFromDiskWhileTheInMemoryWindowStaysBounded() {
        val file = journalFile()
        val store = TlsConnectionStore(
            captureId,
            TlsConnectionStoreLimits(maxEvents = 8, maxConnections = 16),
            journal = TlsConnectionJournal(file)
        )
        try {
            store.begin()
            for (sequence in 1L..200L) {
                assertTrue(store.append(event("connection-${sequence % 7}", sequence, TlsConnectionPhase.RELAYING)))
            }
            // The live window is bounded (C10); nothing keeps the whole run resident.
            assertEquals(8, store.eventsAfter(0L).size)
        } finally {
            store.close()
        }
        // History is read back from the file, on demand, entire and in order.
        val history = store.history()
        assertEquals(200, history.size)
        assertEquals(1L, history.first().eventSequence)
        assertEquals(200L, history.last().eventSequence)
        assertEquals(150, store.history(since = 50L).size)
        assertEquals(0L, store.snapshot().counts.eventsNotPersisted)
    }

    @Test
    fun aLongRunStaysBoundedInMemoryAndPersistsEveryAcceptedEvent() {
        val file = journalFile()
        val store = TlsConnectionStore(
            captureId,
            TlsConnectionStoreLimits(maxEvents = 16, maxConnections = 16),
            journal = TlsConnectionJournal(file)
        )
        try {
            store.begin()
            for (sequence in 1L..2_000L) {
                assertTrue(store.append(event("connection-${sequence % 5}", sequence, TlsConnectionPhase.RELAYING)))
            }
        } finally {
            store.close()
        }
        val snapshot = store.snapshot()
        assertTrue("window grew past its budget: ${store.eventsAfter(0L).size}", store.eventsAfter(0L).size <= 16)
        assertTrue("retained summaries grew past budget", snapshot.connections.size <= 16)
        assertEquals(5L, snapshot.counts.accepted)
        assertEquals(0L, snapshot.counts.eventsNotPersisted)
        assertEquals(2_000, file.readLines().count { it.isNotBlank() })
    }

    @Test
    fun theRepositoryNamesTheConnectionJournalInsideTheCaptureDirectory() {
        val root = Files.createTempDirectory("captures").toFile()
        val repository = CaptureArtifactRepository(root)
        assertEquals(
            File(File(root, captureId), "tls-connections.jsonl"),
            repository.connectionEventsFile(captureId)
        )
    }
    @Test
    fun failedJournalCountsEveryUndeliveredLineAndRejectsLaterOffers() {
        val directory = Files.createTempDirectory("journal-target-directory").toFile()
        val journal = TlsConnectionJournal(directory, capacity = 4)
        try {
            repeat(10) { journal.offer("bounded record $it") }
            journal.close()
            val metrics = journal.queueMetrics
            assertEquals(10L, metrics.notPersisted)
            assertEquals(1L, metrics.writeFailures)
            assertEquals(0, metrics.queued)
            assertFalse(metrics.workerAlive)
            journal.offer("later record")
            assertEquals(11L, journal.droppedLines)
        } finally { journal.close() }
    }

    @Test
    fun projectionEvictsCompletedStateBeforeAnActiveStateAndCountsIt() {
        val store = TlsConnectionStore(captureId, TlsConnectionStoreLimits(maxConnections = 2))
        store.begin()
        assertTrue(store.append(event("active", 1, TlsConnectionPhase.RELAYING)))
        assertTrue(store.append(event("complete", 2, TlsConnectionPhase.CLOSED)))
        assertTrue(store.append(event("new", 3, TlsConnectionPhase.RELAYING)))
        val snapshot = store.snapshot()
        assertEquals(setOf("active", "new"), snapshot.connections.map { it.connectionId }.toSet())
        assertEquals(1L, snapshot.counts.connectionStatesEvicted)
        store.close()
    }

}
