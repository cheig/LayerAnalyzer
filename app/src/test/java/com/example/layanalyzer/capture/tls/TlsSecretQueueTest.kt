// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Synthetic in-memory NSS data, unrelated to real traffic, a shipped PCAP or any
 * captured secret. These cases cover the real-time path (TLS-210) the way the
 * import cases cover the offline one: a record is persisted only through the
 * TLS-103 container, and only the watermark that was reached is published.
 */
class TlsSecretQueueTest {
    @get:Rule val temporary = TemporaryFolder()
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val provider = AesGcmTlsWrappingKeyProvider { key }
    private val lineA = "CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}"
    private val lineB = "CLIENT_TRAFFIC_SECRET_0 ${"ef".repeat(32)} ${"12".repeat(32)}"
    private val lineC = "CLIENT_HANDSHAKE_TRAFFIC_SECRET ${"34".repeat(32)} ${"56".repeat(32)}"
    private val captureId = "capture-live"
    private val connectionId = "connection-1"
    private fun store() = TlsSecretStore(temporary.root, provider)
    private fun capture() = File(temporary.root, "capture-secrets/$captureId")
    private fun index() = File(capture(), "current.json")
    private fun assetDirectories() = capture().listFiles().orEmpty().filter { it.isDirectory }.map { it.name }

    private fun bytes(text: String) = text.toByteArray(Charsets.US_ASCII)

    @Test fun queuedByteCounterTracksCanonicalBytesAndDrain() {
        val gate = Gate()
        val sink = store().openLiveSecrets(captureId, TlsLiveSecretLimits(), gate.factory)
        try {
            assertEquals(0L, sink.queuedBytes())
            assertTrue(sink.offer(connectionId, bytes(lineA)))
            assertTrue(sink.offer(connectionId, bytes(lineB)))
            assertEquals((lineA.length + lineB.length).toLong(), sink.queuedBytes())
            val metrics = sink.queueMetrics()
            assertEquals(2, metrics.pendingRecords)
            assertEquals(0L, metrics.inFlightBytes)
            assertEquals(metrics.pendingBytes, metrics.peakRetainedBytes)
            assertEquals(metrics.pendingBytes, metrics.peakPendingBytes)
        } finally { gate.release(); sink.finish() }
        assertEquals(0L, sink.queuedBytes())
        val metrics = sink.queueMetrics()
        assertEquals(0L, metrics.inFlightBytes)
        assertFalse(metrics.consumerAlive)
        assertEquals(2L, metrics.persisted)
        assertEquals((lineA.length + lineB.length).toLong(), metrics.peakPendingBytes)
    }

    /** A consumer that cannot start until the test releases it, so the queue is observable. */
    private class Gate {
        private val open = CountDownLatch(1)
        var thread: Thread? = null
        val factory: (Runnable) -> Thread = { runnable ->
            Thread({ open.await(); runnable.run() }, "tls-live-secrets-test").also { thread = it }
        }
        fun release() = open.countDown()
        fun awaitExit(millis: Long = 5_000) { thread?.join(millis) }
    }

    @Test fun liveRecordsArePersistedPublishedAndReadableByTheAnalysisLease() {
        val store = store()
        val sink = store.openLiveSecrets(captureId)
        try {
            assertNull("a live asset must not be reachable before it is finished", store.currentAsset(captureId))
            assertTrue(sink.offer(connectionId, bytes(lineA)))
            assertTrue(sink.offer(connectionId, bytes(lineB)))
            assertTrue(sink.offer(connectionId, bytes(lineC)))
        } finally {
            val result = sink.finish()
            assertEquals(3L, result.accepted)
            assertEquals(3L, result.persisted)
            assertEquals(0L, result.rejected)
            assertNull(result.failure)
            assertTrue(result.complete)
            assertFalse(result.mitmSuspended)
        }
        val reference = required(store.currentAsset(captureId), "the finished live capture published no asset")
        assertEquals(3L, reference.watermark.sequence)
        assertEquals(reference.watermark.plaintextBytes + 3L, reference.keyLogBytes)
        assertEquals(reference, store().currentAsset(captureId))

        val lease = store.acquireLease(captureId, reference.assetId)
        val file = lease.configureNative({}) { File(it) }
        try {
            assertEquals("$lineA\n$lineB\n$lineC\n", file.readText())
        } finally {
            lease.close()
        }
        val encrypted = File(capture(), "${reference.assetId}/downstream.keys.enc").readBytes()
            .toString(Charsets.ISO_8859_1)
        assertFalse("the container must not hold a plaintext secret", encrypted.contains("cd".repeat(48)))
        assertFalse("the index must not hold a secret", index().readText().contains("cd".repeat(48)))
    }

    @Test fun offeredLinesAreValidatedAndCanonicalizedTheSameWayImportDoes() {
        val store = store()
        val sink = store.openLiveSecrets(captureId)
        // Tabs, extra separators and uppercase hex are the same record as the
        // canonical line; an unknown label and a malformed line are not records
        // this capture can decrypt with.
        assertTrue(sink.offer(connectionId, bytes("CLIENT_RANDOM\t${"AB".repeat(32)}  ${"CD".repeat(48)}")))
        assertFalse(sink.offer(connectionId, bytes("SOME_FUTURE_SECRET ${"ab".repeat(32)} ${"cd".repeat(32)}")))
        assertFalse(sink.offer(connectionId, bytes("CLIENT_RANDOM ${"ab".repeat(32)}")))
        assertFalse(sink.offer(connectionId, bytes("CLIENT_RANDOM ${"ab".repeat(31)}zz ${"cd".repeat(48)}")))
        assertFalse(sink.offer(connectionId, bytes("CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(47)}")))
        assertFalse(sink.offer(connectionId, bytes("CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}\u0000")))
        assertFalse(sink.offer(connectionId, ByteArray(0)))
        assertFalse(sink.offer(connectionId, ByteArray(KeyLogParser.MAX_LINE_BYTES + 1) { 'a'.code.toByte() }))
        assertFalse(sink.offer("a/b", bytes(lineA)))
        val result = sink.finish()

        assertEquals(1L, result.accepted)
        assertEquals(1L, result.persisted)
        assertEquals(8L, result.rejected)
        assertFalse(result.complete)
        assertTrue(result.mitmSuspended)
        val reference = required(result.asset, "one accepted record must publish an asset")
        store.acquireLease(captureId, reference.assetId).use { lease ->
            assertEquals("$lineA\n", lease.configureNative({}) { File(it) }.readText())
        }
    }

    @Test fun aFullQueueRefusesRecordsWithoutBlockingAndSuspendsNewInterception() {
        val store = store()
        val gate = Gate()
        // Two CLIENT_RANDOM lines fit in 400 bytes; the consumer cannot drain, so
        // the third record has nowhere to go.
        val sink = store.openLiveSecrets(
            captureId, TlsLiveSecretLimits(queueBytes = 400), gate.factory
        )
        val started = System.nanoTime()
        assertTrue(sink.offer(connectionId, bytes(lineA)))
        assertTrue(sink.offer(connectionId, bytes(lineB)))
        assertFalse(sink.offer(connectionId, bytes(lineC)))
        assertFalse(sink.offer(connectionId, bytes(lineA)))
        assertTrue("offer must return immediately", System.nanoTime() - started < 2_000_000_000L)

        val blocked = sink.snapshot()
        assertEquals(2L, blocked.accepted)
        assertEquals(0L, blocked.persisted)
        assertEquals(2L, blocked.rejected)
        assertNull(blocked.failure)
        assertFalse(blocked.complete)
        assertTrue("a full queue must stop new interception candidates", blocked.mitmSuspended)

        gate.release()
        val result = sink.finish()
        assertEquals(2L, result.accepted)
        assertEquals("the records that were accepted must still reach the disk", 2L, result.persisted)
        assertEquals(2L, result.rejected)
        assertFalse("a refused record keeps the capture incomplete", result.complete)
    }

    @Test fun aFailedPersistLeavesAcceptedAbovePersistedAndKeepsTheSinkUsable() {
        val store = store()
        // Two records fit; the container then refuses the third, which is what a
        // full disk or an exhausted budget looks like from the consumer's side.
        val sink = store.openLiveSecrets(
            captureId,
            TlsLiveSecretLimits(asset = TlsAssetLimits(maxPlaintextBytes = 400, maxRecords = 2, maxFileBytes = 1024))
        )
        assertTrue(sink.offer(connectionId, bytes(lineA)))
        assertTrue(sink.offer(connectionId, bytes(lineB)))
        assertTrue(sink.offer(connectionId, bytes(lineC)))
        val result = sink.finish()

        assertEquals(3L, result.accepted)
        assertEquals(2L, result.persisted)
        assertTrue("accepted above persisted is the incomplete state", result.accepted > result.persisted)
        assertEquals(TlsAssetErrorCode.CAPACITY_EXCEEDED, result.failure)
        assertFalse(result.complete)
        assertTrue(result.mitmSuspended)
        val reference = required(result.asset, "the records that were synced must still be published")
        assertEquals(2L, reference.watermark.sequence)
        store.acquireLease(captureId, reference.assetId).use { lease ->
            assertEquals("$lineA\n$lineB\n", lease.configureNative({}) { File(it) }.readText())
        }
    }

    @Test fun finishWaitsForAcceptedRecordsAndRefusesEverythingAfterIt() {
        val store = store()
        val gate = Gate()
        val sink = store.openLiveSecrets(captureId, TlsLiveSecretLimits(), gate.factory)
        assertTrue(sink.offer(connectionId, bytes(lineA)))
        assertTrue(sink.offer(connectionId, bytes(lineB)))

        val pool = Executors.newSingleThreadExecutor()
        try {
            val finishing = pool.submit<TlsSecretPersistence> { sink.finish() }
            Thread.sleep(200)
            assertFalse("finish must wait for the accepted records", finishing.isDone)
            assertTrue("a record offered during the drain is refused", !sink.offer(connectionId, bytes(lineC)))
            gate.release()
            val result = finishing.get(10, TimeUnit.SECONDS)
            assertEquals(2L, result.accepted)
            assertEquals(2L, result.persisted)
            assertEquals(1L, result.rejected)
            assertFalse(result.complete)
        } finally {
            gate.release()
            pool.shutdownNow()
        }
        assertFalse("a record offered after finish is refused", sink.offer(connectionId, bytes(lineA)))
        assertTrue(sink.snapshot().rejected >= 1)
    }

    @Test fun aConsumerThatNeverReturnsIsBoundedAndPublishesNothing() {
        val store = store()
        val gate = Gate()
        val sink = store.openLiveSecrets(captureId, TlsLiveSecretLimits(drainTimeoutMillis = 100), gate.factory)
        assertTrue(sink.offer(connectionId, bytes(lineA)))

        val started = System.nanoTime()
        val result = sink.finish()
        val elapsed = System.nanoTime() - started
        assertTrue("finish must not wait without bound", elapsed < 3_000_000_000L)
        assertEquals(1L, result.accepted)
        assertEquals(0L, result.persisted)
        assertEquals(TlsAssetErrorCode.IO_ERROR, result.failure)
        assertFalse(result.complete)
        assertNull("an unfinished asset must not be published", result.asset)
        assertNull(store.currentAsset(captureId))
        assertTrue("the unpublished asset stays in its private directory", assetDirectories().isNotEmpty())

        // Once the consumer returns, the leftover is an unpublished asset with no
        // index, which is exactly what the startup sweep removes.
        gate.release()
        gate.awaitExit()
        store.cleanupOrphans()
        assertTrue(assetDirectories().isEmpty())
        assertFalse(index().exists())
    }

    @Test fun theOrphanSweepAndCurrentAssetNeverDisturbALiveCapture() {
        val store = store()
        val published = store.importRecords(captureId, parsed(lineA))
        val gate = Gate()
        val sink = store.openLiveSecrets(captureId, TlsLiveSecretLimits(), gate.factory)
        assertTrue(sink.offer(connectionId, bytes(lineB)))

        // The previous asset is still the current one, and neither reading it nor
        // sweeping the store may delete the asset that is still being written.
        assertEquals(published, store.currentAsset(captureId))
        store.cleanupOrphans()
        assertEquals(published, store.currentAsset(captureId))
        assertEquals(2, assetDirectories().size)

        gate.release()
        val result = sink.finish()
        assertTrue(result.complete)
        val replacement = required(result.asset, "the live capture published no asset")
        assertNotEquals(published.assetId, replacement.assetId)
        assertEquals(replacement, store.currentAsset(captureId))
        assertEquals(listOf(replacement.assetId), assetDirectories())
        assertFalse("the replaced asset is removed only after the new one is published", published.assetId in assetDirectories())
    }

    @Test fun anEmptyLiveCapturePublishesNothingAndLeavesNothingBehind() {
        val store = store()
        val result = store.openLiveSecrets(captureId).finish()
        assertEquals(0L, result.accepted)
        assertEquals(0L, result.persisted)
        assertTrue("a capture with no intercepted connection lost nothing", result.complete)
        assertNull(result.asset)
        assertNull(store.currentAsset(captureId))
        assertFalse(index().exists())
        assertTrue(assetDirectories().isEmpty())
    }

    @Test fun finishIsIdempotentAndSnapshotsStayConsistent() {
        val store = store()
        val sink = store.openLiveSecrets(captureId)
        assertTrue(sink.offer(connectionId, bytes(lineA)))
        val first = sink.finish()
        val second = sink.finish()
        assertEquals(first, second)
        assertEquals(first, sink.snapshot())
        assertTrue(first.complete)
        // Counters, ids and fixed codes only: nothing a caller could put in an
        // event, a UI state or a log may carry the secret or the client random.
        val reference = required(first.asset, "the finished capture published no asset")
        for (text in listOf(first.toString(), reference.toString())) {
            assertFalse(text.contains("cd".repeat(48)))
            assertFalse(text.contains("ab".repeat(32)))
        }
    }

    @Test fun concurrentOffersDuringAStopHaveNoDeadlockAndNoLostAccounting() {
        val store = store()
        val sink = store.openLiveSecrets(captureId)
        val pool = Executors.newFixedThreadPool(4)
        try {
            val offers = (0 until 4).map { index ->
                pool.submit<Int> {
                    var accepted = 0
                    repeat(200) {
                        if (sink.offer("connection-$index", bytes(lineA))) accepted++
                    }
                    accepted
                }
            }
            Thread.sleep(20)
            val stopping = pool.submit<TlsSecretPersistence> { sink.finish() }
            val acceptedByCallers = offers.sumOf { it.get(10, TimeUnit.SECONDS) }
            val result = stopping.get(10, TimeUnit.SECONDS)
            assertEquals("every accepted offer is accounted for", acceptedByCallers.toLong(), result.accepted)
            assertEquals(800L, result.accepted + result.rejected)
            assertTrue(result.persisted <= result.accepted)
            if (result.rejected > 0L) assertFalse(result.complete)
        } finally {
            pool.shutdownNow()
        }
    }

    @Test fun liveLimitsRejectValuesAboveTheirCeilings() {
        val invalid = listOf<() -> TlsLiveSecretLimits>(
            { TlsLiveSecretLimits(queueBytes = 0) },
            { TlsLiveSecretLimits(queueBytes = TlsLiveSecretLimits.MAX_QUEUE_BYTES + 1) },
            { TlsLiveSecretLimits(drainTimeoutMillis = 0) },
            { TlsLiveSecretLimits(drainTimeoutMillis = TlsLiveSecretLimits.MAX_DRAIN_MILLIS + 1) }
        )
        for (build in invalid) {
            val error = runCatching { build() }.exceptionOrNull()
            assertTrue("an out-of-range live limit must be rejected", error is TlsAssetException)
            assertEquals(TlsAssetErrorCode.INVALID_ARGUMENT, (error as TlsAssetException).code)
        }
        val store = store()
        for (id in listOf("../capture-live", "a/b", "", "a b")) {
            val error = runCatching { store.openLiveSecrets(id) }.exceptionOrNull()
            assertTrue(error is TlsAssetException)
        }
        assertFalse(capture().exists())
    }

    @Test fun aLiveCaptureKeepsWritingWhileAnotherStoreInstancePublishes() {
        val first = store()
        val second = store()
        val gate = Gate()
        val sink = first.openLiveSecrets(captureId, TlsLiveSecretLimits(), gate.factory)
        assertTrue(sink.offer(connectionId, bytes(lineA)))
        // A second store instance must see the live asset as unpublished rather
        // than as garbage, even though it holds no in-process reference to it.
        assertNull(second.currentAsset(captureId))
        second.cleanupOrphans()
        assertEquals(1, assetDirectories().size)
        gate.release()
        assertTrue(sink.finish().complete)
        assertNotNull(second.currentAsset(captureId))
    }

    /** JUnit's fail() returns Unit in Kotlin, which cannot narrow a nullable. */
    private fun <T> required(value: T?, message: String): T = value ?: throw AssertionError(message)

    private fun parsed(text: String) = KeyLogParser.parse(text.byteInputStream()) as KeyLogParseResult.Success}
