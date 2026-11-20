// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import androidx.paging.PagingSource
import com.example.layanalyzer.capture.tls.TlsAssetWatermark
import com.example.layanalyzer.capture.tls.TlsSecretAssetRef
import com.example.layanalyzer.model.DisplayFilterResult
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.PacketSummary
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class TlsAnalysisTransactionTest {
    private class Harness : TlsAnalysisBackend, AutoCloseable {
        val gate = CaptureAnalysisGate()
        val transaction = TlsAnalysisTransaction(gate, this)
        val directory = Files.createTempDirectory("tls-transaction-test").toFile()
        val calls = mutableListOf<String>()
        var configured = false
        var handle = 7L
        var generation = 2L // e.g. Decode As was applied before the TLS transaction
        var revision = 0L
        var failAt = ""
        var onFrame: (Int) -> Unit = {}
        var activePath: String? = null
        var visible = 0
        var observed = false
        var afterClosed: () -> Unit = {}
        var failRelease = false
        init { transaction.opened(handle) }
        fun lease(id: String): TlsAnalysisSecretLease {
            val file = File(directory, id).apply { writeText("synthetic-unused-test-material") }
            return TlsAnalysisSecretLease(
                TlsSecretAssetRef("capture", id, TlsAssetWatermark(1, 1, 1), file.length()), file
            ) {
                check(activePath != file.absolutePath) { "File released before native clear." }
                calls += "release:$id"
                check(!failRelease) { "Synthetic lease cleanup failure." }
                check(file.delete())
            }
        }
        override fun configure(path: String?, revision: Long): NativeTlsConfiguration {
            calls += "configure:$revision"
            if (failAt == "configure") error("private path must not escape")
            if (revision == this.revision && path == activePath) {
                return NativeTlsConfiguration(true, generation, revision, configured, false)
            }
            activePath = path
            configured = path != null
            this.revision = revision
            return NativeTlsConfiguration(true, ++generation, revision, configured, false)
        }
        override fun frameCount() = 4
        override fun dissectFrame(packetIndex: Int): Boolean {
            calls += "frame:$packetIndex"
            assertFalse(gate.revisions.value.ready)
            onFrame(packetIndex)
            return failAt != "frame:$packetIndex"
        }
        override fun restoreFilter(filter: String): Int {
            calls += "filter:$filter"
            if (failAt == "filter") error("filter failed")
            visible = if (configured && filter == "http") 2 else 0
            return visible
        }
        override fun closeSession() {
            calls += "close"
            handle = 0
            activePath = null
            configured = false
        }
        override fun invalidateCaches() { calls += "invalidate" }
        override fun plaintextStats(): TlsPlaintextStats =
            if (!observed) TlsPlaintextStats.EMPTY else TlsPlaintextStats(
                connections = 2, tls13Connections = 1, tls12Connections = 1,
                decryptedRecords = 3, decryptedBytes = 48, observed = true, scannedFrames = 4
            )
        override fun onClosed() = afterClosed()
        fun configure(lease: TlsAnalysisSecretLease? = null, check: () -> Unit = {}) =
            transaction.configure(lease, gate.revisions.value, "http", check) { _, _ -> }
        override fun close() { transaction.close(); directory.deleteRecursively() }
    }

    @Test fun publishesOnlyAfterFullOrderedScanAndFilterRestore() = Harness().use { h ->
        val original = h.gate.revisions.value
        val result = h.configure(h.lease("a"))
        assertTrue(result.success)
        assertEquals(listOf("configure:1", "invalidate", "frame:0", "frame:1", "frame:2", "frame:3", "filter:http"), h.calls)
        assertEquals(2, result.visibleFrameCount)
        assertEquals(3L, result.analysis.dissectionGeneration)
        assertEquals(1L, result.analysis.secretsGeneration)
        assertTrue(result.analysis.ready)
        assertNotEquals(original, result.analysis)
    }

    @Test fun replacementAndClearReleaseOldFileWithoutClearingNewConfiguration() = Harness().use { h ->
        val a = h.lease("a")
        val b = h.lease("b")
        assertTrue(h.configure(a).success)
        assertTrue(h.configure(b).success)
        a.close() // late idempotent callback cannot clear b
        assertTrue(h.activePath!!.endsWith("b"))
        assertTrue(h.calls.indexOf("configure:2") < h.calls.indexOf("release:a"))
        val cleared = h.configure()
        assertTrue(cleared.success)
        assertFalse(cleared.analysis.configured)
        assertEquals(3L, cleared.analysis.secretsGeneration)
        assertFalse(File(h.directory, "b").exists())
        assertEquals(0, cleared.visibleFrameCount)
    }

    @Test fun cancellingScanClosesBeforeReleasingAndNeverPublishesReady() = Harness().use { h ->
        var cancel = false
        h.onFrame = { if (it == 1) cancel = true }
        try {
            h.configure(h.lease("a")) { if (cancel) throw CancellationException() }
            fail("Expected cancellation")
        } catch (_: CancellationException) { }
        assertEquals(0L, h.handle)
        assertFalse(h.gate.revisions.value.ready)
        assertTrue(h.calls.indexOf("close") < h.calls.indexOf("release:a"))
        assertFalse(h.calls.any { it.startsWith("filter:") || it == "frame:2" })
    }

    @Test fun partialNativeOrScanOrFilterFailureRequiresReopen() {
        for (stage in listOf("configure", "frame:2", "filter")) Harness().use { h ->
            h.failAt = stage
            val result = h.configure(h.lease("a"))
            assertFalse(result.success)
            assertTrue(result.reopenRequired)
            assertEquals("IO_ERROR", result.errorCode)
            assertFalse(result.analysis.ready)
            assertEquals(0L, result.analysis.sessionHandle)
            assertFalse(File(h.directory, "a").exists())
        }
    }

    @Test fun cancelledAnalysisNotifiesArtifactCleanupAfterNativeAndLeaseTeardown() = Harness().use { h ->
        var notified = false
        h.afterClosed = {
            assertEquals(0L, h.handle)
            assertFalse(File(h.directory, "a").exists())
            assertTrue(h.calls.indexOf("close") < h.calls.indexOf("release:a"))
            notified = true
        }
        h.onFrame = { throw CancellationException() }
        try { h.configure(h.lease("a")); fail() } catch (_: CancellationException) { }
        assertTrue(notified)
    }

    @Test fun artifactCleanupWaitsUntilFailedLeaseReleaseHasBeenRetried() = Harness().use { h ->
        h.configure(h.lease("a"))
        var notified = false
        h.afterClosed = { notified = true }
        h.failRelease = true
        try { h.transaction.close(); fail() } catch (_: IllegalStateException) { }
        assertFalse(notified)
        assertTrue(File(h.directory, "a").exists())
        h.failRelease = false
        h.transaction.close()
        assertTrue(notified)
    }

    @Test fun staleCaptureRequestReleasesOnlyUnconfiguredLease() = Harness().use { h ->
        val old = h.gate.revisions.value
        h.configure(h.lease("a"))
        val calls = h.calls.size
        val result = h.transaction.configure(h.lease("b"), old, "http", {}) { _, _ -> }
        assertEquals("STALE_GENERATION", result.errorCode)
        assertEquals(listOf("release:b"), h.calls.drop(calls))
        assertTrue(h.activePath!!.endsWith("a"))
    }

    @Test fun writeWaitsForReadLeaseAndNewReadsCannotEnterTransaction() = Harness().use { h ->
        val pool = Executors.newFixedThreadPool(2)
        val reading = CountDownLatch(1)
        val releaseRead = CountDownLatch(1)
        val writing = CountDownLatch(1)
        val releaseWrite = CountDownLatch(1)
        try {
            val read = pool.submit { h.gate.read { reading.countDown(); check(releaseRead.await(5, TimeUnit.SECONDS)) } }
            assertTrue(reading.await(5, TimeUnit.SECONDS))
            h.onFrame = { if (it == 0) { writing.countDown(); check(releaseWrite.await(5, TimeUnit.SECONDS)) } }
            val write = pool.submit<TlsAnalysisResult> { h.configure() }
            assertFalse(writing.await(50, TimeUnit.MILLISECONDS))
            releaseRead.countDown()
            read.get(5, TimeUnit.SECONDS)
            assertTrue(writing.await(5, TimeUnit.SECONDS))
            try { h.gate.read { fail("Read entered write transaction") }; fail("Expected stale") }
            catch (_: StaleCaptureAnalysisException) { }
            releaseWrite.countDown()
            assertTrue(write.get(5, TimeUnit.SECONDS).success)
        } finally { releaseRead.countDown(); releaseWrite.countDown(); pool.shutdownNow() }
    }

    @Test fun oldPagingSourceCannotReturnPageAfterConfiguration() = runBlocking {
        Harness().use { h ->
            val reader = object : PacketPageReader {
                override fun currentAnalysisRevision() = h.gate.revisions.value
                override fun getVisibleFrameCount() = 1
                override fun getPacketSummaries(start: Int, count: Int): List<PacketSummary> {
                    h.configure()
                    return emptyList()
                }
            }
            val paging = PacketPagingSource(reader, Dispatchers.Unconfined)
            assertTrue(paging.load(PagingSource.LoadParams.Refresh(null, 10, false)) is PagingSource.LoadResult.Invalid)
        }
    }

    @Test fun malformedNativeResponseIsNeverSuccess() {
        for (raw in listOf("{}", "", "{\"schemaVersion\":2,\"success\":true}")) {
            assertTrue(runCatching { NativeTlsConfiguration.parse(raw) }.isFailure)
        }
    }

    /**
     * Frames are never skipped once plaintext is known: P2-2 established that the
     * in-order pass is what rebuilds Wireshark's cross-frame reassembly state, and
     * P2-3 makes the same pass count every frame, so the totals are totals.
     */
    @Test fun scanDissectsEveryFrameInOrderEvenWhenPlaintextWasAlreadyObserved() = Harness().use { h ->
        h.observed = true
        val result = h.configure(h.lease("a"))
        assertTrue(result.success)
        assertTrue(result.observedDecryptedData)
        assertEquals(
            listOf("frame:0", "frame:1", "frame:2", "frame:3"),
            h.calls.filter { it.startsWith("frame:") }
        )
        assertTrue(h.calls.indexOf("frame:3") < h.calls.indexOf("filter:http"))
    }

    @Test fun decryptedConnectionTotalsReachTheCallerWithTheirVersionSplit() = Harness().use { h ->
        h.observed = true
        val result = h.configure(h.lease("a"))
        assertEquals(
            TlsPlaintextStats(connections = 2, tls13Connections = 1, tls12Connections = 1,
                decryptedRecords = 3, decryptedBytes = 48, observed = true, scannedFrames = 4),
            result.plaintextStats
        )
        assertEquals(1, result.plaintextStats.tls13Connections)
        assertEquals(1, result.plaintextStats.tls12Connections)
    }

    /** A failed scan measured nothing; it must not look like "decrypted nothing". */
    @Test fun aFailedScanReportsNoPlaintextMeasurement() {
        for (stage in listOf("configure", "frame:2", "filter")) Harness().use { h ->
            h.observed = true
            h.failAt = stage
            val result = h.configure(h.lease("a"))
            assertFalse(result.observedDecryptedData)
            assertEquals(TlsPlaintextStats.EMPTY, result.plaintextStats)
        }
    }

    @Test fun plaintextProbeNeverTurnsAMalformedOrInconsistentReplyIntoObservation() {
        val usable = "{\"schemaVersion\":1,\"success\":true,\"decryptedSources\":1," +
            "\"decryptedBytes\":16,\"observed\":true,\"streamId\":4,\"tlsVersion\":772}"
        for (raw in listOf(
            "{}",
            "",
            // Version mismatch, a failed envelope, observation without bytes, a reply
            // that never named a connection, and identity attached to a frame that
            // carried no plaintext are all unusable, never "no plaintext".
            "{\"schemaVersion\":2,\"success\":true,\"decryptedSources\":1," +
                "\"decryptedBytes\":16,\"observed\":true,\"streamId\":4,\"tlsVersion\":772}",
            "{\"schemaVersion\":1,\"success\":false,\"decryptedSources\":1," +
                "\"decryptedBytes\":16,\"observed\":true,\"streamId\":4,\"tlsVersion\":772}",
            "{\"schemaVersion\":1,\"success\":true,\"decryptedSources\":0," +
                "\"decryptedBytes\":0,\"observed\":true,\"streamId\":-1,\"tlsVersion\":0}",
            "{\"schemaVersion\":1,\"success\":true,\"decryptedSources\":1," +
                "\"decryptedBytes\":16,\"observed\":true}",
            "{\"schemaVersion\":1,\"success\":true,\"decryptedSources\":0," +
                "\"decryptedBytes\":0,\"observed\":false,\"streamId\":4,\"tlsVersion\":772}",
            "{\"schemaVersion\":1,\"success\":true,\"decryptedSources\":1," +
                "\"decryptedBytes\":16,\"observed\":true,\"streamId\":-2,\"tlsVersion\":772}"
        )) {
            assertNull(raw, NativePlaintextProbe.parse(raw))
        }
        assertEquals(
            NativePlaintextProbe(1, 16, true, 4, 0x0304),
            NativePlaintextProbe.parse(usable)
        )
        // A version this build does not model is reported, not rejected: DTLS is a real
        // thing to find in a capture, and a failed parse would abort the analysis.
        assertEquals(
            NativePlaintextProbe(1, 16, true, 4, 0xFEFD),
            NativePlaintextProbe.parse(
                "{\"schemaVersion\":1,\"success\":true,\"decryptedSources\":1," +
                    "\"decryptedBytes\":16,\"observed\":true,\"streamId\":4,\"tlsVersion\":65277}"
            )
        )
        assertEquals(
            NativePlaintextProbe(0, 0, false, -1, 0),
            NativePlaintextProbe.parse(
                "{\"schemaVersion\":1,\"success\":true,\"decryptedSources\":0," +
                    "\"decryptedBytes\":0,\"observed\":false,\"streamId\":-1,\"tlsVersion\":0}"
            )
        )
    }

    @Test fun unrelatedEpanResetRefreshesGenerationWithoutChangingSecretsRevision() = Harness().use { h ->
        h.configure(h.lease("a"))
        val before = h.gate.revisions.value
        h.transaction.changeDissectionSettings { h.generation++ }
        val after = h.gate.revisions.value
        assertEquals(before.dissectionGeneration + 1, after.dissectionGeneration)
        assertEquals(before.secretsGeneration, after.secretsGeneration)
        assertTrue(after.configured)
        assertTrue(h.activePath!!.endsWith("a"))
    }

    @Test fun coordinatorCancelsAndWaitsForFilterLeaseBeforeNativeConfiguration() = runBlocking {
        Harness().use { h ->
            val source = object : CaptureSessionDataSource {
                override fun currentSessionHandle() = h.handle
                override fun currentFile(): FileSessionInfo? = null
                override fun getFrameCount() = 4
                override fun getVisibleFrameCount() = h.visible
                override fun getAppliedDisplayFilter() = "http"
                override fun applyDisplayFilter(filter: String, expectedSessionHandle: Long) = DisplayFilterResult(true, h.visible)
                override fun validateDisplayFilter(filter: String) = Result.success(Unit)
                override fun cancelLongRunningOperations() { }
                override fun currentAnalysisRevision() = h.gate.revisions.value
                override fun configureTlsAnalysis(lease: TlsAnalysisSecretLease?, expected: CaptureAnalysisRevision, filter: String,
                    checkCancelled: () -> Unit, progress: (Int, Int) -> Unit) =
                    h.transaction.configure(lease, expected, filter, checkCancelled, progress)
            }
            val coordinator = CaptureSessionCoordinator(source, nativeDispatcher = Dispatchers.Default)
            coordinator.onSessionOpened(FileSessionInfo("a", 1, "pcap", 4, h.directory.path))
            val oldToken = coordinator.currentToken()!!
            val entered = CompletableDeferred<Unit>()
            val exited = CompletableDeferred<Unit>()
            val reader = launch {
                coordinator.withTemporaryFilter("tcp") {
                    entered.complete(Unit)
                    try { awaitCancellation() } finally { exited.complete(Unit) }
                }
            }
            entered.await()
            val configured = withTimeout(5000) { coordinator.configureTlsSecrets(h.lease("a")) }
            reader.join()
            assertTrue(exited.isCompleted)
            assertTrue(configured.success)
            assertFalse(coordinator.isCurrent(oldToken))
            assertEquals(configured.analysis.dissectionGeneration, coordinator.state.value.dissectionGeneration)
            assertFalse(coordinator.state.value.analysisReconfiguring)
        }
    }
}
