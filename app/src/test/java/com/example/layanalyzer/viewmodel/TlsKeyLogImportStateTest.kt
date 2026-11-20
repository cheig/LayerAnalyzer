// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import javax.crypto.KeyGenerator

/** Real bounded parser, authenticated store, leases and transaction; native backend is a test double. */
class TlsKeyLogImportStateTest {
    private val line = "CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}"

    private class Harness(scope: CoroutineScope, io: CoroutineDispatcher = Dispatchers.Unconfined) : TlsKeyLogImportBackend, TlsAnalysisBackend, AutoCloseable {
        val root = Files.createTempDirectory("tls-import-state").toFile()
        private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val store = TlsSecretStore(root, AesGcmTlsWrappingKeyProvider { key })
        val gate = CaptureAnalysisGate()
        val transaction = TlsAnalysisTransaction(gate, this)
        val controller = TlsKeyLogImportController(scope, this, io)
        var targetId = "capture-a"
        var sessionGeneration = 1L
        var generation = 0L
        var nativeConfigured = false
        var nativePath: String? = null
        var nativeCalls = 0
        var acquired = 0
        var observation = false
        var failure: String? = null
        var afterAcquire: (() -> Unit)? = null
        var onFrame: (() -> Unit)? = null
        var beforeConfigure: (suspend () -> Unit)? = null
        init { transaction.opened(7) }
        override fun currentAnalysis() = gate.revisions.value
        override fun currentTarget() = currentAnalysis().takeIf { it.ready && it.sessionHandle != 0L }?.let {
            TlsKeyLogImportTarget(targetId, CaptureSessionToken(it.sessionHandle, sessionGeneration), it)
        }
        override fun acquire(target: TlsKeyLogImportTarget, parsed: KeyLogParseResult.Success,
                             checkCancelled: () -> Unit): TlsAnalysisSecretLease {
            val lease = store.acquireImportedLease(target.captureId, parsed, checkCancelled)
            acquired++
            afterAcquire?.invoke()
            return lease
        }
        override suspend fun configure(target: TlsKeyLogImportTarget, lease: TlsAnalysisSecretLease?,
                                       progress: (Int, Int) -> Unit): TlsAnalysisResult {
            val caller = currentCoroutineContext()
            try { beforeConfigure?.invoke() } catch (error: Throwable) { lease?.close(); throw error }
            return transaction.configure(lease, target.analysis, "", { caller.ensureActive() }, progress)
        }
        override fun configure(path: String?, revision: Long): NativeTlsConfiguration {
            nativeCalls++
            assertTrue(nativePath == null || File(nativePath!!).exists())
            if (failure != null) return NativeTlsConfiguration(false, generation, revision - 1,
                nativeConfigured, false, failure)
            nativePath = path
            nativeConfigured = path != null
            return NativeTlsConfiguration(true, ++generation, revision, nativeConfigured, false)
        }
        override fun frameCount() = 4
        override fun dissectFrame(packetIndex: Int): Boolean { onFrame?.invoke(); return true }
        override fun restoreFilter(filter: String) = 4
        override fun invalidateCaches() { }
        override fun plaintextStats(): TlsPlaintextStats =
            if (!nativeConfigured || !observation) TlsPlaintextStats.EMPTY else TlsPlaintextStats(
                connections = 3, tls13Connections = 2, tls12Connections = 1,
                decryptedRecords = 5, decryptedBytes = 80, observed = true, scannedFrames = 4
            )
        override fun closeSession() { nativePath = null; nativeConfigured = false }
        fun leaseCount() = File(root, "tls-analysis-leases").listFiles().orEmpty().size
        /** What the analysis would report for a capture with two 1.3 and one 1.2 connection. */
        fun reportedPlaintext() = TlsPlaintextStats(connections = 3, tls13Connections = 2,
            tls12Connections = 1, decryptedRecords = 5, decryptedBytes = 80,
            observed = true, scannedFrames = 4)
        fun select(text: String) { assertTrue(controller.beginSelection()); controller.selected { text.byteInputStream() } }
        suspend fun done() { withTimeout(5_000) { while (controller.state.value.busy) delay(1) } }
        override fun close() { controller.invalidate(); transaction.close(); root.deleteRecursively() }
    }

    @Test fun importedKeysDoNotClaimPlaintextAndClearThenReimportWorks() = runBlocking {
        Harness(this).use { h ->
            h.select(line); h.done()
            assertTrue(h.controller.state.value.configured)
            assertFalse(h.controller.state.value.observedDecryptedData)
            assertEquals(1, h.leaseCount())
            val first = h.currentAnalysis()
            h.controller.clear(); h.done()
            assertFalse(h.controller.state.value.configured)
            assertEquals(0, h.leaseCount())
            assertTrue(h.currentAnalysis().secretsGeneration > first.secretsGeneration)
            assertNull(h.store.currentAsset("capture-a")) // manual import never publishes retained keys
            h.observation = true
            h.select(line); h.done()
            assertTrue(h.controller.state.value.observedDecryptedData)
        }
    }

    @Test fun duplicateAndUnsupportedCountsDoNotInflateImportedRecords() = runBlocking {
        Harness(this).use { h ->
            h.select("$line\n$line\nFUTURE_SECRET ${"ab".repeat(32)} 1234\n"); h.done()
            assertEquals(1, h.controller.state.value.importedRecords)
            assertEquals(1, h.controller.state.value.duplicateLines)
            assertEquals(1, h.controller.state.value.unsupportedLines)
        }
    }

    @Test fun invalidInputDoesNotReplaceExistingConfigurationOrExposeSecrets() = runBlocking {
        Harness(this).use { h ->
            h.observation = true
            h.select(line); h.done()
            val before = h.currentAnalysis()
            h.select("PRIVATE_INPUT wrong columns extra"); h.done()
            assertEquals(before, h.currentAnalysis())
            assertEquals(1, h.nativeCalls)
            assertTrue(h.controller.state.value.observedDecryptedData)
            assertEquals(KeyLogParseErrorCode.INVALID_COLUMN_COUNT, h.controller.state.value.parseError?.code)
            assertFalse(h.controller.state.value.toString().contains("PRIVATE_INPUT"))
        }
    }

    @Test fun oversizedLineAndTotalLimitNeverReachStoreOrNative() = runBlocking {
        Harness(this).use { h ->
            h.select("#".repeat(KeyLogParser.MAX_LINE_BYTES + 1)); h.done()
            assertEquals(KeyLogParseErrorCode.LINE_SIZE_EXCEEDED, h.controller.state.value.parseError?.code)
            assertTrue(h.controller.beginSelection())
            h.controller.selected { object : InputStream() {
                override fun read() = '\n'.code // no allocation of a giant test input
                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    java.util.Arrays.fill(b, off, off + len, '\n'.code.toByte()); return len
                }
            } }
            h.done()
            assertEquals(KeyLogParseErrorCode.TOTAL_SIZE_EXCEEDED, h.controller.state.value.parseError?.code)
            assertEquals(0, h.acquired)
            assertEquals(0, h.nativeCalls)
        }
    }

    @Test fun cancellingPickerKeepsCurrentAnalysisUntouched() = runBlocking {
        Harness(this).use { h ->
            val before = h.currentAnalysis()
            assertTrue(h.controller.beginSelection()); h.controller.selected(null)
            assertEquals(before, h.currentAnalysis())
            assertFalse(h.controller.state.value.busy)
            assertNull(h.controller.state.value.errorCode)
        }
    }

    @Test fun latePickerResultAfterFileSwitchIsIgnored() = runBlocking {
        Harness(this).use { h ->
            assertTrue(h.controller.beginSelection())
            h.controller.invalidate(); h.sessionGeneration++; h.targetId = "capture-b"
            var opened = false
            h.controller.selected { opened = true; line.byteInputStream() }
            assertFalse(opened)
            assertEquals(0, h.nativeCalls)
        }
    }

    @Test fun changedGenerationWhilePickerIsOpenIsRejected() = runBlocking {
        Harness(this).use { h ->
            assertTrue(h.controller.beginSelection())
            h.gate.publish(h.currentAnalysis().copy(revision = 2))
            h.controller.selected { line.byteInputStream() }
            assertEquals("STALE_GENERATION", h.controller.state.value.errorCode)
            assertEquals(0, h.nativeCalls)
        }
    }

    @Test fun providerErrorIsRedactedAndInputIsClosed() = runBlocking {
        Harness(this).use { h ->
            var closed = false
            assertTrue(h.controller.beginSelection())
            h.controller.selected { object : InputStream() {
                override fun read(): Int = throw IOException("SECRET path")
                override fun close() { closed = true }
            } }
            h.done()
            assertTrue(closed)
            assertEquals(KeyLogParseErrorCode.IO_ERROR, h.controller.state.value.parseError?.code)
            assertFalse(h.controller.state.value.toString().contains("SECRET"))
        }
    }

    @Test fun cancelledAfterAcquireReleasesUnconfiguredLease() = runBlocking {
        Harness(this).use { h ->
            h.afterAcquire = { h.controller.cancel() }
            h.select(line); h.done()
            assertEquals(0, h.leaseCount())
            assertEquals(0, h.nativeCalls)
            assertTrue(h.controller.state.value.cancelled)
            assertTrue(h.currentAnalysis().ready)
        }
    }

    @Test fun cancellingRedissectionClosesNativeBeforeReleasingLease() = runBlocking {
        Harness(this).use { h ->
            h.onFrame = { h.controller.cancel() }
            h.select(line); h.done()
            assertEquals(0, h.currentAnalysis().sessionHandle)
            assertNull(h.nativePath)
            assertEquals(0, h.leaseCount())
            assertTrue(h.controller.state.value.cancelled)
            assertTrue(h.controller.state.value.reopenRequired)
        }
    }

    @Test fun cancellingRedissectionPublishesIdleAfterDispatchedCleanup() = runBlocking {
        java.util.concurrent.Executors.newSingleThreadExecutor().asCoroutineDispatcher().use { io ->
            Harness(this, io).use { h ->
                h.onFrame = { h.controller.cancel() }
                h.select(line)
                h.done()
                assertEquals(TlsKeyLogImportPhase.Idle, h.controller.state.value.phase)
                assertTrue(h.controller.state.value.cancelled)
                assertTrue(h.controller.state.value.reopenRequired)
                assertEquals(0, h.currentAnalysis().sessionHandle)
                assertEquals(0, h.leaseCount())
            }
        }
    }

    @Test fun unsupportedNativeReasonSurvivesTransactionAndUi() = runBlocking {
        Harness(this).use { h ->
            h.failure = "UNSUPPORTED"
            h.select(line); h.done()
            assertEquals("UNSUPPORTED", h.controller.state.value.errorCode)
            assertTrue(h.controller.state.value.reopenRequired)
            assertEquals(0, h.leaseCount())
            assertFalse(h.controller.state.value.configured)
        }
    }

    @Test fun invalidatedInFlightOperationCannotPublishIntoNextFile() = runBlocking {
        Harness(this).use { h ->
            val entered = CompletableDeferred<Unit>()
            h.beforeConfigure = { entered.complete(Unit); awaitCancellation() }
            h.select(line)
            entered.await()
            h.controller.invalidate()
            h.sessionGeneration++; h.targetId = "capture-b"
            delay(20)
            assertEquals(TlsKeyLogImportState(), h.controller.state.value)
            assertEquals(0, h.nativeCalls)
            assertEquals(0, h.leaseCount())
        }
    }

    @Test fun aNewAnalysisRevisionResetsObservedPlaintext() = runBlocking {
        Harness(this).use { h ->
            h.observation = true
            h.select(line); h.done()
            assertTrue(h.controller.state.value.observedDecryptedData)
            // The totals belong to the revision that produced them.
            assertEquals(2, h.controller.state.value.plaintextStats.tls13Connections)
            h.controller.syncAnalysis(h.currentAnalysis().copy(revision = 99))
            assertFalse(h.controller.state.value.observedDecryptedData)
            assertEquals(TlsPlaintextStats.EMPTY, h.controller.state.value.plaintextStats)
        }
    }

    /** Opening a capture with retained secrets never runs an import job; it still must report. */
    @Test fun openPathObservationDoesNotNeedAnImport() = runBlocking {
        Harness(this).use { h ->
            h.observation = true
            h.select(line); h.done()
            val revision = h.currentAnalysis()
            assertTrue(h.controller.state.value.observedDecryptedData)
            h.controller.invalidate()
            assertFalse(h.controller.state.value.observedDecryptedData)
            h.controller.recordObservation(revision, h.reportedPlaintext())
            assertTrue(h.controller.state.value.observedDecryptedData)
            assertTrue(h.controller.state.value.configured)
            // P2-3: the page can answer "how many connections, under which version".
            assertEquals(3, h.controller.state.value.plaintextStats.connections)
            assertEquals(1, h.controller.state.value.plaintextStats.tls12Connections)
        }
    }

    @Test fun observationOfAStaleRevisionNeverClaimsPlaintext() = runBlocking {
        Harness(this).use { h ->
            h.observation = true
            h.select(line); h.done()
            val revision = h.currentAnalysis()
            h.controller.invalidate()
            h.controller.recordObservation(
                revision.copy(revision = revision.revision - 1), h.reportedPlaintext()
            )
            assertFalse(h.controller.state.value.observedDecryptedData)
            assertEquals(TlsPlaintextStats.EMPTY, h.controller.state.value.plaintextStats)
            // State is resynchronised from the authoritative revision, not the stale report.
            assertTrue(h.controller.state.value.configured)
            h.controller.recordObservation(revision, TlsPlaintextStats.EMPTY)
            assertFalse(h.controller.state.value.observedDecryptedData)
            assertEquals(TlsPlaintextStats.EMPTY, h.controller.state.value.plaintextStats)
        }
    }

    @Test fun secondActionCannotStartDuringRedissection() = runBlocking {
        Harness(this).use { h ->
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            h.beforeConfigure = { entered.complete(Unit); release.await() }
            h.select(line); entered.await()
            assertFalse(h.controller.beginSelection())
            h.controller.clear()
            release.complete(Unit); h.done()
            assertEquals(1, h.nativeCalls)
        }
    }
}
