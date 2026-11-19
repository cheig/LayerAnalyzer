// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.data.TlsAnalysisSecretLease
import com.example.layanalyzer.data.withTlsAnalysisLease
import kotlinx.coroutines.*
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.Executors
import javax.crypto.KeyGenerator
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Synthetic in-memory NSS data, unrelated to real traffic or a shipped PCAP. */
class TlsSecretStoreTest {
    @get:Rule val temporary = TemporaryFolder()
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private var available = true
    private val provider = AesGcmTlsWrappingKeyProvider {
        if (!available) throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
        key
    }
    private val firstLine = "CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}"
    private val secondLine = "CLIENT_TRAFFIC_SECRET_0 ${"ef".repeat(32)} ${"12".repeat(32)}"
    private val leaseRoot get() = File(temporary.root, "tls-analysis-leases")
    private fun store(limits: TlsSecretStoreLimits = TlsSecretStoreLimits()) = TlsSecretStore(temporary.root, provider, limits)
    private fun parsed(text: String = firstLine) = KeyLogParser.parse(text.byteInputStream()) as KeyLogParseResult.Success
    private fun capture(id: String = "capture-a") = File(temporary.root, "capture-secrets/$id")
    private fun asset(ref: TlsSecretAssetRef) = File(capture(ref.captureId), ref.assetId)
    private fun index(id: String = "capture-a") = File(capture(id), "current.json")
    private fun leaseFiles() = leaseRoot.listFiles().orEmpty().toList()
    private fun TlsAnalysisSecretLease.file(cleanup: () -> Unit = {}): File = configureNative(cleanup) { File(it) }

    @Test fun parserStoreLeaseRoundTripAndReopen() {
        val store = store()
        val ref = store.importRecords("capture-a", parsed("# ignored\n$firstLine\r\n$firstLine\n$secondLine"))
        assertEquals(2L, ref.watermark.sequence)
        assertEquals(ref.watermark.plaintextBytes + 2, ref.keyLogBytes)
        assertEquals(ref, store().currentAsset("capture-a"))
        repeat(3) {
            val lease = store().acquireLease("capture-a", ref.assetId)
            val file = lease.file()
            assertEquals("$firstLine\n$secondLine\n", file.readText())
            assertTrue(file.canonicalPath.startsWith(leaseRoot.canonicalPath + File.separator))
            lease.close()
            lease.close()
            assertFalse(file.exists())
            assertTrue(leaseFiles().isEmpty())
        }
        assertFalse(File(asset(ref), "downstream.keys.enc").readBytes().toString(Charsets.ISO_8859_1).contains(firstLine))
        assertFalse(index().readText().contains("cd".repeat(48)))
    }

    @Test fun replacementUsesNewAssetAndKeyWhileExistingLeaseKeepsSnapshot() {
        val store = store()
        val first = store.importRecords("capture-a", parsed())
        val key1 = File(asset(first), "wrapped-data-key").readBytes()
        val oldLease = store.acquireLease("capture-a", first.assetId)
        val oldFile = oldLease.file()
        try {
            val second = store.importRecords("capture-a", parsed(secondLine))
            assertNotEquals(first.assetId, second.assetId)
            assertFalse(key1.contentEquals(File(asset(second), "wrapped-data-key").readBytes()))
            assertFalse(asset(first).exists())
            assertEquals("$firstLine\n", oldFile.readText())
            store.acquireLease("capture-a", second.assetId).use { assertEquals("$secondLine\n", it.file().readText()) }
            expect(TlsAssetErrorCode.BINDING_MISMATCH) { store.acquireLease("capture-a", first.assetId) }
        } finally { oldLease.close() }
    }

    @Test fun manualAnalysisImportPreservesRetainedAssetAndReopensOriginalKeys() {
        val store = store()
        val original = store.importRecords("capture-a", parsed())
        val indexBefore = index().readBytes()
        store.acquireLease("capture-a", original.assetId).use { existing ->
            store.acquireImportedLease("capture-a", parsed(secondLine)).use { imported ->
                assertEquals("$secondLine\n", imported.file().readText())
                assertEquals("$firstLine\n", existing.file().readText())
                assertArrayEquals(indexBefore, index().readBytes())
                assertTrue(asset(original).exists())
                assertEquals(original, store.currentAsset("capture-a"))
            }
        }
        // Same ID the existing VPN manifest names remains resolvable after close/reopen.
        store().acquireLease("capture-a", original.assetId).use {
            assertEquals("$firstLine\n", it.file().readText())
        }
        assertTrue(leaseFiles().isEmpty())
    }

    @Test fun manualAnalysisWithoutRetainedKeysPublishesNoAssetAndReleasesCapacity() {
        val store = store()
        repeat(4) {
            store.acquireImportedLease("capture-a", parsed()).use { lease ->
                assertEquals("$firstLine\n", lease.file().readText())
                assertNull(store.currentAsset("capture-a"))
            }
            assertTrue(leaseFiles().isEmpty())
        }
    }

    @Test fun cancellingAfterLeaseCreationBeforeReturningFromIoDeletesPlaintext() = runBlocking {
        val store = store()
        val original = store.importRecords("capture-a", parsed())
        repeat(4) {
            lateinit var operation: Job
            operation = launch(start = CoroutineStart.LAZY) {
                withTlsAnalysisLease(acquire = { check ->
                    store.acquireLease("capture-a", original.assetId, check).also {
                        // Cancellation exactly after the resource is delivered by storage,
                        // before the IO block can return it to the caller.
                        operation.cancel()
                    }
                }) { lease ->
                    lease.close()
                    fail("Cancelled acquisition must never transfer to native")
                }
            }
            operation.start()
            operation.join()
            assertTrue(operation.isCancelled)
            assertTrue("No live lock or plaintext may survive cancellation", leaseFiles().isEmpty())
        }
        store.acquireLease("capture-a", original.assetId).close()
    }

    @Test fun cancellationCheckInsideRetainedLeaseAcquisitionActuallyThrowsAndCleansUp() = runBlocking {
        val store = store()
        val original = store.importRecords("capture-a", parsed("$firstLine\n$secondLine"))
        lateinit var operation: Job
        operation = launch(start = CoroutineStart.LAZY) {
            withTlsAnalysisLease(acquire = { check ->
                var checks = 0
                store.acquireLease("capture-a", original.assetId) {
                    if (++checks == 3) operation.cancel()
                    check()
                }
            }) { lease -> lease.close(); fail("Cancelled input reached native") }
        }
        operation.start()
        operation.join()
        assertTrue(operation.isCancelled)
        assertTrue(leaseFiles().isEmpty())
        assertEquals(original, store.currentAsset("capture-a"))
    }

    @Test fun incorrectCaptureAndTraversalCannotAccessOtherSecrets() {
        val store = store()
        val ref = store.importRecords("capture-a", parsed())
        assertNull(store.currentAsset("capture-b"))
        expect(TlsAssetErrorCode.NOT_FOUND) { store.acquireLease("capture-b", ref.assetId) }
        for (id in listOf("../capture-a", "a/b", "a\\b", "/capture-a", "C:\\capture-a", ".", "", "a:b")) {
            expect(TlsAssetErrorCode.INVALID_ARGUMENT) { store.currentAsset(id) }
            expect(TlsAssetErrorCode.INVALID_ARGUMENT) { store.importRecords(id, parsed()) }
        }
        assertTrue(leaseFiles().isEmpty())
    }

    @Test fun copiedIndexAndChangedCaptureIdentityCannotReadForeignAsset() {
        val store = store()
        val ref = store.importRecords("capture-a", parsed())
        val b = capture("capture-b").also { it.mkdir() }
        File(b, "current.json").writeBytes(index().readBytes())
        expect(TlsAssetErrorCode.BINDING_MISMATCH) { store.acquireLease("capture-b") }
        File(b, "current.json").writeText(JSONObject(index().readText()).put("captureId", "capture-b").toString())
        val target = File(b, ref.assetId).also { it.mkdir() }
        asset(ref).listFiles()!!.forEach { it.copyTo(File(target, it.name)) }
        expect(TlsAssetErrorCode.BINDING_MISMATCH) { store.acquireLease("capture-b") }
        assertTrue(leaseFiles().isEmpty())
    }

    @Test fun cancelledImportKeepsOldPublicationAndRemovesIncompleteAsset() {
        val store = store()
        val ref = store.importRecords("capture-a", parsed())
        val original = index().readBytes()
        var checks = 0
        cancelled {
            store.importRecords("capture-a", parsed("$firstLine\n$secondLine")) {
                // Beginning, two budget checks, first append, then cancel after a synced record.
                if (++checks == 5) throw CancellationException()
            }
        }
        assertEquals(ref, store.currentAsset("capture-a"))
        assertArrayEquals(original, index().readBytes())
        assertEquals(setOf("current.json", ref.assetId), capture().list()!!.toSet())
    }

    @Test fun wrappingKeyFailureDoesNotReplaceOrDestroyOldAsset() {
        val store = store()
        val ref = store.importRecords("capture-a", parsed())
        val before = index().readBytes()
        available = false
        expect(TlsAssetErrorCode.KEY_UNAVAILABLE) { store.importRecords("capture-a", parsed(secondLine)) }
        expect(TlsAssetErrorCode.KEY_UNAVAILABLE) { store.acquireLease("capture-a") }
        assertArrayEquals(before, index().readBytes())
        assertTrue(asset(ref).exists())
        assertTrue(leaseFiles().isEmpty())
        available = true
        store.acquireLease("capture-a").use { assertEquals("$firstLine\n", it.file().readText()) }
    }

    @Test fun publishedReplacementRemainsSuccessIfOldFileCannotYetBeDeleted() {
        val store = store()
        val old = store.importRecords("capture-a", parsed())
        lateinit var replacement: TlsSecretAssetRef
        // Windows prevents deleting a locked file; POSIX may unlink it immediately.
        // In both cases an already committed replacement must remain a success.
        RandomAccessFile(File(asset(old), "downstream.keys.enc"), "rw").use { handle ->
            handle.channel.lock().use {
                replacement = store.importRecords("capture-a", parsed(secondLine))
                assertEquals(replacement.assetId, JSONObject(index().readText()).getString("assetId"))
            }
        }
        store.cleanupOrphans()
        assertFalse(asset(old).exists())
        store.acquireLease("capture-a", replacement.assetId).use { assertEquals("$secondLine\n", it.file().readText()) }
    }

    @Test fun leaseOutputAndActiveCountHaveIndependentBudgets() {
        val store = store(TlsSecretStoreLimits(firstLine.length + 1L))
        val ref = store.importRecords("capture-a", parsed())
        expect(TlsAssetErrorCode.CAPACITY_EXCEEDED) { store.importRecords("capture-a", parsed("$firstLine\n$secondLine")) }
        assertEquals(ref, store.currentAsset("capture-a"))
        expect(TlsAssetErrorCode.CAPACITY_EXCEEDED) {
            store(TlsSecretStoreLimits(firstLine.length.toLong())).acquireLease("capture-a")
        }
        val a = store.acquireLease("capture-a")
        val b = store().acquireLease("capture-a")
        try {
            expect(TlsAssetErrorCode.CAPACITY_EXCEEDED) { store().acquireLease("capture-a") }
            a.close()
            store().acquireLease("capture-a").close()
        } finally { a.close(); b.close() }
        assertTrue(leaseFiles().isEmpty())
    }

    @Test fun cancellationDuringDecryptDeletesPartialPlaintext() {
        val store = store()
        store.importRecords("capture-a", parsed("$firstLine\n$secondLine"))
        var checks = 0
        cancelled {
            store.acquireLease("capture-a") {
                if (++checks == 4) throw CancellationException()
            }
        }
        assertEquals(4, checks)
        assertTrue(leaseFiles().isEmpty())
        store.acquireLease("capture-a").close()
    }

    @Test fun ioErrorDuringDecryptIsSanitizedAndLeavesNoPlaintext() {
        val store = store()
        store.importRecords("capture-a", parsed())
        var checks = 0
        val error = expect(TlsAssetErrorCode.IO_ERROR) {
            store.acquireLease("capture-a") { if (++checks == 3) throw IOException(firstLine) }
        }
        assertNull(error.cause)
        assertFalse(error.toString().contains(firstLine))
        assertTrue(leaseFiles().isEmpty())
    }

    @Test fun cleanupRunsBeforeFileDeletionAndFailureKeepsLeaseForRetry() {
        val store = store()
        store.importRecords("capture-a", parsed())
        val lease = store.acquireLease("capture-a")
        lateinit var file: File
        var clears = 0
        file = lease.file {
            assertTrue(file.exists())
            if (++clears == 1) throw IOException(firstLine)
        }
        expect(TlsAssetErrorCode.NATIVE_CLEANUP_FAILED) { lease.close() }
        assertTrue(file.exists())
        assertEquals(0, store().cleanupOrphans())
        lease.close()
        assertEquals(2, clears)
        assertFalse(file.exists())
        lease.close()
        assertEquals(2, clears)
    }

    @Test fun failedNativeConfigureStillRequiresCleanupBeforeDeletingFile() {
        val store = store()
        store.importRecords("capture-a", parsed())
        val lease = store.acquireLease("capture-a")
        var cleared = false
        lateinit var file: File
        cancelled {
            lease.configureNative({ cleared = true; assertTrue(file.exists()) }) {
                file = File(it)
                throw CancellationException()
            }
        }
        assertTrue(file.exists())
        assertFalse(cleared)
        expect(TlsAssetErrorCode.IN_USE) { lease.configureNative({}) {} }
        lease.close()
        assertTrue(cleared)
        assertFalse(file.exists())
        expect(TlsAssetErrorCode.CLOSED) { lease.configureNative({}) {} }
    }

    @Test fun unconfiguredLeaseCanCloseWithoutCallingNative() {
        val store = store()
        store.importRecords("capture-a", parsed())
        val lease = store.acquireLease("capture-a")
        assertEquals(1, leaseFiles().size)
        assertFalse(lease.toString().contains("keylog.tmp"))
        lease.close()
        assertTrue(leaseFiles().isEmpty())
    }

    @Test fun startupSweepDeletesOrphansAndProtectsActiveLeasesFromOtherStoreInstances() {
        val store = store()
        store.importRecords("capture-a", parsed())
        val lease = store.acquireLease("capture-a")
        val liveFile = lease.file()
        try {
            val orphan = File(leaseRoot, UUID.randomUUID().toString()).also { it.mkdir() }
            File(orphan, "keylog.tmp").writeText(firstLine)
            assertEquals(1, store().cleanupOrphans())
            assertFalse(orphan.exists())
            assertTrue(liveFile.exists())
            assertEquals(0, store().cleanupOrphans())
        } finally { lease.close() }
    }

    @Test fun startupSweepUsesLockNotAgeAndRetriesAfterOwnerUnlocks() {
        val store = store()
        store.cleanupOrphans()
        val directory = File(leaseRoot, UUID.randomUUID().toString()).also { it.mkdir() }
        File(directory, "keylog.tmp").writeText(firstLine)
        RandomAccessFile(File(directory, "lease.lock"), "rw").use { handle ->
            handle.channel.lock().use {
                assertEquals(0, store().cleanupOrphans())
                assertTrue(directory.exists())
            }
        }
        assertEquals(1, store().cleanupOrphans())
        assertFalse(directory.exists())
    }

    @Test fun startupRemovesUnpublishedPairAndIndexTemporaryButRetainsPublishedAsset() {
        val store = store()
        val ref = store.importRecords("capture-a", parsed())
        val orphan = File(capture(), UUID.randomUUID().toString()).also { it.mkdir() }
        File(orphan, "downstream.keys.enc").writeBytes(byteArrayOf(1, 2))
        File(capture(), ".index-${UUID.randomUUID()}.tmp").writeText("partial")
        val uncommittedCapture = capture("new-capture").also { it.mkdir() }
        val uncommittedAsset = File(uncommittedCapture, UUID.randomUUID().toString()).also { it.mkdir() }
        File(uncommittedAsset, "wrapped-data-key").writeBytes(byteArrayOf(1))
        store().cleanupOrphans()
        assertFalse(orphan.exists())
        assertFalse(uncommittedAsset.exists())
        assertEquals(setOf("current.json", ref.assetId), capture().list()!!.toSet())
        assertEquals(ref, store().currentAsset("capture-a"))
    }

    @Test fun damagedCiphertextAndMissingKeyNeverProduceLease() {
        val store = store()
        val ref = store.importRecords("capture-a", parsed())
        val encrypted = File(asset(ref), "downstream.keys.enc")
        val original = encrypted.readBytes()
        val damaged = original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        encrypted.writeBytes(damaged)
        expect(TlsAssetErrorCode.AUTHENTICATION_FAILED) { store.acquireLease("capture-a") }
        assertArrayEquals(damaged, encrypted.readBytes())
        assertTrue(leaseFiles().isEmpty())
        encrypted.writeBytes(original)
        File(asset(ref), "wrapped-data-key").delete()
        expect(TlsAssetErrorCode.IO_ERROR) { store.acquireLease("capture-a") }
        assertTrue(leaseFiles().isEmpty())
    }

    @Test fun deletionOfWholeAuthenticatedRecordFailsPersistedWatermarkCheck() {
        val store = store()
        val ref = store.importRecords("capture-a", parsed("$firstLine\n$secondLine"))
        val encrypted = File(asset(ref), "downstream.keys.enc")
        RandomAccessFile(encrypted, "rw").use { file ->
            file.seek(6)
            val headerEnd = 10L + file.readInt()
            file.seek(headerEnd)
            val firstRecordSize = 4L + file.readInt()
            file.setLength(headerEnd + firstRecordSize)
        }
        expect(TlsAssetErrorCode.INVALID_FORMAT) { store.acquireLease("capture-a") }
        assertTrue(leaseFiles().isEmpty())
    }

    @Test fun malformedIndexFailsClosedWithoutDeletingEvidence() {
        val store = store()
        val ref = store.importRecords("capture-a", parsed())
        val original = index().readText()
        val bad = listOf(
            original + " trailing", "x".repeat(2049),
            JSONObject(original).put("assetId", "../elsewhere").toString(),
            JSONObject(original).put("fileBytes", "100").toString(),
            JSONObject(original).put("schemaVersion", 2).toString(),
            JSONObject(original).put("keyLogBytes", 1).toString(),
            JSONObject(original).put("path", "/anything").toString()
        )
        for (text in bad) {
            index().writeText(text)
            expect(TlsAssetErrorCode.INVALID_FORMAT) { store.acquireLease("capture-a") }
            assertTrue(asset(ref).exists())
            assertTrue(leaseFiles().isEmpty())
        }
    }

    @Test fun concurrentStoreInstancesPublishTwoIndependentLeases() {
        val store = store()
        store.importRecords("capture-a", parsed())
        val executor = Executors.newFixedThreadPool(2)
        try {
            val requests = (1..2).map { executor.submit<TlsAnalysisSecretLease> { store().acquireLease("capture-a") } }
            val leases = requests.map { it.get() }
            try {
                val files = leases.map { it.file() }
                assertNotEquals(files[0], files[1])
                files.forEach { assertEquals("$firstLine\n", it.readText()) }
            } finally { leases.forEach { it.close() } }
        } finally { executor.shutdownNow() }
    }

    @Test fun storeRevalidatesInternalRecordValuesAndNeverWritesInjectedLines() {
        val bad = KeyLogRecord(KeyLogLabel.CLIENT_RANDOM, "ab".repeat(32), "cd".repeat(48) + "\n")
        val forged = KeyLogParseResult.Success(listOf(bad), KeyLogParseStats(0, 0, 0, 0, 0))
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) { store().importRecords("capture-a", forged) }
        assertNull(store().currentAsset("capture-a"))
    }

    private fun expect(code: TlsAssetErrorCode, block: () -> Unit): TlsAssetException {
        try { block(); fail("Expected $code") } catch (error: TlsAssetException) {
            assertEquals(code, error.code)
            assertEquals(code.name, error.message)
            assertNull(error.cause)
            return error
        }
        error("unreachable")
    }

    private fun cancelled(block: () -> Unit) {
        try { block(); fail("Expected cancellation") } catch (_: CancellationException) { }
    }
}
