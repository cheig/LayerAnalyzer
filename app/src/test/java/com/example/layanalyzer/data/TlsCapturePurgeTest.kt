// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.RawPcapWriter
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.model.*
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.UUID
import javax.crypto.KeyGenerator
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Synthetic PCAP records and NSS lines only; no captured private traffic. */
class TlsCapturePurgeTest {
    @get:Rule val temporary = TemporaryFolder()
    private val files get() = File(temporary.root, "files").apply { mkdirs() }
    private val privateDir get() = File(temporary.root, "private").apply { mkdirs() }
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private var keyAvailable = true
    private val provider = AesGcmTlsWrappingKeyProvider {
        if (!keyAvailable) throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
        key
    }
    private val secrets get() = TlsSecretStore(privateDir, provider)
    private val artifacts get() = CaptureArtifactRepository(File(files, "captures"))
    private val lifecycle get() = CaptureArtifactLifecycle(files, privateDir, secrets)
    private val line = "CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}"
    private fun parsed() = KeyLogParser.parse(line.byteInputStream()) as KeyLogParseResult.Success
    private fun pcap(): ByteArray = ByteArrayOutputStream().also { output ->
        RawPcapWriter(output).use { writer -> writer.writeHeader(); writer.writePacket(1234, byteArrayOf(1, 2, 3), 3) }
    }.toByteArray()
    private fun make(id: String = "capture-a", transient: Boolean = false, finalized: Boolean = true): TlsSecretAssetRef {
        val directory = artifacts.captureDirectory(id).apply { mkdirs() }
        File(directory, "packets.pcap").writeBytes(pcap())
        val ref = secrets.importRecords(id, parsed())
        val manifest = CaptureArtifactManifest(id, segments = listOf(CaptureSegmentRef("packets.pcap", 1, 1)),
            secretsPersistedSequence = ref.watermark.sequence,
            retentionPolicy = if (transient) CaptureRetentionPolicy.KeepCaptureTransientSecrets else CaptureRetentionPolicy.KeepCaptureAndSecrets,
            tls = CaptureTlsAssets(enabled = true, secretsAssetId = ref.assetId, complete = true), complete = true)
        if (finalized) artifacts.commit(manifest) else artifacts.writeUnfinalized(manifest)
        return ref
    }
    private fun encrypted(ref: TlsSecretAssetRef) = File(privateDir, "capture-secrets/${ref.captureId}/${ref.assetId}/downstream.keys.enc")
    private fun state(id: String = "capture-a") = (artifacts.read(id) as CaptureArtifactState.Present).manifest
    private fun expect(code: TlsAssetErrorCode, block: () -> Unit) {
        try { block(); fail("Expected $code") } catch (error: TlsAssetException) { assertEquals(code, error.code) }
    }

    @Test fun explicitIntegrityShareCopiesOnlyTheReportAndCaptureDeletionRemovesTheCopy() {
        make(); val other = make("capture-b")
        val capture = File(artifacts.captureDirectory("capture-a"), "packets.pcap")
        val report = File(capture.parentFile, "${capture.name}.report.json").apply { writeText("{\"complete\":true}") }
        val journal = File(capture.parentFile, "tls-connections.jsonl").apply { writeText("private connection metadata") }
        val exported = lifecycle.exportIntegrityReport(capture)
        assertEquals(report.readText(), exported.readText())
        assertEquals(listOf(report.name), exported.parentFile!!.list()!!.toList())
        assertEquals("private connection metadata", journal.readText())
        lifecycle.purge("capture-a")
        assertFalse(exported.exists())
        assertFalse(journal.exists())
        assertEquals(other, secrets.currentAsset("capture-b"))
    }

    @Test fun reportSharingRejectsSecretsAndOversizedReportsBeforeCreatingExports() {
        make()
        val capture = File(artifacts.captureDirectory("capture-a"), "packets.pcap")
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) {
            lifecycle.exportIntegrityReport(File(privateDir, "capture-secrets/keys.enc"))
        }
        File(capture.parentFile, "${capture.name}.report.json").writeBytes(ByteArray(256 * 1024 + 1))
        expect(TlsAssetErrorCode.CAPACITY_EXCEEDED) { lifecycle.exportIntegrityReport(capture) }
        assertFalse(File(files, "exports").exists())
    }

    @Test fun deletionIsIdempotentAndLeavesOtherCaptureAndCaIntact() {
        make(); val other = make("capture-b")
        File(artifacts.captureDirectory("capture-a"), "merged-analysis.pcap").writeBytes(pcap())
        val export = File(lifecycle.exportDirectory(artifacts.analysisFile("capture-a")), "tls-stream.bin").apply { writeText("synthetic body") }
        val ca = File(privateDir, "tls-ca/test-ca").apply { mkdirs() }
        File(ca, "wrapped-data-key").writeText("synthetic CA marker")
        repeat(2) { lifecycle.purge("capture-a") }
        assertFalse(artifacts.captureDirectory("capture-a").exists())
        assertFalse(File(privateDir, "capture-secrets/capture-a").exists())
        assertFalse(export.exists())
        assertEquals(other, secrets.currentAsset("capture-b"))
        assertTrue(File(ca, "wrapped-data-key").exists())
        val event = lifecycle.cleanupEvents().single()
        assertEquals("capture-a", event.captureId); assertEquals(CaptureCleanupReason.Deleted, event.reason)
        assertTrue(event.completed)
        assertEquals(setOf(CaptureFingerprintCalculator().calculate(File(artifacts.captureDirectory("capture-b"), "packets.pcap"))), event.captureFingerprints)
    }

    @Test fun nativeAndLeaseOwnershipMustBothEndBeforePurge() {
        make()
        val native = CaptureFileAccess.retain(artifacts.analysisFile("capture-a"))
        val lease = secrets.acquireLease("capture-a")
        var nativeCleared = false
        lease.configureNative({ nativeCleared = true }) { }
        expect(TlsAssetErrorCode.IN_USE) { lifecycle.purge("capture-a") }
        native.close()
        expect(TlsAssetErrorCode.IN_USE) { lifecycle.purge("capture-a") }
        assertTrue(lifecycle.cleanupEvents().isEmpty())
        lease.close()
        assertTrue(nativeCleared)
        lifecycle.purge("capture-a")
        assertTrue(File(privateDir, "tls-analysis-leases").listFiles()!!.isEmpty())
    }

    @Test fun failedNativeCleanupKeepsAssetsAndCanBeRetried() {
        make()
        val lease = secrets.acquireLease("capture-a")
        var failClear = true
        lease.configureNative({ if (failClear) error("synthetic") }) { }
        expect(TlsAssetErrorCode.NATIVE_CLEANUP_FAILED) { lease.close() }
        expect(TlsAssetErrorCode.IN_USE) { lifecycle.purge("capture-a") }
        failClear = false
        lease.close()
        lifecycle.purge("capture-a")
    }

    @Test fun lostKeystoreStillAllowsDeletionWithoutAffectingOtherCapture() {
        make(); make("capture-b")
        keyAvailable = false
        lifecycle.purge("capture-a")
        assertTrue(artifacts.manifestFile("capture-b").exists())
        keyAvailable = true
        secrets.acquireLease("capture-b").close()
    }

    @Test fun transientCloseDeletesSecretsAndDerivedFilesButPreservesOriginalBytes() {
        make(transient = true)
        val merged = artifacts.openForAnalysis("capture-a") as CaptureAnalysisSource.Merged
        val original = File(artifacts.captureDirectory("capture-a"), "packets.pcap")
        val bytes = original.readBytes()
        val exported = File(lifecycle.exportDirectory(merged.analysisFile), "stream.txt").apply { writeText("synthetic") }
        secrets.acquireLease("capture-a").use { lease -> lease.configureNative({ }) { } }
        lifecycle.analysisClosed(merged.analysisFile)
        assertArrayEquals(bytes, original.readBytes())
        assertFalse(merged.analysisFile.exists()); assertFalse(exported.exists())
        assertNull(secrets.currentAsset("capture-a"))
        assertFalse(state().tls.complete); assertNull(state().tls.secretsAssetId)
        expect(TlsAssetErrorCode.NOT_FOUND) { secrets.acquireLease("capture-a") }
        assertTrue(artifacts.openForAnalysis("capture-a") is CaptureAnalysisSource.Merged)
    }

    @Test fun retainedCloseDoesNotRemoveKeysOrPcap() {
        val ref = make()
        lifecycle.analysisClosed(artifacts.analysisFile("capture-a"))
        assertEquals(ref, secrets.currentAsset("capture-a")); assertTrue(state().tls.complete)
    }

    @Test fun transientExpiryWaitsForAnExportLeaseAndRunsWhenItCloses() {
        make(transient = true)
        val lease = secrets.acquireLease("capture-a")
        lifecycle.analysisClosed(artifacts.analysisFile("capture-a"))
        assertFalse(lifecycle.cleanupEvents().single().completed)
        assertNotNull(secrets.currentAsset("capture-a"))
        lease.close()
        assertNull(secrets.currentAsset("capture-a"))
        assertTrue(lifecycle.cleanupEvents().single().completed)
    }

    @Test fun aRedirectedCaptureDirectoryCannotDeleteAnotherCapture() {
        make("capture-b")
        val target = artifacts.captureDirectory("capture-b")
        val link = File(target.parentFile, "capture-a")
        if (System.getProperty("os.name").orEmpty().startsWith("Windows")) {
            val process = ProcessBuilder("cmd.exe", "/c", "mklink", "/J", link.path, target.path)
                .redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            assertEquals(output, 0, process.waitFor())
        } else Files.createSymbolicLink(link.toPath(), target.toPath())
        try {
            expect(TlsAssetErrorCode.INVALID_ARGUMENT) { lifecycle.purge("capture-a") }
            assertTrue(state("capture-b").complete)
        } finally { Files.delete(link.toPath()) }
    }

    @Test fun startupExpiresTransientCaptureEvenWhenItWasFinalized() {
        make(transient = true)
        assertTrue(lifecycle.recoverAtStartup().all { it.errorCode == null })
        assertNull(secrets.currentAsset("capture-a")); assertTrue(artifacts.manifestFile("capture-a").exists())
    }

    @Test fun recoveryTrimsOnlyPartialPacketAndAuthenticatedSecretTail() {
        val ref = make(finalized = false)
        val packet = File(artifacts.captureDirectory("capture-a"), "packets.pcap")
        val original = packet.readBytes()
        packet.appendBytes(byteArrayOf(0, 1, 2))
        encrypted(ref).appendBytes(byteArrayOf(0, 0))
        repeat(2) { assertTrue(lifecycle.recoverAtStartup().all { it.errorCode == null }) }
        assertArrayEquals(original, packet.readBytes())
        assertEquals(ref.watermark.fileBytes, encrypted(ref).length())
        assertTrue(state().interrupted); assertFalse(state().complete); assertFalse(state().tls.complete)
        assertEquals(1L, state().segments.single().frameCount)
        secrets.acquireLease("capture-a").close()
    }

    @Test fun unpublishedLiveAssetIsRecoveredByAuthenticatingItsLocalIdentity() {
        val ref = make(finalized = false)
        File(privateDir, "capture-secrets/capture-a/current.json").delete()
        assertTrue(lifecycle.recoverAtStartup().all { it.errorCode == null })
        assertEquals(ref, secrets.currentAsset("capture-a")); assertFalse(state().tls.complete)
    }

    @Test fun completeTagCorruptionIsNotTreatedAsAnIncompleteTail() {
        val ref = make(finalized = false)
        val encrypted = encrypted(ref)
        RandomAccessFile(encrypted, "rw").use { file ->
            file.seek(file.length() - 1); val value = file.read(); file.seek(file.length() - 1); file.write(value xor 1)
        }
        val bad = encrypted.readBytes()
        assertEquals(TlsAssetErrorCode.AUTHENTICATION_FAILED, lifecycle.recoverAtStartup().single().errorCode)
        assertArrayEquals(bad, encrypted.readBytes())
        assertTrue(state().interrupted); assertFalse(state().tls.complete)
    }

    @Test fun keystoreLossDuringRecoveryKeepsOtherCaptureRecoverable() {
        make(finalized = false); make("capture-b")
        keyAvailable = false
        assertEquals(TlsAssetErrorCode.KEY_UNAVAILABLE, lifecycle.recoverAtStartup().first { it.captureId == "capture-a" }.errorCode)
        assertTrue(state().interrupted); assertTrue(state("capture-b").complete)
        keyAvailable = true
        secrets.acquireLease("capture-b").close()
    }

    @Test fun invalidCompletePcapRecordIsNotTrimmed() {
        make(finalized = false)
        val packet = File(artifacts.captureDirectory("capture-a"), "packets.pcap")
        val bytes = packet.readBytes().also { it[32] = 0x7f } // incl_len > orig_len
        packet.writeBytes(bytes)
        assertEquals(TlsAssetErrorCode.INVALID_FORMAT, lifecycle.recoverAtStartup().single().errorCode)
        assertArrayEquals(bytes, packet.readBytes()); assertTrue(state().interrupted)
    }

    @Test fun activeWriterIsNotRecoveredOrPurgedAndStopPreservesIncomplete() {
        make(finalized = false)
        LiveCaptureStore.installArtifactRepository(artifacts)
        try {
            LiveCaptureStore.start(File(artifacts.captureDirectory("capture-a"), "packets.pcap").path,
                LiveCaptureManifestConfig("capture-a"))
            assertEquals(TlsAssetErrorCode.IN_USE, lifecycle.recoverAtStartup().single().errorCode)
            assertFalse(state().interrupted)
            expect(TlsAssetErrorCode.IN_USE) { lifecycle.purge("capture-a") }
            LiveCaptureStore.recordIoError("synthetic write failure")
            LiveCaptureStore.stop(); LiveCaptureStore.stop()
            assertTrue(LiveCaptureStore.state.value.incomplete); assertFalse(state().complete)
        } finally { LiveCaptureStore.stop(); LiveCaptureStore.installArtifactRepository(null) }
    }

    @Test fun startupSweepsOnlyOrphanPlaintextAndWorkspaces() {
        make()
        val orphan = File(privateDir, "tls-analysis-leases/${UUID.randomUUID()}").apply { mkdirs() }
        File(orphan, "keylog.tmp").writeText(line)
        val workspaceRoot = File(privateDir, "tls-bundle-work").apply { mkdirs() }
        val stale = File(workspaceRoot, "operation-orphan").apply { mkdirs() }
        File(stale, "keys.log").writeText(line)
        secrets.acquireLease("capture-a").use { lease ->
            val plaintext = lease.configureNative({ }) { File(it) }
            TlsBundleWorkspaces.use(workspaceRoot) { active ->
                val activePlaintext = File(active, "keys.log").apply { writeText(line) }
                lifecycle.recoverAtStartup()
                assertTrue(plaintext.exists()); assertTrue(activePlaintext.exists())
                assertFalse(orphan.exists()); assertFalse(stale.exists())
            }
        }
        assertTrue(workspaceRoot.listFiles()!!.isEmpty())
    }

    @Test fun failedDeletionIntentIsRetriedAtStartup() {
        make()
        val failing = CaptureArtifactLifecycle(files, privateDir, secrets) { _, _, _ -> throw java.io.IOException("synthetic") }
        try { failing.purge("capture-a"); fail() } catch (_: java.io.IOException) { }
        assertFalse(lifecycle.cleanupEvents().single().completed)
        assertTrue(artifacts.manifestFile("capture-a").exists())
        lifecycle.recoverAtStartup()
        assertTrue(lifecycle.cleanupEvents().single().completed)
        assertFalse(artifacts.manifestFile("capture-a").exists())
    }

    @Test fun invalidIdsAndUnrelatedPathsCannotBeDeleted() {
        make("capture-b")
        for (id in listOf("../capture-b", "a/b", "a\\b", "", ".", "C:drive"))
            expect(TlsAssetErrorCode.INVALID_ARGUMENT) { lifecycle.purge(id) }
        val outside = File(files, "unrelated.pcap").apply { writeBytes(pcap()) }
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) { lifecycle.purgeFile(outside) }
        assertTrue(outside.exists()); assertTrue(state("capture-b").complete)
    }

    @Test fun malformedCleanupIntentDoesNotDeleteItsClaimedCaptureOrBlockOtherRecovery() {
        make("capture-b", finalized = false)
        val journal = File(privateDir, "capture-cleanup-events").apply { mkdirs() }
        File(journal, "capture-a.json").writeText("""{"schemaVersion":1,"captureId":"capture-b","reason":"Deleted","completed":false,"legacyName":null}""")
        val results = lifecycle.recoverAtStartup()
        assertEquals(TlsAssetErrorCode.INVALID_FORMAT, results.first { it.captureId == "capture-a" }.errorCode)
        assertNull(results.first { it.captureId == "capture-b" }.errorCode)
        assertTrue(state("capture-b").interrupted)
    }

    @Test fun startupMigratesOldFlatPlaintextCachesWithoutRemovingScopedExports() {
        make("capture-b")
        val root = File(files, "exports").apply { mkdirs() }
        val legacy = File(root, "tls-stream-1-1.bin").apply { writeText("synthetic body") }
        val scoped = File(lifecycle.exportDirectory(artifacts.analysisFile("capture-b")), "tls-stream-1-1.bin")
            .apply { writeText("synthetic body") }
        lifecycle.recoverAtStartup()
        assertFalse(legacy.exists()); assertTrue(scoped.exists())
    }

    @Test fun legacyDeletionUsesTheSameIdentityAsManualSecretImport() {
        val capture = File(File(files, "captures").apply { mkdirs() }, "legacy.pcap").apply { writeBytes(pcap()) }
        val id = lifecycle.identityForFile(capture)
        secrets.importRecords(id, parsed())
        File(lifecycle.exportDirectory(capture), "stream.bin").writeText("synthetic")
        repeat(2) { lifecycle.purgeFile(capture) }
        assertFalse(capture.exists()); assertNull(secrets.currentAsset(id))
    }

    @Test fun multipleAnalysisOwnersCannotReleaseEachOthersProtection() {
        make()
        val a = CaptureFileAccess.retain(artifacts.analysisFile("capture-a"))
        val b = CaptureFileAccess.retain(artifacts.analysisFile("capture-a"))
        a.close(); a.close()
        expect(TlsAssetErrorCode.IN_USE) { lifecycle.purge("capture-a") }
        b.close(); lifecycle.purge("capture-a")
    }

    private fun quotaUsage(): Long = File(files, "captures").walkTopDown()
        .filter { it.isFile }.sumOf { it.length() }

    @Test fun quotaCountsCaptureDirectoriesAndPurgesTheirAssociatedAssets() {
        make()
        val directory = artifacts.captureDirectory("capture-a")
        File(directory, "second.pcap").writeBytes(pcap())
        File(directory, "merged-analysis.pcap").writeBytes(pcap())
        File(directory, "capture.pcap.report.json").writeText("{}")
        val export = File(lifecycle.exportDirectory(artifacts.analysisFile("capture-a")), "stream.bin")
            .apply { writeText("synthetic body") }

        assertTrue(lifecycle.enforceQuota(quotaUsage(), 1, emptyList()))

        assertFalse(directory.exists())
        assertNull(secrets.currentAsset("capture-a"))
        assertFalse(export.exists())
        assertTrue(lifecycle.cleanupEvents().single().completed)
    }

    @Test fun quotaProtectsTheWholeCaptureForAnOriginalOrMergedPath() {
        make()
        val directory = artifacts.captureDirectory("capture-a")
        val merged = File(directory, "merged-analysis.pcap").apply { writeBytes(pcap()) }
        val paths = listOf(File(directory, "packets.pcap"), merged, directory)

        paths.forEach { path ->
            assertFalse(lifecycle.enforceQuota(quotaUsage(), 1, listOf(path)))
            assertTrue(directory.exists())
            assertTrue(lifecycle.cleanupEvents().isEmpty())
        }
    }

    @Test fun quotaSkipsAnActiveSecretLeaseAndPurgesTheNextOldestCapture() {
        make("capture-a")
        make("capture-b")
        val first = artifacts.captureDirectory("capture-a")
        val second = artifacts.captureDirectory("capture-b")
        assertTrue(first.setLastModified(1000L))
        assertTrue(second.setLastModified(2000L))

        secrets.acquireLease("capture-a").use {
            assertTrue(lifecycle.enforceQuota(quotaUsage(), 1, emptyList()))
            assertTrue(first.exists())
            assertFalse(second.exists())
        }
        assertNotNull(secrets.currentAsset("capture-a"))
    }

    @Test fun quotaCannotReclaimAnActiveCaptureDirectory() {
        make()
        CaptureFileAccess.retain(artifacts.analysisFile("capture-a")).use {
            assertFalse(lifecycle.enforceQuota(quotaUsage(), 1, emptyList()))
            assertTrue(artifacts.manifestFile("capture-a").exists())
        }
        assertTrue(lifecycle.enforceQuota(quotaUsage(), 1, emptyList()))
        assertFalse(artifacts.captureDirectory("capture-a").exists())
    }

    @Test fun quotaKeepsFailedCleanupCounted() {
        make()
        val failing = CaptureArtifactLifecycle(files, privateDir, secrets) { _, _, _ ->
            throw java.io.IOException("synthetic cleanup failure")
        }

        assertFalse(failing.enforceQuota(quotaUsage(), 1, emptyList()))

        assertTrue(artifacts.manifestFile("capture-a").exists())
        assertNotNull(secrets.currentAsset("capture-a"))
    }

    @Test fun quotaCountsRemovedLegacyReportsBeforeEvictingAnotherCapture() {
        val root = File(files, "captures").apply { mkdirs() }
        val first = File(root, "first.pcap").apply { writeBytes(pcap()) }
        val report = File(root, "first.pcap.report.json").apply { writeText("{}") }
        val second = File(root, "second.pcapng").apply { writeBytes(pcap()) }
        assertTrue(first.setLastModified(1000L))
        assertTrue(second.setLastModified(2000L))

        assertTrue(lifecycle.enforceQuota(second.length() + 1, 1, emptyList()))

        assertFalse(first.exists())
        assertFalse(report.exists())
        assertTrue(second.exists())
    }

    @Test fun quotaCountsButDoesNotPurgePartialImportsOrUnrelatedFiles() {
        val root = File(files, "captures").apply { mkdirs() }
        val partial = File(root, "capture.partial").apply { writeBytes(pcap()) }
        val unrelated = File(root, "notes.txt").apply { writeText("preserve") }

        assertFalse(lifecycle.enforceQuota(0, 0, emptyList()))

        assertTrue(partial.exists())
        assertTrue(unrelated.exists())
    }

    @Test fun oversizedImportDoesNotEvictExistingCaptures() {
        val root = File(files, "captures").apply { mkdirs() }
        val legacy = File(root, "legacy.pcap").apply { writeBytes(pcap()) }

        assertFalse(lifecycle.enforceQuota(100, 101, emptyList()))

        assertTrue(legacy.exists())
    }
}
