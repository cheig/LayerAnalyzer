// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.*
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.security.KeyStore
import java.util.UUID
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** ARM64 runtime verification with real Android Keystore and the bundled Wireshark. */
@RunWith(AndroidJUnit4::class)
class TlsCaptureRecoveryTest {
    @Before fun ready() { NativeTestSupport.awaitApplicationEngine() }
    @Test fun transientTls12BecomesCiphertextAfterClosingNativeAnalysis() = expire("tls12-h1")
    @Test fun transientTls13BecomesCiphertextAfterClosingNativeAnalysis() = expire("tls13-h1")

    private fun expire(fixtureId: String) = withCapture(fixtureId, transient = true) { fixture, h ->
        val repository = PacketRepository().apply { artifactLifecycle = h.lifecycle }
        try {
            val merged = h.artifacts.openForAnalysis(h.id) as CaptureAnalysisSource.Merged
            repository.openFile(merged.analysisFile.path).getOrThrow()
            assertTrue(repository.applyDecodeAsRule(rule(fixture)).success)
            val lease = h.secrets.acquireLease(h.id)
            assertTrue(repository.configureTlsAnalysis(lease, repository.currentAnalysisRevision(), "", {}, { _, _ -> }).success)
            fixture.assertBody(repository.currentSessionHandle(), true)
            expect(TlsAssetErrorCode.IN_USE) { h.lifecycle.purge(h.id) }
            repository.closeFile()
            assertNull(h.secrets.currentAsset(h.id))
            assertFalse(merged.analysisFile.exists())
            val reopened = h.artifacts.openForAnalysis(h.id) as CaptureAnalysisSource.Merged
            repository.openFile(reopened.analysisFile.path).getOrThrow()
            assertTrue(repository.applyDecodeAsRule(rule(fixture)).success)
            fixture.assertBody(repository.currentSessionHandle(), false)
        } finally { repository.closeFile() }
    }

    @Test fun recoveredAuthenticatedTailStillDecryptsAndRemainsInterrupted() =
        withCapture("tls12-h1", finalized = false) { fixture, h ->
            val original = h.packet.readBytes()
            h.packet.appendBytes(byteArrayOf(0, 1))
            h.encrypted.appendBytes(byteArrayOf(0, 0))
            val orphan = File(h.privateDir, "tls-analysis-leases/${UUID.randomUUID()}").apply { mkdirs() }
            File(orphan, "keylog.tmp").writeText("synthetic orphan")
            assertTrue(h.lifecycle.recoverAtStartup().all { it.errorCode == null })
            assertArrayEquals(original, h.packet.readBytes()); assertFalse(orphan.exists())
            val manifest = (h.artifacts.read(h.id) as CaptureArtifactState.Present).manifest
            assertTrue(manifest.interrupted); assertFalse(manifest.tls.complete); assertFalse(manifest.complete)
            val repository = PacketRepository()
            try {
                val merged = h.artifacts.openForAnalysis(h.id) as CaptureAnalysisSource.Merged
                repository.openFile(merged.analysisFile.path).getOrThrow()
                assertTrue(repository.applyDecodeAsRule(rule(fixture)).success)
                assertTrue(repository.configureTlsAnalysis(h.secrets.acquireLease(h.id),
                    repository.currentAnalysisRevision(), "", {}, { _, _ -> }).success)
                fixture.assertBody(repository.currentSessionHandle(), true)
            } finally { repository.closeFile() }
        }

    @Test fun missingKeystoreAliasDoesNotPreventIdempotentCaptureDeletion() =
        withCapture("tls13-h1", finalized = false) { _, h ->
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(h.alias) }
            assertEquals(TlsAssetErrorCode.KEY_UNAVAILABLE,
                h.lifecycle.recoverAtStartup().single { it.captureId == h.id }.errorCode)
            assertTrue(h.packet.exists())
            repeat(2) { h.lifecycle.purge(h.id) }
            assertFalse(h.packet.exists()); assertNull(h.secrets.currentAsset(h.id))
        }

    @Test fun cancellingRedissectionAlsoExpiresTransientKeysAfterNativeClose() =
        withCapture("tls12-h1", transient = true) { fixture, h ->
            val repository = PacketRepository().apply { artifactLifecycle = h.lifecycle }
            try {
                val merged = h.artifacts.openForAnalysis(h.id) as CaptureAnalysisSource.Merged
                repository.openFile(merged.analysisFile.path).getOrThrow()
                assertTrue(repository.applyDecodeAsRule(rule(fixture)).success)
                var cancel = false
                try {
                    repository.configureTlsAnalysis(h.secrets.acquireLease(h.id), repository.currentAnalysisRevision(), "",
                        { if (cancel) throw java.util.concurrent.CancellationException() },
                        { done, _ -> if (done > 0) cancel = true })
                    fail("Expected cancellation")
                } catch (_: java.util.concurrent.CancellationException) { }
                assertEquals(0L, repository.currentSessionHandle())
                assertNull(h.secrets.currentAsset(h.id))
                assertFalse(merged.analysisFile.exists())
            } finally { repository.closeFile() }
        }

    @Test fun authenticatedRecordCorruptionIsReportedWithoutTrimmingIt() =
        withCapture("tls12-h1", finalized = false) { _, h ->
            RandomAccessFile(h.encrypted, "rw").use { file ->
                file.seek(file.length() - 1); val value = file.read()
                file.seek(file.length() - 1); file.write(value xor 1)
            }
            val bytes = h.encrypted.readBytes()
            assertEquals(TlsAssetErrorCode.AUTHENTICATION_FAILED,
                h.lifecycle.recoverAtStartup().single { it.captureId == h.id }.errorCode)
            assertArrayEquals(bytes, h.encrypted.readBytes())
            assertFalse((h.artifacts.read(h.id) as CaptureArtifactState.Present).manifest.tls.complete)
        }

    @Test fun interruptedDeletionJournalRetriesOnlyItsCapture() =
        withCapture("tls13-h1") { _, h ->
            val failing = CaptureArtifactLifecycle(h.files, h.privateDir, h.secrets) { _, _, _ ->
                throw java.io.IOException("synthetic interruption after durable delete intent")
            }
            try { failing.purge(h.id); fail("Expected interruption") } catch (_: java.io.IOException) { }
            assertFalse(h.lifecycle.cleanupEvents().single { it.captureId == h.id }.completed)
            assertTrue(h.packet.exists())
            assertTrue(h.lifecycle.recoverAtStartup().all { it.errorCode == null })
            assertFalse(h.packet.exists())
            assertTrue(h.lifecycle.cleanupEvents().single { it.captureId == h.id }.completed)
            h.lifecycle.purge(h.id)
        }

    private fun rule(fixture: TlsPassiveFixture) = DecodeAsRule("fixture", DecodeAsScope.Port,
        DecodeAsTransport.TCP, "", "", null, fixture.port, "tls")

    private class Harness(val root: File, val alias: String) {
        val privateDir = File(root, "private").apply { mkdirs() }
        val files = File(root, "files").apply { mkdirs() }
        val id = "capture-${UUID.randomUUID()}"
        val secrets = TlsSecretStore(privateDir, AndroidTlsWrappingKeyProvider(alias))
        val artifacts = CaptureArtifactRepository(File(files, "captures"))
        val lifecycle = CaptureArtifactLifecycle(files, privateDir, secrets)
        val packet get() = File(artifacts.captureDirectory(id), "packets.pcap")
        lateinit var ref: TlsSecretAssetRef
        val encrypted get() = File(privateDir, "capture-secrets/$id/${ref.assetId}/downstream.keys.enc")
    }

    private fun withCapture(fixtureId: String, transient: Boolean = false, finalized: Boolean = true,
                            block: (TlsPassiveFixture, Harness) -> Unit) {
        TlsPassiveFixture(fixtureId).use { fixture ->
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val root = File(context.noBackupFilesDir, "tls-312-${UUID.randomUUID()}").apply { mkdirs() }
            val h = Harness(root, "layeranalyzer.test.tls312.${UUID.randomUUID()}")
            // A different capture and CA remain byte-for-byte intact even when the
            // tested capture loses its Keystore alias or is repeatedly deleted.
            val sibling = Harness(root, "layeranalyzer.test.tls312.sibling.${UUID.randomUUID()}")
            try {
                sibling.artifacts.captureDirectory(sibling.id).mkdirs()
                fixture.file("pcap").copyTo(sibling.packet)
                sibling.ref = fixture.file("keylog").inputStream().use {
                    sibling.secrets.importRecords(sibling.id, KeyLogParser.parse(it) as KeyLogParseResult.Success)
                }
                val siblingPacket = sibling.packet.readBytes()
                val siblingEncrypted = sibling.encrypted.readBytes()
                val siblingFrames = sibling.packet.inputStream().use {
                    TlsRawCaptureWriter.copy(it, ByteArrayOutputStream())
                }
                sibling.artifacts.commit(CaptureArtifactManifest(sibling.id,
                    segments = listOf(CaptureSegmentRef(sibling.packet.name, 1, siblingFrames)),
                    secretsPersistedSequence = sibling.ref.watermark.sequence,
                    tls = CaptureTlsAssets(enabled = true, secretsAssetId = sibling.ref.assetId, complete = true),
                    complete = true))
                val ca = File(h.privateDir, "tls-ca/test-ca/sentinel").apply {
                    parentFile!!.mkdirs(); writeText("synthetic CA boundary sentinel")
                }
                h.artifacts.captureDirectory(h.id).mkdirs()
                fixture.file("pcap").copyTo(h.packet)
                h.ref = fixture.file("keylog").inputStream().use {
                    h.secrets.importRecords(h.id, KeyLogParser.parse(it) as KeyLogParseResult.Success)
                }
                val frames = h.packet.inputStream().use { TlsRawCaptureWriter.copy(it, ByteArrayOutputStream()) }
                val manifest = CaptureArtifactManifest(h.id, segments = listOf(CaptureSegmentRef(h.packet.name, 1, frames)),
                    secretsPersistedSequence = h.ref.watermark.sequence,
                    retentionPolicy = if (transient) CaptureRetentionPolicy.KeepCaptureTransientSecrets else CaptureRetentionPolicy.KeepCaptureAndSecrets,
                    tls = CaptureTlsAssets(enabled = true, secretsAssetId = h.ref.assetId, complete = true), complete = true)
                if (finalized) h.artifacts.commit(manifest) else h.artifacts.writeUnfinalized(manifest)
                block(fixture, h)
                assertArrayEquals(siblingPacket, sibling.packet.readBytes())
                assertArrayEquals(siblingEncrypted, sibling.encrypted.readBytes())
                sibling.secrets.acquireLease(sibling.id).close()
                assertEquals("synthetic CA boundary sentinel", ca.readText())
            } finally {
                check(root.canonicalFile.parentFile == context.noBackupFilesDir.canonicalFile)
                CaptureFiles.deleteTree(root)
                KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(h.alias) }
                KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(sibling.alias) }
            }
        }
    }

    private fun expect(code: TlsAssetErrorCode, block: () -> Unit) {
        try { block(); fail("Expected $code") } catch (error: TlsAssetException) { assertEquals(code, error.code) }
    }
}
