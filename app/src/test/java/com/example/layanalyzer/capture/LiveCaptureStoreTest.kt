// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import com.example.layanalyzer.capture.tls.AesGcmTlsWrappingKeyProvider
import com.example.layanalyzer.capture.tls.TlsSecretStore
import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.data.CaptureArtifactState
import com.example.layanalyzer.data.TlsCaptureBundle
import com.example.layanalyzer.model.CaptureTlsAssets
import com.example.layanalyzer.model.LiveCaptureManifestConfig
import java.io.ByteArrayOutputStream
import java.io.File
import javax.crypto.KeyGenerator
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class LiveCaptureStoreTest {
    @get:Rule
    val temporary = TemporaryFolder()

    @After
    fun detachRepository() {
        LiveCaptureStore.stop()
        LiveCaptureStore.installArtifactRepository(null)
    }
    @Test
    fun reportsDroppedPacketsAndWriteErrors() {
        LiveCaptureStore.start("capture.pcap")
        LiveCaptureStore.recordOffered()
        LiveCaptureStore.recordDropped()
        LiveCaptureStore.recordIoError("disk full")
        LiveCaptureStore.stop()

        val state = LiveCaptureStore.state.value
        assertEquals(1L, state.offeredPacketCount)
        assertEquals(1L, state.droppedPacketCount)
        assertEquals(1L, state.ioErrorCount)
        assertEquals("disk full", state.lastIoError)
        assertFalse(state.captureIsComplete)
    }

    @Test
    fun serviceFailureIsIncompleteEvenWhenNoPacketWasDropped() {
        LiveCaptureStore.start("capture-failure.pcap")
        LiveCaptureStore.recordOffered()
        LiveCaptureStore.recordPacket(0L, byteArrayOf(1), 1)
        LiveCaptureStore.fail("network changed")

        val state = LiveCaptureStore.state.value
        assertFalse(state.captureIsComplete)
        assertEquals("network changed", state.error)
    }

    @Test
    fun parsesIpv4AndClampsLength() {
        val packet = ByteArray(20)
        packet[0] = 0x45
        packet[9] = 6
        packet[12] = 192.toByte()
        packet[13] = 168.toByte()
        packet[14] = 1
        packet[15] = 2
        packet[16] = 8
        packet[17] = 8
        packet[18] = 4
        packet[19] = 4

        val preview = LiveCaptureStore.parsePreview(7, 123, packet, 999)
        assertEquals(20, preview.length)
        assertEquals(4, preview.ipVersion)
        assertEquals("TCP", preview.protocol)
        assertEquals("192.168.1.2", preview.source)
        assertEquals("8.8.4.4", preview.destination)
    }

    @Test
    fun parsesIpv6AndReportsTruncation() {
        val packet = ByteArray(40)
        packet[0] = 0x60
        packet[6] = 17
        packet[8] = 0x20
        packet[9] = 0x01
        packet[23] = 1
        packet[24] = 0x20
        packet[25] = 0x01
        packet[39] = 2

        val preview = LiveCaptureStore.parsePreview(1, 0, packet, packet.size)
        assertEquals(6, preview.ipVersion)
        assertEquals("UDP", preview.protocol)
        assertEquals("2001:0:0:0:0:0:0:1", preview.source)
        assertEquals("2001:0:0:0:0:0:0:2", preview.destination)

        val truncated = LiveCaptureStore.parsePreview(2, 0, byteArrayOf(0x45), 1)
        assertEquals("truncated", truncated.source)
        assertEquals("IPv4", truncated.protocol)
    }

    private fun install(captureId: String): Pair<CaptureArtifactRepository, File> {
        val root = File(temporary.root, "captures")
        val repository = CaptureArtifactRepository(root)
        LiveCaptureStore.installArtifactRepository(repository)
        return repository to File(root, captureId).apply { mkdirs() }
    }

    @Test
    fun startedCaptureWritesAnUnfinalizedManifest() {
        val captureId = "live-100"
        val (repository, directory) = install(captureId)
        val first = File(directory, "packets-0001.pcap").apply { writeBytes(byteArrayOf(1, 2, 3)) }

        LiveCaptureStore.start(first.absolutePath, LiveCaptureManifestConfig(captureId = captureId))

        val manifest = (repository.read(captureId) as CaptureArtifactState.Present).manifest
        assertFalse(manifest.finalized)
        assertFalse(manifest.complete)
        assertFalse(manifest.captureIsComplete)
    }

    @Test
    fun stopAfterDrainWritesCompleteManifestWithRealFrameCounts() {
        val captureId = "live-101"
        val (repository, directory) = install(captureId)
        val first = File(directory, "packets-0001.pcap").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val second = File(directory, "packets-0002.pcap").apply { writeBytes(byteArrayOf(4, 5)) }

        LiveCaptureStore.start(first.absolutePath, LiveCaptureManifestConfig(captureId = captureId))
        // Offered-but-never-written packets must not occupy a frame number.
        repeat(7) { LiveCaptureStore.recordOffered() }
        repeat(3) { LiveCaptureStore.recordPacket(0L, byteArrayOf(0x45), 1) }
        LiveCaptureStore.recordSegment(second.absolutePath)
        repeat(2) { LiveCaptureStore.recordPacket(0L, byteArrayOf(0x45), 1) }
        LiveCaptureStore.recordSecretsPersistedSequence(9L)
        LiveCaptureStore.recordWritersDrained()
        LiveCaptureStore.stop()

        val manifest = (repository.read(captureId) as CaptureArtifactState.Present).manifest
        assertTrue(manifest.captureIsComplete)
        assertEquals(9L, manifest.secretsPersistedSequence)
        // Secrets were never declared complete, so decryption completeness stays false.
        assertFalse(manifest.decryptionIsComplete)
        assertEquals(2, manifest.segments.size)
        assertEquals(1L, manifest.segments[0].firstGlobalFrame)
        assertEquals(3L, manifest.segments[0].frameCount)
        assertEquals(3L, manifest.segments[0].lengthBytes)
        assertEquals(4L, manifest.segments[1].firstGlobalFrame)
        assertEquals(2L, manifest.segments[1].frameCount)
    }

    @Test
    fun stopWithoutWriterDrainNeverWritesCompleteManifest() {
        val captureId = "live-102"
        val (repository, directory) = install(captureId)
        val first = File(directory, "packets-0001.pcap").apply { writeBytes(byteArrayOf(1, 2, 3)) }

        LiveCaptureStore.start(first.absolutePath, LiveCaptureManifestConfig(captureId = captureId))
        LiveCaptureStore.recordPacket(0L, byteArrayOf(0x45), 1)
        LiveCaptureStore.stop()

        val manifest = (repository.read(captureId) as CaptureArtifactState.Present).manifest
        assertFalse(manifest.finalized)
        assertFalse(manifest.complete)
    }

    @Test
    fun writerFailureNeverWritesCompleteManifest() {
        val captureId = "live-103"
        val (repository, directory) = install(captureId)
        val first = File(directory, "packets-0001.pcap").apply { writeBytes(byteArrayOf(1, 2, 3)) }

        LiveCaptureStore.start(first.absolutePath, LiveCaptureManifestConfig(captureId = captureId))
        LiveCaptureStore.recordPacket(0L, byteArrayOf(0x45), 1)
        LiveCaptureStore.recordIoError("disk full")
        LiveCaptureStore.recordWritersDrained()
        LiveCaptureStore.stop()

        val manifest = (repository.read(captureId) as CaptureArtifactState.Present).manifest
        assertFalse(manifest.finalized)
        assertFalse(manifest.complete)
        assertFalse(manifest.captureIsComplete)
    }

    @Test
    fun failureWritesAnIncompleteManifest() {
        val captureId = "live-104"
        val (repository, directory) = install(captureId)
        val first = File(directory, "packets-0001.pcap").apply { writeBytes(byteArrayOf(1, 2, 3)) }

        LiveCaptureStore.start(first.absolutePath, LiveCaptureManifestConfig(captureId = captureId))
        LiveCaptureStore.recordPacket(0L, byteArrayOf(0x45), 1)
        LiveCaptureStore.recordWritersDrained()
        LiveCaptureStore.fail("network changed")

        val manifest = (repository.read(captureId) as CaptureArtifactState.Present).manifest
        assertFalse(manifest.complete)
        assertFalse(manifest.captureIsComplete)
    }

    @Test
    fun stoppedCaptureExportsItsPublishedSecrets() {
        val captureId = "live-export"
        val (repository, directory) = install(captureId)
        val packet = byteArrayOf(0x45, 0, 0, 0)
        val first = File(directory, "$captureId.pcap")
        RawPcapWriter(first.outputStream()).use { writer ->
            writer.writeHeader()
            writer.writePacket(1000L, packet, packet.size)
        }
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val secrets = TlsSecretStore(temporary.newFolder("private"), AesGcmTlsWrappingKeyProvider { key })
        val line = "CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}"
        val persisted = secrets.openLiveSecrets(captureId).use { sink ->
            assertTrue(sink.offer("connection-1", line.toByteArray()))
            sink.finish()
        }
        assertTrue(persisted.complete)
        val asset = requireNotNull(persisted.asset)
        LiveCaptureStore.start(first.absolutePath, LiveCaptureManifestConfig(
            captureId = captureId, tls = CaptureTlsAssets(enabled = true)))
        LiveCaptureStore.recordPacket(1000L, packet, packet.size)
        LiveCaptureStore.recordWritersDrained()
        LiveCaptureStore.recordSecretsAsset(asset, persisted.complete)
        LiveCaptureStore.stop()

        val state = repository.read(captureId) as CaptureArtifactState.Present
        assertTrue(state.isComplete)
        assertTrue(state.manifest.decryptionIsComplete)
        val bundle = TlsCaptureBundle(repository, secrets, temporary.newFolder("bundle-work"))
        val exported = ByteArrayOutputStream()
        bundle.writeComplete(captureId, exported, filtered = false, confirmed = true)
        assertTrue(exported.size() > 0)
        assertEquals(asset.watermark.sequence, state.manifest.secretsPersistedSequence)
    }

    @Test
    fun unpublishedSecretsCannotLeaveAStaleWatermarkOrClaimCompleteness() {
        val captureId = "live-no-secrets"
        val (repository, directory) = install(captureId)
        val first = File(directory, "$captureId.pcap").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        LiveCaptureStore.start(first.absolutePath, LiveCaptureManifestConfig(
            captureId = captureId, tls = CaptureTlsAssets(enabled = true)))
        LiveCaptureStore.recordSecretsPersistedSequence(9L)
        LiveCaptureStore.recordSecretsAsset(null, complete = true)
        LiveCaptureStore.recordWritersDrained()
        LiveCaptureStore.stop()

        val manifest = (repository.read(captureId) as CaptureArtifactState.Present).manifest
        assertEquals(0L, manifest.secretsPersistedSequence)
        assertEquals(null, manifest.tls.secretsAssetId)
        assertFalse(manifest.decryptionIsComplete)
    }

    @Test
    fun failedNextStartPreservesTheCompletedCapture() {
        val captureId = "live-start-failure"
        val (repository, directory) = install(captureId)
        val first = File(directory, "$captureId.pcap").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        LiveCaptureStore.start(first.absolutePath, LiveCaptureManifestConfig(captureId = captureId))
        LiveCaptureStore.recordWritersDrained()
        LiveCaptureStore.stop()
        val manifestFile = repository.manifestFile(captureId)
        val before = manifestFile.readBytes()
        val previousState = LiveCaptureStore.state.value

        repeat(2) { LiveCaptureStore.fail("Unable to establish VPN capture interface.") }

        assertArrayEquals(before, manifestFile.readBytes())
        assertTrue((repository.read(captureId) as CaptureArtifactState.Present).isComplete)
        assertEquals(previousState.stoppedAtMillis, LiveCaptureStore.state.value.stoppedAtMillis)
        assertEquals(previousState.incomplete, LiveCaptureStore.state.value.incomplete)
        assertEquals("Unable to establish VPN capture interface.", LiveCaptureStore.state.value.error)
    }
}
