// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsAssetException
import com.example.layanalyzer.model.CaptureArtifactManifest
import com.example.layanalyzer.model.CaptureRetentionPolicy
import com.example.layanalyzer.model.CaptureSegmentRef
import com.example.layanalyzer.model.CaptureTlsAssets
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.security.MessageDigest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Synthetic assets in a temp directory; no real capture, keylog or traffic. The
 * segment bytes are arbitrary and only their length/SHA-256 matter here.
 */
class CaptureArtifactRepositoryTest {
    @get:Rule
    val temporary = TemporaryFolder()

    private val capturesRoot get() = File(temporary.root, "captures")
    private val captureId = "live-1000"
    private val segmentBytes = byteArrayOf(1, 2, 3, 4)

    private fun repository() = CaptureArtifactRepository(capturesRoot)
    private fun captureDirectory() = File(capturesRoot, captureId)
    private fun manifestFile() = File(captureDirectory(), "capture.json")

    private fun writeSegment(name: String = "packets-0001.pcap", bytes: ByteArray = segmentBytes): File {
        val directory = captureDirectory().apply { mkdirs() }
        return File(directory, name).apply { writeBytes(bytes) }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private fun segment(
        file: String = "packets-0001.pcap",
        firstGlobalFrame: Long = 1L,
        frameCount: Long = 4L,
        lengthBytes: Long = segmentBytes.size.toLong(),
        sha256: String = sha256(segmentBytes),
        finalized: Boolean = true
    ) = CaptureSegmentRef(file, firstGlobalFrame, frameCount, lengthBytes, sha256, finalized)

    private fun manifest(
        segments: List<CaptureSegmentRef> = listOf(segment()),
        complete: Boolean = true,
        finalized: Boolean = true,
        interrupted: Boolean = false,
        tls: CaptureTlsAssets = CaptureTlsAssets()
    ) = CaptureArtifactManifest(
        captureId = captureId,
        segments = segments,
        finalized = finalized,
        complete = complete,
        interrupted = interrupted,
        tls = tls
    )

    private fun expect(code: TlsAssetErrorCode, block: () -> Unit) {
        try {
            block()
            fail("Expected $code")
        } catch (error: TlsAssetException) {
            assertEquals(code, error.code)
        }
    }

    @Test
    fun legacyCaptureWithoutManifestStillOpens() {
        File(capturesRoot, "$captureId.pcap").apply { parentFile?.mkdirs(); writeBytes(segmentBytes) }
        // A sibling keylog must never be discovered by scanning the directory (C08).
        File(capturesRoot, "keylog.txt").writeText("CLIENT_RANDOM ignored\n")

        val state = repository().read(captureId)
        assertTrue(state is CaptureArtifactState.Legacy)
        state as CaptureArtifactState.Legacy
        assertEquals(captureId, state.captureId)
        assertEquals(File(capturesRoot, "$captureId.pcap"), state.captureFile)
    }

    @Test
    fun missingCaptureIsReportedAsMissing() {
        assertTrue(repository().read(captureId) is CaptureArtifactState.Missing)
    }

    @Test
    fun unfinalizedManifestIsPresentButNotComplete() {
        writeSegment()
        val written = repository().writeUnfinalized(manifest(complete = false, finalized = false))
        assertFalse(written.finalized)
        assertFalse(written.complete)

        val state = repository().read(captureId) as CaptureArtifactState.Present
        assertFalse(state.manifest.finalized)
        assertFalse(state.manifest.complete)
        assertFalse(state.manifest.captureIsComplete)
        assertFalse(state.isComplete)
    }

    @Test
    fun commitFillsRealLengthAndHashAndFinalizes() {
        writeSegment()
        val committed = repository().commit(manifest())

        assertTrue(committed.finalized)
        assertTrue(committed.complete)
        assertTrue(committed.finalizedAtMillis > 0L)
        assertEquals(segmentBytes.size.toLong(), committed.segments.single().lengthBytes)
        assertEquals(sha256(segmentBytes), committed.segments.single().segmentSha256)

        val state = repository().read(captureId) as CaptureArtifactState.Present
        assertTrue(state.isComplete)
        assertTrue(state.manifest.captureIsComplete)
    }

    @Test
    fun corruptManifestIsRejected() {
        captureDirectory().mkdirs()
        manifestFile().writeText("{ this is not a manifest")

        val state = repository().read(captureId)
        assertTrue(state is CaptureArtifactState.Corrupt)
        assertEquals(TlsAssetErrorCode.INVALID_FORMAT, (state as CaptureArtifactState.Corrupt).reason)
    }

    @Test
    fun unknownEnumValueIsRejected() {
        writeSegment()
        repository().commit(manifest())
        val json = JSONObject(manifestFile().readText())
        json.put("captureMode", "not_a_mode")
        manifestFile().writeText(json.toString())

        assertTrue(repository().read(captureId) is CaptureArtifactState.Corrupt)
    }

    @Test
    fun wrongCaptureIdIsRejected() {
        writeSegment()
        repository().commit(manifest())
        val json = JSONObject(manifestFile().readText())
        json.put("captureId", "live-9999")
        manifestFile().writeText(json.toString())

        val state = repository().read(captureId) as CaptureArtifactState.Corrupt
        assertEquals(TlsAssetErrorCode.BINDING_MISMATCH, state.reason)
    }

    @Test
    fun pathTraversalSegmentIsRejected() {
        writeSegment()
        repository().commit(manifest())
        manifestFile().writeText(manifestFile().readText().replace("\"packets-0001.pcap\"", "\"../evil.pcap\""))

        val state = repository().read(captureId)
        assertTrue(state is CaptureArtifactState.Corrupt)
        assertFalse(File(capturesRoot, "evil.pcap").exists())
    }

    @Test
    fun absoluteSegmentPathOnWriteIsRefused() {
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) {
            repository().writeUnfinalized(
                manifest(segments = listOf(segment(file = "/data/data/secret-keylog.txt")), complete = false, finalized = false)
            )
        }
    }

    @Test
    fun duplicateSegmentIsRejectedOnRead() {
        writeSegment()
        repository().commit(manifest())
        val json = JSONObject(manifestFile().readText())
        val segments = json.getJSONArray("segments")
        segments.put(segments.get(0))
        manifestFile().writeText(json.toString())

        val state = repository().read(captureId)
        assertTrue(state is CaptureArtifactState.Corrupt)
    }

    @Test
    fun duplicateSegmentIsRejectedOnWrite() {
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) {
            repository().writeUnfinalized(
                manifest(segments = listOf(segment(), segment()), complete = false, finalized = false)
            )
        }
    }

    @Test
    fun wrongHashIsMarkedIncomplete() {
        val file = writeSegment()
        repository().commit(manifest())
        // Same length, different content: only the hash can reveal the tampering.
        file.writeBytes(byteArrayOf(9, 9, 9, 9))

        val state = repository().read(captureId) as CaptureArtifactState.Present
        assertTrue(state.issues.contains(CaptureSegmentIssue.SEGMENT_HASH_MISMATCH))
        assertFalse(state.isComplete)
    }

    @Test
    fun missingSegmentFileIsMarkedIncomplete() {
        val file = writeSegment()
        repository().commit(manifest())
        assertTrue(file.delete())

        val state = repository().read(captureId) as CaptureArtifactState.Present
        assertTrue(state.issues.contains(CaptureSegmentIssue.SEGMENT_FILE_MISSING))
        assertFalse(state.isComplete)
    }

    @Test
    fun commitRefusesAnIncompleteManifest() {
        writeSegment()
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) { repository().commit(manifest(complete = false)) }
    }

    @Test
    fun commitWithAMissingSegmentWritesNothingComplete() {
        captureDirectory().mkdirs()
        expect(TlsAssetErrorCode.NOT_FOUND) { repository().commit(manifest()) }
        assertFalse(manifestFile().exists())
        assertTrue(repository().read(captureId) is CaptureArtifactState.Missing)
    }

    @Test
    fun failedAtomicReplaceKeepsThePreviousValidVersion() {
        var failNext = false
        val repository = CaptureArtifactRepository(capturesRoot) { source, target ->
            if (failNext) throw IOException("simulated replace failure")
            Files.move(source, target, ATOMIC_MOVE, REPLACE_EXISTING)
        }
        writeSegment()
        repository.commit(manifest())
        val before = manifestFile().readText()
        assertTrue(before.contains("\"complete\":true"))

        failNext = true
        try {
            repository.writeUnfinalized(manifest(complete = false, finalized = false))
            fail("Expected the replace to fail")
        } catch (_: TlsAssetException) {
            // Expected: the failed replace must not have deleted the old manifest.
        }

        assertEquals(before, manifestFile().readText())
        // No temporary file is left behind by the failed replace.
        assertEquals(
            setOf("capture.json", "packets-0001.pcap"),
            captureDirectory().listFiles()!!.map { it.name }.toSet()
        )
    }

    @Test
    fun manifestNeverCarriesAnAbsolutePathOrKeyMaterial() {
        writeSegment()
        repository().commit(manifest())
        val text = manifestFile().readText()

        assertFalse(text.contains(capturesRoot.absolutePath))
        assertFalse(text.contains("PRIVATE KEY"))
        assertFalse(text.contains("CLIENT_RANDOM"))
        assertTrue(text.contains("\"file\":\"packets-0001.pcap\""))
    }

    @Test
    fun invalidCaptureIdsAreRejectedWithoutNormalising() {
        val invalid = listOf("", "..", ".", "a/b", "a\\b", "a b", "a\nb", "../evil", "/abs", "c:drive", "a.b")
        for (id in invalid) {
            expect(TlsAssetErrorCode.INVALID_ARGUMENT) { repository().read(id) }
            assertFalse(repository().isValidCaptureId(id))
        }
    }

    @Test
    fun captureCompletenessIsSeparateFromDecryptionCompleteness() {
        val pcapCompleteWithoutSecrets = manifest(tls = CaptureTlsAssets(enabled = true, complete = false))
        assertTrue(pcapCompleteWithoutSecrets.captureIsComplete)
        assertFalse(pcapCompleteWithoutSecrets.decryptionIsComplete)

        val secretsWithoutCompletePcap = manifest(complete = false, tls = CaptureTlsAssets(enabled = true, complete = true))
        assertFalse(secretsWithoutCompletePcap.captureIsComplete)
        assertTrue(secretsWithoutCompletePcap.decryptionIsComplete)
        // A PCAP flagged complete must not have leaked a decryption claim.
        assertFalse(pcapCompleteWithoutSecrets.copy(tls = CaptureTlsAssets()).decryptionIsComplete)
    }

    @Test
    fun capturedFrameNumbersAndVantageRoundTrip() {
        writeSegment("packets-0001.pcap", byteArrayOf(1, 2, 3))
        writeSegment("packets-0002.pcap", byteArrayOf(4, 5))
        val two = listOf(
            segment("packets-0001.pcap", firstGlobalFrame = 1L, frameCount = 3L, lengthBytes = 3L, sha256 = sha256(byteArrayOf(1, 2, 3))),
            segment("packets-0002.pcap", firstGlobalFrame = 4L, frameCount = 2L, lengthBytes = 2L, sha256 = sha256(byteArrayOf(4, 5)))
        )
        repository().commit(manifest(segments = two).copy(retentionPolicy = CaptureRetentionPolicy.KeepCaptureTransientSecrets))

        val state = repository().read(captureId) as CaptureArtifactState.Present
        assertEquals(2, state.manifest.segments.size)
        assertEquals(1L, state.manifest.segments[0].firstGlobalFrame)
        assertEquals(3L, state.manifest.segments[0].frameCount)
        assertEquals(4L, state.manifest.segments[1].firstGlobalFrame)
        assertEquals(2L, state.manifest.segments[1].frameCount)
        assertEquals(CaptureRetentionPolicy.KeepCaptureTransientSecrets, state.manifest.retentionPolicy)
        assertEquals(5L, state.manifest.segments[1].lastGlobalFrame)
    }

    @Test
    fun captureDirectoryAndManifestPathsAreDerivedFromTheId() {
        val repository = repository()
        assertEquals(File(capturesRoot, captureId), repository.captureDirectory(captureId))
        assertEquals(File(File(capturesRoot, captureId), "capture.json"), repository.manifestFile(captureId))
        assertEquals(File(capturesRoot, "$captureId.pcap"), repository.legacyCaptureFile(captureId))
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) { repository.captureDirectory("../escape") }
    }
}
