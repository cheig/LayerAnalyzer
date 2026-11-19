// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsAssetException
import com.example.layanalyzer.model.CaptureArtifactManifest
import com.example.layanalyzer.model.CaptureSegmentRef
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Synthetic LINKTYPE_RAW PCAP segments in a temp directory; the payloads are arbitrary
 * bytes and only the PCAP framing, ordering and lengths matter here. No real capture,
 * keylog or traffic is used.
 */
class CaptureSegmentAssemblerTest {
    @get:Rule
    val temporary = TemporaryFolder()

    private val capturesRoot get() = File(temporary.root, "captures")
    private val captureId = "live-2000"

    private fun repository() = CaptureArtifactRepository(capturesRoot)
    private fun captureDirectory() = File(capturesRoot, captureId).apply { mkdirs() }
    private fun outputFile() = File(captureDirectory(), "merged-analysis.pcap")
    private fun captureFiles(): Set<String> =
        (captureDirectory().listFiles() ?: emptyArray()).map { it.name }.toSet()

    // ---- synthetic PCAP builders ------------------------------------------------

    private fun payload(size: Int, seed: Int): ByteArray = ByteArray(size) { ((it + seed) and 0xff).toByte() }

    private fun globalHeader(
        littleEndian: Boolean = true,
        versionMajor: Int = 2,
        versionMinor: Int = 4,
        snaplen: Long = 65535L,
        linkType: Long = 101L
    ): ByteArray {
        val bytes = ByteArray(24)
        if (littleEndian) {
            bytes[0] = 0xd4.toByte(); bytes[1] = 0xc3.toByte(); bytes[2] = 0xb2.toByte(); bytes[3] = 0xa1.toByte()
        } else {
            bytes[0] = 0xa1.toByte(); bytes[1] = 0xb2.toByte(); bytes[2] = 0xc3.toByte(); bytes[3] = 0xd4.toByte()
        }
        putU16(bytes, 4, versionMajor, littleEndian)
        putU16(bytes, 6, versionMinor, littleEndian)
        putU32(bytes, 8, 0L, littleEndian)
        putU32(bytes, 12, 0L, littleEndian)
        putU32(bytes, 16, snaplen, littleEndian)
        putU32(bytes, 20, linkType, littleEndian)
        return bytes
    }

    private fun record(
        tsSec: Long,
        tsUsec: Long,
        data: ByteArray,
        littleEndian: Boolean = true,
        inclOverride: Long? = null,
        origOverride: Long? = null
    ): ByteArray {
        val bytes = ByteArray(16 + data.size)
        putU32(bytes, 0, tsSec, littleEndian)
        putU32(bytes, 4, tsUsec, littleEndian)
        putU32(bytes, 8, inclOverride ?: data.size.toLong(), littleEndian)
        putU32(bytes, 12, origOverride ?: data.size.toLong(), littleEndian)
        System.arraycopy(data, 0, bytes, 16, data.size)
        return bytes
    }

    private fun segment(records: List<ByteArray>, littleEndian: Boolean = true, header: ByteArray = globalHeader(littleEndian)): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(header)
        records.forEach(out::write)
        return out.toByteArray()
    }

    private fun putU16(bytes: ByteArray, offset: Int, value: Int, littleEndian: Boolean) {
        if (littleEndian) {
            bytes[offset] = value.toByte(); bytes[offset + 1] = (value ushr 8).toByte()
        } else {
            bytes[offset] = (value ushr 8).toByte(); bytes[offset + 1] = value.toByte()
        }
    }

    private fun putU32(bytes: ByteArray, offset: Int, value: Long, littleEndian: Boolean) {
        if (littleEndian) {
            for (index in 0 until 4) bytes[offset + index] = (value ushr (8 * index)).toByte()
        } else {
            for (index in 0 until 4) bytes[offset + index] = (value ushr (8 * (3 - index))).toByte()
        }
    }

    private fun writeSegment(name: String, bytes: ByteArray): File =
        File(captureDirectory(), name).apply { writeBytes(bytes) }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private fun ref(file: String, firstGlobalFrame: Long, frameCount: Long, bytes: ByteArray) =
        CaptureSegmentRef(file, firstGlobalFrame, frameCount, bytes.size.toLong(), sha256(bytes), true)

    private fun manifest(segments: List<CaptureSegmentRef>) =
        CaptureArtifactManifest(captureId = captureId, segments = segments, finalized = true, complete = true)

    private fun expect(code: TlsAssetErrorCode, block: () -> Unit) {
        try {
            block()
            fail("Expected $code")
        } catch (error: TlsAssetException) {
            assertEquals(code, error.code)
        }
    }

    private fun defaultAssembler() = CaptureSegmentAssembler(
        freeSpaceBytes = { Long.MAX_VALUE },
        openOutput = { BufferedOutputStream(FileOutputStream(it)) },
        publish = { source, target -> Files.move(source, target, ATOMIC_MOVE, REPLACE_EXISTING) }
    )

    // ---- happy path -------------------------------------------------------------

    @Test
    fun mergesSegmentsVerbatimInManifestOrderWithGlobalFrameMapping() {
        val first = segment(listOf(record(1, 0, payload(4, 0)), record(1, 10, payload(8, 1))))
        val second = segment(listOf(record(2, 0, payload(6, 2))))
        val third = segment(listOf(record(3, 0, payload(2, 3)), record(3, 5, payload(9, 4))))
        writeSegment("packets-0001.pcap", first)
        writeSegment("packets-0002.pcap", second)
        writeSegment("packets-0003.pcap", third)
        val refs = listOf(
            ref("packets-0001.pcap", 1, 2, first),
            ref("packets-0002.pcap", 3, 1, second),
            ref("packets-0003.pcap", 4, 2, third)
        )

        val result = defaultAssembler().merge(repository(), captureId, refs, outputFile())
        assertTrue(result is CaptureAnalysisSource.Merged)
        result as CaptureAnalysisSource.Merged
        assertTrue(result.captureIsComplete)
        assertFalse(result.contextIncomplete)

        // One global header plus every record of every segment, byte-for-byte, in order.
        val expected = java.io.ByteArrayOutputStream().apply {
            write(first)
            write(second, 24, second.size - 24)
            write(third, 24, third.size - 24)
        }.toByteArray()
        assertArrayEquals(expected, outputFile().readBytes())
        assertEquals(expected.size.toLong(), result.byteLength)
        assertEquals(5L, result.totalFrames)
        assertTrue(result.issues.isEmpty())

        // Frame 1 lives in segment 1; the frame with global number 3 lives in segment 2.
        val firstFrame = result.locate(1L)!!
        assertEquals("packets-0001.pcap", firstFrame.segmentFile)
        assertEquals(0L, firstFrame.localFrameIndex)
        assertEquals(1L, firstFrame.mergedFrame)

        val inSecondSegment = result.locate(3L)!!
        assertEquals("packets-0002.pcap", inSecondSegment.segmentFile)
        assertEquals(0L, inSecondSegment.localFrameIndex)
        assertEquals(3L, inSecondSegment.mergedFrame)

        // The reverse mapping is the inverse of locate().
        assertEquals(4L, result.locateMerged(4L)!!.globalFrame)
        assertEquals("packets-0003.pcap", result.locateMerged(4L)!!.segmentFile)
        assertEquals(0L, result.locateMerged(4L)!!.localFrameIndex)
        assertEquals(5L, result.locateMerged(5L)!!.globalFrame)
        assertEquals(1L, result.locateMerged(5L)!!.localFrameIndex)

        // A frame number past the capture is not invented.
        assertNull(result.locate(6L))
        assertNull(result.locateMerged(6L))
    }

    // ---- incompatible headers ---------------------------------------------------

    @Test
    fun bigEndianVersusLittleEndianHeaderIsRefused() {
        val little = segment(listOf(record(1, 0, payload(4, 0))))
        val big = segment(listOf(record(2, 0, payload(4, 0), littleEndian = false)), littleEndian = false)
        writeSegment("packets-0001.pcap", little)
        writeSegment("packets-0002.pcap", big)
        val refs = listOf(ref("packets-0001.pcap", 1, 1, little), ref("packets-0002.pcap", 2, 1, big))

        expect(TlsAssetErrorCode.INVALID_FORMAT) {
            defaultAssembler().merge(repository(), captureId, refs, outputFile())
        }
        assertFalse(outputFile().exists())
        assertTrue(captureFiles().none { it.endsWith(".pcap.part") })
    }

    @Test
    fun differentLinkTypeIsRefused() {
        val raw = segment(listOf(record(1, 0, payload(4, 0))))
        val ethernet = segment(listOf(record(2, 0, payload(4, 0))), header = globalHeader(linkType = 1L))
        writeSegment("packets-0001.pcap", raw)
        writeSegment("packets-0002.pcap", ethernet)
        val refs = listOf(ref("packets-0001.pcap", 1, 1, raw), ref("packets-0002.pcap", 2, 1, ethernet))

        expect(TlsAssetErrorCode.INVALID_FORMAT) {
            defaultAssembler().merge(repository(), captureId, refs, outputFile())
        }
        assertFalse(outputFile().exists())
    }

    @Test
    fun versionMismatchIsRefused() {
        val v24 = segment(listOf(record(1, 0, payload(4, 0))))
        val v23 = segment(listOf(record(2, 0, payload(4, 0))), header = globalHeader(versionMinor = 3))
        writeSegment("packets-0001.pcap", v24)
        writeSegment("packets-0002.pcap", v23)
        val refs = listOf(ref("packets-0001.pcap", 1, 1, v24), ref("packets-0002.pcap", 2, 1, v23))

        expect(TlsAssetErrorCode.INVALID_FORMAT) {
            defaultAssembler().merge(repository(), captureId, refs, outputFile())
        }
        assertFalse(outputFile().exists())
    }

    @Test
    fun absurdSnaplenIsRefusedAtHeaderParse() {
        val absurd = segment(listOf(record(1, 0, payload(4, 0))), header = globalHeader(snaplen = 0xFFFFFFFFL))
        writeSegment("packets-0001.pcap", absurd)
        val refs = listOf(ref("packets-0001.pcap", 1, 1, absurd))

        expect(TlsAssetErrorCode.INVALID_FORMAT) {
            defaultAssembler().merge(repository(), captureId, refs, outputFile())
        }
        assertFalse(outputFile().exists())
    }

    @Test
    fun overflowingInclLengthIsRefusedRatherThanTrusted() {
        // A record claiming 4 GiB of data with no bytes behind it must be rejected outright.
        val overflowing = segment(listOf(record(1, 0, ByteArray(0), inclOverride = 0xFFFFFFFFL)))
        writeSegment("packets-0001.pcap", overflowing)
        val refs = listOf(ref("packets-0001.pcap", 1, 1, overflowing))

        expect(TlsAssetErrorCode.INVALID_FORMAT) {
            defaultAssembler().merge(repository(), captureId, refs, outputFile())
        }
        assertFalse(outputFile().exists())
    }

    @Test
    fun absurdOriginalLengthIsRefused() {
        val absurd = segment(listOf(record(1, 0, payload(4, 0), origOverride = 0xFFFFFFFFL)))
        writeSegment("packets-0001.pcap", absurd)
        val refs = listOf(ref("packets-0001.pcap", 1, 1, absurd))

        expect(TlsAssetErrorCode.INVALID_FORMAT) {
            defaultAssembler().merge(repository(), captureId, refs, outputFile())
        }
        assertFalse(outputFile().exists())
    }

    // ---- missing / truncated ----------------------------------------------------

    @Test
    fun missingSegmentIsMarkedAndItsFramesAreNotInvented() {
        val first = segment(listOf(record(1, 0, payload(4, 0))))
        val third = segment(listOf(record(3, 0, payload(5, 1))))
        writeSegment("packets-0001.pcap", first)
        writeSegment("packets-0003.pcap", third)
        // The manifest still names the middle segment, which is not on disk.
        val refs = listOf(
            ref("packets-0001.pcap", 1, 1, first),
            ref("packets-0002.pcap", 2, 1, payload(5, 9)),
            ref("packets-0003.pcap", 3, 1, third)
        )

        val result = defaultAssembler().merge(repository(), captureId, refs, outputFile()) as CaptureAnalysisSource.Merged
        assertEquals(1, result.issues.count { it.kind == CaptureMergeIssueKind.SEGMENT_FILE_MISSING })
        assertEquals("packets-0002.pcap", result.issues.first { it.kind == CaptureMergeIssueKind.SEGMENT_FILE_MISSING }.segmentFile)
        assertTrue(result.contextIncomplete)
        assertFalse(result.captureIsComplete)
        assertEquals(2L, result.totalFrames)
        // Global frame 2 belonged to the missing segment and is honestly absent.
        assertNull(result.locate(2L))
        assertEquals("packets-0003.pcap", result.locate(3L)!!.segmentFile)
        assertEquals(2L, result.locate(3L)!!.mergedFrame)
        // Only the two present segments' records were written.
        val expected = java.io.ByteArrayOutputStream().apply {
            write(first)
            write(third, 24, third.size - 24)
        }.toByteArray()
        assertArrayEquals(expected, outputFile().readBytes())
    }

    @Test
    fun truncatedTailRecordIsMarkedAndNoPartialRecordIsWritten() {
        val full = record(1, 0, payload(20, 0))
        val tail = record(1, 1, payload(20, 1))
        // Keep only the first five bytes of the tail record's payload.
        val truncated = tail.copyOf(tail.size - 15)
        val bytes = java.io.ByteArrayOutputStream().apply {
            write(globalHeader())
            write(full)
            write(truncated)
        }.toByteArray()
        writeSegment("packets-0001.pcap", bytes)
        val refs = listOf(ref("packets-0001.pcap", 1, 2, bytes))

        val result = defaultAssembler().merge(repository(), captureId, refs, outputFile()) as CaptureAnalysisSource.Merged
        val issue = result.issues.single { it.kind == CaptureMergeIssueKind.SEGMENT_TRUNCATED_TAIL }
        assertEquals("packets-0001.pcap", issue.segmentFile)
        assertEquals(1L, issue.localFrameIndex)
        assertTrue(result.contextIncomplete)
        assertEquals(1L, result.totalFrames)
        assertNull(result.locate(2L))
        // The merged file holds one complete record, never the partial tail.
        assertArrayEquals(segment(listOf(full)), outputFile().readBytes())
    }

    // ---- cancel / disk full -----------------------------------------------------

    @Test
    fun cancellationPublishesNothingUnderTheFinalName() {
        val first = segment(listOf(record(1, 0, payload(40, 0)), record(1, 1, payload(40, 1))))
        val second = segment(listOf(record(2, 0, payload(40, 2)), record(2, 1, payload(40, 3))))
        writeSegment("packets-0001.pcap", first)
        writeSegment("packets-0002.pcap", second)
        val refs = listOf(ref("packets-0001.pcap", 1, 2, first), ref("packets-0002.pcap", 3, 2, second))
        val repository = repository()
        repository.commit(manifest(refs))

        var calls = 0
        val result = repository.openForAnalysis(captureId, isCancelled = { ++calls > 2 })

        assertTrue(result is CaptureAnalysisSource.Cancelled)
        assertFalse(repository.analysisFile(captureId).exists())
        // No partial merge leaked as a temporary, and the committed manifest is untouched.
        assertEquals(setOf("capture.json", "packets-0001.pcap", "packets-0002.pcap"), captureFiles())
        assertTrue((repository.read(captureId) as CaptureArtifactState.Present).isComplete)
    }

    @Test
    fun insufficientSpaceIsRefusedBeforeWriting() {
        val bytes = segment(listOf(record(1, 0, payload(4, 0))))
        writeSegment("packets-0001.pcap", bytes)
        val refs = listOf(ref("packets-0001.pcap", 1, 1, bytes))
        val assembler = CaptureSegmentAssembler(
            freeSpaceBytes = { 0L },
            openOutput = { BufferedOutputStream(FileOutputStream(it)) },
            publish = { source, target -> Files.move(source, target, ATOMIC_MOVE, REPLACE_EXISTING) }
        )

        expect(TlsAssetErrorCode.DISK_FULL) { assembler.merge(repository(), captureId, refs, outputFile()) }
        assertFalse(outputFile().exists())
        assertTrue(captureFiles().none { it.endsWith(".pcap.part") })
    }

    @Test
    fun diskFullDuringWriteLeavesNoTruncatedFileUnderTheFinalName() {
        val bytes = segment(listOf(record(1, 0, payload(4, 0))))
        writeSegment("packets-0001.pcap", bytes)
        val refs = listOf(ref("packets-0001.pcap", 1, 1, bytes))
        val failing = object : OutputStream() {
            override fun write(b: Int) = throw IOException("ENOSPC: No space left on device")
        }
        val assembler = CaptureSegmentAssembler(
            freeSpaceBytes = { Long.MAX_VALUE },
            openOutput = { failing },
            publish = { source, target -> Files.move(source, target, ATOMIC_MOVE, REPLACE_EXISTING) }
        )

        expect(TlsAssetErrorCode.DISK_FULL) { assembler.merge(repository(), captureId, refs, outputFile()) }
        assertFalse(outputFile().exists())
        assertTrue(captureFiles().none { it.endsWith(".pcap.part") })
    }

    // ---- repository entry point -------------------------------------------------

    @Test
    fun repositoryMergesACommittedCaptureAndMapsFrames() {
        val first = segment(listOf(record(1, 0, payload(4, 0)), record(1, 10, payload(6, 1))))
        val second = segment(listOf(record(2, 0, payload(3, 2))))
        writeSegment("packets-0001.pcap", first)
        writeSegment("packets-0002.pcap", second)
        val refs = listOf(ref("packets-0001.pcap", 1, 2, first), ref("packets-0002.pcap", 3, 1, second))
        val repository = repository()
        repository.commit(manifest(refs))

        val result = repository.openForAnalysis(captureId) as CaptureAnalysisSource.Merged
        assertTrue(result.captureIsComplete)
        assertEquals(3L, result.totalFrames)
        assertEquals("packets-0002.pcap", result.locate(3L)!!.segmentFile)
        assertArrayEquals(
            java.io.ByteArrayOutputStream().apply {
                write(first)
                write(second, 24, second.size - 24)
            }.toByteArray(),
            repository.analysisFile(captureId).readBytes()
        )
    }

    @Test
    fun singleSegmentMergeCarriesIncompleteContext() {
        val first = segment(listOf(record(1, 0, payload(4, 0)), record(1, 10, payload(6, 1))))
        val second = segment(listOf(record(2, 0, payload(3, 2))))
        writeSegment("packets-0001.pcap", first)
        writeSegment("packets-0002.pcap", second)
        val refs = listOf(ref("packets-0001.pcap", 1, 2, first), ref("packets-0002.pcap", 3, 1, second))
        val repository = repository()
        repository.commit(manifest(refs))

        val result = repository.openSingleSegmentForAnalysis(captureId, "packets-0002.pcap") as CaptureAnalysisSource.Merged
        assertTrue(result.singleSegment)
        assertTrue(result.contextIncomplete)
        assertFalse(result.captureIsComplete)
        assertEquals(1L, result.totalFrames)
        // The single segment is copied whole; it is not presented as the whole capture.
        assertArrayEquals(second, repository.analysisFile(captureId).readBytes())
    }

    @Test
    fun legacyCaptureIsHandledAsItsOwnPathNotAsOneSegment() {
        File(capturesRoot, "$captureId.pcap").apply { parentFile?.mkdirs(); writeBytes(segment(listOf(record(1, 0, payload(4, 0))))) }
        val result = repository().openForAnalysis(captureId)
        assertTrue(result is CaptureAnalysisSource.Legacy)
        assertEquals(File(capturesRoot, "$captureId.pcap"), (result as CaptureAnalysisSource.Legacy).captureFile)
    }

    @Test
    fun missingAndCorruptCapturesAreNotPartiallyTrusted() {
        val repository = repository()
        assertTrue(repository.openForAnalysis(captureId) is CaptureAnalysisSource.Missing)

        captureDirectory().mkdirs()
        File(captureDirectory(), "capture.json").writeText("{ not a manifest")
        val refused = repository.openForAnalysis(captureId)
        assertTrue(refused is CaptureAnalysisSource.Refused)
        assertEquals(TlsAssetErrorCode.INVALID_FORMAT, (refused as CaptureAnalysisSource.Refused).reason)
    }
}
