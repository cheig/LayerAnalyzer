// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsAssetException
import com.example.layanalyzer.model.CaptureSegmentRef
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING

/** The byte order a PCAP global header declares. Records must be read in that order. */
enum class PcapEndianness { LittleEndian, BigEndian }

/**
 * A parsed, validated PCAP global header (design §8.5).
 *
 * [raw] is the exact 24 bytes that were read, so the merged file copies the first
 * segment's header verbatim instead of re-serialising it. Two headers are compatible
 * only when every field that would change how records are decoded matches: a big-endian
 * segment cannot be copied verbatim next to a little-endian one even if the numeric
 * values agree, because its record headers are byte-swapped.
 */
class PcapGlobalHeader internal constructor(
    internal val raw: ByteArray,
    val endianness: PcapEndianness,
    val nanosecondResolution: Boolean,
    val versionMajor: Int,
    val versionMinor: Int,
    val snaplen: Long,
    val linkType: Long
) {
    /** True when [other]'s records decode exactly as this header's do. */
    fun isCompatibleWith(other: PcapGlobalHeader): Boolean =
        endianness == other.endianness &&
            nanosecondResolution == other.nanosecondResolution &&
            versionMajor == other.versionMajor &&
            versionMinor == other.versionMinor &&
            snaplen == other.snaplen &&
            linkType == other.linkType

    internal fun unsignedInt(bytes: ByteArray, offset: Int): Long = readU32(bytes, offset, endianness)

    companion object {
        const val SIZE = 24

        /** Above any real capture buffer size; rejects an overflowing snaplen outright. */
        const val MAX_SNAPLEN = 16L * 1024 * 1024

        /** Parses and sanity-checks a 24-byte global header, or rejects it. */
        fun parse(bytes: ByteArray): PcapGlobalHeader {
            if (bytes.size < SIZE) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            val m0 = bytes[0].toInt() and 0xff
            val m1 = bytes[1].toInt() and 0xff
            val m2 = bytes[2].toInt() and 0xff
            val m3 = bytes[3].toInt() and 0xff
            val endianness: PcapEndianness
            val nanosecond: Boolean
            when {
                m0 == 0xd4 && m1 == 0xc3 && m2 == 0xb2 && m3 == 0xa1 -> { endianness = PcapEndianness.LittleEndian; nanosecond = false }
                m0 == 0xa1 && m1 == 0xb2 && m2 == 0xc3 && m3 == 0xd4 -> { endianness = PcapEndianness.BigEndian; nanosecond = false }
                m0 == 0x4d && m1 == 0x3c && m2 == 0xb2 && m3 == 0xa1 -> { endianness = PcapEndianness.LittleEndian; nanosecond = true }
                m0 == 0xa1 && m1 == 0xb2 && m2 == 0x3c && m3 == 0x4d -> { endianness = PcapEndianness.BigEndian; nanosecond = true }
                else -> throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            }
            val snaplen = readU32(bytes, 16, endianness)
            if (snaplen > MAX_SNAPLEN) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            return PcapGlobalHeader(
                raw = bytes.copyOf(SIZE),
                endianness = endianness,
                nanosecondResolution = nanosecond,
                versionMajor = readU16(bytes, 4, endianness),
                versionMinor = readU16(bytes, 6, endianness),
                snaplen = snaplen,
                linkType = readU32(bytes, 20, endianness)
            )
        }
    }
}

/** Why one segment could not be merged whole. Attached to a specific segment and frame. */
enum class CaptureMergeIssueKind {
    SEGMENT_NOT_FINALIZED,
    SEGMENT_FILE_MISSING,
    SEGMENT_UNREADABLE,
    SEGMENT_TRUNCATED_TAIL,
    SEGMENT_FRAME_COUNT_MISMATCH
}

/**
 * A content-level finding about one segment, never a whole-capture error code.
 * [localFrameIndex] is the 0-based index inside the segment of the record that could
 * not be copied, or null when the problem is the segment as a whole.
 */
data class CaptureMergeIssue(
    val segmentFile: String,
    val kind: CaptureMergeIssueKind,
    val localFrameIndex: Long? = null
)

/**
 * One segment's place in the merged file. A frame number in the merged file maps back
 * to (segment file, local frame index) through this span; [localFrames] is how many
 * complete records were actually copied, which can be fewer than the manifest's
 * [manifestFrameCount] when the segment's tail was truncated.
 */
data class SegmentFrameSpan(
    val segmentFile: String,
    /** 1-based global frame number the manifest assigned to this segment's first frame. */
    val globalFirstFrame: Long,
    /** Frames the manifest recorded for this segment. */
    val manifestFrameCount: Long,
    /** Complete records copied into the merged file. */
    val localFrames: Long,
    /** 1-based position of the first copied record in the merged file, or 0 when none. */
    val mergedFirstFrame: Long,
    val lengthBytes: Long,
    val segmentSha256: String,
    val complete: Boolean
)

/** One frame's identity in both the merged file and its source segment. */
data class FrameLocation(
    val segmentFile: String,
    /** 1-based global frame number (users' and correlator's identity). */
    val globalFrame: Long,
    /** 0-based index of the record inside [segmentFile]. */
    val localFrameIndex: Long,
    /** 1-based position of the record in the merged analysis file. */
    val mergedFrame: Long
)

/**
 * The entry point the analysis path opens for one capture (design §8.5).
 *
 * A merged capture is a temporary read-only PCAP whose records are copied verbatim, in
 * manifest order, from the capture's segments behind a single global header. It is never
 * a byte concatenation of whole PCAP files and never re-serialises records, so timestamps
 * and frame order stay exactly as captured and the global frame number keeps its meaning.
 */
sealed class CaptureAnalysisSource {
    abstract val captureId: String

    /**
     * A merged read-only analysis file. [contextIncomplete] is true when the merge does
     * not represent the whole capture: a segment was missing/truncated/not finalized, or
     * the caller deliberately merged a subset (single-segment fallback, requirement 5).
     */
    data class Merged(
        override val captureId: String,
        val analysisFile: File,
        val globalHeader: PcapGlobalHeader,
        val segments: List<SegmentFrameSpan>,
        val issues: List<CaptureMergeIssue>,
        val manifestIssues: List<CaptureSegmentIssue>,
        val totalFrames: Long,
        val byteLength: Long,
        val singleSegment: Boolean
    ) : CaptureAnalysisSource() {

        /** True when the merged view must not be presented as the whole capture. */
        val contextIncomplete: Boolean get() = issues.isNotEmpty() || manifestIssues.isNotEmpty() || singleSegment

        /** True only when every segment merged whole and the whole capture was merged. */
        val captureIsComplete: Boolean get() = issues.isEmpty() && manifestIssues.isEmpty() && !singleSegment

        /** Trace a global frame number (manifest identity) back to its source segment. */
        fun locate(globalFrame: Long): FrameLocation? {
            if (globalFrame < 1L) return null
            for (span in segments) {
                if (span.localFrames <= 0L) continue
                val offset = globalFrame - span.globalFirstFrame
                if (offset in 0 until span.localFrames) {
                    return FrameLocation(span.segmentFile, globalFrame, offset, span.mergedFirstFrame + offset)
                }
            }
            return null
        }

        /** Trace a merged-file frame position back to its source segment and global frame. */
        fun locateMerged(mergedFrame: Long): FrameLocation? {
            if (mergedFrame < 1L) return null
            for (span in segments) {
                if (span.localFrames <= 0L) continue
                val offset = mergedFrame - span.mergedFirstFrame
                if (offset in 0 until span.localFrames) {
                    return FrameLocation(span.segmentFile, span.globalFirstFrame + offset, offset, mergedFrame)
                }
            }
            return null
        }
    }

    /** An old single-file capture with no manifest; its one PCAP is already whole (C08). */
    data class Legacy(override val captureId: String, val captureFile: File) : CaptureAnalysisSource()

    /** No manifest and no legacy PCAP under this id. */
    data class Missing(override val captureId: String) : CaptureAnalysisSource()

    /** The manifest is unreadable, unsafe or has no segments; do not analyse it partially. */
    data class Refused(override val captureId: String, val reason: TlsAssetErrorCode) : CaptureAnalysisSource()

    /** The caller cancelled the merge; nothing was published under the final name. */
    data class Cancelled(override val captureId: String) : CaptureAnalysisSource()
}

/**
 * Merges a capture's segments into one read-only analysis PCAP by parsing, not by
 * concatenation (design §8.5, contract C08).
 *
 * Rules:
 * - Segment files are resolved only through [CaptureArtifactRepository] (flat relative
 *   names, traversal rejected); manifest order is copied as-is.
 * - Every present segment's global header must be compatible with the first one; one
 *   target header is written and each complete record is copied verbatim. Records are
 *   never re-serialised, re-ordered or re-timestamped.
 * - A missing segment or a truncated tail record is an explicit [CaptureMergeIssue];
 *   no short or invented record is ever written.
 * - Space is checked before writing and the output is written to a temporary name and
 *   published atomically only on success, so a failure or cancel leaves no truncated
 *   file under the final name.
 */
class CaptureSegmentAssembler internal constructor(
    private val freeSpaceBytes: (File) -> Long,
    private val openOutput: (File) -> OutputStream,
    private val publish: (Path, Path) -> Unit
) {
    constructor() : this(
        freeSpaceBytes = { it.usableSpace },
        openOutput = { BufferedOutputStream(FileOutputStream(it), FILE_BUFFER_SIZE) },
        publish = { source, target -> Files.move(source, target, ATOMIC_MOVE, REPLACE_EXISTING) }
    )

    /**
     * Merges [segments] (manifest order) into [analysisFile]. Throws [TlsAssetException]
     * for a typed refusal (empty set, incompatible headers, absurd lengths, no space,
     * I/O); returns [CaptureAnalysisSource.Cancelled] when [isCancelled] becomes true.
     */
    fun merge(
        repository: CaptureArtifactRepository,
        captureId: String,
        segments: List<CaptureSegmentRef>,
        analysisFile: File,
        manifestIssues: List<CaptureSegmentIssue> = emptyList(),
        singleSegment: Boolean = false,
        isCancelled: () -> Boolean = { false }
    ): CaptureAnalysisSource {
        return try {
            mergeInternal(repository, captureId, segments, analysisFile, manifestIssues, singleSegment, isCancelled)
        } catch (cancelled: MergeCancelled) {
            CaptureAnalysisSource.Cancelled(captureId)
        } catch (error: Exception) {
            throw sanitized(error)
        }
    }

    private fun mergeInternal(
        repository: CaptureArtifactRepository,
        captureId: String,
        segments: List<CaptureSegmentRef>,
        analysisFile: File,
        manifestIssues: List<CaptureSegmentIssue>,
        singleSegment: Boolean,
        isCancelled: () -> Boolean
    ): CaptureAnalysisSource {
        if (segments.isEmpty()) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        val parent = analysisFile.absoluteFile.parentFile
            ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)

        val issues = ArrayList<CaptureMergeIssue>()
        val filesBySegment = LinkedHashMap<String, File>(segments.size)
        for (segment in segments) {
            val file = repository.resolveSegment(captureId, segment)
            if (file.isFile) filesBySegment[segment.file] = file
            else issues += CaptureMergeIssue(segment.file, CaptureMergeIssueKind.SEGMENT_FILE_MISSING)
        }
        if (filesBySegment.isEmpty()) throw TlsAssetException(TlsAssetErrorCode.NOT_FOUND)

        // Validate every present header before writing a single byte, so an incompatible
        // sibling refuses the whole merge instead of leaving a half-written file.
        val headers = LinkedHashMap<String, PcapGlobalHeader>(filesBySegment.size)
        var globalHeader: PcapGlobalHeader? = null
        for ((name, file) in filesBySegment) {
            val header = try {
                PcapGlobalHeader.parse(readHeaderBytes(file))
            } catch (error: TlsAssetException) {
                issues += CaptureMergeIssue(name, CaptureMergeIssueKind.SEGMENT_UNREADABLE)
                throw error
            }
            val target = globalHeader
            if (target == null) globalHeader = header
            else if (!target.isCompatibleWith(header)) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            headers[name] = header
        }
        val target = globalHeader ?: throw TlsAssetException(TlsAssetErrorCode.NOT_FOUND)

        val required = PcapGlobalHeader.SIZE + filesBySegment.values.sumOf { file ->
            (file.length() - PcapGlobalHeader.SIZE).coerceAtLeast(0L)
        }
        if (freeSpaceBytes(parent) < required) throw TlsAssetException(TlsAssetErrorCode.DISK_FULL)

        val temporary = File.createTempFile(TEMP_PREFIX, TEMP_SUFFIX, parent)
        var published = false
        val spans = ArrayList<SegmentFrameSpan>(segments.size)
        var mergedFrames = 0L
        try {
            openOutput(temporary).use { output ->
                output.write(target.raw)
                for (segment in segments) {
                    val file = filesBySegment[segment.file]
                    if (file == null) {
                        spans += SegmentFrameSpan(
                            segmentFile = segment.file,
                            globalFirstFrame = segment.firstGlobalFrame,
                            manifestFrameCount = segment.frameCount,
                            localFrames = 0L,
                            mergedFirstFrame = 0L,
                            lengthBytes = segment.lengthBytes,
                            segmentSha256 = segment.segmentSha256,
                            complete = false
                        )
                        continue
                    }
                    if (isCancelled()) throw MergeCancelled()
                    val header = headers.getValue(segment.file)
                    val copied = copyRecords(output, segment, file, header, isCancelled, issues)
                    spans += SegmentFrameSpan(
                        segmentFile = segment.file,
                        globalFirstFrame = segment.firstGlobalFrame,
                        manifestFrameCount = segment.frameCount,
                        localFrames = copied,
                        mergedFirstFrame = if (copied > 0L) mergedFrames + 1L else 0L,
                        lengthBytes = segment.lengthBytes,
                        segmentSha256 = segment.segmentSha256,
                        complete = copied == segment.frameCount
                    )
                    mergedFrames += copied
                }
                output.flush()
            }
            publish(temporary.toPath(), analysisFile.toPath())
            published = true
            return CaptureAnalysisSource.Merged(
                captureId = captureId,
                analysisFile = analysisFile,
                globalHeader = target,
                segments = spans,
                issues = issues,
                manifestIssues = manifestIssues,
                totalFrames = mergedFrames,
                byteLength = analysisFile.length(),
                singleSegment = singleSegment
            )
        } finally {
            // Every failure and cancel path deletes the temporary so a partial merge can
            // never be mistaken for a finished capture (requirement 6).
            if (!published) temporary.delete()
        }
    }

    /** Copies complete records of one segment verbatim; returns how many were copied. */
    private fun copyRecords(
        output: OutputStream,
        segment: CaptureSegmentRef,
        file: File,
        header: PcapGlobalHeader,
        isCancelled: () -> Boolean,
        issues: MutableList<CaptureMergeIssue>
    ): Long {
        var localFrames = 0L
        var truncatedAt: Long? = null
        file.inputStream().use { input ->
            skipFully(input, PcapGlobalHeader.SIZE)
            val recordHeader = ByteArray(RECORD_HEADER_SIZE)
            while (true) {
                if (isCancelled()) throw MergeCancelled()
                val got = readUpTo(input, recordHeader)
                if (got == 0) break
                if (got < RECORD_HEADER_SIZE) {
                    truncatedAt = localFrames
                    break
                }
                val inclLen = header.unsignedInt(recordHeader, 8)
                val origLen = header.unsignedInt(recordHeader, 12)
                val limit = if (header.snaplen in 1..MAX_RECORD_DATA_BYTES) header.snaplen else MAX_RECORD_DATA_BYTES
                if (inclLen > limit || origLen > MAX_ORIGINAL_LENGTH) {
                    throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
                }
                val data = ByteArray(inclLen.toInt())
                if (readUpTo(input, data) < inclLen) {
                    truncatedAt = localFrames
                    break
                }
                output.write(recordHeader)
                output.write(data)
                localFrames++
            }
        }
        if (truncatedAt != null) {
            issues += CaptureMergeIssue(segment.file, CaptureMergeIssueKind.SEGMENT_TRUNCATED_TAIL, truncatedAt)
        } else if (localFrames != segment.frameCount) {
            issues += CaptureMergeIssue(segment.file, CaptureMergeIssueKind.SEGMENT_FRAME_COUNT_MISMATCH)
        }
        return localFrames
    }

    private fun readHeaderBytes(file: File): ByteArray {
        val bytes = ByteArray(PcapGlobalHeader.SIZE)
        file.inputStream().use { input ->
            if (readUpTo(input, bytes) < PcapGlobalHeader.SIZE) {
                throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            }
        }
        return bytes
    }

    private fun readUpTo(input: InputStream, buffer: ByteArray): Int {
        var total = 0
        while (total < buffer.size) {
            val read = input.read(buffer, total, buffer.size - total)
            if (read <= 0) break
            total += read
        }
        return total
    }

    private fun skipFully(input: InputStream, count: Int) {
        var remaining = count.toLong()
        while (remaining > 0L) {
            val skipped = input.skip(remaining)
            if (skipped <= 0L) {
                if (input.read() < 0) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
                remaining--
            } else {
                remaining -= skipped
            }
        }
    }

    /** Internal control-flow signal, never surfaced as a second public error vocabulary. */
    private class MergeCancelled : RuntimeException()

    private companion object {
        const val RECORD_HEADER_SIZE = 16
        const val FILE_BUFFER_SIZE = 64 * 1024
        const val TEMP_PREFIX = "merged-"
        const val TEMP_SUFFIX = ".pcap.part"

        /** Upper bound for one record's captured bytes; a larger incl_len is an overflow. */
        const val MAX_RECORD_DATA_BYTES = 16L * 1024 * 1024

        /** Upper bound for one record's original length. */
        const val MAX_ORIGINAL_LENGTH = 16L * 1024 * 1024

        fun sanitized(error: Exception): Exception = when (error) {
            is TlsAssetException -> error
            is IOException -> {
                val message = error.message.orEmpty().lowercase()
                val full = "enospc" in message || "no space left" in message ||
                    "disk full" in message || "not enough space" in message
                TlsAssetException(if (full) TlsAssetErrorCode.DISK_FULL else TlsAssetErrorCode.IO_ERROR)
            }
            is SecurityException -> TlsAssetException(TlsAssetErrorCode.IO_ERROR)
            else -> error
        }
    }
}

private fun readU16(bytes: ByteArray, offset: Int, endianness: PcapEndianness): Int =
    if (endianness == PcapEndianness.LittleEndian) {
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)
    } else {
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
    }

private fun readU32(bytes: ByteArray, offset: Int, endianness: PcapEndianness): Long {
    var value = 0L
    if (endianness == PcapEndianness.LittleEndian) {
        for (index in 3 downTo 0) value = (value shl 8) or (bytes[offset + index].toLong() and 0xff)
    } else {
        for (index in 0 until 4) value = (value shl 8) or (bytes[offset + index].toLong() and 0xff)
    }
    return value
}
