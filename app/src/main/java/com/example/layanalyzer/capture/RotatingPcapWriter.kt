// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.File
import com.example.layanalyzer.data.CaptureFileAccess

/**
 * What one written segment holds. The manifest records the same length/frame count, so
 * TLS-301/310 can describe a segment without re-reading the file; [linkType] is the
 * LINKTYPE_RAW value the global header was written with.
 */
data class PcapSegmentInfo(
    val file: File,
    val byteLength: Long,
    val frameCount: Long,
    val linkType: Int
)

internal class RotatingPcapWriter(
    private val firstOutputFile: File,
    private val segmentLimitBytes: Long,
    private val onSegmentStarted: (File) -> Unit = {}
) : Closeable {
    private val fileUses = mutableListOf<AutoCloseable>()
    private var writer = openOwnedWriter(firstOutputFile)
    private var currentSegmentBytes = PCAP_GLOBAL_HEADER_BYTES
    private val segments = mutableListOf(firstOutputFile)
    private val segmentStats = mutableListOf(SegmentStats(PCAP_GLOBAL_HEADER_BYTES, 0L))
    private var closed = false

    init {
        try { writer.writeHeader() } catch (error: Throwable) {
            try { writer.close() } finally { fileUses.forEach { it.close() } }
            throw error
        }
    }

    fun writePacket(timestampMillis: Long, bytes: ByteArray, length: Int) {
        check(!closed) { "PCAP writer is closed." }
        val safeLength = length.coerceIn(0, bytes.size)
        rotateIfNeeded(safeLength)
        writer.writePacket(timestampMillis, bytes, safeLength)
        val recordBytes = PCAP_PACKET_HEADER_BYTES + safeLength
        currentSegmentBytes += recordBytes
        segmentStats.last().apply {
            byteLength += recordBytes
            frameCount += 1L
        }
    }

    fun segmentFiles(): List<File> = segments.toList()

    /** Per-segment file length, frame count and linktype; metadata only, no behaviour change. */
    fun segmentInfo(): List<PcapSegmentInfo> = segments.indices.map { index ->
        val stats = segmentStats[index]
        PcapSegmentInfo(segments[index], stats.byteLength, stats.frameCount, LINKTYPE_RAW)
    }

    override fun close() {
        if (closed) return
        closed = true
        try { writer.close() } finally { fileUses.forEach { it.close() }; fileUses.clear() }
    }

    private fun rotateIfNeeded(packetLength: Int) {
        val nextRecordBytes = PCAP_PACKET_HEADER_BYTES + packetLength
        if (currentSegmentBytes <= PCAP_GLOBAL_HEADER_BYTES || currentSegmentBytes + nextRecordBytes <= segmentLimitBytes) return
        writer.close()
        val nextFile = nextSegmentFile()
        writer = openOwnedWriter(nextFile)
        writer.writeHeader()
        currentSegmentBytes = PCAP_GLOBAL_HEADER_BYTES
        segments += nextFile
        segmentStats += SegmentStats(PCAP_GLOBAL_HEADER_BYTES, 0L)
        onSegmentStarted(nextFile)
    }

    private fun nextSegmentFile(): File {
        val name = firstOutputFile.nameWithoutExtension
        val extension = firstOutputFile.extension.ifBlank { "pcap" }
        val index = segments.size + 1
        return File(firstOutputFile.parentFile, "$name-part-${index.toString().padStart(3, '0')}.$extension")
    }

    /** Mutable counters for one segment; the current segment is always the last. */
    private class SegmentStats(var byteLength: Long, var frameCount: Long)

    private fun openOwnedWriter(file: File): RawPcapWriter {
        val use = CaptureFileAccess.retain(file)
        return try { openWriter(file).also { fileUses += use } }
        catch (error: Throwable) { use.close(); throw error }
    }

    private companion object {
        const val PCAP_GLOBAL_HEADER_BYTES = 24L
        const val PCAP_PACKET_HEADER_BYTES = 16L
        const val FILE_BUFFER_SIZE = 64 * 1024

        /** Must match the LINKTYPE_RAW global header [RawPcapWriter] writes. */
        const val LINKTYPE_RAW = 101

        fun openWriter(file: File): RawPcapWriter =
            RawPcapWriter(BufferedOutputStream(file.outputStream(), FILE_BUFFER_SIZE))
    }
}
