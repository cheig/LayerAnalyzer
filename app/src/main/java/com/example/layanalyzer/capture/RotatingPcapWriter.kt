// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.File

internal class RotatingPcapWriter(
    private val firstOutputFile: File,
    private val segmentLimitBytes: Long,
    private val onSegmentStarted: (File) -> Unit = {}
) : Closeable {
    private var writer = openWriter(firstOutputFile)
    private var currentSegmentBytes = PCAP_GLOBAL_HEADER_BYTES
    private val segments = mutableListOf(firstOutputFile)
    private var closed = false

    init {
        writer.writeHeader()
    }

    fun writePacket(timestampMillis: Long, bytes: ByteArray, length: Int) {
        check(!closed) { "PCAP writer is closed." }
        val safeLength = length.coerceIn(0, bytes.size)
        rotateIfNeeded(safeLength)
        writer.writePacket(timestampMillis, bytes, safeLength)
        currentSegmentBytes += PCAP_PACKET_HEADER_BYTES + safeLength
    }

    fun segmentFiles(): List<File> = segments.toList()

    override fun close() {
        if (closed) return
        closed = true
        writer.close()
    }

    private fun rotateIfNeeded(packetLength: Int) {
        val nextRecordBytes = PCAP_PACKET_HEADER_BYTES + packetLength
        if (currentSegmentBytes <= PCAP_GLOBAL_HEADER_BYTES || currentSegmentBytes + nextRecordBytes <= segmentLimitBytes) return
        writer.close()
        val nextFile = nextSegmentFile()
        writer = openWriter(nextFile)
        writer.writeHeader()
        currentSegmentBytes = PCAP_GLOBAL_HEADER_BYTES
        segments += nextFile
        onSegmentStarted(nextFile)
    }

    private fun nextSegmentFile(): File {
        val name = firstOutputFile.nameWithoutExtension
        val extension = firstOutputFile.extension.ifBlank { "pcap" }
        val index = segments.size + 1
        return File(firstOutputFile.parentFile, "$name-part-${index.toString().padStart(3, '0')}.$extension")
    }

    private companion object {
        const val PCAP_GLOBAL_HEADER_BYTES = 24L
        const val PCAP_PACKET_HEADER_BYTES = 16L
        const val FILE_BUFFER_SIZE = 64 * 1024

        fun openWriter(file: File): RawPcapWriter =
            RawPcapWriter(BufferedOutputStream(file.outputStream(), FILE_BUFFER_SIZE))
    }
}
