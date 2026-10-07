// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class RotatingPcapWriterTest {
    @Test
    fun `rotation keeps each segment valid and preserves packet count`() {
        val directory = Files.createTempDirectory("rotating-pcap").toFile()
        val first = File(directory, "live.pcap")
        try {
            val started = mutableListOf<File>()
            RotatingPcapWriter(first, 24L + 16L + 4L + 1L) { started += it }.use { writer ->
                repeat(3) { index -> writer.writePacket(index.toLong() * 1000L, byteArrayOf(1, 2, 3, index.toByte()), 4) }
                assertEquals(3, writer.segmentFiles().size)
            }
            assertEquals(2, started.size)
            val files = listOf(first) + started
            assertEquals(3, files.size)
            files.forEach { file ->
                assertTrue(file.isFile)
                val bytes = file.readBytes()
                assertEquals(0xd4.toByte(), bytes[0])
                assertEquals(0xc3.toByte(), bytes[1])
                assertTrue(bytes.size >= 24 + 16 + 4)
            }
        } finally {
            directory.deleteRecursively()
        }
    }
}
