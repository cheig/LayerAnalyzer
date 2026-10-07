// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

object PeaksFile {
    data class Header(
        val sampleRate: Int,
        val samplesPerBucket: Int,
        val count: Int
    )

    fun read(file: File): Pair<Header, ShortArray> {
        val bytes = file.readBytes()
        require(bytes.size >= HEADER_BYTES) { "Peaks file is too short." }

        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        requireMagic(buffer, "PKS1", "peaks")
        val sampleRate = requirePositiveInt(buffer.int, "Peaks sample rate")
        val samplesPerBucket = requirePositiveInt(
            buffer.int,
            "Peaks samples-per-bucket"
        )
        val count = requireCount(buffer.int, "Peaks bucket")
        require(count <= Int.MAX_VALUE / 2) { "Peaks bucket count is too large." }

        val expectedBytes = HEADER_BYTES.toLong() + count.toLong() * 4L
        require(bytes.size.toLong() == expectedBytes) {
            "Peaks file size does not match its header."
        }

        val values = ShortArray(count * 2)
        for (index in values.indices) {
            values[index] = buffer.short
        }
        return Header(sampleRate, samplesPerBucket, count) to values
    }

    private const val HEADER_BYTES = 16
}

object FrameMapFile {
    data class Entry(val atMs: Long, val frame: Long)

    fun read(file: File): List<Entry> {
        val bytes = file.readBytes()
        require(bytes.size >= HEADER_BYTES) { "Frame map file is too short." }

        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        requireMagic(buffer, "MAP1", "frame map")
        val count = requireCount(buffer.int, "Frame map")

        val expectedBytes = HEADER_BYTES.toLong() + count.toLong() * ENTRY_BYTES
        require(bytes.size.toLong() == expectedBytes) {
            "Frame map file size does not match its header."
        }

        return buildList(count) {
            repeat(count) {
                add(
                    Entry(
                        atMs = unsignedInt(buffer.int),
                        frame = unsignedInt(buffer.int)
                    )
                )
            }
        }
    }

    private const val HEADER_BYTES = 8
    private const val ENTRY_BYTES = 8L
}

fun FrameMapFile.frameAt(ms: Long, entries: List<FrameMapFile.Entry>): Long? {
    if (entries.isEmpty()) return null
    if (ms <= entries.first().atMs) return entries.first().frame
    if (ms >= entries.last().atMs) return entries.last().frame

    var low = 0
    var high = entries.lastIndex
    while (low <= high) {
        val middle = (low + high).ushr(1)
        if (entries[middle].atMs <= ms) {
            low = middle + 1
        } else {
            high = middle - 1
        }
    }
    return entries[high].frame
}

object WavHeader {
    data class Info(
        val sampleRate: Int,
        val channels: Int,
        val bitsPerSample: Int,
        val dataBytes: Long,
        val frameCount: Long
    )

    fun parse(file: File): Info? = runCatching {
        RandomAccessFile(file, "r").use { input ->
            if (input.length() < RIFF_HEADER_BYTES) return@use null
            if (readFourCc(input) != "RIFF") return@use null

            val riffSize = readUnsignedInt(input)
            val riffEnd = 8L + riffSize
            if (riffEnd > input.length()) return@use null
            if (readFourCc(input) != "WAVE") return@use null

            var format: PcmFormat? = null
            var dataBytes: Long? = null
            var offset = RIFF_HEADER_BYTES
            while (offset + CHUNK_HEADER_BYTES <= riffEnd) {
                input.seek(offset)
                val chunkId = readFourCc(input) ?: return@use null
                val chunkSize = readUnsignedInt(input)
                val chunkDataStart = offset + CHUNK_HEADER_BYTES
                val chunkDataEnd = chunkDataStart + chunkSize
                if (chunkDataEnd < chunkDataStart || chunkDataEnd > riffEnd) {
                    return@use null
                }

                when (chunkId) {
                    "fmt " -> {
                        if (chunkSize < PCM_FMT_BYTES) return@use null
                        format = readPcmFormat(input)
                    }

                    "data" -> {
                        if (dataBytes == null) dataBytes = chunkSize
                    }
                }

                offset = chunkDataEnd + (chunkSize and 1L)
            }

            val pcm = format ?: return@use null
            val payloadBytes = dataBytes ?: return@use null
            if (pcm.audioFormat != PCM_FORMAT ||
                pcm.channels <= 0 ||
                pcm.sampleRate <= 0L ||
                pcm.bitsPerSample <= 0 ||
                pcm.bitsPerSample % 8 != 0
            ) {
                return@use null
            }

            val blockAlign = pcm.channels * (pcm.bitsPerSample / 8)
            if (pcm.blockAlign != blockAlign ||
                payloadBytes % blockAlign.toLong() != 0L
            ) {
                return@use null
            }

            Info(
                sampleRate = pcm.sampleRate.toInt(),
                channels = pcm.channels,
                bitsPerSample = pcm.bitsPerSample,
                dataBytes = payloadBytes,
                frameCount = payloadBytes / blockAlign
            )
        }
    }.getOrNull()

    private fun readPcmFormat(input: RandomAccessFile): PcmFormat =
        PcmFormat(
            audioFormat = readUnsignedShort(input),
            channels = readUnsignedShort(input),
            sampleRate = readUnsignedInt(input),
            byteRate = readUnsignedInt(input),
            blockAlign = readUnsignedShort(input),
            bitsPerSample = readUnsignedShort(input)
        )

    private data class PcmFormat(
        val audioFormat: Int,
        val channels: Int,
        val sampleRate: Long,
        val byteRate: Long,
        val blockAlign: Int,
        val bitsPerSample: Int
    )

    private const val RIFF_HEADER_BYTES = 12L
    private const val CHUNK_HEADER_BYTES = 8L
    private const val PCM_FMT_BYTES = 16L
    private const val PCM_FORMAT = 1
}

private fun requireMagic(
    buffer: ByteBuffer,
    expected: String,
    formatName: String
) {
    val bytes = ByteArray(expected.length)
    buffer.get(bytes)
    val actual = String(bytes, Charsets.US_ASCII)
    require(actual == expected) {
        "Invalid $formatName magic: expected $expected, found $actual."
    }
}

private fun requirePositiveInt(value: Int, field: String): Int {
    require(value > 0) { "$field must be positive." }
    return value
}

private fun requireCount(value: Int, field: String): Int {
    require(value >= 0) { "$field count must not be negative." }
    return value
}

private fun unsignedInt(value: Int): Long = value.toLong() and 0xffffffffL

private fun readFourCc(input: RandomAccessFile): String? {
    val bytes = ByteArray(4)
    return if (input.read(bytes) == bytes.size) {
        String(bytes, Charsets.US_ASCII)
    } else {
        null
    }
}

private fun readUnsignedShort(input: RandomAccessFile): Int {
    val low = input.read()
    val high = input.read()
    if (low < 0 || high < 0) throw IllegalStateException("Unexpected end of file.")
    return low or (high shl 8)
}

private fun readUnsignedInt(input: RandomAccessFile): Long {
    val low = readUnsignedShort(input).toLong()
    val high = readUnsignedShort(input).toLong()
    return low or (high shl 16)
}
