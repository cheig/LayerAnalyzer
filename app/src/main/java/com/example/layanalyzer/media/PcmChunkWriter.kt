// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Writes the `.pcmchunks` file the RTP4-NAT-07 renderer consumes (RTP4-KT-01).
 *
 * Layout, little-endian throughout, packed with no padding anywhere:
 *
 * ```
 *   "PCM1"            4 octets
 *   u32 sampleRate
 *   u16 channels
 *   block...          u32 fidxIndex, u32 samples, i16[samples * channels]
 * ```
 *
 * `samples` counts frames per channel, so a block carries
 * `samples * channels` signed 16-bit values interleaved channel by channel --
 * exactly the field-by-field layout `RtpMediaCodecRenderTest.writePcmChunks`
 * writes and `parse_pcm_chunks` in `jni/RtpJni.cpp` reads. That test is the
 * authority for this format; this writer must not drift from it.
 *
 * The header is written when the writer is constructed, so the header fields
 * are fixed for the file's lifetime: whoever builds the writer has to know the
 * final sample rate and channel count up front. (The decoder gets them from
 * `INFO_OUTPUT_FORMAT_CHANGED` before its first output buffer, so it can.)
 * [writeChunk] may be called any number of times and with blocks in any order;
 * `fidxIndex` is what ties a block back to its `.fidx` entry, not the file
 * order.
 *
 * [close] is idempotent and flushes before closing. An exception thrown by
 * [writeChunk] leaves the file valid up to the last complete block, which is
 * the caller's cue to delete it: a `.pcmchunks` file the renderer might accept
 * must never describe half a stream.
 */
class PcmChunkWriter(
    file: File,
    private val sampleRate: Int,
    private val channels: Int
) : Closeable {

    private val sink = BufferedOutputStream(FileOutputStream(file), BUFFER_BYTES)
    private var closed = false
    private var chunkCount = 0

    /** Number of complete blocks written so far. */
    val chunksWritten: Int
        get() = chunkCount

    init {
        require(sampleRate > 0) { "PCM chunk sample rate must be positive." }
        require(channels in MIN_CHANNELS..MAX_CHANNELS) {
            "PCM chunk channel count must be $MIN_CHANNELS or $MAX_CHANNELS."
        }
        val header = ByteBuffer.allocate(HEADER_BYTES.toInt())
            .order(ByteOrder.LITTLE_ENDIAN)
        header.put(MAGIC.toByteArray(Charsets.US_ASCII))
        header.putInt(sampleRate)
        header.putShort(channels.toShort())
        sink.write(header.array())
    }

    /**
     * Appends one block for `.fidx` entry [fidxIndex].
     *
     * [samples] is the block's interleaved 16-bit PCM; its length must be a whole
     * number of frames (a multiple of the channel count). An empty array is a
     * legal zero-frame block.
     */
    fun writeChunk(fidxIndex: Int, samples: ShortArray) {
        check(!closed) { "PCM chunk writer is already closed." }
        require(fidxIndex >= 0) { "PCM chunk index must not be negative." }
        require(samples.size % channels == 0) {
            "PCM chunk samples must be a whole number of frames."
        }

        val block = ByteBuffer
            .allocate(BLOCK_HEADER_BYTES + samples.size * BYTES_PER_SAMPLE)
            .order(ByteOrder.LITTLE_ENDIAN)
        block.putInt(fidxIndex)
        block.putInt(samples.size / channels)
        for (sample in samples) {
            block.putShort(sample)
        }
        sink.write(block.array())
        chunkCount++
    }

    override fun close() {
        if (closed) return
        closed = true
        sink.flush()
        sink.close()
    }

    companion object {
        const val MAGIC = "PCM1"

        /** Magic plus `u32 sampleRate` plus `u16 channels`. */
        const val HEADER_BYTES = 10L

        /** `u32 fidxIndex` plus `u32 samples`. */
        const val BLOCK_HEADER_BYTES = 8

        const val BYTES_PER_SAMPLE = 2

        private const val MIN_CHANNELS = 1
        private const val MAX_CHANNELS = 2
        private const val BUFFER_BYTES = 64 * 1024
    }
}
