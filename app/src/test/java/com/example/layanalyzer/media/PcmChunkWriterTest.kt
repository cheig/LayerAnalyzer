package com.example.layanalyzer.media

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * RTP4-KT-01: the `.pcmchunks` file format, field by field.
 *
 * The reader below is a second, independent implementation of the layout, not a
 * call into [PcmChunkWriter]: `RtpMediaCodecRenderTest.writePcmChunks` and
 * `parse_pcm_chunks` in `jni/RtpJni.cpp` are the other two, and a writer tested
 * through its own reader would agree with itself while disagreeing with both.
 * The octet offsets here are spelled out for the same reason -- if the writer
 * ever reorders a field, this test has to notice.
 *
 *  - magic        0..3     `"PCM1"`
 *  - sampleRate   4..7     u32 little-endian
 *  - channels     8..9     u16 little-endian
 *  - block        10..     u32 fidxIndex, u32 samples, i16[samples * channels]
 *
 * `samples` counts frames per channel, so the payload is
 * `samples * channels * 2` octets and the whole file is exactly
 * `10 + sum(8 + payload)`.
 */
class PcmChunkWriterTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `header carries the sample rate and the channel count`() {
        val file = outputFile()
        PcmChunkWriter(file, sampleRate = 16_000, channels = 1).close()

        val parsed = readPcmChunks(file)
        assertEquals("PCM1", parsed.magic)
        assertEquals(16_000, parsed.sampleRate)
        assertEquals(1, parsed.channels)
        assertEquals(emptyList<Int>(), parsed.blocks.map { it.samples })
        assertEquals(HEADER_BYTES.toLong(), file.length())
    }

    @Test
    fun `mono block round trips every sample and its index`() {
        val file = outputFile()
        val samples = ShortArray(160) { index -> (index * 7 - 300).toShort() }
        PcmChunkWriter(file, SAMPLE_RATE, 1).use { writer ->
            writer.writeChunk(fidxIndex = 4, samples = samples)
        }

        val parsed = readPcmChunks(file)
        assertEquals(SAMPLE_RATE, parsed.sampleRate)
        assertEquals(1, parsed.channels)
        assertEquals(1, parsed.blocks.size)
        val block = parsed.blocks.single()
        assertEquals(4, block.fidxIndex)
        assertEquals(160, block.samples)
        assertArrayEquals(samples, block.values)
    }

    @Test
    fun `stereo block round trips interleaved samples`() {
        val file = outputFile()
        // Left ramps up and right ramps down, so a reader that dropped or
        // swapped a channel is visible in the payload.
        val samples = ShortArray(320) { position ->
            if (position % 2 == 0) (position / 2).toShort()
            else (2_000 - position / 2).toShort()
        }
        PcmChunkWriter(file, 48_000, 2).use { writer ->
            writer.writeChunk(fidxIndex = 0, samples = samples)
        }

        val parsed = readPcmChunks(file)
        assertEquals(48_000, parsed.sampleRate)
        assertEquals(2, parsed.channels)
        val block = parsed.blocks.single()
        assertEquals("samples counts frames, not shorts", 160, block.samples)
        assertEquals(320, block.values.size)
        assertArrayEquals(samples, block.values)
    }

    @Test
    fun `blocks keep the order they were written in, whatever their index`() {
        val file = outputFile()
        val payloads = listOf(
            ShortArray(8) { 11 },
            ShortArray(16) { 22 },
            ShortArray(24) { 33 }
        )
        // Deliberately out of order: `fidxIndex` is what ties a block back to
        // its `.fidx` entry, and the file order must stay the write order.
        val indices = listOf(2, 0, 1)
        PcmChunkWriter(file, SAMPLE_RATE, 1).use { writer ->
            for (position in indices.indices) {
                writer.writeChunk(indices[position], payloads[position])
            }
        }

        val parsed = readPcmChunks(file)
        assertEquals(indices, parsed.blocks.map { it.fidxIndex })
        assertEquals(listOf(8, 16, 24), parsed.blocks.map { it.samples })
        for (position in indices.indices) {
            assertArrayEquals(payloads[position], parsed.blocks[position].values)
        }
    }

    @Test
    fun `an empty block list writes only the header`() {
        val file = outputFile()
        PcmChunkWriter(file, 8_000, 1).use { }

        val parsed = readPcmChunks(file)
        assertTrue("no block may follow an empty chunk list", parsed.blocks.isEmpty())
        assertEquals(HEADER_BYTES.toLong(), file.length())
    }

    @Test
    fun `a zero frame block is a header with no payload`() {
        val file = outputFile()
        PcmChunkWriter(file, 8_000, 1).use { writer ->
            writer.writeChunk(fidxIndex = 0, samples = ShortArray(0))
        }

        val parsed = readPcmChunks(file)
        val block = parsed.blocks.single()
        assertEquals(0, block.fidxIndex)
        assertEquals(0, block.samples)
        assertEquals(0, block.values.size)
        assertEquals(
            HEADER_BYTES + BLOCK_HEADER_BYTES.toLong(),
            file.length()
        )
    }

    @Test
    fun `chunksWritten counts the blocks written`() {
        val file = outputFile()
        PcmChunkWriter(file, 8_000, 1).use { writer ->
            assertEquals(0, writer.chunksWritten)
            writer.writeChunk(0, ShortArray(2))
            writer.writeChunk(1, ShortArray(2))
            assertEquals(2, writer.chunksWritten)
        }
    }

    @Test
    fun `close is idempotent and later writes are rejected`() {
        val file = outputFile()
        val writer = PcmChunkWriter(file, 8_000, 1)
        writer.writeChunk(0, ShortArray(4))
        writer.close()
        writer.close()

        assertEquals(1, readPcmChunks(file).blocks.size)
        assertThrows(IllegalStateException::class.java) {
            writer.writeChunk(1, ShortArray(4))
        }
    }

    @Test
    fun `a partial frame is rejected instead of being written`() {
        val file = outputFile()
        PcmChunkWriter(file, 8_000, 2).use { writer ->
            assertThrows(IllegalArgumentException::class.java) {
                writer.writeChunk(0, ShortArray(3))
            }
            assertEquals(0, writer.chunksWritten)
        }
        assertTrue("nothing may be written for a rejected block",
            readPcmChunks(file).blocks.isEmpty())
    }

    // ------------------------------------------------------- independent reader

    private class ParsedFile(
        val magic: String,
        val sampleRate: Int,
        val channels: Int,
        val blocks: List<ParsedBlock>
    )

    private class ParsedBlock(
        val fidxIndex: Int,
        val samples: Int,
        val values: ShortArray
    )

    /** Reads the layout as documented at the top of this file, octet by octet. */
    private fun readPcmChunks(file: File): ParsedFile {
        val bytes = file.readBytes()
        assertTrue(
            "a `.pcmchunks` file is never shorter than its 10 octet header",
            bytes.size >= HEADER_BYTES.toInt()
        )
        val magic = String(bytes, 0, 4, Charsets.US_ASCII)
        val sampleRate = littleEndianInt(bytes, 4)
        val channels = littleEndianUnsignedShort(bytes, 8)

        val blocks = mutableListOf<ParsedBlock>()
        var offset = HEADER_BYTES.toInt()
        while (offset < bytes.size) {
            assertTrue(
                "truncated block header at $offset",
                bytes.size - offset >= BLOCK_HEADER_BYTES
            )
            val fidxIndex = littleEndianInt(bytes, offset)
            val samples = littleEndianInt(bytes, offset + 4)
            offset += BLOCK_HEADER_BYTES
            val payloadBytes = samples * channels * 2
            assertTrue(
                "block $fidxIndex declares more payload than the file holds",
                bytes.size - offset >= payloadBytes
            )
            val values = ShortArray(samples * channels) { sample ->
                littleEndianShort(bytes, offset + sample * 2)
            }
            offset += payloadBytes
            blocks += ParsedBlock(fidxIndex, samples, values)
        }
        assertEquals("reader and writer disagree about the file length",
            bytes.size, offset)
        return ParsedFile(magic, sampleRate, channels, blocks)
    }

    private fun littleEndianInt(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)

    private fun littleEndianUnsignedShort(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8)

    private fun littleEndianShort(bytes: ByteArray, offset: Int): Short =
        littleEndianUnsignedShort(bytes, offset).toShort()

    private fun outputFile(): File =
        File(tempFolder.newFolder(), "s3.pcmchunks")

    private companion object {
        const val SAMPLE_RATE = 8_000
        const val HEADER_BYTES = 10L
        const val BLOCK_HEADER_BYTES = 8
    }
}
