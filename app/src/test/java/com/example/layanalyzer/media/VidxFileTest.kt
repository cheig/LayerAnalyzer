// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.IOException
import java.io.RandomAccessFile
import java.io.File

/**
 * RTP5-KT-01: the `.vidx` access-unit index format, octet by octet.
 *
 * The layout is frozen by `cards/m5.md`'s RTP5-NAT-03 section and
 * `task_rtp_m5_video.md` section 3.2, and the C++ half
 * (`app/src/main/cpp/layanalyzer/rtp/core/VidxFile.{h,cpp}`) plus its host test
 * (`native_build/verification/rtp/host_tests/lib/VidxFileTest.cpp`) are the
 * authority; the writer here and the reader here have to agree with *those*,
 * not merely with each other. So the byte-level case below is the same
 * hand-written octet array the host test spells out, and the round-trip case
 * uses the same values -- including the offset and length above 32 bits, which
 * are the difference between a 25-octet record and the 32 a struct copy would
 * write (`ptsUs` is a u64 between two u32s, so the natural declaration order is
 * exactly the one a compiler pads).
 *
 * The reader's fail-closed cases are the host test's too: a bad magic, a
 * truncated header, a count larger than the file can hold, a truncated record
 * and a missing file. A missing file throws [java.io.FileNotFoundException],
 * which is an [IOException] and is asserted as one.
 */
class VidxFileTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `record size is the frozen 25 octets`() {
        assertEquals(25L, VidxFile.RECORD_BYTES)
        assertEquals(8L, VidxFile.HEADER_BYTES)
        assertEquals(0x01, VidxFile.FLAG_KEY)
        assertEquals(0x02, VidxFile.FLAG_CORRUPT)
        assertEquals(0x04, VidxFile.FLAG_PARAM_SETS)
    }

    @Test
    fun `round trips every field including all flag bits`() {
        val written = listOf(
            VidxEntry(offset = 0, length = 7, ptsUs = 0, firstFrame = 12, flags = 0x00),
            VidxEntry(
                offset = 7,
                length = 7,
                ptsUs = 33_333,
                firstFrame = 13,
                flags = VidxFile.FLAG_KEY or VidxFile.FLAG_CORRUPT or VidxFile.FLAG_PARAM_SETS
            ),
            VidxEntry(offset = 14, length = 7, ptsUs = 66_666, firstFrame = 15, flags = VidxFile.FLAG_KEY),
            // Above 32 bits in both of the wide fields, and an offset that is
            // not a multiple of anything. `length` and `firstFrame` are u32 on
            // disk, so the last one round-trips as a negative Int.
            VidxEntry(
                offset = 0x1_0000_0001L,
                length = -2, // 0xFFFFFFFE as an Int
                ptsUs = 0x2_0000_0003L,
                firstFrame = -1, // 0xFFFFFFFF as an Int
                flags = VidxFile.FLAG_CORRUPT
            )
        )

        val file = outputFile()
        VidxFile.write(file, written)
        val read = VidxFile.read(file)

        assertEquals(written.size, read.entries.size)
        for (index in written.indices) {
            assertEquals("offset $index", written[index].offset, read.entries[index].offset)
            assertEquals("length $index", written[index].length, read.entries[index].length)
            assertEquals("ptsUs $index", written[index].ptsUs, read.entries[index].ptsUs)
            assertEquals(
                "firstFrame $index",
                written[index].firstFrame,
                read.entries[index].firstFrame
            )
            assertEquals("flags $index", written[index].flags, read.entries[index].flags)
        }
    }

    @Test
    fun `the flag bits are the C++ kVidxFlag constants`() {
        assertEquals(0x01, VidxFile.FLAG_KEY)
        assertTrue(entry(flags = VidxFile.FLAG_KEY).isKeyFrame)
        assertTrue(entry(flags = VidxFile.FLAG_CORRUPT).isCorrupt)
        assertTrue(entry(flags = VidxFile.FLAG_PARAM_SETS).hasParamSets)
        assertTrue(
            "all three bits at once",
            entry(
                flags = VidxFile.FLAG_KEY or VidxFile.FLAG_CORRUPT or VidxFile.FLAG_PARAM_SETS
            ).let { it.isKeyFrame && it.isCorrupt && it.hasParamSets }
        )
        assertTrue(!entry(flags = 0x00).isKeyFrame && !entry(flags = 0x00).isCorrupt)
    }

    /**
     * The whole file, spelled out. `write` produces 4 magic octets, the u32
     * count, then two packed 25-octet records -- and this is the array the host
     * test `VidxFileTest.cpp` checks the C++ writer against, so a Kotlin writer
     * that drifted would fail here with the same octets.
     */
    @Test
    fun `writes the frozen 25 octet record layout`() {
        val written = listOf(
            VidxEntry(
                offset = 0x0102_0304_0506_0708L,
                length = 0x0A0B_0C0D,
                ptsUs = 0x1112_1314_1516_1718L,
                firstFrame = 0x2122_2324,
                flags = 0x07
            ),
            VidxEntry(offset = 0, length = 0, ptsUs = 0, firstFrame = 0, flags = 0)
        )
        val file = outputFile()
        VidxFile.write(file, written)

        val bytes = file.readBytes()
        assertEquals(8 + 2 * VidxFile.RECORD_BYTES, bytes.size.toLong())

        val expected = byteArrayOf(
            // "VID1"
            0x56, 0x49, 0x44, 0x31,
            // u32 count = 2
            0x02, 0x00, 0x00, 0x00,
            // record 0 ...
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // u64 offset
            0x0D, 0x0C, 0x0B, 0x0A,                         // u32 len
            0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, // u64 ptsUs (after len)
            0x24, 0x23, 0x22, 0x21,                         // u32 firstFrame
            0x07,                                           // u8 flags
            // record 1: all zero
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
            0x00
        )
        assertArrayEquals(expected, bytes)
    }

    /**
     * The reader against hand-built octets, not against the writer: a writer
     * tested only through its own reader agrees with itself and can still
     * disagree with the format. Here every field is written by hand at its
     * documented offset and read back.
     */
    @Test
    fun `reads a hand-built file at the documented offsets`() {
        val bytes = ByteArray(8 + 25)
        // "VID1"
        bytes[0] = 'V'.code.toByte()
        bytes[1] = 'I'.code.toByte()
        bytes[2] = 'D'.code.toByte()
        bytes[3] = '1'.code.toByte()
        // u32 count = 1
        bytes[4] = 0x01
        // u64 offset = 0x00000000_00000402
        bytes[8] = 0x02
        bytes[9] = 0x04
        // u32 len = 0x00000301
        bytes[16] = 0x01
        bytes[17] = 0x03
        // u64 ptsUs = 0x000000000000A1B2 (the field after len)
        bytes[20] = 0xB2.toByte()
        bytes[21] = 0xA1.toByte()
        // u32 firstFrame = 0x0000007B
        bytes[28] = 0x7B
        // u8 flags = key | corrupt
        bytes[32] = 0x03

        val file = outputFile()
        RandomAccessFile(file, "rw").use { output ->
            output.write(bytes)
        }

        val entry = VidxFile.read(file).entries.single()
        assertEquals("u64 offset at octet 8", 0x402L, entry.offset)
        assertEquals("u32 len at octet 16", 0x301, entry.length)
        assertEquals("u64 ptsUs at octet 20", 0xA1B2L, entry.ptsUs)
        assertEquals("u32 firstFrame at octet 28", 0x7B, entry.firstFrame)
        assertEquals("u8 flags at octet 32", 0x03, entry.flags)
        assertTrue(entry.isKeyFrame)
        assertTrue(entry.isCorrupt)
    }

    @Test
    fun `round trips an empty entry list`() {
        val file = outputFile()
        VidxFile.write(file, emptyList())

        assertArrayEquals(
            byteArrayOf(0x56, 0x49, 0x44, 0x31, 0x00, 0x00, 0x00, 0x00),
            file.readBytes()
        )
        assertTrue(VidxFile.read(file).entries.isEmpty())
    }

    @Test
    fun `write replaces an existing file rather than appending to it`() {
        val file = outputFile()
        VidxFile.write(file, listOf(entry(), entry(), entry()))
        VidxFile.write(file, listOf(entry()))

        assertEquals(1, VidxFile.read(file).entries.size)
        assertEquals(8 + VidxFile.RECORD_BYTES, file.length())
    }

    @Test
    fun `rejects a bad magic`() {
        // A valid-looking header whose magic is one octet off.
        val file = outputFile()
        file.writeBytes(byteArrayOf(0x56, 0x49, 0x44, 0x32, 0x00, 0x00, 0x00, 0x00))

        assertThrows(IOException::class.java) { VidxFile.read(file) }
    }

    @Test
    fun `rejects a truncated header`() {
        val file = outputFile()
        // Fewer octets than the magic itself.
        file.writeBytes(byteArrayOf(0x56, 0x49))
        assertThrows(IOException::class.java) { VidxFile.read(file) }

        // Magic present, count cut in half.
        file.writeBytes(byteArrayOf(0x56, 0x49, 0x44, 0x31, 0x01, 0x00))
        assertThrows(IOException::class.java) { VidxFile.read(file) }
    }

    @Test
    fun `rejects a count larger than the file holds`() {
        val file = outputFile()
        VidxFile.write(file, listOf(entry()))
        val bytes = file.readBytes()
        assertEquals(8 + VidxFile.RECORD_BYTES, bytes.size.toLong())
        // Claim two records while only one is present.
        bytes[4] = 0x02
        file.writeBytes(bytes)

        assertThrows(IOException::class.java) { VidxFile.read(file) }
    }

    @Test
    fun `rejects an impossible count without allocating for it`() {
        // A count of 0xFFFFFFFF with no records behind it: the reader has to
        // reject it on the arithmetic rather than ask for four billion entries.
        val file = outputFile()
        file.writeBytes(
            byteArrayOf(
                0x56, 0x49, 0x44, 0x31,
                0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()
            )
        )

        assertThrows(IOException::class.java) { VidxFile.read(file) }
    }

    @Test
    fun `rejects a truncated record`() {
        val file = outputFile()
        VidxFile.write(file, listOf(entry()))
        val bytes = file.readBytes()
        // Drop the trailing flags octet of the only record.
        file.writeBytes(bytes.copyOf(bytes.size - 1))

        assertThrows(IOException::class.java) { VidxFile.read(file) }
    }

    @Test
    fun `fails closed on a missing file`() {
        val missing = File(tempFolder.newFolder(), "not-there.vidx")

        val error = assertThrows(IOException::class.java) { VidxFile.read(missing) }
        assertTrue(
            "a missing .vidx must be an IOException: ${error.javaClass.name}",
            error is IOException
        )
    }

    private fun outputFile(): File = File(tempFolder.newFolder(), "s4.vidx")

    private fun entry(flags: Int = 0): VidxEntry =
        VidxEntry(offset = 0, length = 4, ptsUs = 0, firstFrame = 1, flags = flags)
}
