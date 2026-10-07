// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

/**
 * One `.fidx` record (RTP4-KT-01).
 *
 * Field names, order and types mirror the C++ `layanalyzer::rtp::FidxEntry` in
 * `app/src/main/cpp/layanalyzer/rtp/core/FidxFile.h`, which is the authority for
 * the on-disk layout: the two sides must agree octet for octet.
 *
 *  - [offset]     absolute byte offset of the frame inside the `.frames` blob
 *  - [length]     frame length in octets (0 for a lost frame)
 *  - [frame]      capture frame number
 *  - [extTs]      RTP timestamp (a 64-bit field on disk, not a wrapped u32)
 *  - [arrivalRel] arrival time relative to capture frame 0, seconds
 *  - [flags]      bit field, see [FidxFile.FLAG_LOST] / [FidxFile.FLAG_SID] /
 *                 [FidxFile.FLAG_LATE]
 */
data class FidxEntry(
    val offset: Long,
    val length: Int,
    val frame: Long,
    val extTs: Long,
    val arrivalRel: Double,
    val flags: Int
)

/** A `lost` entry holds no frame data at all: the slot is a gap, not a frame. */
val FidxEntry.isLost: Boolean
    get() = flags and FidxFile.FLAG_LOST != 0

/**
 * Reads the `.fidx` frame index RTP4-NAT-06 writes and RTP4-NAT-07 consumes.
 *
 * Layout, little-endian throughout, packed with no padding anywhere:
 *
 * ```
 *   "FID1"            4 octets
 *   u32 count         number of records that follow
 *   count x record    33 octets each, in this order:
 *                       u64 offset, u32 len, u32 frame, u64 extTs,
 *                       f64 arrivalRel, u8 flags
 * ```
 *
 * The 33 octets are exact (8 + 4 + 4 + 8 + 8 + 1). Every field is read octet by
 * octet rather than by copying a struct, because a struct would silently pick up
 * whatever padding the compilers chose and the host and the Android ABIs are not
 * required to agree on any of it.
 *
 * [read] fails closed -- it throws [IOException], it never returns a partially
 * populated index -- on a missing or unreadable file, a truncated header, a bad
 * magic, and a declared record count the file cannot hold (which is also what a
 * truncated record reports). Octets beyond the declared count are ignored, the
 * same way the C++ reader ignores them.
 */
class FidxFile(val entries: List<FidxEntry>) {

    companion object {
        /** Magic of the index file. */
        const val MAGIC = "FID1"

        /** Octets before the first record: magic plus the `u32` record count. */
        const val HEADER_BYTES = 8L

        /** Octets per packed record. Deliberately not a struct size. */
        const val RECORD_BYTES = 33L

        /** `flags` bits, matching the C++ `kFidxFlag*` constants. */
        const val FLAG_LOST = 0x01
        const val FLAG_SID = 0x02
        const val FLAG_LATE = 0x04

        /** Reads [file] into a new index, or throws [IOException]. */
        fun read(file: File): FidxFile {
            RandomAccessFile(file, "r").use { input ->
                val fileSize = input.length()
                if (fileSize < HEADER_BYTES) {
                    throw IOException("Truncated FIDX header.")
                }

                val magic = ByteArray(MAGIC.length)
                input.readFully(magic)
                if (String(magic, Charsets.US_ASCII) != MAGIC) {
                    throw IOException("Invalid FIDX magic.")
                }

                val count = readLittleEndianU32(input)
                // Reject a count the file cannot hold before allocating for it.
                // A truncated record reports the same error, which is what the
                // caller sees either way.
                val available = fileSize - HEADER_BYTES
                if (count > available / RECORD_BYTES || count > Int.MAX_VALUE) {
                    throw IOException("Truncated FIDX record.")
                }

                val entries = ArrayList<FidxEntry>(count.toInt())
                repeat(count.toInt()) {
                    entries += FidxEntry(
                        offset = readLittleEndianU64(input),
                        length = readLittleEndianU32(input).toInt(),
                        frame = readLittleEndianU32(input),
                        extTs = readLittleEndianU64(input),
                        arrivalRel = Double.fromBits(readLittleEndianU64(input)),
                        flags = input.readUnsignedByte()
                    )
                }
                return FidxFile(entries)
            }
        }

        private fun readLittleEndianU32(input: RandomAccessFile): Long {
            val bytes = ByteArray(4)
            input.readFully(bytes)
            return (bytes[0].toLong() and 0xffL) or
                ((bytes[1].toLong() and 0xffL) shl 8) or
                ((bytes[2].toLong() and 0xffL) shl 16) or
                ((bytes[3].toLong() and 0xffL) shl 24)
        }

        private fun readLittleEndianU64(input: RandomAccessFile): Long {
            val bytes = ByteArray(8)
            input.readFully(bytes)
            var value = 0L
            for (index in bytes.indices) {
                value = value or ((bytes[index].toLong() and 0xffL) shl (index * 8))
            }
            return value
        }
    }
}
