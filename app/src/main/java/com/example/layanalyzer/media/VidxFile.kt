// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

/**
 * One `.vidx` record (RTP5-NAT-03).
 *
 * Field names, order and types mirror the C++ `layanalyzer::rtp::VidxEntry` in
 * `app/src/main/cpp/layanalyzer/rtp/core/VidxFile.h`, which is the authority for
 * the on-disk layout: the two sides must agree octet for octet.
 *
 *  - [offset]     absolute byte offset of the access unit inside the ES file
 *  - [length]     access-unit length in octets (Annex-B, start codes included)
 *  - [ptsUs]      presentation time, microseconds, as the capture's own clock
 *  - [firstFrame] capture frame number of the access unit's first packet
 *  - [flags]      bit field, see [VidxFile.FLAG_KEY] / [VidxFile.FLAG_CORRUPT] /
 *                 [VidxFile.FLAG_PARAM_SETS]
 */
data class VidxEntry(
    val offset: Long,
    val length: Int,
    val ptsUs: Long,
    val firstFrame: Int,
    val flags: Int
)

/** The access unit holds an IDR (H.264) or an IRAP (H.265) NAL. */
val VidxEntry.isKeyFrame: Boolean
    get() = flags and VidxFile.FLAG_KEY != 0

/** A packet of this access unit was lost, so its NAL sequence is incomplete. */
val VidxEntry.isCorrupt: Boolean
    get() = flags and VidxFile.FLAG_CORRUPT != 0

/** This access unit is the SDP parameter sets NAT-03 injected at the front. */
val VidxEntry.hasParamSets: Boolean
    get() = flags and VidxFile.FLAG_PARAM_SETS != 0

/**
 * Reads (and writes) the `.vidx` access-unit index RTP5-NAT-05 produces and
 * RTP5-KT-01 / RTP5-KT-03 consume. It is the Kotlin mirror of
 * `layanalyzer/rtp/core/VidxFile.{h,cpp}` and deliberately reads like
 * [FidxFile], the other binary index in this package.
 *
 * Layout, little-endian throughout, packed with no padding or alignment
 * anywhere:
 *
 * ```
 *   "VID1"            4 octets
 *   u32 count         number of records that follow
 *   count x record    25 octets each, in this order:
 *                       u64 offset, u32 len, u64 ptsUs, u32 firstFrame,
 *                       u8 flags
 * ```
 *
 * The 25 octets are exact (8 + 4 + 8 + 4 + 1). Every field is read and written
 * octet by octet rather than by copying a struct: the C++ side spells out why
 * (`VidxFile.h`), and it is worth repeating because this layout is worse than
 * `.fidx`'s -- `ptsUs` is a u64 sitting between two u32s, so the natural
 * declaration order is exactly the one a compiler pads, and a struct copy would
 * be 32 octets per record where the format says 25. The byte-level test
 * (`VidxFileTest`) pins the octets themselves, and it pins them against the
 * same hand-written octet array the host test `VidxFileTest.cpp` uses, so a
 * change that breaks one breaks both.
 *
 * [read] fails closed -- it throws [IOException], it never returns a partially
 * populated index -- on a missing or unreadable file, a bad magic, a truncated
 * header, and a declared record count the file cannot hold (which is also what
 * a truncated record reports). Octets beyond the declared count are ignored,
 * the same way the C++ reader ignores them. [write] mirrors the C++ writer: it
 * removes the file it was writing when anything goes wrong, so a caller never
 * finds half an index.
 *
 * `count` is a `u32` on disk and an `Int` here, so the C++ writer's "more
 * records than the count field can hold" guard has no Kotlin counterpart: no
 * `List` in this process can be longer than `Int.MAX_VALUE`.
 */
class VidxFile(val entries: List<VidxEntry>) {

    companion object {
        /** Magic of the index file. */
        const val MAGIC = "VID1"

        /** Octets before the first record: magic plus the `u32` record count. */
        const val HEADER_BYTES = 8L

        /** Octets per packed record. Deliberately not a struct size. */
        const val RECORD_BYTES = 25L

        /** `flags` bits, matching the C++ `kVidxFlag*` constants. */
        const val FLAG_KEY = 0x01
        const val FLAG_CORRUPT = 0x02
        const val FLAG_PARAM_SETS = 0x04

        /** Reads [file] into a new index, or throws [IOException]. */
        fun read(file: File): VidxFile {
            RandomAccessFile(file, "r").use { input ->
                val fileSize = input.length()
                if (fileSize < HEADER_BYTES) {
                    throw IOException("Truncated VIDX header.")
                }

                val magic = ByteArray(MAGIC.length)
                input.readFully(magic)
                if (String(magic, Charsets.US_ASCII) != MAGIC) {
                    throw IOException("Invalid VIDX magic.")
                }

                val count = readLittleEndianU32(input)
                // Reject a count the file cannot hold before allocating for it.
                // A truncated record reports the same error, which is what the
                // caller sees either way.
                val available = fileSize - HEADER_BYTES
                if (count > available / RECORD_BYTES || count > Int.MAX_VALUE) {
                    throw IOException("Truncated VIDX record.")
                }

                val entries = ArrayList<VidxEntry>(count.toInt())
                repeat(count.toInt()) {
                    entries += VidxEntry(
                        offset = readLittleEndianU64(input),
                        length = readLittleEndianU32(input).toInt(),
                        ptsUs = readLittleEndianU64(input),
                        firstFrame = readLittleEndianU32(input).toInt(),
                        flags = input.readUnsignedByte()
                    )
                }
                return VidxFile(entries)
            }
        }

        /**
         * Writes `"VID1"`, the count and every record to [file], replacing
         * whatever was there, and returns the index it wrote.
         *
         * This is the other half of the mirror: RTP5-KT-03's binary search wants
         * to read an index, but the instrumented tests need one to read, and
         * hand-building the octets in every test would test the reader against
         * a second private copy of the layout instead of against this one. It
         * is not used by production code -- RTP5-NAT-05 writes `.vidx` natively
         * -- and it fails closed the way the C++ writer does: any failure
         * removes the file rather than leaving a partial index behind.
         *
         * A record's `length`/`firstFrame` are written as the low 32 bits of
         * their `Int`, which is the same bit pattern the C++ side's `uint32_t`
         * holds; a negative `Int` therefore round-trips.
         */
        fun write(file: File, entries: List<VidxEntry>): VidxFile {
            try {
                RandomAccessFile(file, "rw").use { output ->
                    output.setLength(0L)
                    output.write(MAGIC.toByteArray(Charsets.US_ASCII))
                    writeLittleEndianU32(output, entries.size.toLong())
                    for (entry in entries) {
                        writeLittleEndianU64(output, entry.offset)
                        writeLittleEndianU32(output, entry.length.toLong())
                        writeLittleEndianU64(output, entry.ptsUs)
                        writeLittleEndianU32(output, entry.firstFrame.toLong())
                        output.write(entry.flags and 0xff)
                    }
                }
            } catch (error: Exception) {
                file.delete()
                throw error
            }
            return VidxFile(entries.toList())
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

        private fun writeLittleEndianU32(output: RandomAccessFile, value: Long) {
            for (index in 0 until 4) {
                output.write(((value shr (index * 8)) and 0xffL).toInt())
            }
        }

        private fun writeLittleEndianU64(output: RandomAccessFile, value: Long) {
            for (index in 0 until 8) {
                output.write(((value shr (index * 8)) and 0xffL).toInt())
            }
        }
    }
}
