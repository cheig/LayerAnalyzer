// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Copies packet bytes, never dissector plaintext. Removes every pcapng DSB, in every section. */
internal object TlsRawCaptureWriter {
    fun copy(input: InputStream, output: OutputStream, checkCancelled: () -> Unit = {}): Long {
        val source = DataInputStream(input.buffered())
        val magic = ByteArray(4).also(source::readFully)
        return if (magic.contentEquals(byteArrayOf(10, 13, 13, 10))) {
            copyPcapng(source, output, magic, checkCancelled)
        } else {
            val header = magic + ByteArray(20).also(source::readFully)
            val parsed = PcapGlobalHeader.parse(header)
            output.write(header)
            var frames = 0L
            val buffer = ByteArray(64 * 1024)
            while (true) {
                checkCancelled()
                val first = source.read()
                if (first == -1) break
                val record = ByteArray(16)
                record[0] = first.toByte()
                source.readFully(record, 1, 15)
                val length = parsed.unsignedInt(record, 8)
                require(length <= PcapGlobalHeader.MAX_SNAPLEN && length <= parsed.unsignedInt(record, 12))
                require(parsed.snaplen == 0L || length <= parsed.snaplen)
                output.write(record)
                var remaining = length
                while (remaining > 0) {
                    checkCancelled()
                    val size = minOf(remaining, buffer.size.toLong()).toInt()
                    source.readFully(buffer, 0, size)
                    output.write(buffer, 0, size)
                    remaining -= size
                }
                frames++
            }
            frames
        }
    }

    private fun copyPcapng(input: DataInputStream, output: OutputStream, first: ByteArray, check: () -> Unit): Long {
        var typeBytes = first
        var order = ByteOrder.LITTLE_ENDIAN
        var frames = 0L
        while (true) {
            check()
            val prefix = typeBytes + ByteArray(8).also(input::readFully)
            val section = typeBytes.contentEquals(byteArrayOf(10, 13, 13, 10))
            if (section) {
                order = when {
                    prefix.copyOfRange(8, 12).contentEquals(byteArrayOf(0x4d, 0x3c, 0x2b, 0x1a)) -> ByteOrder.LITTLE_ENDIAN
                    prefix.copyOfRange(8, 12).contentEquals(byteArrayOf(0x1a, 0x2b, 0x3c, 0x4d)) -> ByteOrder.BIG_ENDIAN
                    else -> error("INVALID_PCAPNG")
                }
            }
            val view = ByteBuffer.wrap(prefix).order(order)
            val type = view.getInt(0)
            val length = view.getInt(4)
            require(length in (if (section) 28 else 12)..(16 * 1024 * 1024 + 1024) && length % 4 == 0)
            val block = prefix + ByteArray(length - 12).also(input::readFully)
            require(ByteBuffer.wrap(block).order(order).getInt(length - 4) == length)
            if (section) {
                // Removing a DSB changes section size; use the standard unspecified length.
                ByteBuffer.wrap(block).order(order).putLong(16, -1L)
            }
            if (type != 0x0000000a) output.write(block)
            if (type == 6 || type == 2 || type == 3) frames++
            val next = input.read()
            if (next == -1) break
            typeBytes = ByteArray(4)
            typeBytes[0] = next.toByte()
            input.readFully(typeBytes, 1, 3)
        }
        return frames
    }
}
