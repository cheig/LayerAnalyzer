// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import java.io.Closeable
import java.io.OutputStream

class RawPcapWriter(private val output: OutputStream) : Closeable {
    fun writeHeader() {
        writeIntLE(0xa1b2c3d4.toInt())
        writeShortLE(2)
        writeShortLE(4)
        writeIntLE(0)
        writeIntLE(0)
        writeIntLE(65535)
        writeIntLE(LINKTYPE_RAW)
    }

    fun writePacket(timestampMillis: Long, bytes: ByteArray, length: Int) {
        val seconds = timestampMillis / 1000L
        val micros = (timestampMillis % 1000L) * 1000L
        writeIntLE(seconds.toInt())
        writeIntLE(micros.toInt())
        writeIntLE(length)
        writeIntLE(length)
        output.write(bytes, 0, length)
    }

    private fun writeShortLE(value: Int) {
        output.write(value and 0xff)
        output.write((value ushr 8) and 0xff)
    }

    private fun writeIntLE(value: Int) {
        output.write(value and 0xff)
        output.write((value ushr 8) and 0xff)
        output.write((value ushr 16) and 0xff)
        output.write((value ushr 24) and 0xff)
    }

    override fun close() {
        output.flush()
        output.close()
    }

    private companion object {
        const val LINKTYPE_RAW = 101
    }
}
