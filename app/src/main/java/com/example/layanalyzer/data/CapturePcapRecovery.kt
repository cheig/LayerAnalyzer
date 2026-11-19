// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsAssetException
import java.io.File
import java.io.RandomAccessFile

/** Bounded scan; only an incomplete last record may be removed. Invalid complete headers fail. */
internal object CapturePcapRecovery {
    fun recover(file: File): Long {
        CaptureFiles.checkTree(file)
        RandomAccessFile(file, "rw").use { input ->
            if (input.length() < PcapGlobalHeader.SIZE) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            val header = PcapGlobalHeader.parse(ByteArray(PcapGlobalHeader.SIZE).also(input::readFully))
            if (header.versionMajor != 2 || header.versionMinor != 4 || header.snaplen == 0L)
                throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            var end = PcapGlobalHeader.SIZE.toLong()
            var frames = 0L
            val record = ByteArray(16)
            while (end < input.length()) {
                if (input.length() - end < record.size) break
                input.readFully(record)
                val fraction = header.unsignedInt(record, 4)
                val included = header.unsignedInt(record, 8)
                val original = header.unsignedInt(record, 12)
                if (included > header.snaplen || included > original ||
                    fraction >= if (header.nanosecondResolution) 1_000_000_000L else 1_000_000L)
                    throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
                if (input.length() - end - record.size < included) break
                end += record.size + included
                frames++
                input.seek(end)
            }
            if (end != input.length()) {
                input.setLength(end)
                input.fd.sync()
            }
            return frames
        }
    }
}
