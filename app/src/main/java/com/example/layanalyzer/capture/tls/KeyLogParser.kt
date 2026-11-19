// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import java.io.IOException
import java.io.InputStream
import java.util.Collections
import java.util.Locale

/** Fixed labels used by the TLS-002 fixtures and the initial TLS 1.2/1.3 implementation. */
enum class KeyLogLabel(val wireName: String) {
    CLIENT_RANDOM("CLIENT_RANDOM"),
    CLIENT_HANDSHAKE_TRAFFIC_SECRET("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
    SERVER_HANDSHAKE_TRAFFIC_SECRET("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
    CLIENT_TRAFFIC_SECRET_0("CLIENT_TRAFFIC_SECRET_0"),
    SERVER_TRAFFIC_SECRET_0("SERVER_TRAFFIC_SECRET_0"),
    EXPORTER_SECRET("EXPORTER_SECRET");

    internal fun acceptsSecretBytes(size: Int): Boolean =
        if (this == CLIENT_RANDOM) size == 48 else size == 32 || size == 48 || size == 64

    companion object {
        fun fromWire(value: String): KeyLogLabel? = entries.firstOrNull { it.wireName == value }
    }
}

/** Validated, lowercase hex. This object is secret material, never an event or log DTO. */
class KeyLogRecord internal constructor(
    val label: KeyLogLabel,
    val clientRandomHex: String,
    val secretHex: String
) {
    /** Explicit secret export for the encrypted store/private analysis lease; no trailing LF. */
    fun toNssLine(): String = "${label.wireName} $clientRandomHex $secretHex"

    val encodedSizeBytes: Int get() = label.wireName.length + 2 + clientRandomHex.length + secretHex.length

    override fun toString(): String = "KeyLogRecord(label=${label.wireName}, redacted=true)"
}

enum class KeyLogParseErrorCode {
    TOTAL_SIZE_EXCEEDED, LINE_SIZE_EXCEEDED, NON_ASCII, INVALID_CHARACTER, INVALID_LINE_ENDING,
    INVALID_COLUMN_COUNT, INVALID_LABEL, INVALID_CLIENT_RANDOM, INVALID_SECRET_HEX,
    INVALID_SECRET_LENGTH, CONFLICTING_SECRET, NO_SUPPORTED_RECORDS, IO_ERROR
}

/** Only fixed codes and a one-based physical line number; never include input or an I/O cause. */
data class KeyLogParseError(val code: KeyLogParseErrorCode, val lineNumber: Int)

data class KeyLogParseStats(
    val bytesRead: Long,
    val linesRead: Int,
    val ignoredLines: Int,
    val duplicateLines: Int,
    val unsupportedLines: Int
)

sealed class KeyLogParseResult {
    abstract val stats: KeyLogParseStats

    class Success internal constructor(
        val records: List<KeyLogRecord>,
        override val stats: KeyLogParseStats
    ) : KeyLogParseResult() {
        override fun toString(): String = "KeyLogParseResult.Success(recordCount=${records.size}, stats=$stats)"
    }

    /** A failed import exposes no partial records, even if earlier lines were valid. */
    data class Failure(val error: KeyLogParseError, override val stats: KeyLogParseStats) : KeyLogParseResult()
}

/**
 * Bounded NSS keylog import with no Android, path, logging or persistence dependencies.
 * The caller owns [InputStream] and must close it. LF and CRLF are supported; limits count
 * all input bytes, while the line limit excludes the line ending. At most 4 KiB is prefetched.
 * Success means syntax validation only, not that a capture can actually be decrypted.
 */
object KeyLogParser {
    const val MAX_TOTAL_BYTES: Long = 16L * 1024 * 1024
    const val MAX_LINE_BYTES: Int = 8 * 1024
    private const val READ_BUFFER_BYTES = 4 * 1024

    fun parse(input: InputStream): KeyLogParseResult = Import().parse(input)

    private data class RecordIdentity(val label: KeyLogLabel, val clientRandomHex: String)

    private class Import {
        private val records = LinkedHashMap<RecordIdentity, KeyLogRecord>()
        private val line = ByteArray(MAX_LINE_BYTES)
        private var lineSize = 0
        private var pendingCr = false
        private var lineNumber = 1
        private var bytesRead = 0L
        private var linesRead = 0
        private var ignoredLines = 0
        private var duplicateLines = 0
        private var unsupportedLines = 0

        fun parse(input: InputStream): KeyLogParseResult {
            val buffer = ByteArray(READ_BUFFER_BYTES)
            try {
                while (true) {
                    // Read one extra byte to distinguish an exact limit from an oversized stream.
                    val readLimit = minOf(buffer.size.toLong(), MAX_TOTAL_BYTES - bytesRead + 1).toInt()
                    val count = input.read(buffer, 0, readLimit)
                    if (count == -1) break
                    if (count == 0) {
                        // Avoid spinning for a stream implementation returning zero for a bulk read.
                        val value = input.read()
                        if (value == -1) break
                        acceptByte(value)?.let { return failure(it) }
                    } else {
                        for (index in 0 until count) {
                            acceptByte(buffer[index].toInt() and 0xff)?.let { return failure(it) }
                        }
                    }
                }
                if (pendingCr) return failure(KeyLogParseErrorCode.INVALID_LINE_ENDING)
                if (lineSize > 0) consumeLine()?.let { return failure(it) }
                if (records.isEmpty()) return failure(KeyLogParseErrorCode.NO_SUPPORTED_RECORDS)
                return KeyLogParseResult.Success(
                    Collections.unmodifiableList(ArrayList(records.values)), stats()
                )
            } catch (_: IOException) {
                // Provider exceptions can contain a URI, a path or secret bytes. Do not retain them.
                return failure(KeyLogParseErrorCode.IO_ERROR)
            } finally {
                buffer.fill(0)
                line.fill(0)
                records.clear()
            }
        }

        private fun acceptByte(value: Int): KeyLogParseErrorCode? {
            bytesRead++
            if (bytesRead > MAX_TOTAL_BYTES) return KeyLogParseErrorCode.TOTAL_SIZE_EXCEEDED
            if (value > 0x7f) return KeyLogParseErrorCode.NON_ASCII
            if (pendingCr && value != '\n'.code) return KeyLogParseErrorCode.INVALID_LINE_ENDING
            when (value) {
                '\n'.code -> {
                    consumeLine()?.let { return it }
                    line.fill(0, 0, lineSize)
                    lineSize = 0
                    pendingCr = false
                    lineNumber++
                }
                '\r'.code -> pendingCr = true
                else -> {
                    if ((value < 0x20 && value != '\t'.code) || value == 0x7f) {
                        return KeyLogParseErrorCode.INVALID_CHARACTER
                    }
                    if (lineSize == MAX_LINE_BYTES) return KeyLogParseErrorCode.LINE_SIZE_EXCEEDED
                    line[lineSize++] = value.toByte()
                }
            }
            return null
        }

        private fun consumeLine(): KeyLogParseErrorCode? {
            linesRead++
            var cursor = 0
            while (cursor < lineSize && isSeparator(cursor)) cursor++
            if (cursor == lineSize || line[cursor] == '#'.code.toByte()) {
                ignoredLines++
                return null
            }

            // Bound the number of columns before constructing strings; no regex or whole-file copy.
            val boundaries = IntArray(6)
            for (column in 0 until 3) {
                if (cursor == lineSize) return KeyLogParseErrorCode.INVALID_COLUMN_COUNT
                boundaries[column * 2] = cursor
                while (cursor < lineSize && !isSeparator(cursor)) cursor++
                boundaries[column * 2 + 1] = cursor
                while (cursor < lineSize && isSeparator(cursor)) cursor++
            }
            if (cursor != lineSize) return KeyLogParseErrorCode.INVALID_COLUMN_COUNT

            fun column(index: Int): String {
                val start = boundaries[index * 2]
                return String(line, start, boundaries[index * 2 + 1] - start, Charsets.US_ASCII)
            }

            val labelText = column(0)
            if (labelText.first() !in 'A'..'Z' || labelText.any { it !in 'A'..'Z' && it !in '0'..'9' && it != '_' }) {
                return KeyLogParseErrorCode.INVALID_LABEL
            }
            val randomText = column(1)
            if (randomText.length != 64 || !randomText.isHex()) return KeyLogParseErrorCode.INVALID_CLIENT_RANDOM
            val secretText = column(2)
            if (secretText.length % 2 != 0 || !secretText.isHex()) return KeyLogParseErrorCode.INVALID_SECRET_HEX
            val label = KeyLogLabel.fromWire(labelText)
            if (label == null) {
                unsupportedLines++
                return null
            }
            if (!label.acceptsSecretBytes(secretText.length / 2)) return KeyLogParseErrorCode.INVALID_SECRET_LENGTH

            val random = randomText.lowercase(Locale.ROOT)
            val secret = secretText.lowercase(Locale.ROOT)
            val identity = RecordIdentity(label, random)
            val previous = records[identity]
            if (previous != null) {
                if (previous.secretHex != secret) return KeyLogParseErrorCode.CONFLICTING_SECRET
                duplicateLines++
            } else {
                records[identity] = KeyLogRecord(label, random, secret)
            }
            return null
        }

        private fun isSeparator(index: Int): Boolean = line[index] == ' '.code.toByte() || line[index] == '\t'.code.toByte()

        private fun String.isHex(): Boolean = isNotEmpty() && all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

        private fun stats() = KeyLogParseStats(bytesRead, linesRead, ignoredLines, duplicateLines, unsupportedLines)

        private fun failure(code: KeyLogParseErrorCode) = KeyLogParseResult.Failure(KeyLogParseError(code, lineNumber), stats())
    }
}
