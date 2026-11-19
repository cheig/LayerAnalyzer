// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.SequenceInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyLogParserTest {
    // Synthetic parser inputs generated in memory, unrelated to any real TLS session or PCAP.
    private val random = "aB".repeat(32)
    private val secret = "cD".repeat(48)
    private val validLine = "CLIENT_RANDOM $random $secret"

    @Test
    fun supportedLabelsAndAllSupportedLengthsProduceCanonicalRecords() {
        val inputs = KeyLogLabel.entries.flatMap { label ->
            val lengths = if (label == KeyLogLabel.CLIENT_RANDOM) listOf(48) else listOf(32, 48, 64)
            lengths.map { size ->
                val uniqueRandom = size.toString(16).padStart(2, '0').repeat(32)
                "\t${label.wireName}\t$uniqueRandom   ${"aB".repeat(size)}  "
            }
        }
        val result = success(inputs.joinToString("\r\n"))
        assertEquals(16, result.records.size)
        assertEquals(16, result.stats.linesRead)
        assertEquals(0, result.stats.unsupportedLines)
        result.records.forEach { record ->
            assertEquals(record.secretHex.lowercase(), record.secretHex)
            assertEquals(record.clientRandomHex.lowercase(), record.clientRandomHex)
            assertEquals(record.toNssLine().toByteArray(Charsets.US_ASCII).size, record.encodedSizeBytes)
            assertFalse(record.toNssLine().contains('\t'))
            assertFalse(record.toNssLine().endsWith(' '))
        }
    }

    @Test
    fun ignoresBlankLinesAndLeadingWhitespaceCommentsWithAccurateCounts() {
        val text = "\r\n \t\n  # SSLKEYLOGFILE=/not/a/directive\r\n$validLine\n# comment"
        val result = success(text)
        assertEquals(1, result.records.size)
        assertEquals(5, result.stats.linesRead)
        assertEquals(4, result.stats.ignoredLines)
        assertEquals(text.length.toLong(), result.stats.bytesRead)
    }

    @Test
    fun deduplicatesNormalizedRecordsButKeepsDifferentLabelsAndRandoms() {
        val text = listOf(
            validLine,
            "CLIENT_RANDOM ${random.lowercase()} ${secret.uppercase()}",
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET $random $secret",
            "CLIENT_RANDOM ${"12".repeat(32)} $secret"
        ).joinToString("\n")
        val result = success(text)
        assertEquals(3, result.records.size)
        assertEquals(1, result.stats.duplicateLines)
        assertEquals("CLIENT_RANDOM ${random.lowercase()} ${secret.lowercase()}", result.records.first().toNssLine())
        assertEquals(KeyLogLabel.CLIENT_HANDSHAKE_TRAFFIC_SECRET, result.records[1].label)
    }

    @Test
    fun aConflictingSecretRejectsTheWholeImportWithoutPartialRecords() {
        val result = failure("$validLine\nCLIENT_RANDOM $random ${"ef".repeat(48)}\n$validLine",
            KeyLogParseErrorCode.CONFLICTING_SECRET, 2)
        assertEquals(2, result.stats.linesRead)
        assertEquals(0, result.stats.duplicateLines)
        assertSafeText(result.toString())
    }

    @Test
    fun unsupportedLabelsAreCountedIndependentlyAndNotReturnedAsRecords() {
        val unsupported = listOf("FUTURE_SECRET", "FUTURE_SECRET", "CLIENT_TRAFFIC_SECRET_1", "CLIENT_EARLY_TRAFFIC_SECRET")
        val input = unsupported.joinToString("\n") { "$it $random 12" } + "\n$validLine"
        val result = success(input)
        assertEquals(1, result.records.size)
        assertEquals(4, result.stats.unsupportedLines)
        assertEquals(0, result.stats.duplicateLines)
        assertNull(KeyLogLabel.fromWire("CLIENT_TRAFFIC_SECRET_12"))
        assertNull(KeyLogLabel.fromWire("client_random"))
    }

    @Test
    fun emptyCommentOnlyAndUnknownOnlyInputsNeverSucceed() {
        failure("", KeyLogParseErrorCode.NO_SUPPORTED_RECORDS, 1)
        failure("# comment\n \t", KeyLogParseErrorCode.NO_SUPPORTED_RECORDS, 2)
        val result = failure("FUTURE_SECRET $random 1234", KeyLogParseErrorCode.NO_SUPPORTED_RECORDS, 1)
        assertEquals(1, result.stats.unsupportedLines)
    }

    @Test
    fun unknownLabelsStillRequireThreeColumnsValidRandomAndEvenHex() {
        failure("FUTURE_SECRET $random", KeyLogParseErrorCode.INVALID_COLUMN_COUNT)
        failure("FUTURE_SECRET bad 12", KeyLogParseErrorCode.INVALID_CLIENT_RANDOM)
        failure("FUTURE_SECRET $random 123", KeyLogParseErrorCode.INVALID_SECRET_HEX)
        failure("FUTURE_SECRET $random zzzz", KeyLogParseErrorCode.INVALID_SECRET_HEX)
    }

    @Test
    fun rejectsMissingOrAdditionalColumnsIncludingInlineComments() {
        listOf("CLIENT_RANDOM", "CLIENT_RANDOM $random", "$validLine extra", "$validLine # comment")
            .forEach { failure(it, KeyLogParseErrorCode.INVALID_COLUMN_COUNT) }
    }

    @Test
    fun rejectsClientRandomWithWrongLengthOrNonHexCharacters() {
        listOf("a".repeat(63), "a".repeat(65), "z".repeat(64), "0x" + "a".repeat(62)).forEach {
            failure("CLIENT_RANDOM $it $secret", KeyLogParseErrorCode.INVALID_CLIENT_RANDOM)
        }
    }

    @Test
    fun rejectsOddOrInvalidSecretHex() {
        listOf("a".repeat(95), "a".repeat(97), "z".repeat(96), "0x" + "a".repeat(94)).forEach {
            failure("CLIENT_RANDOM $random $it", KeyLogParseErrorCode.INVALID_SECRET_HEX)
        }
    }

    @Test
    fun enforcesLabelSpecificSecretLengths() {
        KeyLogLabel.entries.forEach { label ->
            val badLengths = if (label == KeyLogLabel.CLIENT_RANDOM) listOf(32, 47, 49, 64)
            else listOf(1, 31, 33, 47, 49, 63, 65)
            badLengths.forEach { size ->
                failure("${label.wireName} $random ${"ab".repeat(size)}", KeyLogParseErrorCode.INVALID_SECRET_LENGTH)
            }
        }
    }

    @Test
    fun rejectsNonAsciiIncludingUtf8BomAndNonAsciiInComments() {
        listOf("\uFEFF$validLine", "# café", "$validLine\n# 中文").forEach { text ->
            failure(text, KeyLogParseErrorCode.NON_ASCII, if (text.contains('\n')) 2 else 1)
        }
    }

    @Test
    fun rejectsAsciiControlCharactersInsteadOfHidingThemInCommentsOrColumns() {
        listOf('\u0000', '\u000b', '\u000c', '\u001b', '\u007f').forEach { value ->
            failure("# hidden$value", KeyLogParseErrorCode.INVALID_CHARACTER)
            failure("CLIENT_RANDOM$value $random $secret", KeyLogParseErrorCode.INVALID_CHARACTER)
        }
    }

    @Test
    fun acceptsCrLfAcrossReadBoundariesAndRejectsBareCr() {
        val stream = object : ByteArrayInputStream("$validLine\r\n$validLine\n".toByteArray()) {
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int = super.read(bytes, offset, minOf(1, length))
        }
        val result = KeyLogParser.parse(stream) as KeyLogParseResult.Success
        assertEquals(1, result.records.size)
        assertEquals(1, result.stats.duplicateLines)
        failure("$validLine\r", KeyLogParseErrorCode.INVALID_LINE_ENDING)
        failure("$validLine\r$validLine", KeyLogParseErrorCode.INVALID_LINE_ENDING)
    }

    @Test
    fun pathsAndIncludeDirectivesAreOnlyInvalidInputNeverInstructions() {
        listOf("/tmp/secrets", "file:///tmp/secrets", "SSLKEYLOGFILE=/tmp/secrets", "@include", "client_random")
            .forEach { label -> failure("$label $random $secret", KeyLogParseErrorCode.INVALID_LABEL) }
        failure("INCLUDE /tmp/secrets $secret", KeyLogParseErrorCode.INVALID_CLIENT_RANDOM)
    }

    @Test
    fun acceptsExactlyEightKibLineWithLfCrLfOrEof() {
        val paddedLine = validLine.padEnd(KeyLogParser.MAX_LINE_BYTES, ' ')
        listOf("", "\n", "\r\n").forEach { ending ->
            val result = success(paddedLine + ending)
            assertEquals(1, result.records.size)
            assertEquals((KeyLogParser.MAX_LINE_BYTES + ending.length).toLong(), result.stats.bytesRead)
        }
    }

    @Test
    fun stopsAtTheFirstByteBeyondEightKibEvenForAComment() {
        listOf(validLine.padEnd(KeyLogParser.MAX_LINE_BYTES + 1, ' '), "#".repeat(KeyLogParser.MAX_LINE_BYTES + 1))
            .forEach { text ->
                val result = failure(text + "\n$validLine", KeyLogParseErrorCode.LINE_SIZE_EXCEEDED)
                assertEquals(KeyLogParser.MAX_LINE_BYTES.toLong() + 1, result.stats.bytesRead)
                assertEquals(0, result.stats.linesRead)
            }
    }

    @Test
    fun acceptsExactlySixteenMibWithoutReadingTheWholeInputIntoMemory() {
        val prefix = "$validLine\n".toByteArray(Charsets.US_ASCII)
        val tail = RepeatedLfStream(KeyLogParser.MAX_TOTAL_BYTES - prefix.size)
        val result = KeyLogParser.parse(SequenceInputStream(ByteArrayInputStream(prefix), tail)) as KeyLogParseResult.Success
        assertEquals(KeyLogParser.MAX_TOTAL_BYTES, result.stats.bytesRead)
        assertEquals(1, result.records.size)
        assertTrue(tail.maxReadRequest <= 4096)
    }

    @Test
    fun rejectsSixteenMibPlusOneAndDoesNotReadAnUnboundedTail() {
        val prefix = "$validLine\n".toByteArray(Charsets.US_ASCII)
        val tail = RepeatedLfStream(Long.MAX_VALUE)
        val result = KeyLogParser.parse(SequenceInputStream(ByteArrayInputStream(prefix), tail)) as KeyLogParseResult.Failure
        assertEquals(KeyLogParseErrorCode.TOTAL_SIZE_EXCEEDED, result.error.code)
        assertEquals(KeyLogParser.MAX_TOTAL_BYTES + 1, result.stats.bytesRead)
        assertEquals(KeyLogParser.MAX_TOTAL_BYTES + 1 - prefix.size, tail.emitted)
        assertTrue(tail.maxReadRequest <= 4096)
    }

    @Test
    fun boundsPrefetchAndStopsAfterTheFirstMalformedLine() {
        val prefix = "CLIENT_RANDOM bad secret\n".toByteArray(Charsets.US_ASCII)
        val tail = RepeatedLfStream(Long.MAX_VALUE)
        val result = KeyLogParser.parse(SequenceInputStream(ByteArrayInputStream(prefix), tail)) as KeyLogParseResult.Failure
        assertEquals(KeyLogParseErrorCode.INVALID_CLIENT_RANDOM, result.error.code)
        assertEquals(prefix.size.toLong(), result.stats.bytesRead)
        assertEquals(0L, tail.emitted)
    }

    @Test
    fun sanitizesIoFailuresAndNeverClosesTheCallerStream() {
        var closed = false
        val stream = object : InputStream() {
            override fun read(): Int = throw IOException("content://private/$secret")
            override fun close() { closed = true }
        }
        val result = KeyLogParser.parse(stream) as KeyLogParseResult.Failure
        assertEquals(KeyLogParseErrorCode.IO_ERROR, result.error.code)
        assertSafeText(result.toString())
        assertFalse(result.toString().contains("content://"))
        assertFalse(closed)

        val validStream = object : ByteArrayInputStream(validLine.toByteArray()) {
            override fun close() { closed = true }
        }
        assertTrue(KeyLogParser.parse(validStream) is KeyLogParseResult.Success)
        assertFalse(closed)
    }

    @Test
    fun doesNotSpinWhenBulkReadReturnsZero() {
        val stream = object : ByteArrayInputStream(validLine.toByteArray()) {
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int = 0
        }
        assertEquals(1, (KeyLogParser.parse(stream) as KeyLogParseResult.Success).records.size)
    }

    @Test
    fun defaultRenderingNeverIncludesSecretMaterialAndSuccessListIsImmutable() {
        val result = success(validLine)
        assertSafeText(result.toString())
        assertSafeText(result.records.toString())
        assertSafeText(result.records.single().toString())
        var rejected = false
        try {
            (result.records as MutableList<KeyLogRecord>).clear()
        } catch (_: UnsupportedOperationException) {
            rejected = true
        }
        assertTrue(rejected)
        assertEquals(1, result.records.size)
    }

    private fun success(text: String): KeyLogParseResult.Success =
        KeyLogParser.parse(ByteArrayInputStream(text.toByteArray(Charsets.UTF_8))) as KeyLogParseResult.Success

    private fun failure(text: String, code: KeyLogParseErrorCode, line: Int = 1): KeyLogParseResult.Failure {
        val result = KeyLogParser.parse(ByteArrayInputStream(text.toByteArray(Charsets.UTF_8))) as KeyLogParseResult.Failure
        assertEquals(code, result.error.code)
        assertEquals(line, result.error.lineNumber)
        assertSafeText(result.toString())
        return result
    }

    private fun assertSafeText(text: String) {
        assertFalse(text.contains(secret, ignoreCase = true))
        assertFalse(text.contains(random, ignoreCase = true))
        assertFalse(text.contains("/tmp/secrets"))
    }

    private class RepeatedLfStream(private val count: Long) : InputStream() {
        var emitted = 0L
            private set
        var maxReadRequest = 0
            private set

        override fun read(): Int = if (emitted == count) -1 else '\n'.code.also { emitted++ }

        override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
            maxReadRequest = maxOf(maxReadRequest, length)
            if (emitted == count) return -1
            val size = minOf(length.toLong(), count - emitted).toInt()
            bytes.fill('\n'.code.toByte(), offset, offset + size)
            emitted += size
            return size
        }
    }
}
