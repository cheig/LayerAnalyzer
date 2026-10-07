// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.core

import com.example.layanalyzer.model.PacketBytesFormat
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class BytesFormatterTest {

    // ---------- RAW ----------

    @Test
    fun rawRendersKnownBytesAsLowercaseHex() {
        val bytes = byteArrayOf(0x52, 0x51, 0x02, 0x08)
        assertEquals("52510208", BytesFormatter.format(bytes, PacketBytesFormat.RAW))
    }

    @Test
    fun rawUsesLowercaseHexDigitsWithoutSeparator() {
        val bytes = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        assertEquals("abcdef", BytesFormatter.format(bytes, PacketBytesFormat.RAW))
    }

    @Test
    fun rawWrapsEveryThirtyTwoBytes() {
        // 33 字节：第一行 32 字节 = 64 个十六进制字符，第二行 1 字节 = 2 个字符
        val bytes = ByteArray(33) { ((it * 7 + 3) and 0xff).toByte() }
        val text = BytesFormatter.format(bytes, PacketBytesFormat.RAW)
        val lines = text.split('\n')
        assertEquals(2, lines.size)
        assertEquals(64, lines[0].length)
        assertEquals(2, lines[1].length)
        assertEquals(text.replace("\n", ""), bytes.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') })
    }

    @Test
    fun rawKeepsExactThirtyTwoBytesOnSingleLine() {
        val bytes = ByteArray(32) { it.toByte() }
        val text = BytesFormatter.format(bytes, PacketBytesFormat.RAW)
        assertFalse(text.contains('\n'))
        assertEquals(64, text.length)
    }

    @Test
    fun rawRendersEmptyInputAsEmptyString() {
        assertEquals("", BytesFormatter.format(ByteArray(0), PacketBytesFormat.RAW))
    }

    // ---------- ASCII ----------

    @Test
    fun asciiKeepsPrintableBytesAndReplacesRestWithDot() {
        val bytes = byteArrayOf('A'.code.toByte(), 'B'.code.toByte(), 0x00, 0x7F, '\n'.code.toByte())
        assertEquals("AB..\n", BytesFormatter.format(bytes, PacketBytesFormat.ASCII))
    }

    @Test
    fun asciiKeepsPrintableBoundariesAndDotsControlAndDelete() {
        val bytes = byteArrayOf(0x20, 0x7E, 0x1F, 0x7F)
        assertEquals(" ~..", BytesFormatter.format(bytes, PacketBytesFormat.ASCII))
    }

    @Test
    fun asciiRendersCrLfAsSingleNewline() {
        // SIP 风格请求头：CRLF 合并为一次换行，不产生多余空行
        val text = "INVITE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP a\r\n\r\n"
        val bytes = text.toByteArray(Charsets.US_ASCII)
        assertEquals("INVITE sip:x SIP/2.0\nVia: SIP/2.0/UDP a\n\n", BytesFormatter.format(bytes, PacketBytesFormat.ASCII))
    }

    @Test
    fun asciiRendersBareCrAndLfAsNewlines() {
        assertEquals("a\nb\nc\n", BytesFormatter.format("a\r\nb\nc\n".toByteArray(Charsets.US_ASCII), PacketBytesFormat.ASCII))
    }

    @Test
    fun asciiDotsControlCharsInsideLine() {
        val bytes = byteArrayOf(0x01, 'A'.code.toByte(), 0x09, 'B'.code.toByte())
        assertEquals(".A.B", BytesFormatter.format(bytes, PacketBytesFormat.ASCII))
    }

    @Test
    fun asciiRendersEmptyInputAsEmptyString() {
        assertEquals("", BytesFormatter.format(ByteArray(0), PacketBytesFormat.ASCII))
    }

    // ---------- HEX_DUMP ----------

    @Test
    fun hexDumpRendersSixteenBytesAsSingleLine() {
        val bytes = sampleBytes().copyOf(16)
        val text = BytesFormatter.format(bytes, PacketBytesFormat.HEX_DUMP)
        assertEquals(SAMPLE_FIRST_LINE, text)
    }

    @Test
    fun hexDumpPadsPartialLastLineToKeepColumnsAligned() {
        val lines = BytesFormatter.format(sampleBytes(), PacketBytesFormat.HEX_DUMP).split('\n')
        assertEquals(2, lines.size)
        assertEquals(SAMPLE_FIRST_LINE, lines[0])
        // 第二行只有 1 字节：hex 区 "1E" 补齐 47 列（45 空格）+ 2 空格分隔 + ASCII 区 "." 补齐 16 列
        assertEquals("00000010  1E" + " ".repeat(45) + "  " + "." + " ".repeat(15), lines[1])
        assertEquals(75, lines[0].length)
        assertEquals(75, lines[1].length)
    }

    @Test
    fun hexDumpWrapsOffsetPerSixteenBytes() {
        val bytes = ByteArray(33) { it.toByte() }
        val lines = BytesFormatter.format(bytes, PacketBytesFormat.HEX_DUMP).split('\n')
        assertEquals(3, lines.size)
        assertTrue(lines[1].startsWith("00000010  10 11"))
        assertTrue(lines[2].startsWith("00000020  20"))
    }

    @Test
    fun hexDumpRendersEmptyInputAsEmptyString() {
        assertEquals("", BytesFormatter.format(ByteArray(0), PacketBytesFormat.HEX_DUMP))
    }

    // ---------- UTF8 ----------

    @Test
    fun utf8RoundTripsChineseText() {
        val text = "中文"
        val encoded = text.toByteArray(Charsets.UTF_8)
        assertEquals(text, BytesFormatter.format(encoded, PacketBytesFormat.UTF8))
    }

    @Test
    fun utf8ReplacesMalformedSequenceWithReplacementChar() {
        val bytes = byteArrayOf(0x41, 0xC3.toByte(), 0x28)
        assertEquals("A\uFFFD(", BytesFormatter.format(bytes, PacketBytesFormat.UTF8))
    }

    // ---------- JSON ----------

    @Test
    fun jsonPrettyPrintsObjectWithTwoSpaceIndent() {
        val text = BytesFormatter.format(
            "{\"b\":1,\"a\":2}".toByteArray(Charsets.UTF_8),
            PacketBytesFormat.JSON
        )
        assertTrue(text.startsWith("{"))
        assertTrue(text.contains("\n  \"")) // 换行 + 2 空格缩进
        assertTrue(text.contains("\"a\""))
        assertTrue(text.contains("\"b\""))
    }

    @Test
    fun jsonPrettyPrintsTopLevelArray() {
        val text = BytesFormatter.format("[1,2]".toByteArray(Charsets.UTF_8), PacketBytesFormat.JSON)
        assertTrue(text.startsWith("["))
        assertTrue(text.contains("\n  1"))
        assertTrue(text.contains("\n  2"))
    }

    @Test
    fun jsonToleratesSurroundingWhitespace() {
        val text = BytesFormatter.format("  [1,2]  ".toByteArray(Charsets.UTF_8), PacketBytesFormat.JSON)
        assertTrue(text.startsWith("["))
    }

    @Test
    fun jsonThrowsFormatExceptionForNonJsonText() {
        jsonFormatShouldFail("not json")
    }

    @Test
    fun jsonThrowsFormatExceptionForEmptyInput() {
        jsonFormatShouldFail("")
    }

    @Test
    fun jsonThrowsFormatExceptionForBrokenObjectSyntax() {
        jsonFormatShouldFail("{invalid")
    }

    // ---------- sliceClamped ----------

    @Test
    fun sliceClampedClampsNegativeStartToFrameStart() {
        // 请求 [-3, 2)，clamp 到帧范围后为 [0, 2)
        assertArrayEquals(byteArrayOf(0x11, 0x22), BytesFormatter.sliceClamped(frame, -3, 5))
    }

    @Test
    fun sliceClampedClampsEndBeyondFrameSize() {
        // 请求 [3, 13)，clamp 到帧范围后为 [3, 5)
        assertArrayEquals(byteArrayOf(0x44, 0x55), BytesFormatter.sliceClamped(frame, 3, 10))
    }

    @Test
    fun sliceClampedReturnsEmptyForNonPositiveLength() {
        assertTrue(BytesFormatter.sliceClamped(frame, 1, 0).isEmpty())
        assertTrue(BytesFormatter.sliceClamped(frame, 1, -2).isEmpty())
    }

    @Test
    fun sliceClampedReturnsEmptyForEmptyFrame() {
        assertTrue(BytesFormatter.sliceClamped(ByteArray(0), 0, 5).isEmpty())
    }

    @Test
    fun sliceClampedReturnsEmptyWhenRangeStartsBeyondFrame() {
        assertTrue(BytesFormatter.sliceClamped(frame, 7, 4).isEmpty())
    }

    @Test
    fun sliceClampedReturnsExactRangeWhenInBounds() {
        assertArrayEquals(byteArrayOf(0x22, 0x33), BytesFormatter.sliceClamped(frame, 1, 2))
    }

    private val frame = byteArrayOf(0x11, 0x22, 0x33, 0x44, 0x55)

    /** 任务文档中的 17 字节样例（第二行仅 1 字节 0x1E） */
    private fun sampleBytes(): ByteArray = byteArrayOf(
        0x52, 0x51, 0x02, 0x00, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x34, 0xA5.toByte(), 0xF1.toByte(), 0x40, 0x00, 0x40, 0x06,
        0x1E
    )

    private val SAMPLE_FIRST_LINE =
        "00000000  52 51 02 00 08 00 45 00 00 34 A5 F1 40 00 40 06  RQ....E..4..@.@."

    private fun jsonFormatShouldFail(input: String) {
        try {
            BytesFormatter.format(input.toByteArray(Charsets.UTF_8), PacketBytesFormat.JSON)
            fail("expected BytesFormatException for input: \"$input\"")
        } catch (expected: BytesFormatException) {
            assertEquals("invalid_json", expected.message)
        }
    }
}
