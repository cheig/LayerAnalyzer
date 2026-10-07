package com.example.layanalyzer.core

import com.example.layanalyzer.model.PacketBytesFormat
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/** JSON 格式化失败等可预期错误，UI 层捕获后展示错误文案，不应导致崩溃 */
class BytesFormatException(message: String, cause: Throwable? = null) : Exception(message, cause)

object BytesFormatter {

    private const val BYTES_PER_LINE = 16
    private const val HEX_AREA_WIDTH = BYTES_PER_LINE * 3 - 1 // 16 组 2 字符 + 15 个单空格 = 47 列
    private const val RAW_BYTES_PER_LINE = 32 // 原始数据每行 32 字节 = 64 个十六进制字符

    private val LOWER_HEX_LABELS = Array(256) { it.toString(16).padStart(2, '0') }
    private val UPPER_HEX_LABELS = Array(256) { it.toString(16).uppercase().padStart(2, '0') }
    private val ASCII_LABELS = Array(256) { if (it in 32..126) it.toChar().toString() else "." }

    /** 按 [start, start+length) 截取帧字节；越界一律 clamp，length<=0 或空帧返回空数组 */
    fun sliceClamped(bytes: ByteArray, start: Int, length: Int): ByteArray {
        if (bytes.isEmpty() || length <= 0) return ByteArray(0)
        val from = start.coerceIn(0, bytes.size)
        // 用 Long 求终点，避免 start+length 溢出成负数后被错误 clamp
        val requestedEnd = start.toLong() + length
        val to = when {
            requestedEnd > bytes.size -> bytes.size
            requestedEnd < from -> from
            else -> requestedEnd.toInt()
        }
        return if (to <= from) ByteArray(0) else bytes.copyOfRange(from, to)
    }

    /** 主入口：把已截取的字节渲染为目标格式文本 */
    fun format(bytes: ByteArray, format: PacketBytesFormat): String = when (format) {
        PacketBytesFormat.RAW -> formatRaw(bytes)
        PacketBytesFormat.ASCII -> formatAscii(bytes)
        PacketBytesFormat.JSON -> formatJson(bytes)
        PacketBytesFormat.HEX_DUMP -> formatHexDump(bytes)
        PacketBytesFormat.UTF8 -> String(bytes, Charsets.UTF_8)
    }

    /** 原始数据：小写十六进制连续串，每 32 字节换一行，配合 UI 纵向滚动查看 */
    private fun formatRaw(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val sb = StringBuilder(bytes.size * 2 + bytes.size / RAW_BYTES_PER_LINE)
        var lineStart = 0
        while (lineStart < bytes.size) {
            val lineEnd = minOf(lineStart + RAW_BYTES_PER_LINE, bytes.size)
            if (lineStart > 0) sb.append('\n')
            for (i in lineStart until lineEnd) {
                sb.append(LOWER_HEX_LABELS[bytes[i].toInt() and 0xff])
            }
            lineStart = lineEnd
        }
        return sb.toString()
    }

    /**
     * ASCII：可打印字符，其余 '.'；仅把 CR/LF 当作换行符输出换行：
     * CRLF 合并为一次换行避免多余空行，裸 CR / 裸 LF 也各自换行，行内其余控制字符仍显示 '.'
     */
    private fun formatAscii(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val sb = StringBuilder()
        var lineStart = 0
        var i = 0
        while (i < bytes.size) {
            val value = bytes[i].toInt() and 0xff
            if (value == 0x0A || value == 0x0D) {
                asciiAppend(bytes, lineStart, i, sb)
                sb.append('\n')
                val next = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xff else -1
                lineStart = if (value == 0x0D && next == 0x0A) i + 2 else i + 1
                i = lineStart
            } else {
                i++
            }
        }
        if (lineStart < bytes.size) asciiAppend(bytes, lineStart, bytes.size, sb)
        return sb.toString()
    }

    private fun asciiAppend(bytes: ByteArray, from: Int, to: Int, sb: StringBuilder) {
        for (j in from until to) sb.append(ASCII_LABELS[bytes[j].toInt() and 0xff])
    }

    private fun formatJson(bytes: ByteArray): String {
        val text = String(bytes, Charsets.UTF_8).trim()
        if (text.isEmpty() || (text[0] != '{' && text[0] != '[')) {
            throw BytesFormatException("invalid_json")
        }
        return try {
            if (text[0] == '{') JSONObject(text).toString(2) else JSONArray(text).toString(2)
        } catch (e: JSONException) {
            throw BytesFormatException("invalid_json", e)
        }
    }

    private fun formatHexDump(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val sb = StringBuilder()
        var lineStart = 0
        while (lineStart < bytes.size) {
            val lineEnd = minOf(lineStart + BYTES_PER_LINE, bytes.size)
            if (lineStart > 0) sb.append('\n')
            val hex = StringBuilder()
            val ascii = StringBuilder()
            for (i in lineStart until lineEnd) {
                val value = bytes[i].toInt() and 0xff
                if (i > lineStart) hex.append(' ')
                hex.append(UPPER_HEX_LABELS[value])
                ascii.append(ASCII_LABELS[value])
            }
            // 末行不足 16 字节时 hex 区右侧补齐 47 列、ASCII 区补齐 16 列，
            // 保证各栏起始列恒定、所有行长度一致
            sb.append(lineStart.toString(16).uppercase().padStart(8, '0'))
                .append("  ")
                .append(hex.toString().padEnd(HEX_AREA_WIDTH))
                .append("  ")
                .append(ascii.toString().padEnd(BYTES_PER_LINE))
            lineStart = lineEnd
        }
        return sb.toString()
    }
}
