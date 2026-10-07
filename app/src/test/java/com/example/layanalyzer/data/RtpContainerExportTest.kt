// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.RtpContainerExportResult
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RTP4-KT-03：`exportRtpContainer` 的 Kotlin 侧契约单测（不碰 JNI）。
 *
 * 请求形状与返回解析是**冻结契约**（`RtpJni.cpp` 的 `exportRtpContainer` 注释），
 * 这里逐字段钉住；端到端的真机断言在 `androidTest` 的 `RtpContainerExportTest`。
 */
class RtpContainerExportTest {

    private val repository = RtpRepository(PacketRepository())

    @Test
    fun `request carries the frozen scanGeneration streamId format triple`() {
        val request = JSONObject(
            repository.buildContainerExportRequest(
                scanGeneration = 7L,
                streamId = "s3",
                format = "awb"
            )
        )
        assertEquals(3, request.length())
        assertEquals(7L, request.getLong("scanGeneration"))
        assertEquals("s3", request.getString("streamId"))
        assertEquals("awb", request.getString("format"))
    }

    @Test
    fun `request escapes the stream id through the json encoder`() {
        val request = JSONObject(
            repository.buildContainerExportRequest(1L, "s\"3", "opus")
        )
        assertEquals("s\"3", request.getString("streamId"))
    }

    @Test
    fun `success response parses every field`() {
        val result = repository.parseContainerExportResult(
            """
            {"schemaVersion":1,"error":"","cancelled":false,
             "path":"/tmp/rtp/1/2/s3.amr","format":"amr",
             "frameCount":1500,"byteCount":45600}
            """.trimIndent()
        )
        assertEquals("/tmp/rtp/1/2/s3.amr", result.path)
        assertEquals("amr", result.format)
        assertEquals(1500L, result.frameCount)
        assertEquals(45600L, result.byteCount)
        assertEquals("", result.error)
        assertFalse(result.cancelled)
        assertTrue(result.isSuccess)
    }

    @Test
    fun `a rejected request is not a success and carries the native error`() {
        val mismatch = repository.parseContainerExportResult(
            """{"schemaVersion":1,"error":"format does not match the stream codec.",
                "cancelled":false,"path":"","format":"amr","frameCount":0,"byteCount":0}"""
        )
        assertEquals("format does not match the stream codec.", mismatch.error)
        assertEquals("", mismatch.path)
        assertFalse(mismatch.isSuccess)

        val nativeDecode = repository.parseContainerExportResult(
            """{"schemaVersion":1,"error":"nativeDecode","cancelled":false,
                "path":"","format":"amr","frameCount":0,"byteCount":0}"""
        )
        assertEquals("nativeDecode", nativeDecode.error)
        assertFalse(nativeDecode.isSuccess)
    }

    @Test
    fun `a cancelled request is not a success even with an errorless envelope`() {
        val cancelled = repository.parseContainerExportResult(
            """{"schemaVersion":1,"error":"","cancelled":true,
                "path":"","format":"opus","frameCount":0,"byteCount":0}"""
        )
        assertTrue(cancelled.cancelled)
        assertFalse(cancelled.isSuccess)
    }

    @Test
    fun `missing fields fall back to empty values instead of throwing`() {
        val result = repository.parseContainerExportResult("""{"schemaVersion":1}""")
        assertEquals("", result.path)
        assertEquals("", result.format)
        assertEquals(0L, result.frameCount)
        assertEquals(0L, result.byteCount)
        assertEquals("", result.error)
        assertFalse(result.cancelled)
    }

    @Test
    fun `malformed json returns a malformed error without throwing`() {
        val result = repository.parseContainerExportResult("not json at all")
        assertEquals("Malformed RTP container export response.", result.error)
        assertFalse(result.isSuccess)
    }

    @Test
    fun `no open capture short circuits before any jni call`() {
        // PacketRepository() 的会话句柄是 0，所以这条路径必然走「没有会话」分支。
        val result: RtpContainerExportResult = repository.exportContainer(
            scanGeneration = 1L,
            streamId = "s0",
            format = "amr",
            outDir = java.io.File("unused")
        )
        assertEquals("No capture is open.", result.error)
        assertFalse(result.isSuccess)
    }
}
