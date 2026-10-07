// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.RtpCodecSource
import com.example.layanalyzer.model.RtpDecodability
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [RtpRepository.parseScanResult] 的纯 JVM 单测（RTP1-KT-01）。
 *
 * 期望值来自任务清单 RtpModels.kt 的示例 JSON。
 */
class RtpRepositoryParsingTest {

    private val repository = RtpRepository(PacketRepository())

    @Test
    fun `full response parses every field`() {
        val result = repository.parseScanResult(
            """
            { "schemaVersion": 1, "error": "", "cancelled": false,
              "scanGeneration": 7, "framesScanned": 12000, "heuristicEnabled": false,
              "streams": [ {
                "id": "s0", "src": "10.0.0.1", "srcPort": 40000, "dst": "10.0.0.2", "dstPort": 30000,
                "ssrc": 439041101, "ssrcHex": "0x1a2b3c4d",
                "pt": 8, "codec": "g711A", "codecSource": "static",
                "clockRate": 8000, "setupFrame": 12, "setupMethod": "SDP",
                "isSrtp": false, "packets": 1500, "expected": 1503, "lost": 3, "lostPct": 0.2,
                "seqErrors": 1, "outOfOrder": 0, "truncated": 0,
                "maxDeltaMs": 61.2, "maxDeltaFrame": 812, "maxJitterMs": 4.1, "meanJitterMs": 1.3, "maxSkewMs": 2.0,
                "firstFrame": 20, "lastFrame": 3100, "startRel": 1.02, "endRel": 31.4,
                "ptsSeen": [8, 101],
                "decodable": "yes", "decodableReason": "" } ] }
            """.trimIndent()
        )

        assertEquals(1, result.schemaVersion)
        assertEquals("", result.error)
        assertFalse(result.cancelled)
        assertEquals(7L, result.scanGeneration)
        assertEquals(12000L, result.framesScanned)
        assertFalse(result.heuristicEnabled)
        assertFalse(result.streamsTruncated)
        assertTrue(result.isSuccess)

        assertEquals(1, result.streams.size)
        val stream = result.streams.single()
        assertEquals("s0", stream.id)
        assertEquals("10.0.0.1", stream.src)
        assertEquals(40000, stream.srcPort)
        assertEquals("10.0.0.2", stream.dst)
        assertEquals(30000, stream.dstPort)
        assertEquals(439041101L, stream.ssrc)
        assertEquals("0x1a2b3c4d", stream.ssrcHex)
        assertEquals(8, stream.pt)
        assertEquals("g711A", stream.codec)
        assertEquals(RtpCodecSource.STATIC, stream.codecSource)
        assertEquals(8000, stream.clockRate)
        assertEquals(12L, stream.setupFrame)
        assertEquals("SDP", stream.setupMethod)
        assertFalse(stream.isSrtp)
        assertEquals(1500L, stream.packets)
        assertEquals(1503L, stream.expected)
        assertEquals(3L, stream.lost)
        assertEquals(0.2, stream.lostPct, 0.0)
        assertEquals(1L, stream.seqErrors)
        assertEquals(0L, stream.outOfOrder)
        assertEquals(0L, stream.truncated)
        assertFalse(stream.problem)
        assertEquals(0.0, stream.minDeltaMs, 0.0)
        assertEquals(0.0, stream.meanDeltaMs, 0.0)
        assertEquals(61.2, stream.maxDeltaMs, 0.0)
        assertEquals(812L, stream.maxDeltaFrame)
        assertNull(stream.minJitterMs)
        assertEquals(1.3, stream.meanJitterMs!!, 0.0)
        assertEquals(4.1, stream.maxJitterMs!!, 0.0)
        assertFalse(stream.jitterAvailable)
        assertEquals(2.0, stream.maxSkewMs, 0.0)
        assertEquals(0L, stream.bytes)
        assertEquals(20L, stream.firstFrame)
        assertEquals(3100L, stream.lastFrame)
        assertEquals(1.02, stream.startRel, 0.0)
        assertEquals(31.4, stream.endRel, 0.0)
        assertEquals(0L, stream.firstAbsEpochUs)
        assertEquals(listOf(8, 101), stream.ptsSeen)
        assertEquals(RtpDecodability.YES, stream.decodable)
        assertEquals("", stream.decodableReason)
        assertEquals(0, stream.primaryPayloadType)
    }

    @Test
    fun `missing fields fall back to defaults`() {
        val result = repository.parseScanResult(
            """{ "streams": [ { "id": "s9", "src": "192.0.2.1", "ssrc": 77 } ] }"""
        )

        assertEquals(1, result.streams.size)
        val stream = result.streams.single()
        assertEquals("s9", stream.id)
        assertEquals("192.0.2.1", stream.src)
        assertEquals(77L, stream.ssrc)
        assertEquals("", stream.dst)
        assertEquals(0, stream.srcPort)
        assertEquals(0, stream.dstPort)
        assertEquals("", stream.ssrcHex)
        assertEquals(0, stream.pt)
        assertEquals("", stream.codec)
        assertEquals(RtpCodecSource.UNKNOWN, stream.codecSource)
        assertEquals(0, stream.clockRate)
        assertEquals("", stream.setupMethod)
        assertFalse(stream.isSrtp)
        assertEquals(0L, stream.packets)
        assertEquals(0L, stream.expected)
        assertEquals(0L, stream.lost)
        assertEquals(0.0, stream.lostPct, 0.0)
        assertEquals(0L, stream.truncated)
        assertEquals(0.0, stream.maxDeltaMs, 0.0)
        assertNull(stream.minJitterMs)
        assertNull(stream.meanJitterMs)
        assertNull(stream.maxJitterMs)
        assertFalse(stream.jitterAvailable)
        assertEquals(0L, stream.firstFrame)
        assertEquals(0L, stream.lastFrame)
        assertEquals(emptyList<Int>(), stream.ptsSeen)
        assertEquals(RtpDecodability.UNSUPPORTED, stream.decodable)
        assertEquals("", stream.decodableReason)
        assertEquals(0, stream.primaryPayloadType)
        assertTrue(result.isSuccess)
    }

    @Test
    fun `non empty error is not success and has no streams`() {
        val result = repository.parseScanResult(
            """
            { "schemaVersion": 1, "error": "No capture is open.", "cancelled": false,
              "scanGeneration": 0, "framesScanned": 0, "heuristicEnabled": false, "streams": [] }
            """.trimIndent()
        )

        assertFalse(result.isSuccess)
        assertEquals("No capture is open.", result.error)
        assertTrue(result.streams.isEmpty())
    }

    @Test
    fun `cancelled result is not success`() {
        val result = repository.parseScanResult(
            """
            { "schemaVersion": 1, "error": "", "cancelled": true,
              "scanGeneration": 8, "framesScanned": 500, "heuristicEnabled": false, "streams": [] }
            """.trimIndent()
        )

        assertTrue(result.cancelled)
        assertFalse(result.isSuccess)
    }

    @Test
    fun `unknown decodability maps to unsupported`() {
        val result = repository.parseScanResult(
            """{ "schemaVersion": 1, "error": "", "cancelled": false, "streams": [
                 { "id": "s0", "decodable": "weird" } ] }"""
        )

        assertEquals(RtpDecodability.UNSUPPORTED, result.streams.single().decodable)
    }

    @Test
    fun `unknown fields are tolerated`() {
        val result = repository.parseScanResult(
            """
            { "schemaVersion": 1, "error": "", "cancelled": false, "futureTopLevel": { "x": 1 },
              "streams": [ { "id": "s0", "src": "10.0.0.1", "ssrc": 1, "futureField": "ignored",
                             "packets": 10, "decodable": "needsMapping" } ],
              "futureList": [ 1, 2, 3 ] }
            """.trimIndent()
        )

        assertEquals(1, result.streams.size)
        val stream = result.streams.single()
        assertEquals("s0", stream.id)
        assertEquals("10.0.0.1", stream.src)
        assertEquals(10L, stream.packets)
        assertEquals(RtpDecodability.NEEDS_MAPPING, stream.decodable)
        assertTrue(result.isSuccess)
    }

    @Test
    fun `malformed json returns malformed error without throwing`() {
        val result = repository.parseScanResult("not a json object")

        assertFalse(result.isSuccess)
        assertEquals("Malformed RTP scan response.", result.error)
        assertTrue(result.streams.isEmpty())
    }

    @Test
    fun `null jitter values stay null while jitterAvailable is parsed`() {
        val result = repository.parseScanResult(
            """{ "streams": [ { "id": "s0", "minJitterMs": null, "meanJitterMs": null,
                                "maxJitterMs": null, "jitterAvailable": false } ] }"""
        )

        val stream = result.streams.single()
        assertNull(stream.minJitterMs)
        assertNull(stream.meanJitterMs)
        assertNull(stream.maxJitterMs)
        assertFalse(stream.jitterAvailable)
    }
}
