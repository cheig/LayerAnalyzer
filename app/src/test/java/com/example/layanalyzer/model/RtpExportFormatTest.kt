// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RTP4-KT-03：导出格式表的纯 JVM 单测。
 *
 * 表住在 `RtpCodecCatalog`（卡片点名），这张测试钉住卡片那一行一行的对应关系。
 * 断言用的是**双向下标**（`assertEquals(setOf(...), actual)`）而不是 `contains`：
 * 「多给了一种格式」与「少给了一种」一样是 bug —— 菜单里多出来的按钮按下去会失败。
 *
 * 有两处与卡片字面表述不同，理由写在 `RtpCodecCatalog.exportFormats` 的 KDoc 里，
 * 这里同样钉住：`L16` 有裸流、`iLBC` 没有。
 */
class RtpExportFormatTest {

    @Test
    fun `mime types are the five the card fixes`() {
        assertEquals("audio/wav", RtpExportFormat.WAV.mimeType)
        assertEquals("application/octet-stream", RtpExportFormat.RAW.mimeType)
        assertEquals("audio/amr", RtpExportFormat.AMR.mimeType)
        assertEquals("audio/amr-wb", RtpExportFormat.AWB.mimeType)
        assertEquals("audio/ogg", RtpExportFormat.OPUS.mimeType)
    }

    @Test
    fun `container formats carry the native format string`() {
        assertNull(RtpExportFormat.WAV.containerFormat)
        assertNull(RtpExportFormat.RAW.containerFormat)
        assertEquals("amr", RtpExportFormat.AMR.containerFormat)
        assertEquals("awb", RtpExportFormat.AWB.containerFormat)
        assertEquals("opus", RtpExportFormat.OPUS.containerFormat)
        assertTrue(RtpExportFormat.AMR.isContainer)
        assertTrue(RtpExportFormat.AWB.isContainer)
        assertTrue(RtpExportFormat.OPUS.isContainer)
        assertTrue(!RtpExportFormat.WAV.isContainer)
        assertTrue(!RtpExportFormat.RAW.isContainer)
    }

    @Test
    fun `wav is offered for every decodable codec and for nothing else`() {
        val decodable = listOf(
            "g711A", "g711U", "L16", "g722", "g729", "iLBC",
            "G726-32", "AAL2-G726-16", "AMR", "AMR-WB", "opus"
        )
        decodable.forEach { codec ->
            assertTrue(
                "WAV is missing for $codec",
                RtpExportFormat.WAV in RtpCodecCatalog.exportFormats(codec)
            )
        }
    }

    @Test
    fun `unsupported codecs have no export format at all`() {
        assertEquals(emptySet<RtpExportFormat>(), RtpCodecCatalog.exportFormats("H264"))
        assertEquals(emptySet<RtpExportFormat>(), RtpCodecCatalog.exportFormats("h265"))
        assertEquals(emptySet<RtpExportFormat>(), RtpCodecCatalog.exportFormats("nope"))
        assertEquals(emptySet<RtpExportFormat>(), RtpCodecCatalog.exportFormats(""))
        assertEquals(emptySet<RtpExportFormat>(), RtpCodecCatalog.exportFormats("   "))
    }

    @Test
    fun `raw payload is offered for the g seven families the card lists`() {
        val raw = listOf(
            "g711A", "g711U", "G722", "G729",
            "G726-16", "G726-24", "G726-32", "G726-40",
            "AAL2-G726-16", "AAL2-G726-24", "AAL2-G726-32", "AAL2-G726-40"
        )
        raw.forEach { codec ->
            assertTrue(
                "RAW is missing for $codec",
                RtpExportFormat.RAW in RtpCodecCatalog.exportFormats(codec)
            )
        }
        // 卡片把裸流写成「G.711/G.722/G.726/G.729」，L16 是 RTP2-KT-02 起就支持的
        // 特例，去掉它会让 G.711 线性编码的流在菜单里凭空少一个入口。
        assertTrue(RtpExportFormat.RAW in RtpCodecCatalog.exportFormats("l16"))
        // iLBC 不在卡片的裸流清单里，所以只给 WAV。
        assertEquals(
            setOf(RtpExportFormat.WAV),
            RtpCodecCatalog.exportFormats("iLBC")
        )
    }

    @Test
    fun `the format table is case insensitive and follows byId`() {
        assertEquals(
            setOf(RtpExportFormat.WAV, RtpExportFormat.RAW),
            RtpCodecCatalog.exportFormats("g711A")
        )
        assertEquals(
            setOf(RtpExportFormat.WAV, RtpExportFormat.RAW),
            RtpCodecCatalog.exportFormats("G711A")
        )
        assertEquals(
            setOf(RtpExportFormat.WAV, RtpExportFormat.RAW),
            RtpCodecCatalog.exportFormats("l16")
        )
        assertEquals(
            setOf(RtpExportFormat.WAV, RtpExportFormat.AWB),
            RtpCodecCatalog.exportFormats("amr-wb")
        )
        assertEquals(
            setOf(RtpExportFormat.WAV, RtpExportFormat.AWB),
            RtpCodecCatalog.exportFormats("AMR-WB")
        )
        assertEquals(
            setOf(RtpExportFormat.WAV, RtpExportFormat.OPUS),
            RtpCodecCatalog.exportFormats("OPUS")
        )
        assertEquals(
            setOf(RtpExportFormat.WAV, RtpExportFormat.AMR),
            RtpCodecCatalog.exportFormats("amr")
        )
        assertEquals(
            setOf(RtpExportFormat.WAV, RtpExportFormat.RAW),
            RtpCodecCatalog.exportFormats("  g729  ")
        )
        // `PCMA`/`PCMU` 这类别名不在 `byId` 里（规范 ID 只有 `g711A`/`g711U`，
        // 原生 `RtpCodecNames::canonical` 早就把它们归一化了），所以格式表也不认：
        // 口径与 `byId` 一致，不在这里多造一套别名表。
        assertEquals(emptySet<RtpExportFormat>(), RtpCodecCatalog.exportFormats("PCMA"))
        assertEquals(emptySet<RtpExportFormat>(), RtpCodecCatalog.exportFormats("PCMU"))
    }

    @Test
    fun `containerFormat answers the native format string or null`() {
        assertEquals(RtpExportFormat.AMR, RtpCodecCatalog.containerFormat("AMR"))
        assertEquals(RtpExportFormat.AMR, RtpCodecCatalog.containerFormat("amr"))
        assertEquals(RtpExportFormat.AWB, RtpCodecCatalog.containerFormat("AMR-WB"))
        assertEquals(RtpExportFormat.OPUS, RtpCodecCatalog.containerFormat("opus"))
        assertNull(RtpCodecCatalog.containerFormat("g711A"))
        assertNull(RtpCodecCatalog.containerFormat("g722"))
        assertNull(RtpCodecCatalog.containerFormat("H264"))
        assertNull(RtpCodecCatalog.containerFormat(""))
    }

    @Test
    fun `container file names follow the frozen stem and container extension`() {
        val amr = stream(codec = "AMR")
        assertEquals(
            "rtp_10.0.0.1_40000-10.0.0.2_30000_0x1a2b3c4d.amr",
            rtpContainerFileName(amr, RtpExportFormat.AMR)
        )
        assertEquals(
            "rtp_10.0.0.1_40000-10.0.0.2_30000_0x1a2b3c4d.awb",
            rtpContainerFileName(stream(codec = "AMR-WB"), RtpExportFormat.AWB)
        )
        assertEquals(
            "rtp_10.0.0.1_40000-10.0.0.2_30000_0x1a2b3c4d.opus",
            rtpContainerFileName(stream(codec = "opus"), RtpExportFormat.OPUS)
        )
        // 非容器格式没有容器文件名。
        assertNull(rtpContainerFileName(amr, RtpExportFormat.WAV))
        assertNull(rtpContainerFileName(amr, RtpExportFormat.RAW))
    }

    @Test
    fun `export file names cover all five formats`() {
        val g711a = stream(codec = "g711A")
        assertEquals(rtpWavFileName(g711a), rtpExportFileName(g711a, RtpExportFormat.WAV))
        assertEquals(rtpRawFileName(g711a), rtpExportFileName(g711a, RtpExportFormat.RAW))
        // 编码与格式不一致时必须给 null，菜单与导出管线才可能一致。
        assertNull(rtpExportFileName(g711a, RtpExportFormat.AMR))
        assertEquals(
            "rtp_10.0.0.1_40000-10.0.0.2_30000_0x1a2b3c4d.g722",
            rtpExportFileName(stream(codec = "g722"), RtpExportFormat.RAW)
        )
        assertEquals(
            "rtp_10.0.0.1_40000-10.0.0.2_30000_0x1a2b3c4d.opus",
            rtpExportFileName(stream(codec = "opus"), RtpExportFormat.OPUS)
        )
        assertNull(rtpExportFileName(stream(codec = "H264"), RtpExportFormat.AMR))
    }

    @Test
    fun `raw extensions were widened to the g seven families`() {
        assertEquals("g722", rtpRawExtension("g722"))
        assertEquals("g729", rtpRawExtension("G729"))
        assertEquals("g729", rtpRawExtension("g729b"))
        assertEquals("g726-32", rtpRawExtension("G726-32"))
        assertEquals("aal2-g726-24", rtpRawExtension("AAL2-G726-24"))
        // 既有取值一个都没变。
        assertEquals("pcma", rtpRawExtension("g711A"))
        assertEquals("pcmu", rtpRawExtension("G711U"))
        assertEquals("l16", rtpRawExtension("L16"))
        assertNull(rtpRawExtension("opus"))
        assertNull(rtpRawExtension("iLBC"))
        assertNull(rtpRawExtension(""))
    }

    private fun stream(
        src: String = "10.0.0.1",
        srcPort: Int = 40_000,
        dst: String = "10.0.0.2",
        dstPort: Int = 30_000,
        ssrcHex: String = "0x1a2b3c4d",
        codec: String = "g711A"
    ): RtpStream = RtpStream(
        id = "s0",
        src = src,
        srcPort = srcPort,
        dst = dst,
        dstPort = dstPort,
        ssrc = 439_041_101L,
        ssrcHex = ssrcHex,
        pt = 8,
        codec = codec,
        codecSource = RtpCodecSource.STATIC,
        clockRate = 8_000,
        setupFrame = 0L,
        setupMethod = "",
        isSrtp = false,
        packets = 1L,
        expected = 1L,
        lost = 0L,
        lostPct = 0.0,
        seqErrors = 0L,
        outOfOrder = 0L,
        truncated = 0L,
        problem = false,
        minDeltaMs = 0.0,
        meanDeltaMs = 0.0,
        maxDeltaMs = 0.0,
        maxDeltaFrame = 0L,
        minJitterMs = null,
        meanJitterMs = null,
        maxJitterMs = null,
        jitterAvailable = false,
        maxSkewMs = 0.0,
        bytes = 0L,
        firstFrame = 1L,
        lastFrame = 1L,
        startRel = 0.0,
        endRel = 0.0,
        firstAbsEpochUs = 0L,
        ptsSeen = emptyList(),
        decodable = RtpDecodability.YES,
        decodableReason = "",
        primaryPayloadType = 8
    )
}
