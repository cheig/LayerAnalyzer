// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RTP5-KT-02：视频导出模型里所有**纯**的部分（命名、后缀、MIME、能力判定、
 * 结果对象上的派生量），不碰 JNI、不碰 `android.*`。
 *
 * 钉的都是「按下去会失败」的那一类结论：后缀与内容不符的文件名、给音频编码取视频
 * MIME、把 `unknown` 的宽高当成已知、把「查询不了」当成「没有解码器」。
 */
class RtpVideoExportModelsTest {

    @Test
    fun `the video codec id is the two the native request accepts`() {
        assertEquals("H264", rtpVideoCodecId("H264"))
        assertEquals("H265", rtpVideoCodecId("h265"))
        assertEquals("H265", rtpVideoCodecId(" H265 "))
        // 原生 request parser 只认这两个字符串，别的取值会让整个请求失败 —— 所以
        // 拿不到规范 ID 的时候必须回 null，让调用方 fail-closed，而不是猜一个。
        assertNull(rtpVideoCodecId("HEVC"))
        assertNull(rtpVideoCodecId("PS"))
        assertNull(rtpVideoCodecId("g711A"))
        assertNull(rtpVideoCodecId(""))
    }

    @Test
    fun `the raw extension follows the codec`() {
        assertEquals("h264", rtpVideoRawExtension("H264"))
        assertEquals("h265", rtpVideoRawExtension("H265"))
        assertNull(rtpVideoRawExtension("g711A"))
    }

    @Test
    fun `the raw stream MIME is the card's pair and nothing for audio`() {
        assertEquals("video/h264", rtpVideoRawMimeType("H264"))
        assertEquals("video/hevc", rtpVideoRawMimeType("H265"))
        assertNull(rtpVideoRawMimeType("g711A"))
        assertNull(rtpVideoRawMimeType("opus"))
    }

    @Test
    fun `the file names use the M2 stem and the codec's own extension`() {
        val h264 = stream("s0", "H264")
        assertEquals("$STEM.h264", rtpVideoRawFileName(h264))
        assertEquals("$STEM.mp4", rtpVideoMp4FileName(h264))
        assertEquals("$STEM.h265", rtpVideoRawFileName(stream("s1", "H265")))

        // RAW 与 MP4 各自回答自己那一种格式，两种都在同一条词干上。
        assertEquals("$STEM.h264", rtpVideoFileName(h264, RtpVideoExportFormat.RAW))
        assertEquals("$STEM.mp4", rtpVideoFileName(h264, RtpVideoExportFormat.MP4))
    }

    @Test
    fun `a non video codec gets no video file name at all`() {
        val audio = stream("s0", "g711A")
        assertNull(rtpVideoRawFileName(audio))
        assertNull(rtpVideoMp4FileName(audio))
        assertNull(rtpVideoFileName(audio, RtpVideoExportFormat.RAW))
        assertNull(rtpVideoFileName(audio, RtpVideoExportFormat.MP4))
    }

    @Test
    fun `a success result exposes its files and its nal counts`() {
        val result = result(
            esPath = "/cache/s0.h264",
            indexPath = "/cache/s0.vidx",
            width = 1280,
            height = 720,
            unsupported = mapOf("STAP-B" to 0L, "MTAP16" to 0L, "FU-B" to 2L, "PACI" to 6L)
        )
        assertTrue(result.isSuccess)
        assertTrue(result.hasFiles)
        assertTrue(result.widthKnown)
        assertEquals(8L, result.unsupportedNalPackets)
    }

    @Test
    fun `a cancelled or failed result is not a success`() {
        assertFalse(result(error = "缺少参数集（SDP 与带内均未找到）").isSuccess)
        assertFalse(result(cancelled = true).isSuccess)
        // 原生把结果预置成中性值：error 为空、cancelled 为 false，但什么都没写。
        // isSuccess 会为 true，所以「能不能动文件」还要看 hasFiles。
        val prePopulated = result()
        assertTrue(prePopulated.isSuccess)
        assertFalse(prePopulated.hasFiles)
        assertFalse(prePopulated.widthKnown)
        assertEquals(-1L, prePopulated.firstKeyframeIndex)
    }

    @Test
    fun `widthSource unknown means the size is not known even when it is not zero`() {
        // 正常路径：键缺失 = 宽高是真读出来的。
        assertTrue(result(width = 1280, height = 720).widthKnown)
        // 原生只在读不出宽高时才带 widthSource:unknown（NAT-05 decision 11）。
        assertFalse(result(width = 1280, height = 720, widthSource = "unknown").widthKnown)
        assertFalse(result(width = 0, height = 0).widthKnown)
        assertFalse(result(width = 1280, height = 0).widthKnown)
    }

    @Test
    fun `the codec specific data knows when it is empty`() {
        assertTrue(RtpVideoCodecData.EMPTY.isEmpty)
        assertTrue(RtpVideoCodecData().isEmpty)
        assertFalse(RtpVideoCodecData(sps = "Z0LAHtk=").isEmpty)
        assertFalse(RtpVideoCodecData(pps = "aM4BQA==").isEmpty)
    }

    @Test
    fun `the decoder probe maps false to a notice and null to unknown`() {
        assertEquals(
            RtpVideoDecoderAvailability.AVAILABLE,
            rtpVideoDecoderAvailability(true)
        )
        assertEquals(RtpVideoDecoderAvailability.MISSING, rtpVideoDecoderAvailability(false))
        assertEquals(RtpVideoDecoderAvailability.UNKNOWN, rtpVideoDecoderAvailability(null))
    }

    @Test
    fun `no decoder means a notice but the export is still allowed`() {
        // 卡片原文：「给出提示，但**仍然允许导出**」。这两条都是行为约束，逐字钉住。
        assertTrue(RtpVideoDecoderAvailability.MISSING.noticeRequired)
        assertTrue(RtpVideoDecoderAvailability.MISSING.exportAllowed)

        // 有解码器不提示；查询不了也不提示（fail-open：别把「不知道」说成「没有」）。
        assertFalse(RtpVideoDecoderAvailability.AVAILABLE.noticeRequired)
        assertFalse(RtpVideoDecoderAvailability.UNKNOWN.noticeRequired)
        RtpVideoDecoderAvailability.entries.forEach { availability ->
            assertTrue("$availability must not block the export", availability.exportAllowed)
        }
    }

    private fun result(
        error: String = "",
        cancelled: Boolean = false,
        esPath: String = "",
        indexPath: String = "",
        width: Int = 0,
        height: Int = 0,
        widthSource: String = "",
        unsupported: Map<String, Long> = emptyMap()
    ) = RtpVideoExportResult(
        schemaVersion = 1,
        error = error,
        cancelled = cancelled,
        esPath = esPath,
        indexPath = indexPath,
        codec = "H264",
        width = width,
        height = height,
        widthSource = widthSource,
        unsupportedNalCounts = unsupported
    )

    private fun stream(id: String, codec: String) = RtpStream(
        id = id,
        src = "10.0.0.1",
        srcPort = 40000,
        dst = "10.0.0.2",
        dstPort = 30000,
        ssrc = 1L,
        ssrcHex = "0x00000001",
        pt = 97,
        codec = codec,
        codecSource = RtpCodecSource.SDP,
        clockRate = 90000,
        setupFrame = 1L,
        setupMethod = "sdp",
        isSrtp = false,
        packets = 10L,
        expected = 10L,
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
        bytes = 10L,
        firstFrame = 1L,
        lastFrame = 10L,
        startRel = 0.0,
        endRel = 1.0,
        firstAbsEpochUs = 0L,
        ptsSeen = emptyList(),
        decodable = RtpDecodability.YES,
        decodableReason = "",
        primaryPayloadType = 97
    )

    private companion object {
        /** `RtpExportFileStem` 的形状：`rtp_<src>_<srcPort>-<dst>_<dstPort>_<ssrcHex>`。 */
        const val STEM = "rtp_10.0.0.1_40000-10.0.0.2_30000_0x00000001"
    }
}
