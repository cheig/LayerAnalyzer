package com.example.layanalyzer.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * RTP5-KT-03：预览可用性的纯决策。
 *
 * 这一段的重点只有一条，但它值得单测：**判定顺序**。文件不在时无论解码器怎么答都必须是
 * 「没有可预览的东西」，不能变成「本机解不开这个编码」—— 后者会把一个导出问题说成设备问题，
 * 而 UI-01 就是按这个结论决定要不要显示入口、显示哪句话的。
 *
 * 「查询失败」（`null`）与「没有解码器」（`false`）也在这条链上分开：前者 fail-open，
 * 与 RTP5-KT-02 的 `RtpVideoDecoderAvailability.UNKNOWN` 同一口径。
 */
class RtpVideoPreviewAvailabilityTest {

    private val mp4 = "/cache/rtp/1/7/s0.mp4"
    private val vidx = "/cache/rtp/1/7/s0.vidx"

    @Test
    fun `both files plus a decoder is ready with both paths`() {
        assertEquals(
            RtpVideoPreviewAvailability.Ready(mp4Path = mp4, indexPath = vidx),
            availability(files = true, codec = "H264", decoder = true)
        )
    }

    @Test
    fun `no files is no export whatever the decoder says`() {
        listOf(null, true, false).forEach { decoder ->
            assertEquals(
                "decoder=$decoder",
                RtpVideoPreviewAvailability.NoExport,
                availability(files = false, codec = "H264", decoder = decoder)
            )
        }
    }

    @Test
    fun `blank paths are no export even when the caller says the files are there`() {
        assertEquals(
            RtpVideoPreviewAvailability.NoExport,
            rtpVideoPreviewAvailability(
                mp4Path = "",
                indexPath = vidx,
                filesPresent = true,
                codec = "H264",
                decoderAvailable = true
            )
        )
        assertEquals(
            RtpVideoPreviewAvailability.NoExport,
            rtpVideoPreviewAvailability(
                mp4Path = mp4,
                indexPath = "  ",
                filesPresent = true,
                codec = "H264",
                decoderAvailable = true
            )
        )
    }

    @Test
    fun `a missing decoder is its own outcome carrying the codec`() {
        assertEquals(
            RtpVideoPreviewAvailability.UnsupportedCodec("H265"),
            availability(files = true, codec = "H265", decoder = false)
        )
    }

    @Test
    fun `a failed decoder query is ready not unsupported`() {
        assertEquals(
            RtpVideoPreviewAvailability.Ready(mp4Path = mp4, indexPath = vidx),
            availability(files = true, codec = "H265", decoder = null)
        )
    }

    @Test
    fun `a codec that is not a video codec has no preview`() {
        listOf(null, true, false).forEach { decoder ->
            assertEquals(
                "decoder=$decoder",
                RtpVideoPreviewAvailability.NoExport,
                availability(files = true, codec = null, decoder = decoder)
            )
        }
    }

    @Test
    fun `the three outcomes are three different answers`() {
        val noExport = availability(files = false, codec = "H264", decoder = false)
        val unsupported = availability(files = true, codec = "H264", decoder = false)
        val ready = availability(files = true, codec = "H264", decoder = true)

        // 卡片：不能预览的原因必须能被 UI-01 区分出来，而不是一个布尔值。
        assertNotEquals(noExport, unsupported)
        assertNotEquals(unsupported, ready)
        assertNotEquals(noExport, ready)
    }

    private fun availability(
        files: Boolean,
        codec: String?,
        decoder: Boolean?
    ): RtpVideoPreviewAvailability = rtpVideoPreviewAvailability(
        mp4Path = mp4,
        indexPath = vidx,
        filesPresent = files,
        codec = codec,
        decoderAvailable = decoder
    )
}
