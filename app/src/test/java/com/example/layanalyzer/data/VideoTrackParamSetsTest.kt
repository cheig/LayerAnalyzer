package com.example.layanalyzer.data

import com.example.layanalyzer.media.VideoMuxFormat
import com.example.layanalyzer.model.RtpVideoCodecData
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RTP5-KT-02：交给封装器的参数集从哪来（两个来源的顺序），以及原生 `csd` →
 * `VideoParamSets` 的映射。
 *
 * 这个顺序决定了 MP4 能不能导出：封装器对缺 SPS/PPS 是 fail-closed，所以「原生已经
 * 报告了带内参数集、却被当成没有」这条路径的代价是**每一条**带内参数集的流都导不出
 * MP4 —— 正是 KT-01 的验收夹具之一。
 *
 * 映射的终点用 `VideoMuxFormat.codecSpecificData` 来验，不重新实现一遍 `csd-0`/`csd-1`
 * 的拼法：那两组的形状是 KT-01 的契约，这里只负责把字节放到正确的字段上。
 *
 * 下面的字节**不是**真实的 SPS/PPS，也不需要是：本测试只做 Base64 → 字节的往返与
 * 字段归位，没有任何一步解析 NAL（真实向量在 `media/VideoMuxFormatTest` 里，那里才是
 * 把它们拼进 `avcC` 的地方）。
 */
class VideoTrackParamSetsTest {

    @Test
    fun `the caller's sdp sets win when both sources have some`() {
        val caller = paramSets(sps = CALLER_SPS, pps = CALLER_PPS)
        val reported = csd(sps = REPORTED_SPS, pps = REPORTED_PPS)

        val merged = videoTrackParamSets(caller, reported)

        assertArrayEquals(CALLER_SPS, merged.sps.single())
        assertArrayEquals(CALLER_PPS, merged.pps.single())
        // 调用方给了就原样用，不去碰原生那一份。
        assertTrue(merged.vps.isEmpty())
    }

    @Test
    fun `the native reported csd is used when the caller has none`() {
        val reported = csd(sps = REPORTED_SPS, pps = REPORTED_PPS)

        val fromNull = videoTrackParamSets(null, reported)
        assertArrayEquals(REPORTED_SPS, fromNull.sps.single())
        assertArrayEquals(REPORTED_PPS, fromNull.pps.single())

        // 空组与 null 是一回事：都是「调用方给不出来」。
        val fromEmpty = videoTrackParamSets(paramSets(), reported)
        assertArrayEquals(REPORTED_SPS, fromEmpty.sps.single())
        assertArrayEquals(REPORTED_PPS, fromEmpty.pps.single())
    }

    @Test
    fun `a caller group with only an sps is used as given and refused by the muxer`() {
        // 「调用方给了」的判据是「这组里有任何一项」，不是「这组完整」：完整性由 KT-01
        // 按编码判（H.264 要 SPS+PPS，H.265 要 SPS+PPS），在这里再判一遍就等于长出第二套
        // 规则。给半组的后果是封装器 fail-closed，仍然是一条明确的失败，不是猜出来的轨道。
        val reported = csd(sps = REPORTED_SPS, pps = REPORTED_PPS)

        val merged = videoTrackParamSets(paramSets(sps = CALLER_SPS), reported)

        assertArrayEquals(CALLER_SPS, merged.sps.single())
        assertTrue(merged.pps.isEmpty())
        assertNull(VideoMuxFormat.codecSpecificData("H264", merged))
    }

    @Test
    fun `an h264 report describes csd-0 and csd-1`() {
        val mapped = csd(sps = REPORTED_SPS, pps = REPORTED_PPS).toParamSets()

        val csd = VideoMuxFormat.codecSpecificData("H264", mapped)
        assertTrue(csd != null)
        assertArrayEquals(
            VideoMuxFormat.START_CODE + REPORTED_SPS,
            csd!!.csd0
        )
        assertArrayEquals(
            VideoMuxFormat.START_CODE + REPORTED_PPS,
            csd.csd1
        )
    }

    @Test
    fun `an h265 report concatenates vps sps and pps into one csd-0`() {
        val mapped = csd(
            sps = REPORTED_SPS,
            pps = REPORTED_PPS,
            vps = REPORTED_VPS
        ).toParamSets()

        val csd = VideoMuxFormat.codecSpecificData("H265", mapped)
        assertTrue(csd != null)
        assertArrayEquals(
            VideoMuxFormat.START_CODE + REPORTED_VPS +
                VideoMuxFormat.START_CODE + REPORTED_SPS +
                VideoMuxFormat.START_CODE + REPORTED_PPS,
            csd!!.csd0
        )
        // H.265 只有 csd-0 一个条目（KT-01 的契约）。
        assertNull(csd.csd1)
    }

    @Test
    fun `an h265 report with no vps still describes the track`() {
        // VPS 是可选的（KT-01 的 codecSpecificData 明说编解码器确实会省掉它）。
        val mapped = csd(sps = REPORTED_SPS, pps = REPORTED_PPS).toParamSets()

        val csd = VideoMuxFormat.codecSpecificData("H265", mapped)
        assertTrue(csd != null)
        assertArrayEquals(
            VideoMuxFormat.START_CODE + REPORTED_SPS +
                VideoMuxFormat.START_CODE + REPORTED_PPS,
            csd!!.csd0
        )
    }

    @Test
    fun `nothing anywhere stays an empty group the muxer refuses`() {
        val merged = videoTrackParamSets(null, RtpVideoCodecData.EMPTY)

        assertFalse(merged.hasAnyParameterSet())
        // 这条就是「带内也没有、SDP 也没有」的流：封装器 fail-closed，回
        // missingParameterSets，不生成坏 MP4。
        assertNull(VideoMuxFormat.codecSpecificData("H264", merged))
        assertNull(VideoMuxFormat.codecSpecificData("H265", merged))
    }

    @Test
    fun `a null or empty or undecodable entry is dropped rather than guessed`() {
        // 非法 Base64：整项丢掉 → 该组为空 → H.264 描述不了轨道。
        val badSps = videoTrackParamSets(
            null,
            RtpVideoCodecData(sps = "not base64 !!", pps = base64(REPORTED_PPS))
        )
        assertTrue(badSps.sps.isEmpty())
        assertNull(VideoMuxFormat.codecSpecificData("H264", badSps))

        // 空串与 null 一样是「没有这一组」。
        val emptyPps = videoTrackParamSets(
            null,
            RtpVideoCodecData(sps = base64(REPORTED_SPS), pps = "")
        )
        assertTrue(emptyPps.pps.isEmpty())
        assertNull(VideoMuxFormat.codecSpecificData("H264", emptyPps))

        // 解出来是 0 字节也算没有（0 字节的「参数集」是假的）。
        val zeroBytes = videoTrackParamSets(
            null,
            RtpVideoCodecData(sps = "", pps = base64(ByteArray(0)))
        )
        assertFalse(zeroBytes.hasAnyParameterSet())
    }

    @Test
    fun `the fmtp scalars are not invented from a csd`() {
        // csd 只说字节，不带 packetization-mode / profile-level-id /
        // sprop-max-don-diff；这三项必须是 null，不是 0 或空串。
        val mapped = csd(sps = REPORTED_SPS, pps = REPORTED_PPS, vps = REPORTED_VPS).toParamSets()

        assertNull(mapped.packetizationMode)
        assertNull(mapped.profileLevelId)
        assertNull(mapped.donDiff)
        assertEquals(1, mapped.sps.size)
        assertEquals(1, mapped.pps.size)
        assertEquals(1, mapped.vps.size)
    }

    private fun paramSets(
        sps: ByteArray? = null,
        pps: ByteArray? = null,
        vps: ByteArray? = null
    ) = VideoParamSets(
        sps = listOfNotNull(sps),
        pps = listOfNotNull(pps),
        vps = listOfNotNull(vps),
        packetizationMode = null,
        profileLevelId = null,
        donDiff = null
    )

    /** 原生结果里的 `csd`：Base64（或 `null`）的三个值，与 `RtpJni.cpp` 的产出一致。 */
    private fun csd(sps: ByteArray? = null, pps: ByteArray? = null, vps: ByteArray? = null) =
        RtpVideoCodecData(
            sps = sps?.let(::base64),
            pps = pps?.let(::base64),
            vps = vps?.let(::base64)
        )

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private companion object {
        val CALLER_SPS = byteArrayOf(0x11, 0x22, 0x33, 0x44)
        val CALLER_PPS = byteArrayOf(0x55, 0x66)
        val REPORTED_SPS = byteArrayOf(0x67, 0x42, 0x00, 0x1E, 0x7F)
        val REPORTED_PPS = byteArrayOf(0x68, 0xCE.toByte(), 0x3C, 0x80.toByte())
        val REPORTED_VPS = byteArrayOf(0x40, 0x01, 0x0C, 0x01)
    }
}
