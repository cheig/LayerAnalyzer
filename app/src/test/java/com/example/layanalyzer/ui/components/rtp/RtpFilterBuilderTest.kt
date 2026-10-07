package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.model.RtpCodecSource
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpStream
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * [RtpFilterBuilder] 的纯 JVM 单测（RTP1-UI-02）。
 *
 * 期望字符串**逐字写死**在本文件里（不调用 `RtpFilterBuilder` 反推期望），
 * 以免实现和测试同源而掩盖错误。
 *
 * [RtpStream] 的构造参数很多，用一个私有 [stream] 帮助函数给出与断言无关字段的默认值，
 * 每个用例只覆盖自己要断言的部分。
 */
class RtpFilterBuilderTest {

    @Test
    fun `ipv4 stream produces the fixed field order`() {
        val stream = stream(
            src = "10.0.0.1", srcPort = 40000,
            dst = "10.0.0.2", dstPort = 30000,
            ssrc = 0x1a2b3c4dL
        )

        assertEquals(
            "ip.src==10.0.0.1 && udp.srcport==40000 && ip.dst==10.0.0.2 && udp.dstport==30000 && rtp.ssrc==0x1a2b3c4d",
            RtpFilterBuilder.forStream(stream)
        )
    }

    @Test
    fun `ipv6 stream uses ipv6 address fields`() {
        val stream = stream(
            src = "2001:db8::1", srcPort = 50000,
            dst = "2001:db8::2", dstPort = 50002,
            ssrc = 0x12345678L
        )

        assertEquals(
            "ipv6.src==2001:db8::1 && udp.srcport==50000 && ipv6.dst==2001:db8::2 && udp.dstport==50002 && rtp.ssrc==0x12345678",
            RtpFilterBuilder.forStream(stream)
        )
    }

    @Test
    fun `ssrc is lower-case hex padded to eight digits`() {
        val stream = stream(ssrc = 0xabcdL)

        assertEquals(
            "ip.src==10.0.0.1 && udp.srcport==40000 && ip.dst==10.0.0.2 && udp.dstport==30000 && rtp.ssrc==0x0000abcd",
            RtpFilterBuilder.forStream(stream)
        )
    }

    @Test
    fun `filter has no stray whitespace`() {
        val filter = RtpFilterBuilder.forStream(stream(ssrc = 0x1a2b3c4dL))

        assertFalse("filter must not contain a double space: <$filter>", filter.contains("  "))
        assertFalse("filter must not start with a space: <$filter>", filter.startsWith(" "))
        assertFalse("filter must not end with a space: <$filter>", filter.endsWith(" "))
        assertEquals(filter.trim(), filter)
    }

    /**
     * 只覆盖本卡关心的字段，其余给固定默认值；`ssrcHex` 由 `ssrc` 推导，避免手工不同步。
     */
    private fun stream(
        src: String = "10.0.0.1",
        srcPort: Int = 40000,
        dst: String = "10.0.0.2",
        dstPort: Int = 30000,
        ssrc: Long = 0x1a2b3c4dL
    ): RtpStream = RtpStream(
        id = "s0",
        src = src, srcPort = srcPort, dst = dst, dstPort = dstPort,
        ssrc = ssrc, ssrcHex = String.format(Locale.US, "0x%08x", ssrc),
        pt = 8, codec = "g711A", codecSource = RtpCodecSource.STATIC, clockRate = 8000,
        setupFrame = 0L, setupMethod = "", isSrtp = false,
        packets = 0L, expected = 0L, lost = 0L, lostPct = 0.0,
        seqErrors = 0L, outOfOrder = 0L, truncated = 0L, problem = false,
        minDeltaMs = 0.0, meanDeltaMs = 0.0, maxDeltaMs = 0.0, maxDeltaFrame = 0L,
        minJitterMs = null, meanJitterMs = null, maxJitterMs = null, jitterAvailable = false,
        maxSkewMs = 0.0, bytes = 0L,
        firstFrame = 0L, lastFrame = 0L, startRel = 0.0, endRel = 0.0,
        firstAbsEpochUs = 0L,
        ptsSeen = emptyList(), decodable = RtpDecodability.YES, decodableReason = "",
        primaryPayloadType = 8
    )
}
