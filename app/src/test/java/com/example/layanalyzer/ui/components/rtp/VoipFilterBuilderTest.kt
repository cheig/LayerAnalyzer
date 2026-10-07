package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.data.LinkedRtpStream
import com.example.layanalyzer.data.RtpLinkReason
import com.example.layanalyzer.data.RtpStreamDirection
import com.example.layanalyzer.data.VoipCall
import com.example.layanalyzer.data.VoipCallState
import com.example.layanalyzer.model.RtpCodecSource
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpStream
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [VoipFilterBuilder] 的纯 JVM 单测（RTP3-UI-04）。
 *
 * 期望字符串**逐字写死**在本文件里（不调用 `RtpFilterBuilder` / `VoipFilterBuilder` 反推期望），
 * 以免实现和测试同源而掩盖错误。单条流内部的字段顺序属于 [RtpFilterBuilder] 的职责，
 * 这里只在 IPv6 用例里顺带钉住一次，其余用例只断言本卡新增的部分：
 * `Call-ID` 条件、括号与 ` || ` 拼接、上限截断、空结果。
 *
 * 含 `"` 与 `\` 的期望值用 [Q] / [BS] 两个常量拼出来，避免满屏 `\\\\` 看不清到底转义了几层。
 *
 * [RtpStream] / [VoipCall] 的构造参数很多，用私有 [stream] / [call] 帮助函数给出与断言无关
 * 字段的默认值，每个用例只覆盖自己要断言的部分。
 */
class VoipFilterBuilderTest {

    @Test
    fun `call id and one stream are joined with parentheses`() {
        val call = call(
            callId = "abcd",
            streams = listOf(linked(stream()))
        )

        assertEquals(
            "sip.Call-ID == \"abcd\" || " +
                "(ip.src==10.0.0.1 && udp.srcport==40000 && ip.dst==10.0.0.2 && udp.dstport==30000 && rtp.ssrc==0x1a2b3c4d)",
            VoipFilterBuilder.forCall(call).filter
        )
        assertFalse(VoipFilterBuilder.forCall(call).truncated)
    }

    @Test
    fun `every stream is parenthesised and separated by or`() {
        val call = call(
            callId = "",
            streams = listOf(
                linked(stream(src = "10.0.0.1", ssrc = 0x1L)),
                linked(stream(src = "10.0.0.3", ssrc = 0x2L))
            )
        )

        // callId 为空：只用流的部分，两条流都带括号、用 " || " 分隔。
        assertEquals(
            "(ip.src==10.0.0.1 && udp.srcport==40000 && ip.dst==10.0.0.2 && udp.dstport==30000 && rtp.ssrc==0x00000001)" +
                " || " +
                "(ip.src==10.0.0.3 && udp.srcport==40000 && ip.dst==10.0.0.2 && udp.dstport==30000 && rtp.ssrc==0x00000002)",
            VoipFilterBuilder.forCall(call).filter
        )
    }

    @Test
    fun `call id with a double quote is escaped`() {
        val call = call(callId = "x\"y", streams = emptyList())

        assertEquals("sip.Call-ID == ${Q}x$BS${Q}y$Q", VoipFilterBuilder.forCall(call).filter)
    }

    @Test
    fun `call id with a backslash is escaped`() {
        val call = call(callId = "x\\y", streams = emptyList())

        assertEquals("sip.Call-ID == ${Q}x${BS}${BS}y$Q", VoipFilterBuilder.forCall(call).filter)
    }

    @Test
    fun `call id with both quote and backslash escapes backslash first`() {
        val call = call(callId = "a\"b\\c", streams = emptyList())

        // 先转义 \ 再转义 "，所以 \ 变成两个、" 变成一个 \ 加 "。
        assertEquals(
            "sip.Call-ID == ${Q}a$BS${Q}b${BS}${BS}c$Q",
            VoipFilterBuilder.forCall(call).filter
        )
    }

    @Test
    fun `blank call id is omitted instead of emitting an empty literal`() {
        val call = call(callId = "   ", streams = listOf(linked(stream())))

        val result = VoipFilterBuilder.forCall(call)
        assertFalse("空白 callId 不应产生 sip.Call-ID 条件: <${result.filter}>", result.filter.contains("sip.Call-ID"))
        assertTrue(result.filter.startsWith("(ip.src==10.0.0.1"))
    }

    @Test
    fun `no sip and no streams returns an empty filter`() {
        val result = VoipFilterBuilder.forCall(call(callId = "", streams = emptyList()))

        assertEquals("", result.filter)
        assertFalse(result.truncated)
    }

    @Test
    fun `exactly the cap keeps every stream`() {
        val call = call(
            callId = "cap",
            streams = List(VoipFilterBuilder.MAX_STREAMS_IN_FILTER) { linked(stream(ssrc = it.toLong())) }
        )

        val result = VoipFilterBuilder.forCall(call)
        assertFalse(result.truncated)
        assertTrue(result.filter.startsWith("sip.Call-ID == \"cap\" || ("))
        // 分隔符恰好等于流数：Call-ID + 20 条流 = 21 个条件、20 个 " || "。
        assertEquals(
            VoipFilterBuilder.MAX_STREAMS_IN_FILTER,
            result.filter.split(" || ").size - 1
        )
        assertTrue(result.filter.endsWith(")"))
    }

    @Test
    fun `over the cap keeps only the call id and reports truncation`() {
        val call = call(
            callId = "cap",
            streams = List(VoipFilterBuilder.MAX_STREAMS_IN_FILTER + 1) { linked(stream(ssrc = it.toLong())) }
        )

        val result = VoipFilterBuilder.forCall(call)
        assertEquals("sip.Call-ID == \"cap\"", result.filter)
        assertTrue(result.truncated)
    }

    @Test
    fun `over the cap without a call id yields nothing to filter`() {
        val call = call(
            callId = "",
            streams = List(VoipFilterBuilder.MAX_STREAMS_IN_FILTER + 1) { linked(stream(ssrc = it.toLong())) }
        )

        // 没有 Call-ID 可退，只剩空字符串；空过滤器恒 truncated == false（没有东西可截断）。
        val result = VoipFilterBuilder.forCall(call)
        assertEquals("", result.filter)
        assertFalse(result.truncated)
    }

    @Test
    fun `ipv6 stream uses ipv6 fields inside the parentheses`() {
        val call = call(
            callId = "abcd",
            streams = listOf(
                linked(
                    stream(
                        src = "2001:db8::1", srcPort = 50000,
                        dst = "2001:db8::2", dstPort = 50002,
                        ssrc = 0x12345678L
                    )
                )
            )
        )

        assertEquals(
            "sip.Call-ID == \"abcd\" || " +
                "(ipv6.src==2001:db8::1 && udp.srcport==50000 && ipv6.dst==2001:db8::2 && udp.dstport==50002 && rtp.ssrc==0x12345678)",
            VoipFilterBuilder.forCall(call).filter
        )
    }

    // ---------------------------------------------------------------- 夹具

    private companion object {
        /** 双引号字面量；用来拼转义断言，避免 `\\\\` 摞在一起数不清。 */
        const val Q = "\""

        /** 单个反斜杠字面量。 */
        const val BS = "\\"
    }

    /** 只覆盖本卡关心的字段，其余给固定默认值；`ssrcHex` 由 `ssrc` 推导，避免手工不同步。 */
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

    /** 关联结果本身不参与过滤字符串，方向/依据给固定值即可。 */
    private fun linked(stream: RtpStream): LinkedRtpStream = LinkedRtpStream(
        stream = stream,
        direction = RtpStreamDirection.FORWARD,
        linkReason = RtpLinkReason.SDP_ADDRESS_PORT,
        callId = ""
    )

    /** 只覆盖本卡关心的字段：`callId` 与 `streams`。 */
    private fun call(callId: String, streams: List<LinkedRtpStream>): VoipCall = VoipCall(
        callId = callId, from = "", to = "", state = VoipCallState.IN_CALL,
        startRel = 0.0, setupMs = null, ringMs = null, durationMs = null,
        sipFrames = emptyList(), sdpFrames = emptyList(),
        streams = streams, mos = null
    )
}
