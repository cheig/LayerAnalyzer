// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.RtpCodecSource
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SdpOfferAnswerAssociation
import com.example.layanalyzer.model.SipDialogEvent
import com.example.layanalyzer.model.SipDialogTimeline
import com.example.layanalyzer.model.SipMessage
import com.example.layanalyzer.model.SipTransaction
import org.junit.Assert.*
import org.junit.Test

/**
 * [RtpCallLinker] 的 JVM 测试：逐条对照 `task_rtp_m3_voip_calls.md` 附录 A 的四张表。
 *
 * 夹具的时间全部以绝对 epoch 秒给出（[CAPTURE_START] + 相对秒数），流的
 * `firstAbsEpochUs` 与 `startRel` 由 [stream] 保证自洽，这样联接器推导出的抓包起点
 * 正好是 [CAPTURE_START]。
 */
class RtpCallLinkerTest {

    // ------------------------------------------------------------ 场景 1

    @Test
    fun `setup frame inside sdpFrames links with SETUP_FRAME and the table 2 direction`() {
        val dialog = standardDialog(byeTime = null)
        val fromCaller = stream(id = "s0", setupFrame = 10)
        val toCaller = stream(
            id = "s1",
            src = CALLEE_ADDRESS,
            srcPort = CALLEE_MEDIA_PORT,
            dst = CALLER_ADDRESS,
            dstPort = CALLER_MEDIA_PORT,
            setupFrame = 14
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(fromCaller, toCaller))

        val call = result.calls.single()
        assertEquals(listOf("s0", "s1"), call.streams.map { it.stream.id })
        assertEquals(RtpLinkReason.SETUP_FRAME, call.streams[0].linkReason)
        assertEquals(RtpStreamDirection.FORWARD, call.streams[0].direction)
        assertEquals(RtpLinkReason.SETUP_FRAME, call.streams[1].linkReason)
        assertEquals(RtpStreamDirection.REVERSE, call.streams[1].direction)
        assertTrue(call.streams.all { it.callId == CALL_ID })
        assertNull(call.streams[0].warning)
        assertTrue(result.unlinkedStreams.isEmpty())
        assertTrue(result.warnings.isEmpty())
    }

    // ------------------------------------------------------------ 场景 2

    @Test
    fun `sdp address and port matching links without a setup frame`() {
        val dialog = standardDialog(byeTime = null)
        val unrelatedA = stream(id = "u0", src = "198.51.100.9", srcPort = 9000, dst = "198.51.100.10", dstPort = 9100)
        val forward = stream(id = "s0", setupFrame = 0L)
        val unrelatedB = stream(id = "u1", src = "198.51.100.11", srcPort = 9001, dst = "198.51.100.12", dstPort = 9101)
        val reverse = stream(
            id = "s1",
            src = CALLEE_ADDRESS,
            srcPort = CALLEE_MEDIA_PORT,
            dst = CALLER_ADDRESS,
            dstPort = CALLER_MEDIA_PORT,
            setupFrame = 0L
        )

        val result = RtpCallLinker.link(
            listOf(CALL_ID),
            emptyMap(),
            listOf(dialog),
            listOf(unrelatedA, forward, unrelatedB, reverse)
        )

        val call = result.calls.single()
        assertEquals(listOf("s0", "s1"), call.streams.map { it.stream.id })
        assertEquals(listOf(RtpLinkReason.SDP_ADDRESS_PORT), call.streams.map { it.linkReason }.distinct())
        assertEquals(listOf(RtpStreamDirection.FORWARD, RtpStreamDirection.REVERSE), call.streams.map { it.direction })
        assertEquals(listOf("u0", "u1"), result.unlinkedStreams.map { it.id })
        assertEquals(VoipCallState.IN_CALL, call.state)
    }

    // ------------------------------------------------------------ 场景 3

    @Test
    fun `a re invite on a new media port keeps both streams on the same call`() {
        val firstOffer = sdp(10, CALLER_ADDRESS, CALLER_MEDIA_PORT)
        val secondOffer = sdp(30, CALLER_ADDRESS, 4010)
        val dialog = standardDialog(
            byeTime = null,
            associations = listOf(
                offerAnswer(offer = firstOffer, answer = sdp(14, CALLEE_ADDRESS, CALLEE_MEDIA_PORT)),
                offerAnswer(offer = secondOffer, answer = sdp(32, CALLEE_ADDRESS, 5010))
            ),
            extraTransactions = listOf(
                transaction(
                    request = sipRequest(30, at(30.0), "INVITE", cSeq = 2, sdp = secondOffer),
                    finals = listOf(response(32, at(30.5), "200 OK", cSeq = 2, sdp = sdp(32, CALLEE_ADDRESS, 5010)))
                )
            )
        )
        val onFirstPort = stream(id = "s0", setupFrame = 0L)
        val onSecondPort = stream(
            id = "s1",
            src = CALLEE_ADDRESS,
            srcPort = 5010,
            dst = CALLER_ADDRESS,
            dstPort = 4010,
            setupFrame = 0L
        )

        val result = RtpCallLinker.link(
            listOf(CALL_ID),
            emptyMap(),
            listOf(dialog),
            listOf(onFirstPort, onSecondPort)
        )

        val call = result.calls.single()
        assertEquals(listOf("s0", "s1"), call.streams.map { it.stream.id })
        assertEquals(listOf(RtpStreamDirection.FORWARD, RtpStreamDirection.REVERSE), call.streams.map { it.direction })
        assertEquals(listOf(RtpLinkReason.SDP_ADDRESS_PORT), call.streams.map { it.linkReason }.distinct())
        assertTrue(result.unlinkedStreams.isEmpty())
    }

    // ------------------------------------------------------------ 场景 4

    @Test
    fun `early media carrying sdp joins sdpFrames and still links its stream`() {
        val dialog = standardDialog(
            okFrame = null,
            ackFrame = null,
            byeTime = null,
            provisional = listOf(
                response(12, at(0.5), "183 Session Progress", sdp = sdp(12, CALLEE_ADDRESS, CALLEE_MEDIA_PORT))
            ),
            associations = listOf(
                offerAnswer(
                    offer = sdp(10, CALLER_ADDRESS, CALLER_MEDIA_PORT),
                    answer = sdp(12, CALLEE_ADDRESS, CALLEE_MEDIA_PORT)
                )
            )
        )
        val earlyMedia = stream(
            id = "s0",
            src = CALLEE_ADDRESS,
            srcPort = CALLEE_MEDIA_PORT,
            dst = CALLER_ADDRESS,
            dstPort = CALLER_MEDIA_PORT,
            setupFrame = 0L
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(earlyMedia))

        val call = result.calls.single()
        assertTrue(call.sdpFrames.contains(12L))
        assertEquals(listOf(10L, 12L), call.sdpFrames)
        assertEquals(RtpLinkReason.SDP_ADDRESS_PORT, call.streams.single().linkReason)
        assertEquals(RtpStreamDirection.REVERSE, call.streams.single().direction)
        assertEquals(VoipCallState.RINGING, call.state)
    }

    // ------------------------------------------------------------ 场景 5

    @Test
    fun `a 486 rejection maps to REJECTED and links no stream`() {
        val dialog = standardDialog(
            okFrame = null,
            ackFrame = null,
            // 486 从 info 里解析（status 为空），顺带覆盖响应码的兜底来源。
            finals = listOf(response(13, at(1.0), info = "SIP/2.0 486 Busy Here"))
        )
        val unrelated = stream(id = "s0", src = "198.51.100.9", srcPort = 9000, dst = "198.51.100.10", dstPort = 9100)

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(unrelated))

        assertEquals(VoipCallState.REJECTED, result.calls.single().state)
        assertTrue(result.calls.single().streams.isEmpty())
        assertEquals(listOf("s0"), result.unlinkedStreams.map { it.id })
    }

    // ------------------------------------------------------------ 场景 6

    @Test
    fun `a stream matching two calls goes to the closer one with a warning`() {
        val earlier = standardDialog(byeTime = null)
        val later = standardDialog(
            callId = SECOND_CALL_ID,
            inviteFrame = 110,
            inviteTime = at(100.0),
            okFrame = 114,
            okTime = at(102.0),
            ackFrame = 116,
            ackTime = at(102.1),
            byeTime = null
        )
        // 首包在 epoch 101：两个呼叫的时间窗都包含它，但离 later（INVITE 在 100）更近。
        val shared = stream(id = "s0", setupFrame = 0L, startRel = 101.0)

        val result = RtpCallLinker.link(
            listOf(CALL_ID, SECOND_CALL_ID),
            emptyMap(),
            listOf(earlier, later),
            listOf(shared)
        )

        assertEquals(listOf(CALL_ID, SECOND_CALL_ID), result.calls.map { it.callId })
        assertTrue(result.calls[0].streams.isEmpty())
        val linked = result.calls[1].streams.single()
        assertEquals(SECOND_CALL_ID, linked.callId)
        assertNotNull(linked.warning)
        assertTrue(linked.warning!!.contains("matched 2 calls"))
        assertEquals(1, result.warnings.size)
        assertTrue(result.warnings.single().contains(SECOND_CALL_ID))
        assertTrue(result.unlinkedStreams.isEmpty())
    }

    // ------------------------------------------------------------ 场景 7

    @Test
    fun `ipv6 sdp endpoints link both directions`() {
        val dialog = standardDialog(
            byeTime = null,
            offer = sdp(10, "2001:db8::1", CALLER_MEDIA_PORT),
            answer = sdp(14, "2001:db8::2", CALLEE_MEDIA_PORT)
        )
        val fromCaller = stream(
            id = "s0",
            src = "2001:db8::1",
            srcPort = CALLER_MEDIA_PORT,
            dst = "2001:db8::2",
            dstPort = CALLEE_MEDIA_PORT
        )
        val toCaller = stream(
            id = "s1",
            src = "2001:db8::2",
            srcPort = CALLEE_MEDIA_PORT,
            dst = "2001:db8::1",
            dstPort = CALLER_MEDIA_PORT
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(fromCaller, toCaller))

        val call = result.calls.single()
        assertEquals(listOf(RtpStreamDirection.FORWARD, RtpStreamDirection.REVERSE), call.streams.map { it.direction })
        assertEquals(listOf(RtpLinkReason.SDP_ADDRESS_PORT), call.streams.map { it.linkReason }.distinct())
        assertTrue(result.unlinkedStreams.isEmpty())
    }

    // ------------------------------------------------------------ 场景 8

    @Test
    fun `rtp without any sip yields no calls and an unchanged unlinked list`() {
        val streams = listOf(stream("s0"), stream("s1", startRel = 2.0), stream("s2", startRel = 3.0))

        val result = RtpCallLinker.link(emptyList(), emptyMap(), emptyList(), streams)

        assertTrue(result.calls.isEmpty())
        assertEquals(listOf("s0", "s1", "s2"), result.unlinkedStreams.map { it.id })
        assertTrue(result.warnings.isEmpty())
    }

    // ------------------------------------------------------------ 场景 9

    @Test
    fun `sipTruncated adds the truncation warning and linking still runs`() {
        val dialog = standardDialog(byeTime = null)

        val result = RtpCallLinker.link(
            listOf(CALL_ID),
            emptyMap(),
            listOf(dialog),
            listOf(stream("s0")),
            sipTruncated = true
        )

        assertEquals(1, result.warnings.size)
        assertTrue(result.warnings.single().contains("truncat", ignoreCase = true))
        assertEquals(1, result.calls.size)
        assertEquals(RtpLinkReason.SDP_ADDRESS_PORT, result.calls.single().streams.single().linkReason)
    }

    // ------------------------------------------------------------ 表 3：其余状态

    @Test
    fun `a 487 final response maps to CANCELLED`() {
        val dialog = standardDialog(
            okFrame = null,
            ackFrame = null,
            provisional = listOf(response(12, at(0.5), "180 Ringing")),
            finals = listOf(response(13, at(1.0), "487 Request Terminated"))
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), emptyList())

        assertEquals(VoipCallState.CANCELLED, result.calls.single().state)
    }

    @Test
    fun `a CANCEL transaction maps to CANCELLED`() {
        val dialog = standardDialog(
            okFrame = null,
            ackFrame = null,
            provisional = listOf(response(12, at(0.5), "180 Ringing")),
            extraTransactions = listOf(transaction(request = cancel(13, at(1.0))))
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), emptyList())

        assertEquals(VoipCallState.CANCELLED, result.calls.single().state)
    }

    @Test
    fun `a 180 without a final response maps to RINGING`() {
        val dialog = standardDialog(
            okFrame = null,
            ackFrame = null,
            provisional = listOf(response(12, at(0.5), "180 Ringing"))
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), emptyList())

        val call = result.calls.single()
        assertEquals(VoipCallState.RINGING, call.state)
        assertNull(call.setupMs)
        assertEquals(500L, call.ringMs)
    }

    @Test
    fun `a bye after the 200 OK maps to COMPLETED`() {
        val dialog = standardDialog(byeTime = at(12.0))

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), emptyList())

        val call = result.calls.single()
        assertEquals(VoipCallState.COMPLETED, call.state)
        assertEquals(12000L, call.durationMs)
    }

    @Test
    fun `an invite without any response maps to SETUP`() {
        val dialog = standardDialog(okFrame = null, ackFrame = null)

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), emptyList())

        val call = result.calls.single()
        assertEquals(VoipCallState.SETUP, call.state)
        assertNull(call.setupMs)
        assertNull(call.ringMs)
        assertNull(call.durationMs)
    }

    @Test
    fun `a 488 final response falls through to UNKNOWN`() {
        val dialog = standardDialog(
            okFrame = null,
            ackFrame = null,
            finals = listOf(response(13, at(1.0), "488 Not Acceptable Here"))
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), emptyList())

        assertEquals(VoipCallState.UNKNOWN, result.calls.single().state)
    }

    @Test
    fun `a dialog without an invite maps to UNKNOWN`() {
        val dialog = timeline(
            transactions = listOf(
                transaction(
                    request = updateRequest(10, at(0.0)),
                    finals = listOf(response(12, at(0.5), "200 OK", method = "UPDATE"))
                )
            )
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), emptyList())

        assertEquals(VoipCallState.UNKNOWN, result.calls.single().state)
    }

    @Test
    fun `a lowercase and padded cseq method is still recognised`() {
        val dialog = timeline(
            transactions = listOf(
                transaction(
                    request = sipRequest(10, at(0.0), "INVITE", sdp = sdp(10, CALLER_ADDRESS, CALLER_MEDIA_PORT)),
                    finals = listOf(response(14, at(2.0), "200 OK")),
                    cSeqMethod = "  invite  "
                )
            )
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), emptyList())

        assertEquals(VoipCallState.IN_CALL, result.calls.single().state)
    }

    @Test
    fun `a missing cseq method falls back to the request method`() {
        val dialog = timeline(
            transactions = listOf(
                transaction(
                    request = sipRequest(10, at(0.0), "invite", sdp = sdp(10, CALLER_ADDRESS, CALLER_MEDIA_PORT)),
                    finals = listOf(response(14, at(2.0), "200 OK")),
                    cSeqMethod = null
                )
            )
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), emptyList())

        assertEquals(VoipCallState.IN_CALL, result.calls.single().state)
    }

    // ------------------------------------------------------------ setupFrame == 0 / 不可用地址

    @Test
    fun `setupFrame zero never counts as a match even when zero is an sdp frame`() {
        val zeroSdp = sdp(0, CALLER_ADDRESS, CALLER_MEDIA_PORT)
        val dialog = standardDialog(
            okFrame = null,
            ackFrame = null,
            associations = listOf(offerAnswer(offer = zeroSdp))
        )
        // 这个流的地址端口本来就能命中，但它必须是因为地址端口而关联，不能因为 setupFrame == 0。
        val matching = stream(id = "s0", setupFrame = 0L)
        val unrelated = stream(id = "s1", src = "198.51.100.9", srcPort = 9000, setupFrame = 0L)

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(matching, unrelated))

        val call = result.calls.single()
        assertTrue(call.sdpFrames.contains(0L))
        assertEquals(RtpLinkReason.SDP_ADDRESS_PORT, call.streams.single().linkReason)
        assertEquals(listOf("s1"), result.unlinkedStreams.map { it.id })
    }

    @Test
    fun `a zero dot zero dot zero dot zero c address is never used for linking`() {
        val dialog = standardDialog(
            byeTime = null,
            offer = sdp(10, UNSPECIFIED_V4, CALLER_MEDIA_PORT),
            answer = sdp(14, UNSPECIFIED_V4, CALLEE_MEDIA_PORT)
        )
        val zeroAddress = stream(
            id = "s0",
            src = UNSPECIFIED_V4,
            srcPort = CALLER_MEDIA_PORT,
            dst = UNSPECIFIED_V4,
            dstPort = CALLEE_MEDIA_PORT
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(zeroAddress))

        assertTrue(result.calls.single().streams.isEmpty())
        assertEquals(listOf("s0"), result.unlinkedStreams.map { it.id })
    }

    @Test
    fun `an empty c address is never used for linking`() {
        val dialog = standardDialog(
            byeTime = null,
            offer = sdp(10, "", CALLER_MEDIA_PORT),
            answer = sdp(14, "", CALLEE_MEDIA_PORT)
        )
        val emptyAddress = stream(id = "s0", src = "", srcPort = CALLER_MEDIA_PORT, dst = "", dstPort = CALLEE_MEDIA_PORT)

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(emptyAddress))

        assertTrue(result.calls.single().streams.isEmpty())
        assertEquals(listOf("s0"), result.unlinkedStreams.map { it.id })
    }

    // ------------------------------------------------------------ 时间点与帧号

    @Test
    fun `setup ring and duration milliseconds come from the invite transaction`() {
        val dialog = standardDialog(
            inviteFrame = 10,
            inviteTime = at(0.0),
            provisional = listOf(response(12, at(0.5), "180 Ringing")),
            okFrame = 14,
            okTime = at(2.0),
            ackFrame = 16,
            ackTime = at(2.1),
            byeFrame = 20,
            byeTime = at(12.0)
        )

        val result = RtpCallLinker.link(
            listOf(CALL_ID),
            mapOf(CALL_ID to ("alice" to "bob")),
            listOf(dialog),
            emptyList()
        )

        val call = result.calls.single()
        assertEquals("alice", call.from)
        assertEquals("bob", call.to)
        assertEquals(2000L, call.setupMs)
        assertEquals(500L, call.ringMs)
        assertEquals(12000L, call.durationMs)
        assertEquals(0.0, call.startRel, 1e-3)
        assertEquals(listOf(10L, 12L, 14L, 16L, 20L), call.sipFrames)
        assertEquals(listOf(10L, 14L), call.sdpFrames)
    }

    @Test
    fun `from and to stay empty when the call id is unknown to the caller`() {
        val dialog = standardDialog(byeTime = null)

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), emptyList())

        assertEquals("", result.calls.single().from)
        assertEquals("", result.calls.single().to)
    }

    // ------------------------------------------------------------ MOS

    @Test
    fun `mos prefers the forward stream`() {
        val dialog = standardDialog(byeTime = null)
        val forward = stream(id = "s0", codec = "g711A", lostPct = 0.0)
        val reverse = stream(
            id = "s1",
            src = CALLEE_ADDRESS,
            srcPort = CALLEE_MEDIA_PORT,
            dst = CALLER_ADDRESS,
            dstPort = CALLER_MEDIA_PORT,
            codec = "g722"
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(forward, reverse))

        val mos = result.calls.single().mos
        assertEquals(MosEstimator.estimate("g711A", 0.0, MosEstimator.defaultOneWayDelayMs()), mos)
        assertTrue(mos!!.mos > 4.0)
    }

    @Test
    fun `mos falls back to the reverse stream when there is no forward stream`() {
        val dialog = standardDialog(byeTime = null)
        val reverse = stream(
            id = "s0",
            src = CALLEE_ADDRESS,
            srcPort = CALLEE_MEDIA_PORT,
            dst = CALLER_ADDRESS,
            dstPort = CALLER_MEDIA_PORT,
            codec = "g711U"
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(reverse))

        val mos = result.calls.single().mos
        assertEquals(MosEstimator.estimate("g711U", 0.0, MosEstimator.defaultOneWayDelayMs()), mos)
        assertEquals("g711U", mos!!.codec)
    }

    @Test
    fun `mos is null for a wideband codec`() {
        val dialog = standardDialog(byeTime = null)

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(stream(id = "s0", codec = "g722")))

        assertNull(result.calls.single().mos)
        assertEquals(1, result.calls.single().streams.size)
    }

    // ------------------------------------------------------------ 表 2：offer 方的判定

    @Test
    fun `a setup frame link with a port mismatch stays UNKNOWN`() {
        val dialog = standardDialog(byeTime = null)
        // setupFrame 命中（关联成立），但地址对、端口不对 → 方向不猜。
        val wrongPort = stream(
            id = "s0",
            src = CALLER_ADDRESS,
            srcPort = 4001,
            dst = "198.51.100.9",
            dstPort = 9000,
            setupFrame = 14
        )
        val wrongSide = stream(
            id = "s1",
            src = "198.51.100.11",
            srcPort = 9001,
            dst = CALLER_ADDRESS,
            dstPort = 4001,
            setupFrame = 10
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(wrongPort, wrongSide))

        val call = result.calls.single()
        assertEquals(listOf(RtpLinkReason.SETUP_FRAME, RtpLinkReason.SETUP_FRAME), call.streams.map { it.linkReason })
        assertEquals(listOf(RtpStreamDirection.UNKNOWN), call.streams.map { it.direction }.distinct())
        assertNull(call.mos)
    }

    @Test
    fun `a callee originated offer swaps the forward and reverse labels`() {
        // 被叫发起的 re-INVITE：offer 是被叫的 192.0.2.2:5060，answer 里主叫把媒体改到 198.51.100.7:6000。
        // timeline.finalToTag 是被叫的 tag（correlator 取 dialog 里最后一个非空 To tag），
        // 所以那条 re-INVITE 的 fromTag 与它相等 —— 表 2 的「offer 方是被叫」分支。
        val calleeOffer = sdp(30, CALLEE_ADDRESS, 5060)
        val dialog = standardDialog(
            byeTime = null,
            associations = listOf(
                offerAnswer(
                    offer = sdp(10, CALLER_ADDRESS, CALLER_MEDIA_PORT),
                    answer = sdp(14, CALLEE_ADDRESS, CALLEE_MEDIA_PORT)
                ),
                offerAnswer(offer = calleeOffer, answer = sdp(32, "198.51.100.7", 6000))
            ),
            extraTransactions = listOf(
                transaction(
                    request = calleeInvite(30, at(30.0), sdp = calleeOffer),
                    finals = listOf(
                        response(
                            32,
                            at(30.5),
                            "200 OK",
                            cSeq = 2,
                            sdp = sdp(32, "198.51.100.7", 6000),
                            fromTag = CALLEE_TAG,
                            toTag = CALLER_TAG,
                            source = CALLER_ADDRESS,
                            destination = CALLEE_ADDRESS
                        )
                    )
                )
            )
        )
        val fromCallee = stream(
            id = "s0",
            src = CALLEE_ADDRESS,
            srcPort = 5060,
            dst = "198.51.100.7",
            dstPort = 6000,
            setupFrame = 0L
        )
        val towardsCallee = stream(
            id = "s1",
            src = "198.51.100.7",
            srcPort = 6000,
            dst = CALLEE_ADDRESS,
            dstPort = 5060,
            setupFrame = 0L
        )

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(fromCallee, towardsCallee))

        val call = result.calls.single()
        assertEquals(listOf("s0", "s1"), call.streams.map { it.stream.id })
        // 只按 offer 地址套表 2 会得到 FORWARD / REVERSE；offer 方是被叫，两个标签对调：
        // s0 是被叫 → 主叫（REVERSE 才是对的方向），s1 是主叫 → 被叫（FORWARD）。
        assertEquals(listOf(RtpStreamDirection.REVERSE, RtpStreamDirection.FORWARD), call.streams.map { it.direction })
        assertEquals(listOf(RtpLinkReason.SDP_ADDRESS_PORT), call.streams.map { it.linkReason }.distinct())
    }

    // ------------------------------------------------------------ 顺序、去重、缺失 timeline

    @Test
    fun `duplicate call ids produce a single call`() {
        val dialog = standardDialog(byeTime = null)

        val result = RtpCallLinker.link(
            listOf(CALL_ID, CALL_ID),
            emptyMap(),
            listOf(dialog),
            listOf(stream("s0"))
        )

        assertEquals(1, result.calls.size)
        assertEquals(1, result.calls.single().streams.size)
        assertTrue(result.warnings.isEmpty())
    }

    @Test
    fun `calls follow the callIds order and a missing timeline adds one warning`() {
        val first = standardDialog(byeTime = null)
        val second = standardDialog(
            callId = SECOND_CALL_ID,
            inviteFrame = 110,
            inviteTime = at(100.0),
            okFrame = 114,
            okTime = at(102.0),
            ackFrame = 116,
            ackTime = at(102.1),
            byeTime = null
        )

        val result = RtpCallLinker.link(
            listOf("missing", SECOND_CALL_ID, CALL_ID),
            emptyMap(),
            listOf(first, second),
            emptyList()
        )

        assertEquals(listOf(SECOND_CALL_ID, CALL_ID), result.calls.map { it.callId })
        assertEquals(1, result.warnings.size)
        assertTrue(result.warnings.single().contains("missing"))
        assertTrue(result.unlinkedStreams.isEmpty())
    }

    @Test
    fun `a stream outside the invite to bye window is not linked`() {
        val dialog = standardDialog(byeTime = at(12.0))
        // 首包在 BYE + 5 s 之后：地址端口对得上也不能关联。
        val late = stream(id = "s0", setupFrame = 0L, startRel = 20.0)

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(late))

        assertTrue(result.calls.single().streams.isEmpty())
        assertEquals(listOf("s0"), result.unlinkedStreams.map { it.id })
    }

    @Test
    fun `a stream before the invite is not linked by address and port`() {
        val dialog = standardDialog(byeTime = null)
        // 首包早于 INVITE（负数相对时间）：窗口下界之外。
        val early = stream(id = "s0", setupFrame = 0L, startRel = -1.0)

        val result = RtpCallLinker.link(listOf(CALL_ID), emptyMap(), listOf(dialog), listOf(early))

        assertTrue(result.calls.single().streams.isEmpty())
        assertEquals(listOf("s0"), result.unlinkedStreams.map { it.id })
    }
}

// ---------------------------------------------------------------- 夹具

private const val CAPTURE_START = 1_700_000_000.0
private const val CALL_ID = "call-1"
private const val SECOND_CALL_ID = "call-2"
private const val CALLER_ADDRESS = "192.0.2.1"
private const val CALLEE_ADDRESS = "192.0.2.2"
private const val CALLER_MEDIA_PORT = 4000
private const val CALLEE_MEDIA_PORT = 5000
private const val CALLER_TAG = "caller-tag"
private const val CALLEE_TAG = "callee-tag"
private const val UNSPECIFIED_V4 = "0.0.0.0"

/** 相对抓包起点的秒数 → 绝对 epoch 秒（原生层的 `time` 就是绝对 epoch 秒）。 */
private fun at(relativeSeconds: Double): Double = CAPTURE_START + relativeSeconds

/**
 * 造一条 RTP 流。[firstAbsEpochUs] 与 [startRel] 始终自洽：
 * `firstAbsEpochUs / 1e6 - startRel == CAPTURE_START`，这正是联接器推导抓包起点的依据。
 *
 * 默认方向是主叫 → 被叫（`192.0.2.1:4000` → `192.0.2.2:5000`）。
 */
private fun stream(
    id: String,
    src: String = CALLER_ADDRESS,
    srcPort: Int = CALLER_MEDIA_PORT,
    dst: String = CALLEE_ADDRESS,
    dstPort: Int = CALLEE_MEDIA_PORT,
    setupFrame: Long = 0L,
    startRel: Double = 1.0,
    codec: String = "g711A",
    lostPct: Double = 0.0
): RtpStream = RtpStream(
    id = id, src = src, srcPort = srcPort, dst = dst, dstPort = dstPort,
    ssrc = 0x0badf00dL, ssrcHex = "0badf00d",
    pt = 8, codec = codec, codecSource = RtpCodecSource.SDP, clockRate = 8000,
    setupFrame = setupFrame, setupMethod = "sdp", isSrtp = false,
    packets = 50, expected = 50, lost = 0, lostPct = lostPct,
    seqErrors = 0, outOfOrder = 0, truncated = 0, problem = false,
    minDeltaMs = 20.0, meanDeltaMs = 20.0, maxDeltaMs = 20.0, maxDeltaFrame = 50,
    minJitterMs = 0.0, meanJitterMs = 0.0, maxJitterMs = 0.0, jitterAvailable = true,
    maxSkewMs = 0.0, bytes = 8000,
    firstFrame = 40, lastFrame = 90, startRel = startRel, endRel = startRel + 10.0,
    firstAbsEpochUs = ((CAPTURE_START + startRel) * 1_000_000.0).toLong(),
    ptsSeen = listOf(8), decodable = RtpDecodability.YES, decodableReason = "",
    primaryPayloadType = 8
)

private fun sdp(frame: Long, address: String, port: Int?): SdpMediaSummary = SdpMediaSummary(
    frameNumber = frame,
    connectionAddress = address,
    mediaType = "audio",
    mediaPort = port,
    mediaProtocol = "RTP/AVP",
    formats = listOf("8"),
    codecs = listOf("PCMA")
)

private fun offerAnswer(offer: SdpMediaSummary, answer: SdpMediaSummary? = null): SdpOfferAnswerAssociation =
    SdpOfferAnswerAssociation(
        offer = offer,
        answer = answer,
        offerFrame = offer.frameNumber,
        answerFrame = answer?.frameNumber
    )

private fun sipRequest(
    frame: Long,
    time: Double,
    method: String,
    callId: String = CALL_ID,
    cSeq: Long = 1,
    fromTag: String? = CALLER_TAG,
    toTag: String? = CALLEE_TAG,
    fromCallee: Boolean = false,
    sdp: SdpMediaSummary? = null
): SipMessage = SipMessage(
    frameNumber = frame,
    time = time,
    source = if (fromCallee) CALLEE_ADDRESS else CALLER_ADDRESS,
    destination = if (fromCallee) CALLER_ADDRESS else CALLEE_ADDRESS,
    sourcePort = 5060,
    destinationPort = 5060,
    method = method,
    callId = callId,
    cSeqNumber = cSeq,
    cSeqMethod = method,
    viaBranch = "z9hG4bK-$callId-$method-$frame",
    fromTag = fromTag,
    toTag = toTag,
    sdp = sdp
)

/** 初始 INVITE：From 是主叫，To 还没有 tag。 */
private fun invite(frame: Long, time: Double, callId: String = CALL_ID, sdp: SdpMediaSummary? = null): SipMessage =
    sipRequest(frame, time, "INVITE", callId = callId, toTag = null, sdp = sdp)

/** 被叫发起的 re-INVITE：From 是被叫，To 是主叫。 */
private fun calleeInvite(frame: Long, time: Double, callId: String = CALL_ID, sdp: SdpMediaSummary? = null): SipMessage =
    sipRequest(
        frame = frame,
        time = time,
        method = "INVITE",
        callId = callId,
        cSeq = 2,
        fromTag = CALLEE_TAG,
        toTag = CALLER_TAG,
        fromCallee = true,
        sdp = sdp
    )

private fun ack(frame: Long, time: Double, callId: String = CALL_ID): SipMessage =
    sipRequest(frame, time, "ACK", callId = callId)

private fun bye(frame: Long, time: Double, callId: String = CALL_ID): SipMessage =
    sipRequest(frame, time, "BYE", callId = callId, cSeq = 2)

private fun cancel(frame: Long, time: Double, callId: String = CALL_ID): SipMessage =
    sipRequest(frame, time, "CANCEL", callId = callId)

private fun updateRequest(frame: Long, time: Double, callId: String = CALL_ID): SipMessage =
    sipRequest(frame, time, "UPDATE", callId = callId, cSeq = 2)

/** 被叫回的响应：From 抄主叫的 tag，To 带上被叫的 tag。 */
private fun response(
    frame: Long,
    time: Double,
    status: String = "",
    info: String = "",
    method: String = "INVITE",
    callId: String = CALL_ID,
    cSeq: Long = 1,
    sdp: SdpMediaSummary? = null,
    fromTag: String? = CALLER_TAG,
    toTag: String? = CALLEE_TAG,
    source: String = CALLEE_ADDRESS,
    destination: String = CALLER_ADDRESS
): SipMessage = SipMessage(
    frameNumber = frame,
    time = time,
    source = source,
    destination = destination,
    sourcePort = 5060,
    destinationPort = 5060,
    method = "",
    status = status,
    info = info,
    callId = callId,
    cSeqNumber = cSeq,
    cSeqMethod = method,
    viaBranch = "z9hG4bK-$callId-$method-$cSeq",
    fromTag = fromTag,
    toTag = toTag,
    sdp = sdp
)

private fun transaction(
    request: SipMessage?,
    provisional: List<SipMessage> = emptyList(),
    finals: List<SipMessage> = emptyList(),
    cSeqMethod: String? = request?.method
): SipTransaction {
    val all = listOfNotNull(request) + provisional + finals
    return SipTransaction(
        callId = request?.callId ?: all.firstOrNull()?.callId.orEmpty(),
        cSeqNumber = request?.cSeqNumber ?: all.firstOrNull()?.cSeqNumber,
        cSeqMethod = cSeqMethod,
        viaBranch = request?.viaBranch,
        request = request,
        provisionalResponses = provisional,
        finalResponses = finals,
        firstTime = all.minOfOrNull { it.time } ?: 0.0,
        lastTime = all.maxOfOrNull { it.time } ?: 0.0
    )
}

private fun timeline(
    callId: String = CALL_ID,
    transactions: List<SipTransaction>,
    initialFromTag: String? = CALLER_TAG,
    finalToTag: String? = CALLEE_TAG,
    sdpOfferAnswers: List<SdpOfferAnswerAssociation> = emptyList()
): SipDialogTimeline = SipDialogTimeline(
    callId = callId,
    callTransactions = transactions,
    events = transactions.map { SipDialogEvent(transaction = it) },
    initialFromTag = initialFromTag,
    finalToTag = finalToTag,
    sdpOfferAnswers = sdpOfferAnswers
)

/**
 * 一次标准呼叫的 dialog（主叫 `192.0.2.1:4000` ← offer，被叫 `192.0.2.2:5000` ← answer）：
 * INVITE（带 offer SDP）→ [provisional] → [finals] / 200 OK（带 answer SDP）→ [ackFrame] → 可选 BYE。
 *
 * @param finals 给定时用它当 INVITE 的最终响应（例如 486/487/488）；此时 [okFrame] / [ackFrame] 不再生效。
 * @param associations 给定时整份覆盖 SDP offer/answer 关联（re-INVITE、早期媒体等）。
 */
private fun standardDialog(
    callId: String = CALL_ID,
    inviteFrame: Long = 10,
    inviteTime: Double = at(0.0),
    offer: SdpMediaSummary = sdp(inviteFrame, CALLER_ADDRESS, CALLER_MEDIA_PORT),
    provisional: List<SipMessage> = emptyList(),
    okFrame: Long? = 14,
    okTime: Double = at(2.0),
    answer: SdpMediaSummary = sdp(okFrame ?: inviteFrame, CALLEE_ADDRESS, CALLEE_MEDIA_PORT),
    finals: List<SipMessage>? = null,
    ackFrame: Long? = 16,
    ackTime: Double = at(2.1),
    byeFrame: Long = 20,
    byeTime: Double? = null,
    associations: List<SdpOfferAnswerAssociation>? = null,
    extraTransactions: List<SipTransaction> = emptyList()
): SipDialogTimeline {
    val inviteTransaction = transaction(
        request = invite(inviteFrame, inviteTime, callId, sdp = offer),
        provisional = provisional,
        finals = finals
            ?: okFrame?.let { listOf(response(it, okTime, "200 OK", callId = callId, sdp = answer)) }.orEmpty()
    )
    val transactions = buildList {
        add(inviteTransaction)
        if (finals == null) ackFrame?.let { add(transaction(ack(it, ackTime, callId))) }
        byeTime?.let { add(transaction(bye(byeFrame, it, callId))) }
        addAll(extraTransactions)
    }
    val offerAnswers = associations ?: listOf(
        offerAnswer(offer = offer, answer = if (finals == null) answer.takeIf { okFrame != null } else null)
    )
    return timeline(callId = callId, transactions = transactions, sdpOfferAnswers = offerAnswers)
}
