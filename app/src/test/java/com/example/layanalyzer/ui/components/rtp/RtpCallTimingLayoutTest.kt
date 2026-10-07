// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.model.SipDialogEvent
import com.example.layanalyzer.model.SipMessage
import com.example.layanalyzer.model.SipTransaction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [layoutSipFlow] / [sipFlowAsRows] 的 JVM 测试（RTP3-UI-02）。
 *
 * 这两个函数是纯 Kotlin（不引用 `android.*`），所以这里就是普通 JUnit，不需要 Robolectric。
 * 夹具的时间是「[BASE] + 相对秒」，绝对量级取小值让 `Double` 加减精确可逆——函数只看差值，
 * 生产里那个数量级（epoch 秒）不影响布局结论。
 */
class RtpCallTimingLayoutTest {

    // ------------------------------------------------------------ 场景 1：顺序

    @Test
    fun `arrows follow message time even when the events list is out of order`() {
        // events 故意按时间倒序传入：函数必须自己按 (time, frameNumber) 排序。
        val events = eventsOf(
            transaction(bye(30L, at(8.0))),
            transaction(ack(20L, at(3.0))),
            inviteTransaction()
        )

        val arrows = layoutSipFlow(events, lanes = 2)

        assertEquals(listOf(10L, 12L, 14L, 20L, 30L), arrows.map { it.frame })
        assertEquals(listOf("INVITE", "180", "200", "ACK", "BYE"), arrows.map { it.label })
        assertEquals(listOf(0.0, 0.5, 2.0, 3.0, 8.0), arrows.map { it.timeRelSec })
    }

    @Test
    fun `messages sharing a timestamp are ordered by frame number`() {
        val events = eventsOf(
            transaction(
                invite(10L, at(1.0)),
                provisional = listOf(response(11L, at(1.0), "100 Trying")),
                finals = listOf(response(9L, at(1.0), "200 OK"))
            )
        )

        val arrows = layoutSipFlow(events, lanes = 2)

        assertEquals(listOf(9L, 10L, 11L), arrows.map { it.frame })
    }

    // ------------------------------------------------------------ 场景 2：yFraction

    @Test
    fun `yFraction is monotonic and spans the unit interval`() {
        val events = eventsOf(
            inviteTransaction(),
            transaction(ack(20L, at(3.0))),
            transaction(bye(30L, at(8.0)))
        )

        val fractions = layoutSipFlow(events, lanes = 2).map { it.yFraction }

        assertEquals(5, fractions.size)
        assertEquals(0f, fractions.first(), 0f)
        assertEquals(1f, fractions.last(), 0f)
        assertEquals(listOf(0f, 0.25f, 0.5f, 0.75f, 1f), fractions)
        fractions.zipWithNext { previous, next ->
            assertTrue("yFraction 不得递减：$previous > $next", next >= previous)
            assertTrue("yFraction 必须留在 [0,1]：$next", next in 0f..1f)
        }
    }

    @Test
    fun `a single arrow sits at the top of the distribution`() {
        val arrows = layoutSipFlow(eventsOf(transaction(invite(10L, at(0.0)))), lanes = 2)

        assertEquals(1, arrows.size)
        assertEquals(0f, arrows.single().yFraction, 0f)
    }

    // ------------------------------------------------------------ 场景 3：泳道与方向

    @Test
    fun `two lanes run from the invite sender to the other endpoint`() {
        val events = eventsOf(
            inviteTransaction(),
            transaction(ack(20L, at(3.0))),
            transaction(bye(30L, at(8.0)))
        )

        val arrows = layoutSipFlow(events, lanes = 2)

        // 泳道 0 = 最早一条消息的发出方（主叫），泳道 1 = 被叫。
        assertEquals(listOf(0, 1, 1, 0, 0), arrows.map { it.fromLane })
        assertEquals(listOf(1, 0, 0, 1, 1), arrows.map { it.toLane })
        assertEquals(listOf(CALLER, CALLEE), sipFlowLanes(events))
    }

    @Test
    fun `a proxy in the middle occupies the lane it first speaks from`() {
        val events = eventsOf(
            transaction(invite(10L, at(0.0), source = CALLER, destination = PROXY)),
            transaction(invite(12L, at(0.2), source = PROXY, destination = CALLEE)),
            transaction(response(14L, at(0.6), "180 Ringing", source = CALLEE, destination = PROXY)),
            transaction(response(16L, at(0.8), "180 Ringing", source = PROXY, destination = CALLER))
        )

        val arrows = layoutSipFlow(events, lanes = 3)

        assertEquals(listOf(CALLER, PROXY, CALLEE), sipFlowLanes(events))
        assertEquals(listOf(0, 1, 2, 1), arrows.map { it.fromLane })
        assertEquals(listOf(1, 2, 1, 0), arrows.map { it.toLane })
    }

    @Test
    fun `addresses beyond the lane count clamp into range`() {
        // 三个端点却只给 2 条泳道：第三个端点夹到泳道 1。
        val events = eventsOf(
            transaction(invite(10L, at(0.0), source = CALLER, destination = PROXY)),
            transaction(invite(12L, at(0.2), source = PROXY, destination = CALLEE))
        )

        val arrows = layoutSipFlow(events, lanes = 2)

        assertEquals(listOf(0, 1), arrows.map { it.fromLane })
        assertEquals(listOf(1, 1), arrows.map { it.toLane })
        assertTrue(arrows.all { it.fromLane in 0..1 && it.toLane in 0..1 })
    }

    @Test
    fun `a destination that never sends still lands one lane over`() {
        // 只有 INVITE、没有被叫发出的消息：被叫不在 source 表里，退到「发出方 + 1」。
        val events = eventsOf(transaction(invite(10L, at(0.0), source = CALLER, destination = CALLEE)))

        val arrows = layoutSipFlow(events, lanes = 2)

        assertEquals(0, arrows.single().fromLane)
        assertEquals(1, arrows.single().toLane)
        assertEquals(listOf(CALLER), sipFlowLanes(events))
    }

    @Test
    fun `messages without addresses stay on a usable lane`() {
        val events = eventsOf(transaction(invite(10L, at(0.0), source = "", destination = "")))

        val arrows = layoutSipFlow(events, lanes = 2)

        assertEquals(0, arrows.single().fromLane)
        assertEquals(1, arrows.single().toLane)
        assertTrue(sipFlowLanes(events).isEmpty())
    }

    // ------------------------------------------------------------ 场景 4：空输入与退化输入

    @Test
    fun `empty events and non positive lane counts produce no arrows`() {
        val oneInvite = eventsOf(transaction(invite(10L, at(0.0))))

        assertTrue(layoutSipFlow(emptyList(), lanes = 2).isEmpty())
        assertTrue(layoutSipFlow(eventsOf(), lanes = 2).isEmpty())
        assertTrue(layoutSipFlow(oneInvite, lanes = 0).isEmpty())
        assertTrue(layoutSipFlow(oneInvite, lanes = -1).isEmpty())
    }

    @Test
    fun `a single lane keeps every arrow on lane zero`() {
        val events = eventsOf(
            transaction(invite(10L, at(0.0))),
            transaction(ack(20L, at(1.0)))
        )

        val arrows = layoutSipFlow(events, lanes = 1)

        assertEquals(listOf(0, 0), arrows.map { it.fromLane })
        assertEquals(listOf(0, 0), arrows.map { it.toLane })
    }

    // ------------------------------------------------------------ 场景 5：时间映射

    @Test
    fun `sipTimeFraction interpolates between arrow positions`() {
        val arrows = layoutSipFlow(
            eventsOf(
                transaction(invite(10L, at(0.0))),
                transaction(ack(20L, at(1.0))),
                transaction(bye(30L, at(2.0)))
            ),
            lanes = 2
        )

        assertEquals(0f, sipTimeFraction(arrows, -5.0), 0f)
        assertEquals(0f, sipTimeFraction(arrows, 0.0), 0f)
        assertEquals(0.25f, sipTimeFraction(arrows, 0.5), 0.0001f)
        assertEquals(0.5f, sipTimeFraction(arrows, 1.0), 0.0001f)
        assertEquals(1f, sipTimeFraction(arrows, 99.0), 0f)
        assertEquals(0f, sipTimeFraction(emptyList(), 1.0), 0f)
    }

    // ------------------------------------------------------------ 场景 6：列表版兜底

    @Test
    fun `sipFlowAsRows renders time direction label and frame`() {
        assertEquals(
            listOf(
                "0.000s | 192.0.2.1:5060 → 192.0.2.2:5060 | INVITE | #10",
                "0.500s | 192.0.2.2:5060 → 192.0.2.1:5060 | 180 | #12",
                "2.000s | 192.0.2.2:5060 → 192.0.2.1:5060 | 200 | #14"
            ),
            sipFlowAsRows(eventsOf(inviteTransaction()))
        )
    }

    @Test
    fun `sipFlowAsRows tolerates missing ports and addresses and empty input`() {
        val events = eventsOf(
            transaction(
                invite(10L, at(0.0), source = "", destination = "", sourcePort = null, destinationPort = null)
            )
        )

        assertEquals(listOf("0.000s | ? → ? | INVITE | #10"), sipFlowAsRows(events))
        assertTrue(sipFlowAsRows(emptyList()).isEmpty())
    }

    @Test
    fun `sipFlowAsRows falls back to the raw status when no code is present`() {
        val events = eventsOf(
            transaction(
                invite(10L, at(0.0)),
                finals = listOf(response(14L, at(2.0), "weird response"))
            )
        )

        assertEquals("weird response", sipFlowAsRows(events).last().split(" | ")[2])
    }

    // ------------------------------------------------------------ 夹具

    /** 保持传入顺序（真实 dialog 的 `events` 顺序没有保证，排序是函数的职责）。 */
    private fun eventsOf(vararg transactions: SipTransaction): List<SipDialogEvent> =
        transactions.map { SipDialogEvent(transaction = it) }

    /** INVITE(10, t=0, 主叫 → 被叫) + 180(12, t=0.5) + 200(14, t=2.0)。 */
    private fun inviteTransaction(): SipTransaction = transaction(
        invite(10L, at(0.0)),
        provisional = listOf(response(12L, at(0.5), "180 Ringing")),
        finals = listOf(response(14L, at(2.0), "200 OK"))
    )

    private fun transaction(
        request: SipMessage? = null,
        provisional: List<SipMessage> = emptyList(),
        finals: List<SipMessage> = emptyList()
    ): SipTransaction {
        val all = listOfNotNull(request) + provisional + finals
        return SipTransaction(
            callId = CALL_ID,
            cSeqNumber = request?.cSeqNumber,
            cSeqMethod = request?.method,
            request = request,
            provisionalResponses = provisional,
            finalResponses = finals,
            firstTime = all.minOfOrNull { it.time } ?: 0.0,
            lastTime = all.maxOfOrNull { it.time } ?: 0.0
        )
    }

    private fun invite(
        frame: Long,
        time: Double,
        source: String = CALLER,
        destination: String = CALLEE,
        sourcePort: Int? = SIP_PORT,
        destinationPort: Int? = SIP_PORT
    ): SipMessage = message(
        frame, time, source, destination,
        method = "INVITE", cSeq = 1L,
        sourcePort = sourcePort, destinationPort = destinationPort
    )

    private fun ack(frame: Long, time: Double): SipMessage =
        message(frame, time, CALLER, CALLEE, method = "ACK", cSeq = 1L)

    private fun bye(frame: Long, time: Double): SipMessage =
        message(frame, time, CALLER, CALLEE, method = "BYE", cSeq = 2L)

    private fun response(
        frame: Long,
        time: Double,
        status: String,
        source: String = CALLEE,
        destination: String = CALLER
    ): SipMessage = message(frame, time, source, destination, status = status, cSeq = 1L)

    private fun message(
        frame: Long,
        time: Double,
        source: String,
        destination: String,
        method: String = "",
        status: String = "",
        cSeq: Long? = null,
        sourcePort: Int? = SIP_PORT,
        destinationPort: Int? = SIP_PORT
    ): SipMessage = SipMessage(
        frameNumber = frame,
        time = time,
        source = source,
        destination = destination,
        sourcePort = sourcePort,
        destinationPort = destinationPort,
        method = method,
        status = status,
        callId = CALL_ID,
        cSeqNumber = cSeq,
        cSeqMethod = method.ifBlank { null }
    )

    private companion object {
        const val BASE = 1000.0
        const val CALL_ID = "call-1"
        const val CALLER = "192.0.2.1"
        const val CALLEE = "192.0.2.2"
        const val PROXY = "192.0.2.9"
        const val SIP_PORT = 5060

        /** 相对夹具起点的秒数 → 绝对时间（原生层的 `time` 就是绝对 epoch 秒）。 */
        fun at(relativeSeconds: Double): Double = BASE + relativeSeconds
    }
}
