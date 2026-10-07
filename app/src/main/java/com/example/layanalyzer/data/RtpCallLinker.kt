// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SdpOfferAnswerAssociation
import com.example.layanalyzer.model.SipDialogTimeline
import com.example.layanalyzer.model.SipMessage
import com.example.layanalyzer.model.SipTransaction
import kotlin.math.abs
import kotlin.math.roundToLong

/** 一条流与呼叫的关联依据（RTP3-KT-01，取自 RTP3-ARCH-01 表 1）。 */
enum class RtpLinkReason { SETUP_FRAME, SDP_ADDRESS_PORT, NONE }

/** 流相对主叫的方向（RTP3-KT-01，取自 RTP3-ARCH-01 表 2）。 */
enum class RtpStreamDirection { FORWARD, REVERSE, UNKNOWN }

/**
 * 已关联到某个呼叫的一条 RTP 流。
 *
 * [direction] 与 [linkReason] 相互独立判定：`SETUP_FRAME` 关联到的流同样要按表 2 定方向。
 * [warning] 只在「同一条流匹配到多个呼叫」时非空，说明它最终落在哪个呼叫上。
 */
data class LinkedRtpStream(
    val stream: RtpStream,
    val direction: RtpStreamDirection,
    val linkReason: RtpLinkReason,
    val callId: String,
    val warning: String? = null
)

/**
 * 一次呼叫及其关联结果。
 *
 * [startRel] 与 [RtpStream.startRel] 在同一条时间轴上（相对抓包第 0 帧的秒数）。
 * [sipFrames] / [sdpFrames] 都是升序去重后的帧号。
 * [mos] 是呼叫主方向（`FORWARD`，没有则 `REVERSE`）的估算值，`null` 表示不适用
 * （宽带编码，见 [MosEstimator]）。
 */
data class VoipCall(
    val callId: String, val from: String, val to: String, val state: VoipCallState,
    val startRel: Double, val setupMs: Long?, val ringMs: Long?, val durationMs: Long?,
    val sipFrames: List<Long>, val sdpFrames: List<Long>,
    val streams: List<LinkedRtpStream>, val mos: MosEstimate?
)

/** 呼叫状态（RTP3-KT-01，取自 RTP3-ARCH-01 表 3）。 */
enum class VoipCallState { SETUP, RINGING, IN_CALL, COMPLETED, REJECTED, CANCELLED, UNKNOWN }

/**
 * 把 RTP 流关联到 SIP 呼叫（RTP3-KT-01）。
 *
 * 纯函数对象：不碰 Android、不做 IO、不起协程、不写日志。输入全部由调用方给出
 * （`timelines` 来自 `SipTransactionCorrelator.correlate(...).dialogs`，本对象**不调用**
 * correlator，也不复制它的逻辑）。四张判定表见
 * NativeEngine.getVoipCalls。
 *
 * ### 时间基准
 *
 * - `SipMessage.time` / `SipTransaction.firstTime` / `SipTransaction.lastTime` 是**绝对 epoch 秒**。
 * - [RtpStream.firstAbsEpochUs] 是流首包的绝对 epoch 时间（微秒），所以它的 epoch 秒数就是
 *   `firstAbsEpochUs / 1e6`，可以直接和 SIP 的时间比较。
 * - [RtpStream.startRel] 是相对抓包第 0 帧的秒数。
 *
 * 于是抓包起点可由任一条流还原：`captureStartEpochSec = firstAbsEpochUs / 1e6 - startRel`。
 * 本实现取**所有流上该表达式的最小值**（同一常量被多条流各测一次，取最小值最不容易被
 * 个别流的异常值抬高）；`streams` 为空时退化为「所有 SIP 事件时间中最早的一个」，
 * 再没有就取 `0.0`。[VoipCall.startRel] 就是 `callStartEpochSec - captureStartEpochSec`。
 *
 * ### 警告顺序（`Result.warnings` 是确定性的）
 *
 * 1. `sipTruncated == true` 时的截断提示（全局，最先）；
 * 2. 没有对应 [SipDialogTimeline] 的 `callId`，按 `callIds` 去重后的顺序，一行一个；
 * 3. 「一条流匹配多个呼叫」的说明，按该流在 `streams` 里的下标升序。
 *
 * 这些文本只用于界面展示，里面不含 SIP URI 与号码。
 *
 * ### MOS
 *
 * [VoipCall.mos] 取的是呼叫主方向那一条流的估算值：`MosEstimator.estimate(codec, lostPct,
 * defaultOneWayDelayMs())`；[MosEstimator.estimate] 对宽带/未知编码返回 `null`，即「不适用」。
 * 界面要给每个方向各自的 MOS 时，按同样的调用方式传入该方向那条流自己的
 * `codec` / `lostPct` 即可（本对象不替调用方做这件事，避免把方向语义写死在模型里）。
 */
object RtpCallLinker {

    /** 关联结果：[calls] 按 `callIds` 顺序；[unlinkedStreams] 保持输入顺序；[warnings] 见类注释。 */
    data class Result(val calls: List<VoipCall>, val unlinkedStreams: List<RtpStream>, val warnings: List<String>)

    /** BYE 之后还允许流首包落入的宽限期（表 1 的 `BYE + 5s`）。 */
    private const val BYE_GRACE_SECONDS = 5.0

    private const val MICROS_PER_SECOND = 1_000_000.0

    /** 不可用的 SDP `c=` 地址：空、未指定地址（表 1 备注）。 */
    private val UNUSABLE_ADDRESSES = setOf("0.0.0.0", "::")

    /** 与 `SipTransactionCorrelator` 相同的响应码提取方式（status 优先，info 兜底）。 */
    private val RESPONSE_CODE = Regex("(?<!\\d)([1-6]\\d{2})(?!\\d)")

    private const val TRUNCATION_WARNING =
        "SIP analysis was truncated: call linking may be incomplete"

    /** 流没有关联到任何呼叫时在 [assignments] 里的取值。 */
    private const val UNASSIGNED = -1

    /**
     * 关联一条流与一个呼叫时可以命中的 SDP 端点（`c=` 地址 + `m=` 端口）。
     */
    private class Endpoint(val address: String, val port: Int)

    /**
     * 一个呼叫在关联前的预处理结果：SDP 帧、时间窗、SDP 端点、呼叫起始时间。
     */
    private class LinkTarget(
        val callId: String,
        val timeline: SipDialogTimeline,
        val sdpFrames: List<Long>,
        val windowStart: Double,
        val windowEnd: Double,
        val endpoints: List<Endpoint>,
        val startEpoch: Double
    )

    /**
     * 把 [streams] 关联到 [callIds] 描述的呼叫上。
     *
     * @param callIds 呼叫标识，结果顺序与它一致；重复项只处理一次。
     * @param fromTo `callId` → `(from, to)`；缺失时 [VoipCall.from] / [VoipCall.to] 取空串。
     * @param timelines `SipTransactionCorrelator` 产出的 dialog；同一个 `callId` 出现多次时取第一个。
     * @param streams RTP 扫描结果里的流，`unlinkedStreams` 保持这个顺序。
     * @param sipTruncated SIP 消息被截断时为 `true`：只影响 [Result.warnings]，关联照常执行。
     */
    fun link(
        callIds: List<String>,
        fromTo: Map<String, Pair<String, String>>,
        timelines: List<SipDialogTimeline>,
        streams: List<RtpStream>,
        sipTruncated: Boolean = false
    ): Result {
        val warnings = mutableListOf<String>()
        if (sipTruncated) warnings += TRUNCATION_WARNING

        val captureStartEpochSec = captureStartEpochSeconds(timelines, streams)
        val timelinesByCallId = timelines.distinctBy { it.callId }.associateBy { it.callId }

        val targets = mutableListOf<LinkTarget>()
        callIds.distinct().forEach { callId ->
            val timeline = timelinesByCallId[callId]
            if (timeline == null) {
                warnings += "call $callId has no SIP dialog timeline; skipped"
            } else {
                targets += linkTarget(callId, timeline)
            }
        }

        // 表 1：先算出每条流能命中的全部候选呼叫（按 callIds 顺序）。
        val candidates = Array(streams.size) { mutableListOf<Pair<Int, RtpLinkReason>>() }
        targets.forEachIndexed { callIndex, target ->
            streams.forEachIndexed { streamIndex, stream ->
                val reason = linkReason(target, stream)
                if (reason != RtpLinkReason.NONE) candidates[streamIndex] += callIndex to reason
            }
        }

        // 表 4：一条流命中多个呼叫时，留给首包时间最接近的那个呼叫（并列取 callIds 靠前者）。
        val assignments = IntArray(streams.size) { UNASSIGNED }
        val streamWarnings = arrayOfNulls<String>(streams.size)
        streams.indices.forEach { streamIndex ->
            val matches = candidates[streamIndex]
            if (matches.isEmpty()) return@forEach
            if (matches.size == 1) {
                assignments[streamIndex] = matches.first().first
                return@forEach
            }
            val firstEpoch = streamFirstEpochSeconds(streams[streamIndex])
            val winner = matches.minByOrNull { abs(targets[it.first].startEpoch - firstEpoch) } ?: matches.first()
            val warning = "stream ${streams[streamIndex].id} matched ${matches.size} calls; " +
                "linked to ${targets[winner.first].callId} (closest first-packet time)"
            assignments[streamIndex] = winner.first
            streamWarnings[streamIndex] = warning
            warnings += warning
        }

        val linkedByCall = Array(targets.size) { mutableListOf<LinkedRtpStream>() }
        streams.forEachIndexed { streamIndex, stream ->
            val callIndex = assignments[streamIndex]
            if (callIndex == UNASSIGNED) return@forEachIndexed
            val target = targets[callIndex]
            val reason = candidates[streamIndex].first { it.first == callIndex }.second
            linkedByCall[callIndex] += LinkedRtpStream(
                stream = stream,
                direction = directionFor(target.timeline, stream),
                linkReason = reason,
                callId = target.callId,
                warning = streamWarnings[streamIndex]
            )
        }

        val calls = targets.mapIndexed { callIndex, target ->
            val callStreams = linkedByCall[callIndex]
            val timing = callTiming(target.timeline)
            VoipCall(
                callId = target.callId,
                from = fromTo[target.callId]?.first ?: "",
                to = fromTo[target.callId]?.second ?: "",
                state = callState(target.timeline),
                startRel = target.startEpoch - captureStartEpochSec,
                setupMs = timing.setupMs,
                ringMs = timing.ringMs,
                durationMs = timing.durationMs,
                sipFrames = sipFrames(target.timeline),
                sdpFrames = target.sdpFrames,
                streams = callStreams,
                mos = mosFor(callStreams)
            )
        }

        val unlinkedStreams = streams.filterIndexed { index, _ -> assignments[index] == UNASSIGNED }
        return Result(calls = calls, unlinkedStreams = unlinkedStreams, warnings = warnings)
    }

    // ---------------------------------------------------------------- 时间基准

    /**
     * 抓包起点（绝对 epoch 秒）。
     *
     * 有流时用 `firstAbsEpochUs / 1e6 - startRel` 在每条流上各算一次再取最小值；
     * 没有流时退化为所有 SIP 事件里最早的 `time`（再退到最早的事务 `firstTime`）；
     * 两者都没有就返回 `0.0`。
     */
    private fun captureStartEpochSeconds(
        timelines: List<SipDialogTimeline>,
        streams: List<RtpStream>
    ): Double {
        if (streams.isNotEmpty()) {
            return streams.minOf { streamFirstEpochSeconds(it) - it.startRel }
        }
        val eventTimes = timelines.flatMap { it.events }.flatMap { it.transaction.allMessages }.map { it.time }
        return eventTimes.minOrNull()
            ?: timelines.flatMap(::dialogTransactions).minOfOrNull { it.firstTime }
            ?: 0.0
    }

    /** [RtpStream.firstAbsEpochUs] 换算成绝对 epoch 秒。 */
    private fun streamFirstEpochSeconds(stream: RtpStream): Double =
        stream.firstAbsEpochUs / MICROS_PER_SECOND

    // ---------------------------------------------------------------- 呼叫预处理

    private fun linkTarget(callId: String, timeline: SipDialogTimeline): LinkTarget {
        val messages = timeline.events.flatMap { it.transaction.allMessages }
        val transactions = dialogTransactions(timeline)
        val invite = inviteTransaction(transactions)
        val sdpFrames = (
            messages.filter { it.sdp != null }.map { it.frameNumber } +
                timeline.sdpOfferAnswers.flatMap { listOfNotNull(it.offerFrame, it.answerFrame) }
            ).distinct().sorted()
        val endpoints = timeline.sdpOfferAnswers
            .flatMap { listOfNotNull(it.offer, it.answer) }
            .mapNotNull(::endpoint)
        return LinkTarget(
            callId = callId,
            timeline = timeline,
            sdpFrames = sdpFrames,
            // 时间窗下界 = 最早的 INVITE 事务时间；没有 INVITE 时退到最早的事务时间。
            windowStart = invite?.firstTime ?: transactions.minOfOrNull { it.firstTime } ?: 0.0,
            // 上界 = 最晚的 BYE + 5 s；没有 BYE 则不设上界。
            windowEnd = lastBye(transactions)?.let { it.lastTime + BYE_GRACE_SECONDS }
                ?: Double.POSITIVE_INFINITY,
            endpoints = endpoints,
            // 与 `SipCallSummary.startTime` 同样的口径：dialog 里最早的消息时间。
            startEpoch = messages.minOfOrNull { it.time }
                ?: transactions.minOfOrNull { it.firstTime }
                ?: 0.0
        )
    }

    /** dialog 里的事务：`callTransactions` 与 `events` 的并集（去重）。 */
    private fun dialogTransactions(timeline: SipDialogTimeline): List<SipTransaction> =
        (timeline.callTransactions + timeline.events.map { it.transaction }).distinct()

    private fun endpoint(media: SdpMediaSummary): Endpoint? {
        val address = media.connectionAddress
        if (address.isBlank() || address in UNUSABLE_ADDRESSES) return null
        val port = media.mediaPort ?: return null
        return Endpoint(address, port)
    }

    // ---------------------------------------------------------------- 表 1：关联优先级

    private fun linkReason(target: LinkTarget, stream: RtpStream): RtpLinkReason {
        // 优先级 1：setupFrame 命中 SDP 帧；0 表示原生层没有这个信息，绝不能当成命中。
        if (stream.setupFrame != 0L && target.sdpFrames.contains(stream.setupFrame)) {
            return RtpLinkReason.SETUP_FRAME
        }
        // 优先级 2：SDP 端点匹配 + 首包时间落在 [INVITE, BYE+5s] 内。
        val firstEpoch = streamFirstEpochSeconds(stream)
        if (firstEpoch < target.windowStart || firstEpoch > target.windowEnd) return RtpLinkReason.NONE
        return if (target.endpoints.any { matchesEndpoint(stream, it) }) {
            RtpLinkReason.SDP_ADDRESS_PORT
        } else {
            RtpLinkReason.NONE
        }
    }

    /** 地址与端口必须落在流的**同一侧**（与 `CommunicationAnalyzer.matchesSdpEndpoint` 同口径）。 */
    private fun matchesEndpoint(stream: RtpStream, endpoint: Endpoint): Boolean =
        (stream.src == endpoint.address && stream.srcPort == endpoint.port) ||
            (stream.dst == endpoint.address && stream.dstPort == endpoint.port)

    // ---------------------------------------------------------------- 表 2：方向

    /**
     * 按表 2 判定方向：以**主叫侧**（通常是 offer 方）的 SDP 地址 + `m=` 端口为基准。
     *
     * 若 offer 是**被叫**发的（例如被叫发起的 re-INVITE），则把 `FORWARD`/`REVERSE` 两个标签对调，
     * 保证 `FORWARD` 始终是「主叫 → 被叫」。地址命中而端口不匹配、或两侧都不命中时为 `UNKNOWN`。
     */
    private fun directionFor(timeline: SipDialogTimeline, stream: RtpStream): RtpStreamDirection {
        timeline.sdpOfferAnswers.forEach { association ->
            val offer = endpoint(association.offer) ?: return@forEach
            val callerView = !offererIsCallee(timeline, association)
            if (stream.dst == offer.address && stream.dstPort == offer.port) {
                return if (callerView) RtpStreamDirection.REVERSE else RtpStreamDirection.FORWARD
            }
            if (stream.src == offer.address && stream.srcPort == offer.port) {
                return if (callerView) RtpStreamDirection.FORWARD else RtpStreamDirection.REVERSE
            }
        }
        return RtpStreamDirection.UNKNOWN
    }

    /**
     * offer 是不是**被叫**发的。
     *
     * 找到 `offerFrame` 对应的那条消息，看它的 `fromTag`：等于 [SipDialogTimeline.finalToTag]
     * 说明 offer 来自被叫。找不到消息、没有 tag、或 tag 两边都不沾时一律按「offer 方就是主叫」
     * 处理（也就是「先发出 INVITE 的一方」）。
     */
    private fun offererIsCallee(
        timeline: SipDialogTimeline,
        association: SdpOfferAnswerAssociation
    ): Boolean {
        val message = timeline.events
            .flatMap { it.transaction.allMessages }
            .firstOrNull { it.frameNumber == association.offerFrame }
            ?: return false
        val fromTag = message.fromTag?.takeIf { it.isNotBlank() } ?: return false
        val finalToTag = timeline.finalToTag?.takeIf { it.isNotBlank() } ?: return false
        return fromTag == finalToTag
    }

    // ---------------------------------------------------------------- 表 3：状态

    private fun callState(timeline: SipDialogTimeline): VoipCallState {
        val transactions = dialogTransactions(timeline)
        val invite = inviteTransaction(transactions)
        val finalCode = invite?.finalResponses?.lastOrNull()?.let(::responseCode)
        val okResponse = isSuccess(finalCode)

        if (finalCode == 487 || hasMethod(transactions, "CANCEL")) return VoipCallState.CANCELLED
        if (finalCode != null && finalCode >= 400 && finalCode < 487) return VoipCallState.REJECTED
        if (hasMethod(transactions, "BYE")) return VoipCallState.COMPLETED
        if (okResponse || hasMethod(transactions, "ACK")) return VoipCallState.IN_CALL
        if (invite != null && !okResponse && invite.provisionalResponses.any { isProvisional(responseCode(it)) }) {
            return VoipCallState.RINGING
        }
        if (invite != null && invite.provisionalResponses.isEmpty() && invite.finalResponses.isEmpty()) {
            return VoipCallState.SETUP
        }
        return VoipCallState.UNKNOWN
    }

    private fun hasMethod(transactions: List<SipTransaction>, method: String): Boolean =
        transactions.any { transactionMethod(it) == method }

    /**
     * 事务方法：先规范化 `cSeqMethod`，为空再用 `request?.method`。
     *
     * 这里重写 `SipTransactionCorrelator` 里那个私有 helper 的两行规范化（trim → 取第一个空格
     * 之前的部分 → 大写），**不调用**它（私有，而且那属于 correlator 的实现细节）。
     */
    private fun transactionMethod(transaction: SipTransaction): String =
        normalizeMethod(transaction.cSeqMethod).ifBlank { normalizeMethod(transaction.request?.method) }

    private fun normalizeMethod(value: String?): String =
        value?.trim()?.substringBefore(' ')?.uppercase().orEmpty()

    private fun responseCode(message: SipMessage): Int? =
        RESPONSE_CODE.find(message.status.ifBlank { message.info })?.groupValues?.get(1)?.toIntOrNull()

    private fun isProvisional(code: Int?): Boolean = code != null && code in 100..199

    private fun isSuccess(code: Int?): Boolean = code != null && code in 200..299

    // ---------------------------------------------------------------- 表 3 用到的时间点

    private class CallTiming(val setupMs: Long?, val ringMs: Long?, val durationMs: Long?)

    private fun callTiming(timeline: SipDialogTimeline): CallTiming {
        val transactions = dialogTransactions(timeline)
        val invite = inviteTransaction(transactions)
        val inviteTime = invite?.request?.time
        if (inviteTime == null) return CallTiming(null, null, null)

        // setupMs：INVITE → 第一个 2xx 最终响应。
        val setupMs = invite.finalResponses
            .firstOrNull { isSuccess(responseCode(it)) }
            ?.let { millisBetween(inviteTime, it.time) }
        // ringMs：INVITE → 第一个 1xx 临时响应。
        val ringMs = invite.provisionalResponses
            .filter { isProvisional(responseCode(it)) }
            .minByOrNull { it.time }
            ?.let { millisBetween(inviteTime, it.time) }
        // durationMs：INVITE → 最后一个 BYE（用它的请求时间，没有就用事务起始时间）。
        val durationMs = lastBye(transactions)
            ?.let { bye -> millisBetween(inviteTime, bye.request?.time ?: bye.firstTime) }
        return CallTiming(setupMs, ringMs, durationMs)
    }

    private fun inviteTransaction(transactions: List<SipTransaction>): SipTransaction? =
        transactions.filter { transactionMethod(it) == "INVITE" }
            .minWithOrNull(compareBy({ it.firstTime }, { it.firstFrame ?: Long.MAX_VALUE }))

    private fun lastBye(transactions: List<SipTransaction>): SipTransaction? =
        transactions.filter { transactionMethod(it) == "BYE" }
            .maxWithOrNull(compareBy({ it.lastTime }, { it.firstFrame ?: Long.MIN_VALUE }))

    /** 与 correlator 的 `millisBetween` 同口径（差值不为负）。 */
    private fun millisBetween(start: Double, end: Double): Long =
        ((end - start).coerceAtLeast(0.0) * 1_000.0).roundToLong()

    // ---------------------------------------------------------------- 帧号与 MOS

    /** dialog 里出现过的全部 SIP 消息帧号，升序去重。 */
    private fun sipFrames(timeline: SipDialogTimeline): List<Long> =
        timeline.events.flatMap { it.transaction.allMessages }
            .map { it.frameNumber }
            .distinct()
            .sorted()

    /**
     * 呼叫的 MOS：优先 `FORWARD`，没有就用 `REVERSE`，都没有则为 `null`。
     *
     * 每个方向各自的 MOS 由界面按同样的方式对那条流调用 [MosEstimator.estimate] 得到。
     */
    private fun mosFor(linked: List<LinkedRtpStream>): MosEstimate? {
        val stream = linked.firstOrNull { it.direction == RtpStreamDirection.FORWARD }?.stream
            ?: linked.firstOrNull { it.direction == RtpStreamDirection.REVERSE }?.stream
            ?: return null
        return MosEstimator.estimate(
            codec = stream.codec,
            lossPercent = stream.lostPct,
            oneWayDelayMs = MosEstimator.defaultOneWayDelayMs()
        )
    }
}
