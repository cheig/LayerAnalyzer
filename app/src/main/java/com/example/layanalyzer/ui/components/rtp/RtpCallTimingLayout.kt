// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.model.SipDialogEvent
import com.example.layanalyzer.model.SipMessage
import java.util.Locale

/**
 * SIP 时序图的一支箭头（RTP3-UI-02）。
 *
 * @param fromLane 发出方所在泳道，∈ `[0, lanes-1]`
 * @param toLane 接收方所在泳道，∈ `[0, lanes-1]`
 * @param label 请求取方法名（`INVITE` / `ACK`…），响应取状态码（`180` / `200`…）
 * @param frame 该消息的帧号，点击箭头据此跳转
 * @param timeRelSec 相对**本呼叫最早一条 SIP 消息**的秒数（见 [layoutSipFlow]）
 * @param yFraction 纵向分布位置，∈ `[0,1]`，**不是时间轴刻度**（见 [layoutSipFlow]）
 */
data class SipArrow(
    val fromLane: Int,
    val toLane: Int,
    val label: String,
    val frame: Long,
    val timeRelSec: Double,
    val yFraction: Float
)

/**
 * SIP 时序图的箭头布局（RTP3-UI-02）。
 *
 * 本文件是**纯 Kotlin**：不引用 `android.*` / `androidx.compose.*`，也不引用资源，
 * 因此 `RtpCallTimingLayoutTest` 可以当普通 JUnit 测试跑（本仓库没有为 `ui.components.rtp`
 * 配 Robolectric）。字符串本地化一律留给调用方。
 *
 * ### 泳道规则（函数自己推导，签名里没有泳道输入）
 *
 * 1. 把 `events` 里每个事务的 `allMessages` 摊平、按 `(time, frameNumber)` 升序排序；
 * 2. 泳道 0 = **最早一条消息的发出方**（正常就是发 INVITE 的主叫）；
 * 3. 其余泳道按 `SipMessage.source` **首次出现顺序**排（[sipFlowLanes]），所以有代理时
 *    代理会占中间泳道；
 * 4. 地址落在 `lanes` 之外（第 3 个端点却只有 2 条泳道）时夹到 `[0, lanes-1]`；
 * 5. 没有 `source` 记录（原生层没解析出地址）的地址不参与泳道排序；作为发出方时落到泳道 0，
 *    作为接收方时落到「发出方泳道 + 1」再夹紧——这样 `lanes=2` 的常见情形下，
 *    只有一个方向的呼叫（有 INVITE 没有响应）仍然是「发起方 → 接收方」。
 *
 * 排序在函数内完成，调用方**不需要**预先排序。
 *
 * ### `yFraction` 是分布不是时间轴
 *
 * `yFraction = i / (n - 1)`（`i` 是排序后的箭头下标，只有一支箭头时为 `0f`）。这样做的好处：
 * 单调不减、恒在 `[0,1]`、与箭头数量无关（长呼叫不会被压成一团）、并且天然支持虚拟化
 * （第 `i` 行的位置不需要知道别的箭头）。代价是纵向间距**不代表真实时间**，真实时间由
 * [SipArrow.timeRelSec] 单独携带、显示在标签旁。需要把某个绝对时刻映射到同一纵轴时用
 * [sipTimeFraction]（它按箭头的时间做分段线性插值）。
 *
 * ### `timeRelSec` 的时间基准
 *
 * 只用 `events` 是推不出「相对抓包起点」的（`SipMessage.time` 是绝对 epoch 秒，
 * `RtpStream.startRel` 是相对抓包第 0 帧，换算需要流的 `firstAbsEpochUs`，
 * 见 [com.example.layanalyzer.data.RtpCallLinker] 的类注释），所以本函数把基准定为
 * **本呼叫最早一条 SIP 消息**：最早那条的 `timeRelSec` 恒为 `0.0`。
 * 详情页若要和 RTP 线段共用一条时间轴，把流的 `startRel` 减去「最早消息的绝对时间 − 抓包起点」
 * 即可（[VoipCallDetailScreen] 就是这么做的）。
 *
 * ### 边界
 *
 * `events` 为空、`lanes <= 0`、消息地址缺失都不会抛异常，只会返回空表或退化的箭头
 * （例如 `lanes = 1` 时所有箭头都在泳道 0 上自指）。
 *
 * @param lanes 泳道数；调用方一般传 `2`，有代理时传去重后的地址数
 */
fun layoutSipFlow(events: List<SipDialogEvent>, lanes: Int): List<SipArrow> {
    if (lanes <= 0) return emptyList()
    val messages = sipMessages(events)
    if (messages.isEmpty()) return emptyList()

    val addresses = laneAddresses(messages)
    val lastLane = lanes - 1
    val firstTime = messages.first().time
    val lastIndex = messages.size - 1

    return messages.mapIndexed { index, message ->
        val fromLane = laneIndex(addresses, message.source, fallback = 0).coerceIn(0, lastLane)
        // 接收方没在 source 里出现过时退到「发出方 + 1」：2 泳道下正好是「发起方 → 接收方」。
        val toLane = laneIndex(addresses, message.destination, fallback = fromLane + 1)
            .coerceIn(0, lastLane)
        SipArrow(
            fromLane = fromLane,
            toLane = toLane,
            label = arrowLabel(message),
            frame = message.frameNumber,
            timeRelSec = message.time - firstTime,
            yFraction = if (lastIndex <= 0) 0f else index.toFloat() / lastIndex
        )
    }
}

/**
 * 泳道顺序上的端点地址（首次出现顺序，空地址被丢弃）。
 *
 * [layoutSipFlow] 用它定泳道；界面用它给竖线加标签、把 RTP 流的 `src` 映射回泳道。
 */
fun sipFlowLanes(events: List<SipDialogEvent>): List<String> = laneAddresses(sipMessages(events))

/**
 * 把 `timeRelSec` 映射到 [SipArrow.yFraction] 那根纵轴上，分段线性插值并夹到 `[0,1]`。
 *
 * 前提：[arrows] 是 [layoutSipFlow] 产出的、按时间升序的表（函数不重新排序）。
 * RTP 区间（粗线段）的起止要靠它落到和箭头同一根纵轴上；空表返回 `0f`，
 * 单个箭头返回该箭头的 `yFraction`。
 */
fun sipTimeFraction(arrows: List<SipArrow>, timeRelSec: Double): Float {
    if (arrows.isEmpty()) return 0f
    val first = arrows.first()
    val last = arrows.last()
    if (timeRelSec <= first.timeRelSec) return first.yFraction
    if (timeRelSec >= last.timeRelSec) return last.yFraction
    for (index in 0 until arrows.size - 1) {
        val start = arrows[index]
        val end = arrows[index + 1]
        if (timeRelSec <= end.timeRelSec) {
            val span = end.timeRelSec - start.timeRelSec
            if (span <= 0.0) return end.yFraction
            val ratio = ((timeRelSec - start.timeRelSec) / span).toFloat()
            return start.yFraction + ratio * (end.yFraction - start.yFraction)
        }
    }
    return last.yFraction
}

/**
 * 时序图的**列表版兜底**（RtpCallTimingDiagram 要求
 * 先有列表版）：每条 SIP 消息一行，格式固定为
 * `时间 | 方向 | 标签 | 帧号`，例如
 * `0.000s | 10.0.0.1:5060 → 10.0.0.2:5060 | INVITE | #12`。
 *
 * 时间与 [SipArrow.timeRelSec] 同基准（本呼叫最早一条消息为 `0.000`），保留三位小数；
 * 端口缺失时只写地址，地址缺失（原生层没解析出来）写 `?`——不编造端点。
 * 列分隔符与界面上的表头字符串一一对应，两边必须同时改。
 */
fun sipFlowAsRows(events: List<SipDialogEvent>): List<String> {
    val messages = sipMessages(events)
    if (messages.isEmpty()) return emptyList()
    val firstTime = messages.first().time
    return messages.map { message ->
        val time = String.format(Locale.US, "%.3f", message.time - firstTime)
        val direction =
            "${endpointText(message.source, message.sourcePort)} → " +
                endpointText(message.destination, message.destinationPort)
        "${time}s | $direction | ${arrowLabel(message)} | #${message.frameNumber}"
    }
}

// ---------------------------------------------------------------- 内部实现

/** 事务里的全部消息，按 `(time, frameNumber)` 升序；重复消息（同一事务被列两次）只留一条。 */
private fun sipMessages(events: List<SipDialogEvent>): List<SipMessage> =
    events.flatMap { it.transaction.allMessages }
        .distinct()
        .sortedWith(compareBy({ it.time }, { it.frameNumber }))

/** 泳道顺序：非空 `source` 的首次出现顺序。 */
private fun laneAddresses(messages: List<SipMessage>): List<String> =
    messages.mapNotNull { message -> message.source.takeIf { it.isNotBlank() } }.distinct()

/** 地址的泳道号；不在表里（含空地址）就用 [fallback]。 */
private fun laneIndex(addresses: List<String>, address: String, fallback: Int): Int {
    val index = addresses.indexOf(address)
    return if (index >= 0) index else fallback
}

/**
 * 箭头标签：请求取方法名，响应取状态码。
 *
 * 方法名规范化（trim → 取第一个空格前 → 大写）与响应码提取（`status` 优先、`info` 兜底）
 * 与 `SipTransactionCorrelator` 的同名私有实现同口径；这里各写一遍而不是去调用它——
 * 那些是私有成员，而且那样会把「纯函数、无依赖」的边界打破。
 * 两种情况都判不出来时退回原始的 `status` / `info` 文本（可能为空串，箭头就没有标签）。
 */
private fun arrowLabel(message: SipMessage): String {
    val method = normalizeMethod(message.method)
    if (method.isNotEmpty()) return method
    return responseCode(message)?.toString()
        ?: message.status.trim().ifBlank { message.info.trim() }
}

private fun normalizeMethod(value: String?): String =
    value?.trim()?.substringBefore(' ')?.uppercase().orEmpty()

/** 与 `SipTransactionCorrelator` / `RtpCallLinker` 相同的响应码提取方式。 */
private fun responseCode(message: SipMessage): Int? =
    RESPONSE_CODE.find(message.status.ifBlank { message.info })?.groupValues?.get(1)?.toIntOrNull()

private fun endpointText(address: String, port: Int?): String = when {
    address.isBlank() -> UNKNOWN_ENDPOINT
    port != null -> "$address:$port"
    else -> address
}

/** 地址缺失时的占位符；不是本地化文本，界面的本地化标签另有一套。 */
private const val UNKNOWN_ENDPOINT = "?"

private val RESPONSE_CODE = Regex("(?<!\\d)([1-6]\\d{2})(?!\\d)")
