// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.data.LinkedRtpStream
import com.example.layanalyzer.data.MosEstimator
import com.example.layanalyzer.data.RtpLinkReason
import com.example.layanalyzer.data.RtpStreamDirection
import com.example.layanalyzer.data.VoipCall
import com.example.layanalyzer.data.VoipCallState
import com.example.layanalyzer.model.RtpCodecSource
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.SipDialogEvent
import com.example.layanalyzer.model.SipDialogTimeline
import com.example.layanalyzer.model.SipMessage
import com.example.layanalyzer.model.SipTransaction
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import java.util.Locale
import kotlin.math.max
import kotlin.math.min

/**
 * 呼叫详情页 + SIP 时序图（RTP3-UI-02）。
 *
 * ### 数据来源
 *
 * 全部由宿主注入：呼叫本身（[VoipCall]）与它的 SIP dialog（[SipDialogTimeline]，
 * 来自 `VoipCallsViewModel` 的 `Ready.dialogs`）。本组件不持有 ViewModel、不读文件、
 * 不调原生层——与 [VoipCallsScreen] 一样是「哑」的。
 *
 * ### 两种时序渲染，都在
 *
 * 1. **图形版**：`Canvas` 画泳道竖线 + 箭头（[SipFlowDiagram]）。箭头纵向位置取自
 *    [SipArrow.yFraction]（是分布不是时间轴），横向是泳道；每条关联流用**粗线段**画在
 *    它发出方的泳道上，起止由 `startRel` / `endRel` 映射到同一根纵轴（[sipTimeFraction]）。
 *    点击箭头 → [VoipCallDetailScreen] 的 `onPacketClick(frame)`。
 * 2. **列表版兜底**：`时间 | 方向 | 标签 | 帧号` 的文本列表（[sipFlowAsRows]）。
 *    `task_rtp_m3_voip_calls.md` §7.3 要求列表版先落地并且真的可用，所以它不是一个死分支——
 *    卡片右上角的「图形 / 列表」开关可以随时切过去（图形渲染异常时它就是退路）。
 *
 * **什么时候走虚拟化**：箭头数 > [SIP_FLOW_DIAGRAM_ARROW_LIMIT]（200）时整页改用
 * `LazyColumn`，**每行一支箭头**（`events.size > 200` 的卡片要求），可视范围外的箭头不会被
 * 组合也不会有置；两种渲染方式在这个阈值以上都用 `LazyColumn`。阈值以下是一整块 `Canvas`
 * （放在 `verticalScroll` 里），逐行虚拟化对几十支箭头没有收益，反而会让泳道竖线被行距切开。
 *
 * ### 时间基准（绝对 epoch → `startRel`）
 *
 * `SipMessage.time` 是**绝对 epoch 秒**，`RtpStream.startRel` / `endRel` 是**相对抓包第 0 帧**的秒数，
 * 两者不能直接比。抓包起点由流自己还原：`captureStartEpochSec = firstAbsEpochUs / 1e6 - startRel`
 * （[com.example.layanalyzer.data.RtpCallLinker] 的类注释写的就是这条关系，这里在**本呼叫的流**上取最小值，
 * 与联接器的「全部流取最小」口径略有不同——详情页只看得到本呼叫的流，差别是亚毫秒级）。
 * 于是「相对本呼叫最早一条 SIP 消息」的时间轴与 `startRel` 的关系只有一条常数偏移：
 * `callStartRel = firstMessageEpochSec - captureStartEpochSec`。箭头的时间由
 * [layoutSipFlow] 给出（最早一条消息为 0），流的时间减去 `callStartRel` 就落在同一根轴上。
 * 没有流（或没有流首包时间）时不做换算，直接不画 RTP 线段——宁可不画，也不猜。
 *
 * ### 姓名仍然是空的
 *
 * RTP3-NAT-04 的 `readRtpSetupInfo` 在本仓库尚未实现，`from` / `to` 恒为空串，
 * 标题沿用 [voipCallTitle] 的「未知主叫 → 未知被叫」+ 真实存在的 `Call-ID`，
 * **不拿地址或 SSRC 顶替姓名**。
 *
 * @param playback 选中呼叫后的解码结果（宿主把 `VoipCallsViewModel.playback` 传进来）。
 *   `null` 表示还没点过播放。这里只用它显示一行**诚实的**状态：失败原因用错误色，
 *   其余给「已解码 N 条流」这样的中性提示。RTP3-UI-03 会用双轨波形替换这一行。
 * @param onPacketClick 点箭头/列表行跳到该 SIP 消息所在帧
 * @param onPlayCall 「播放」：宿主接到 `VoipCallsViewModel.selectCall(callId)`，点一下就真的开始解码
 * @param filter 「过滤此呼叫」要应用的过滤器（RTP3-UI-04）。宿主用
 *   `remember(selectedCall) { VoipFilterBuilder.forCall(selectedCall) }` 算一次再传进来——
 *   本组件**不自己算**，[filter] 是按钮可用性与截断提示的唯一来源：
 *   `filter.filter` 为空时按钮禁用，`filter.truncated` 为真时给出「只用了 Call-ID」的提示。
 *   默认值是空结果（按钮禁用），与 [onFilterCall] 的默认空实现一致：没接线时就是个哑按钮。
 * @param onFilterCall 点「过滤此呼叫」：宿主把 [filter] 交给 `onApplyScenarioStep` 并切回包列表页
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VoipCallDetailScreen(
    call: VoipCall,
    timeline: SipDialogTimeline?,
    filter: VoipFilterBuilder.Result = VoipFilterBuilder.Result("", false),
    playback: RtpDecodeResult? = null,
    onBack: () -> Unit,
    onPacketClick: (Long) -> Unit = {},
    onPlayCall: () -> Unit = {},
    onFilterCall: () -> Unit = {}
) {
    BackHandler(onBack = onBack)
    var diagram by remember { mutableStateOf(true) }
    val model = remember(call, timeline) { buildFlowModel(call, timeline) }
    val virtualized = model.arrows.size > SIP_FLOW_DIAGRAM_ARROW_LIMIT

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        voipCallTitle(call.from, call.to),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        if (virtualized) {
            // 需求 3：长呼叫（>200 条消息）逐箭头虚拟化，可视范围外的不组合、不绘制。
            LazyColumn(
                modifier = Modifier
                    .padding(padding)
                    .fillMaxSize()
                    .padding(horizontal = 12.dp)
            ) {
                item(key = "header") { DetailHeader(call, filter, playback, onPlayCall, onFilterCall) }
                item(key = "overview") { CallOverviewCard(call) }
                item(key = "flow") {
                    SipFlowHeader(model, diagram = diagram, onDiagramChange = { diagram = it })
                }
                if (model.arrows.isEmpty()) {
                    item(key = "empty") { EmptySignallingText() }
                } else if (diagram) {
                    item(key = "lanes") { LaneLabelsRow(model) }
                    itemsIndexed(model.arrows, key = { index, arrow -> "arrow-$index-${arrow.frame}" }) { index, _ ->
                        VirtualizedArrowRow(
                            model = model,
                            index = index,
                            onPacketClick = onPacketClick
                        )
                    }
                } else {
                    val rows = sipFlowAsRows(timeline?.events.orEmpty())
                    item(key = "list-header") { FlowListHeader() }
                    itemsIndexed(rows, key = { index, _ -> "row-$index" }) { index, row ->
                        FlowListRow(
                            text = row,
                            onClick = model.arrows.getOrNull(index)?.let { { onPacketClick(it.frame) } }
                        )
                    }
                }
            }
        } else {
            Column(
                modifier = Modifier
                    .padding(padding)
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 12.dp)
            ) {
                DetailHeader(call, filter, playback, onPlayCall, onFilterCall)
                CallOverviewCard(call)
                SipFlowHeader(model, diagram = diagram, onDiagramChange = { diagram = it })
                if (model.arrows.isEmpty()) {
                    EmptySignallingText()
                } else if (diagram) {
                    LaneLabelsRow(model)
                    SipFlowDiagram(model = model, onPacketClick = onPacketClick)
                } else {
                    FlowList(rows = sipFlowAsRows(timeline?.events.orEmpty()), model = model, onPacketClick = onPacketClick)
                }
            }
        }
    }
}

// ---------------------------------------------------------------- 顶部动作与状态

/**
 * 详情页顶部（需求 4）：「播放」与「过滤此呼叫」两个按钮，外加一行解码状态。
 *
 * 「播放」直接调宿主回调（接到 `VoipCallsViewModel.selectCall`），点了就真的开始解码，
 * 不是摆设。状态行只说**已经发生的事实**：失败原因用错误色，其余是中性提示。
 *
 * 「过滤此呼叫」的可用性与提示都取自同一个 [filter]（RTP3-UI-04）：过滤器为空就禁用按钮
 * （点了也只会把用户的过滤器清空），截断时明说只用了 `Call-ID` 部分——不做静默回退。
 */
@Composable
private fun DetailHeader(
    call: VoipCall,
    filter: VoipFilterBuilder.Result,
    playback: RtpDecodeResult?,
    onPlayCall: () -> Unit,
    onFilterCall: () -> Unit
) {
    val filterAvailable = filter.filter.isNotBlank()
    Column(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Button(onClick = onPlayCall) {
                Icon(Icons.Default.PlayArrow, contentDescription = null)
                Text(
                    stringResource(R.string.voip_detail_play),
                    modifier = Modifier.padding(start = 4.dp),
                    maxLines = 1
                )
            }
            OutlinedButton(onClick = onFilterCall, enabled = filterAvailable) {
                Icon(Icons.Default.FilterAlt, contentDescription = null)
                Text(
                    stringResource(R.string.voip_detail_filter),
                    modifier = Modifier.padding(start = 4.dp),
                    maxLines = 1
                )
            }
        }
        FilterHint(filter, filterAvailable = filterAvailable)
        PlaybackStatusLine(playback = playback, hasStreams = call.streams.isNotEmpty())
    }
}

/**
 * 「过滤此呼叫」的说明行（RTP3-UI-04）。
 *
 * - 有过滤器但被截断：明说是本呼叫的流超过 [VoipFilterBuilder.MAX_STREAMS_IN_FILTER] 条，
 *   只用了 `Call-ID` 部分。
 * - 过滤器为空：说清按钮为什么是灰的。
 * - 其余（正常可用、未截断）：什么都不显示——没发生的事不占屏幕。
 */
@Composable
private fun FilterHint(filter: VoipFilterBuilder.Result, filterAvailable: Boolean) {
    val text = when {
        !filterAvailable -> stringResource(R.string.voip_detail_filter_unavailable)
        filter.truncated ->
            stringResource(R.string.voip_detail_filter_truncated, VoipFilterBuilder.MAX_STREAMS_IN_FILTER)
        else -> return
    }
    Text(
        text,
        modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

/**
 * 一行解码状态。
 *
 * `playback == null`（还没点过播放）时什么都不显示——空话比没有更糟。
 * 失败原因原样显示（原生层的诊断文本，与 RtpPlayerScreen 的处理一致），用错误色；
 * 其余情况给中性提示，不假装已经能播。
 */
@Composable
private fun PlaybackStatusLine(playback: RtpDecodeResult?, hasStreams: Boolean) {
    if (playback == null) return
    val failed = playback.error.isNotBlank()
    val text = when {
        failed -> playback.error
        playback.cancelled -> stringResource(R.string.voip_detail_playback_cancelled)
        playback.items.isNotEmpty() ->
            stringResource(R.string.voip_detail_playback_ready, playback.items.size)
        !hasStreams -> stringResource(R.string.voip_detail_no_streams)
        else -> stringResource(R.string.voip_detail_playback_unsupported, playback.unsupported.size)
    }
    Text(
        text,
        modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
        style = MaterialTheme.typography.bodySmall,
        color = if (failed) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        }
    )
}

// ---------------------------------------------------------------- 概况区

/**
 * 需求 1 的概况区：主被叫、状态、`setupMs`（INVITE → 2xx）、`ringMs`（INVITE → 1xx）、
 * `durationMs`（INVITE → BYE）、逐方向的丢包/抖动/MOS，以及关联流列表。
 *
 * 三个毫秒值直接取 [VoipCall] 上由 `RtpCallLinker` 算好的字段，本页**不重新推导**——
 * 计时口径只有一处。
 */
@Composable
private fun CallOverviewCard(call: VoipCall) {
    val notApplicable = notApplicableText()
    Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    voipCallTitle(call.from, call.to),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                VoipStatusBadge(call.state)            }

            // 姓名缺失时用真实的 Call-ID 当抓手（与列表页同一口径，见文件头 KDoc）。
            if (call.callId.isNotBlank()) {
                Text(
                    call.callId,
                    modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Text(
                stringResource(R.string.voip_call_start, formatVoipDecimal(call.startRel)),
                modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                stringResource(R.string.voip_detail_setup, millisText(call.setupMs)),
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                stringResource(R.string.voip_detail_ring, millisText(call.ringMs)),
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                stringResource(
                    R.string.voip_detail_duration,
                    call.durationMs?.let(::formatRtpPlayerTime) ?: notApplicable
                ),
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

            Text(
                stringResource(R.string.voip_detail_stream_title, call.streams.size),
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.labelLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            if (call.streams.isEmpty()) {
                Text(
                    stringResource(R.string.voip_detail_no_streams),
                    modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            call.streams.forEach { linked -> LinkedStreamRow(linked) }
        }
    }
}

/**
 * 一条关联流的两个方向信息行。
 *
 * 丢包/抖动/MOS 都取自**这条流自己**：MOS 是对 `stream.codec` + `stream.lostPct` 单独估算的
 * （[VoipCall.mos] 只覆盖主方向）；[RtpStream.jitterAvailable] 为 false 时抖动显示「不适用」，
 * 而不是把 0 ms 当成测出来的结果。数值旁边标「估算」——MOS 是 E-model 期望值不是实测值。
 */
@Composable
private fun LinkedStreamRow(linked: LinkedRtpStream) {
    val stream = linked.stream
    val notApplicable = notApplicableText()
    val mos = MosEstimator.estimate(
        codec = stream.codec,
        lossPercent = stream.lostPct,
        oneWayDelayMs = MosEstimator.defaultOneWayDelayMs()
    )
    Column(modifier = Modifier.fillMaxWidth().padding(top = 4.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                directionLabel(linked.direction),
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                stringResource(R.string.voip_detail_stream_codec, stream.id, stream.codec),
                modifier = Modifier.weight(1f),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.End,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                stringResource(R.string.voip_direction_loss, formatVoipDecimal(stream.lostPct)),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                stringResource(
                    R.string.voip_detail_stream_jitter,
                    stream.meanJitterMs
                        ?.takeIf { stream.jitterAvailable }
                        ?.let(::formatVoipDecimal) ?: notApplicable
                ),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                stringResource(
                    R.string.voip_direction_mos,
                    mos?.let { formatVoipDecimal(it.mos) } ?: notApplicable
                ),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            if (mos != null) {
                Text(
                    stringResource(R.string.voip_mos_estimate),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.tertiary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

// ---------------------------------------------------------------- 时序图容器

/** 时序图卡片的表头：标题、图形/列表开关、RTP 图例。 */
@Composable
private fun SipFlowHeader(
    model: SipFlowModel,
    diagram: Boolean,
    onDiagramChange: (Boolean) -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
            Text(
                stringResource(R.string.voip_detail_flow_title),
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                FilterChip(
                    selected = diagram,
                    onClick = { onDiagramChange(true) },
                    label = { Text(stringResource(R.string.voip_detail_flow_diagram), maxLines = 1) }
                )
                FilterChip(
                    selected = !diagram,
                    onClick = { onDiagramChange(false) },
                    label = { Text(stringResource(R.string.voip_detail_flow_list), maxLines = 1) }
                )
                if (diagram && model.rtpSegments.isNotEmpty()) {
                    Box(
                        modifier = Modifier
                            .size(width = 14.dp, height = 4.dp)
                            .background(MaterialTheme.colorScheme.tertiary, RoundedCornerShape(2.dp))
                    )
                    Text(
                        stringResource(R.string.voip_detail_flow_legend_rtp),
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

/** 泳道标签行：与画布内部的列宽同源（同样的水平内边距 + 等分），所以标签正对竖线。 */
@Composable
private fun LaneLabelsRow(model: SipFlowModel) {
    val unknown = stringResource(R.string.voip_detail_lane_unknown)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = LANE_EDGE_PADDING_DP.dp, vertical = 4.dp)
    ) {
        repeat(model.laneCount) { lane ->
            Text(
                model.laneLabels.getOrNull(lane)?.takeIf { it.isNotBlank() } ?: unknown,
                modifier = Modifier.weight(1f),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

/** 没有可用的 SIP 消息时的说明（不是错误，只是这一通呼叫没有信令可画）。 */
@Composable
private fun EmptySignallingText() {
    Text(
        stringResource(R.string.voip_detail_no_signalling),
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

// ---------------------------------------------------------------- 图形版

/**
 * 一整块 `Canvas` 的时序图（箭头数 ≤ [SIP_FLOW_DIAGRAM_ARROW_LIMIT]）。
 *
 * 高度随箭头数增长（每行 [ARROW_ROW_HEIGHT_DP] dp，最少 [MIN_DIAGRAM_HEIGHT_DP] dp），
 * 外层是 `verticalScroll` 的 `Column`，所以长图可以滚。点击画布时按纵向位置反查是哪一支箭头
 * （行的划分与绘制时的 `yOf` 一致，所以命中是精确的，不是「最近邻」的近似）。
 */
@Composable
private fun SipFlowDiagram(model: SipFlowModel, onPacketClick: (Long) -> Unit) {
    val textMeasurer = rememberTextMeasurer()
    val laneColor = MaterialTheme.colorScheme.outlineVariant
    val arrowColor = MaterialTheme.colorScheme.primary
    val rtpColor = MaterialTheme.colorScheme.tertiary
    val labelColor = MaterialTheme.colorScheme.onSurface
    val timeColor = MaterialTheme.colorScheme.onSurfaceVariant
    val labelStyle = MaterialTheme.typography.labelSmall.copy(color = labelColor)
    val timeStyle = MaterialTheme.typography.labelSmall.copy(color = timeColor)
    val rows = model.arrows.size
    val heightDp = max(rows * ARROW_ROW_HEIGHT_DP, MIN_DIAGRAM_HEIGHT_DP)

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = LANE_EDGE_PADDING_DP.dp)
            .height(heightDp.dp)
            .pointerInput(model.arrows) {
                detectTapGestures { position ->
                    val rowHeight = size.height.toFloat() / rows
                    val index = (position.y / rowHeight).toInt().coerceIn(0, rows - 1)
                    model.arrows.getOrNull(index)?.let { onPacketClick(it.frame) }
                }
            }
    ) {
        val rowHeight = size.height / rows
        drawLaneLines(model.laneCount, laneColor)
        model.rtpSegments.forEach { segment ->
            val top = yOf(segment.startFraction, rows, rowHeight)
            val bottom = yOf(segment.endFraction, rows, rowHeight)
            drawRtpMark(segment, model.laneCount, top, bottom, rtpColor)
        }
        model.arrows.forEach { arrow ->
            val y = yOf(arrow.yFraction, rows, rowHeight)
            drawArrow(arrow, model.laneCount, y, arrowColor)
            drawArrowText(textMeasurer, arrow, model.laneCount, y, labelStyle, timeStyle)
        }
    }
}

/**
 * 虚拟化模式的一行 = 一支箭头（需求 3）。
 *
 * 行内画泳道竖线（相邻行首尾相接，看起来是连续的竖线）与该箭头；RTP 粗线段按「本行覆盖的
 * 纵向分数区间」裁剪，因此跨多行的区间仍然连成一条。点击整行 → 跳帧。
 */
@Composable
private fun VirtualizedArrowRow(
    model: SipFlowModel,
    index: Int,
    onPacketClick: (Long) -> Unit
) {
    val arrow = model.arrows[index]
    val textMeasurer = rememberTextMeasurer()
    val laneColor = MaterialTheme.colorScheme.outlineVariant
    val arrowColor = MaterialTheme.colorScheme.primary
    val rtpColor = MaterialTheme.colorScheme.tertiary
    val labelStyle = MaterialTheme.typography.labelSmall.copy(color = MaterialTheme.colorScheme.onSurface)
    val timeStyle = MaterialTheme.typography.labelSmall.copy(color = MaterialTheme.colorScheme.onSurfaceVariant)
    val rows = model.arrows.size
    val rowTop = rowTopFraction(index, rows)
    val rowBottom = rowBottomFraction(index, rows)

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = LANE_EDGE_PADDING_DP.dp)
            .height(ARROW_ROW_HEIGHT_DP.dp)
            .clickable { onPacketClick(arrow.frame) }
    ) {
        drawLaneLines(model.laneCount, laneColor)
        val y = size.height / 2f
        model.rtpSegments.forEach { segment ->
            val top = max(segment.startFraction, rowTop)
            val bottom = min(segment.endFraction, rowBottom)
            if (bottom <= top) return@forEach
            val span = rowBottom - rowTop
            drawRtpMark(
                segment = segment,
                laneCount = model.laneCount,
                top = (top - rowTop) / span * size.height,
                bottom = (bottom - rowTop) / span * size.height,
                color = rtpColor
            )
        }
        drawArrow(arrow, model.laneCount, y, arrowColor)
        drawArrowText(textMeasurer, arrow, model.laneCount, y, labelStyle, timeStyle)
    }
}

// ---------------------------------------------------------------- 列表版兜底

/** 列表版兜底（`sipFlowAsRows` 的文本行），整块放在可滚动列里。 */
@Composable
private fun FlowList(rows: List<String>, model: SipFlowModel, onPacketClick: (Long) -> Unit) {
    FlowListHeader()
    Column(modifier = Modifier.fillMaxWidth()) {
        rows.forEachIndexed { index, row ->
            FlowListRow(
                text = row,
                onClick = model.arrows.getOrNull(index)?.let { { onPacketClick(it.frame) } }
            )
        }
    }
}

@Composable
private fun FlowListHeader() {
    Text(
        stringResource(R.string.voip_detail_flow_row_header),
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp)
            .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(4.dp))
            .padding(horizontal = 6.dp, vertical = 4.dp),
        fontFamily = FontFamily.Monospace,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

/** 一行「时间 | 方向 | 标签 | 帧号」；关联得到箭头时整行可点跳帧。 */
@Composable
private fun FlowListRow(text: String, onClick: (() -> Unit)?) {
    Text(
        text,
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(horizontal = 6.dp, vertical = 4.dp),
        fontFamily = FontFamily.Monospace,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurface
    )
}

// ---------------------------------------------------------------- 派生模型

/** 一条 RTP 流的媒体区间在时序图上的位置（分数坐标，`[0,1]`）。 */
private class RtpSegment(
    val lane: Int,
    val startFraction: Float,
    val endFraction: Float,
    val offsetDirection: Int
)

/** 泳道标签 + 箭头 + RTP 区间；时序图与列表版共用。 */
private class SipFlowModel(
    val laneLabels: List<String>,
    val laneCount: Int,
    val arrows: List<SipArrow>,
    val rtpSegments: List<RtpSegment>
)

/**
 * 从呼叫与它的 dialog 派生时序图数据。
 *
 * 泳道数 = `max(2, SIP 地址去重数)`（卡片：2 条，或按地址集合去重得到 ≥2 条——有代理时中间
 * 那条就是代理）。时间基准的换算见文件头 KDoc；拿不到流首包绝对时间（老原生层的
 * `firstAbsEpochUs == 0`）或没有流时**不画** RTP 线段——宁可不画，也不把区间画到错的位置。
 */
private fun buildFlowModel(call: VoipCall, timeline: SipDialogTimeline?): SipFlowModel {
    val events = timeline?.events.orEmpty()
    val laneLabels = sipFlowLanes(events)
    val laneCount = max(MIN_LANES, laneLabels.size)
    val arrows = layoutSipFlow(events, laneCount)

    val captureStartEpochSec = call.streams
        .mapNotNull { linked -> linked.stream.takeIf { it.firstAbsEpochUs > 0L } }
        .minOfOrNull { it.firstAbsEpochUs / MICROS_PER_SECOND - it.startRel }
    val firstMessageEpochSec = events
        .flatMap { it.transaction.allMessages }
        .minOfOrNull { it.time }

    val segments = if (arrows.isEmpty() || captureStartEpochSec == null || firstMessageEpochSec == null) {
        emptyList()
    } else {
        // 「相对本呼叫最早一条 SIP 消息」的时间轴与 startRel 只差这一条常数偏移。
        val callStartRel = firstMessageEpochSec - captureStartEpochSec
        call.streams.mapNotNull { linked ->
            val lane = mediaLane(linked, laneLabels, laneCount) ?: return@mapNotNull null
            val start = sipTimeFraction(arrows, linked.stream.startRel - callStartRel)
            val end = sipTimeFraction(arrows, linked.stream.endRel - callStartRel)
            if (end < start) return@mapNotNull null
            RtpSegment(
                lane = lane,
                startFraction = start,
                endFraction = end,
                // 粗线段画在发出方泳道上，稍微朝对端偏一点，避免和泳道竖线重叠。
                offsetDirection = when {
                    laneCount <= 1 -> 0
                    lane == 0 -> 1
                    else -> -1
                }
            )
        }
    }
    return SipFlowModel(
        laneLabels = laneLabels,
        laneCount = laneCount,
        arrows = arrows,
        rtpSegments = segments
    )
}

/**
 * RTP 媒体区间的发出方泳道。
 *
 * 先用流的 `src` 在泳道地址里找（最准确：媒体源就是信令里出现过的那一端）；
 * 找不到（SDP `c=` 地址与信令地址不同，这在 NAT 场景很常见）时按方向退到两端：
 * `FORWARD`（主叫 → 被叫）画在泳道 0，`REVERSE` 画在最右泳道。
 * `UNKNOWN` **不画**——方向判不出来就不猜（表 2 的约定）。
 */
private fun mediaLane(linked: LinkedRtpStream, laneLabels: List<String>, laneCount: Int): Int? {
    val index = laneLabels.indexOf(linked.stream.src)
    if (index >= 0) return index.coerceIn(0, laneCount - 1)
    return when (linked.direction) {
        RtpStreamDirection.FORWARD -> 0
        RtpStreamDirection.REVERSE -> laneCount - 1
        RtpStreamDirection.UNKNOWN -> null
    }
}

// ---------------------------------------------------------------- 画布原语

/** 泳道 i 的列中心 x：等分画布宽度（与 [LaneLabelsRow] 的等权 `Row` 对齐）。 */
private fun DrawScope.laneX(index: Int, laneCount: Int): Float {
    val safeCount = max(laneCount, 1)
    val laneWidth = size.width / safeCount
    return laneWidth * (index.coerceIn(0, safeCount - 1) + 0.5f)
}

private fun DrawScope.drawLaneLines(laneCount: Int, color: Color) {
    repeat(max(laneCount, 1)) { lane ->
        val x = laneX(lane, laneCount)
        drawLine(
            color = color,
            start = Offset(x, 0f),
            end = Offset(x, size.height),
            strokeWidth = LANE_STROKE_DP.dp.toPx(),
            cap = StrokeCap.Round
        )
    }
}

/** 泳道上的 RTP 媒体区间：一条粗线段，两端带圆头（起止都看得清）。 */
private fun DrawScope.drawRtpMark(
    segment: RtpSegment,
    laneCount: Int,
    top: Float,
    bottom: Float,
    color: Color
) {
    val x = laneX(segment.lane, laneCount) + segment.offsetDirection * RTP_LANE_OFFSET_DP.dp.toPx()
    drawLine(
        color = color,
        start = Offset(x, top),
        end = Offset(x, bottom),
        strokeWidth = RTP_STROKE_DP.dp.toPx(),
        cap = StrokeCap.Round
    )
}

/** 一支箭头：从发出方泳道到接收方泳道，箭头尖在接收方。同泳道时画一小段自消息短线。 */
private fun DrawScope.drawArrow(arrow: SipArrow, laneCount: Int, y: Float, color: Color) {
    val fromX = laneX(arrow.fromLane, laneCount)
    val toX = laneX(arrow.toLane, laneCount)
    val headLength = ARROW_HEAD_LENGTH_DP.dp.toPx()
    val strokeWidth = ARROW_STROKE_DP.dp.toPx()
    if (fromX == toX) {
        val half = SELF_MESSAGE_HALF_DP.dp.toPx()
        drawLine(color, Offset(fromX - half, y), Offset(fromX + half - headLength, y), strokeWidth)
        drawArrowHead(fromX + half, y, direction = 1f, color = color, headLength = headLength)
        return
    }
    val direction = if (toX > fromX) 1f else -1f
    drawLine(color, Offset(fromX, y), Offset(toX - direction * headLength, y), strokeWidth)
    drawArrowHead(toX, y, direction, color, headLength)
}

private fun DrawScope.drawArrowHead(
    atX: Float,
    y: Float,
    direction: Float,
    color: Color,
    headLength: Float
) {
    val halfWidth = ARROW_HEAD_WIDTH_DP.dp.toPx() / 2f
    val path = Path().apply {
        moveTo(atX, y)
        lineTo(atX - direction * headLength, y - halfWidth)
        lineTo(atX - direction * headLength, y + halfWidth)
        close()
    }
    // 实心三角：线宽只有 1.5 dp，描边的箭头尖在深色底上几乎看不见。
    drawPath(path = path, color = color)
}

/** 箭头标签（方法名或状态码）+ 相对时间；贴在箭头上方/下方，超出画布时自动换边。 */
private fun DrawScope.drawArrowText(
    textMeasurer: TextMeasurer,
    arrow: SipArrow,
    laneCount: Int,
    y: Float,
    labelStyle: TextStyle,
    timeStyle: TextStyle
) {
    val midX = (laneX(arrow.fromLane, laneCount) + laneX(arrow.toLane, laneCount)) / 2f
    val label = textMeasurer.measure(arrow.label, labelStyle)
    val time = textMeasurer.measure(relativeSecondsText(arrow.timeRelSec), timeStyle)
    val labelTop = y - label.size.height - LABEL_GAP_DP.dp.toPx()
    val above = labelTop >= 0f
    val labelY = if (above) labelTop else y + LABEL_GAP_DP.dp.toPx()
    val timeY = if (above) y + LABEL_GAP_DP.dp.toPx() else labelY + label.size.height
    drawText(
        textLayoutResult = label,
        topLeft = Offset(
            x = (midX - label.size.width / 2f).coerceIn(0f, max(size.width - label.size.width, 0f)),
            y = labelY.coerceIn(0f, max(size.height - label.size.height, 0f))
        )
    )
    drawText(
        textLayoutResult = time,
        topLeft = Offset(
            x = (midX - time.size.width / 2f).coerceIn(0f, max(size.width - time.size.width, 0f)),
            y = timeY.coerceIn(0f, max(size.height - time.size.height, 0f))
        )
    )
}

/** 分数坐标 → 画布 y：每支箭头占一行，箭头落在行中心（`[0,1]` 被映射到首末行中心）。 */
private fun yOf(fraction: Float, rows: Int, rowHeight: Float): Float =
    (fraction * max(rows - 1, 0) + 0.5f) * rowHeight

/** 虚拟化第 [index] 行覆盖的分数区间（与 [yOf] 同一套行划分，所以粗线段能跨行相接）。 */
private fun rowTopFraction(index: Int, rows: Int): Float =
    if (rows <= 1) 0f else (index - 0.5f) / (rows - 1)

private fun rowBottomFraction(index: Int, rows: Int): Float =
    if (rows <= 1) 1f else (index + 0.5f) / (rows - 1)

private fun relativeSecondsText(seconds: Double): String =
    String.format(Locale.US, "%.3f", seconds.coerceAtLeast(0.0)) + "s"

// ---------------------------------------------------------------- 常量

/**
 * 超过这个箭头数就改用 `LazyColumn` 逐行虚拟化（卡片：`events.size > 200`）。
 * 箭头数与消息数一一对应，所以这里是同一件事的等价表达。
 */
internal const val SIP_FLOW_DIAGRAM_ARROW_LIMIT = 200

/** 卡片要求「2，或按地址集合去重得到 ≥2」；地址全缺时至少也要有一条泳道线。 */
private const val MIN_LANES = 2

private const val MICROS_PER_SECOND = 1_000_000.0
private const val ARROW_ROW_HEIGHT_DP = 44
private const val MIN_DIAGRAM_HEIGHT_DP = 200
private const val LANE_EDGE_PADDING_DP = 16
private const val LANE_STROKE_DP = 1f
private const val ARROW_STROKE_DP = 1.5f
private const val ARROW_HEAD_LENGTH_DP = 7f
private const val ARROW_HEAD_WIDTH_DP = 6f
private const val SELF_MESSAGE_HALF_DP = 14f
private const val RTP_STROKE_DP = 6f
private const val RTP_LANE_OFFSET_DP = 5f
private const val LABEL_GAP_DP = 1f

// ---------------------------------------------------------------- 预览夹具

@Preview(name = "Call detail · light", showBackground = true, widthDp = 360, heightDp = 640)
@Composable
private fun VoipCallDetailLightPreview() {
    LayerAnalyzerTheme(darkTheme = false) {
        VoipCallDetailScreen(
            call = previewCall(),
            timeline = previewTimeline(),
            onBack = {}
        )
    }
}

@Preview(name = "Call detail · dark", showBackground = true, widthDp = 360, heightDp = 640)
@Composable
private fun VoipCallDetailDarkPreview() {
    LayerAnalyzerTheme(darkTheme = true) {
        VoipCallDetailScreen(
            call = previewCall(),
            timeline = previewTimeline(),
            playback = RtpDecodeResult(
                error = "",
                cancelled = false,
                items = emptyList(),
                unsupported = emptyList()
            ),
            onBack = {}
        )
    }
}

private fun previewCall(): VoipCall = VoipCall(
    callId = "3f2a91c0-8b4d-4e11-9f7a-1d2c3b4a5e60@10.0.0.1",
    from = "", to = "",
    state = VoipCallState.COMPLETED,
    startRel = 1.4, setupMs = 180L, ringMs = 62L, durationMs = 31_400L,
    sipFrames = listOf(10L, 12L, 14L, 20L),
    sdpFrames = listOf(10L, 14L),
    streams = listOf(
        LinkedRtpStream(previewStream("s0"), RtpStreamDirection.FORWARD, RtpLinkReason.SETUP_FRAME, "c"),
        LinkedRtpStream(previewStream("s1"), RtpStreamDirection.REVERSE, RtpLinkReason.SDP_ADDRESS_PORT, "c")
    ),
    mos = null
)

private fun previewTimeline(): SipDialogTimeline = SipDialogTimeline(
    callId = "3f2a91c0-8b4d-4e11-9f7a-1d2c3b4a5e60@10.0.0.1",
    events = listOf(
        SipDialogEvent(
            transaction = SipTransaction(
                request = previewMessage(10L, 1_700_000_000.0, "10.0.0.1", "10.0.0.2", method = "INVITE"),
                firstTime = 1_700_000_000.0,
                lastTime = 1_700_000_002.0
            )
        ),
        SipDialogEvent(
            transaction = SipTransaction(
                request = previewMessage(12L, 1_700_000_000.4, "10.0.0.2", "10.0.0.1", status = "180 Ringing"),
                firstTime = 1_700_000_000.4,
                lastTime = 1_700_000_000.4
            )
        ),
        SipDialogEvent(
            transaction = SipTransaction(
                request = previewMessage(14L, 1_700_000_002.0, "10.0.0.2", "10.0.0.1", status = "200 OK"),
                firstTime = 1_700_000_002.0,
                lastTime = 1_700_000_002.0
            )
        ),
        SipDialogEvent(
            transaction = SipTransaction(
                request = previewMessage(20L, 1_700_000_002.4, "10.0.0.1", "10.0.0.2", method = "ACK"),
                firstTime = 1_700_000_002.4,
                lastTime = 1_700_000_002.4
            )
        )
    )
)

private fun previewMessage(
    frame: Long,
    time: Double,
    source: String,
    destination: String,
    method: String = "",
    status: String = ""
) = SipMessage(
    frameNumber = frame, time = time, source = source, destination = destination,
    sourcePort = 5060, destinationPort = 5060, method = method, status = status,
    callId = "3f2a91c0-8b4d-4e11-9f7a-1d2c3b4a5e60@10.0.0.1"
)

private fun previewStream(id: String): RtpStream = RtpStream(
    id = id, src = "10.0.0.1", srcPort = 40000, dst = "10.0.0.2", dstPort = 30000,
    ssrc = 439041101L, ssrcHex = "0x1a2b3c4d",
    pt = 8, codec = "g711A", codecSource = RtpCodecSource.STATIC, clockRate = 8000,
    setupFrame = 12L, setupMethod = "SDP", isSrtp = false,
    packets = 1500L, expected = 1530L, lost = 30L, lostPct = 2.0,
    seqErrors = 1L, outOfOrder = 0L, truncated = 0L, problem = false,
    minDeltaMs = 19.4, meanDeltaMs = 20.1, maxDeltaMs = 61.2, maxDeltaFrame = 812L,
    minJitterMs = 0.4, meanJitterMs = 1.3, maxJitterMs = 4.1, jitterAvailable = true,
    maxSkewMs = 2.0, bytes = 192000L,
    firstFrame = 20L, lastFrame = 3100L, startRel = 1.02, endRel = 31.4,
    firstAbsEpochUs = 1_700_000_000_000_000L,
    ptsSeen = listOf(8, 101), decodable = RtpDecodability.YES, decodableReason = "",
    primaryPayloadType = 8
)
