// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import android.content.res.Configuration
import androidx.activity.compose.BackHandler
import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
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
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.VoipCallsUiState

/**
 * 「VoIP 呼叫」列表页（RTP3-UI-01）。
 *
 * 整页结构照抄 [RtpStreamsScreen] 这一居家样式：`Scaffold` + `TopAppBar`（标题 / 返回 / 刷新）
 * + [BackHandler]，颜色一律取 `MaterialTheme.colorScheme` 的语义色（深色模式可读），
 * 每个用户可见字符串都走 `stringResource`。
 *
 * ### 状态与动作全部由宿主注入
 *
 * 本组件是「哑」的：状态取自 [VoipCallsUiState]，动作全部回调给宿主，自己**不**持有
 * `VoipCallsViewModel`（与 [RtpStreamsScreen] 同一分工）。加载由宿主在进入本页时触发，
 * 这里只负责在 `Idle` 时给一句中性提示、在 `Loading` 时转圈、在 `Error` 时显示错误色文本。
 *
 * ### `from` / `to` 目前恒为空串
 *
 * 名字本应来自 RTP3-NAT-04 的 `readRtpSetupInfo`，而**该入口在本仓库尚未实现**，
 * `VoipCallsViewModel` 因此没有注入 `fromToProvider`，[VoipCall.from] 与 [VoipCall.to] 都是空串。
 * 空值一律显示本地化的「未知主叫」/「未知被叫」，**绝不**拿 SDP 端点地址或 SSRC 顶替姓名
 * （那是编造），并在同一张卡片上补一行 SIP `Call-ID`——它是抓包里真实存在的标识，
 * 比空白更有用，也不会被误读成主叫。
 *
 * ### 文案、颜色与格式只有一个来源
 *
 * 状态标签的文案与颜色、方向文案、相对秒与毫秒格式都在 [VoipCallPresentation] 里，
 * 本页与呼叫详情页（RTP3-UI-02）共用，因此同一通呼叫不会在两个页面上出现不同说法。
 *
 * ### 筛选桶与标签颜色只有一个来源
 *
 * 顶栏筛选只有「全部 / 已接通 / 失败」三个桶，卡片状态标签的颜色却有四种（接通绿、失败红、
 * 振铃黄、其它灰）。两者都由 [VoipCallState.bucket] 派生，因此不可能出现「筛进已接通、
 * 标签却显示失败色」这种自相矛盾。
 *
 * ### MOS 按方向单独估算
 *
 * [VoipCall.mos] 只覆盖呼叫的主方向，而卡片要求逐方向的丢包与 MOS，所以这里对每条关联流
 * 调用一次 [MosEstimator.estimate]（输入是流自己的编码与 `lostPct`，时延取
 * [MosEstimator.defaultOneWayDelayMs]，即无 RTCP 时的缺省值）。`null` 表示该编码没有
 * E-model 表项（宽带编码、事件流等），显示「不适用」而不是硬套窄带公式。
 * 有效数值旁边标「估算」——MOS 是期望值不是实测值（`MosEstimate.isEstimate` 恒为真）。
 *
 * ### 尚未使用 [VoipCallsUiState.Ready.warnings]
 *
 * 关联器的 `warnings`（一条流命中多个呼叫等）是诊断信息，卡片没要求展示；呼叫详情页
 * （RTP3-UI-02）也没要它，本页不擅自塞进列表。
 *
 * @param onLoad 重新加载（顶栏刷新按钮）；宿主负责在首次进入时也调用一次
 * @param onOpenCall 点开一张呼叫卡片，参数是 SIP `Call-ID`；宿主用它打开 RTP3-UI-02 的详情页
 * @param onOpenRtpStreams 跳到 RTP 流列表页（底部「未关联 RTP 流」分组与空状态的按钮）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VoipCallsScreen(
    state: VoipCallsUiState,
    onLoad: () -> Unit,
    onBack: () -> Unit,
    onOpenCall: (String) -> Unit = {},
    onOpenRtpStreams: () -> Unit = {}
) {
    BackHandler(onBack = onBack)
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        stringResource(R.string.voip_calls_title),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                },
                actions = {
                    IconButton(onClick = onLoad) {
                        Icon(Icons.Default.Refresh, stringResource(R.string.refresh))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(horizontal = 12.dp)
        ) {
            when (state) {
                VoipCallsUiState.Idle -> Text(
                    stringResource(R.string.voip_idle),
                    modifier = Modifier.padding(top = 16.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                VoipCallsUiState.Loading -> Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }

                is VoipCallsUiState.Error -> Text(
                    state.message,
                    modifier = Modifier.padding(top = 16.dp),
                    color = MaterialTheme.colorScheme.error
                )

                is VoipCallsUiState.Ready -> ReadyContent(
                    state = state,
                    onOpenCall = onOpenCall,
                    onOpenRtpStreams = onOpenRtpStreams
                )
            }
        }
    }
}

@Composable
private fun ColumnScope.ReadyContent(
    state: VoipCallsUiState.Ready,
    onOpenCall: (String) -> Unit,
    onOpenRtpStreams: () -> Unit
) {
    var filter by remember { mutableStateOf(VoipCallFilter.ALL) }

    // 需求 2：信令截断必须显式告知，绝不静默丢呼叫（与流列表的截断提示同一口径）。
    if (state.sipTruncated) {
        TruncationBanner()
    }

    // 需求 5：一条 SIP 呼叫都没识别出来、但确实有 RTP 流时，唯一有意义的下一步就是流列表。
    if (state.calls.isEmpty() && state.unlinked.isNotEmpty()) {
        Text(
            stringResource(R.string.voip_empty_with_streams, state.unlinked.size),
            modifier = Modifier.padding(top = 16.dp)
        )
        Button(
            onClick = onOpenRtpStreams,
            modifier = Modifier.padding(top = 12.dp)
        ) {
            Text(stringResource(R.string.voip_empty_with_streams_action))
        }
        return
    }

    FilterRow(selected = filter, onSelect = { filter = it })

    if (state.calls.isEmpty()) {
        Text(
            stringResource(R.string.voip_no_calls),
            modifier = Modifier.padding(top = 16.dp),
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        return
    }

    val visible = state.calls.filter { filter.matches(it) }
    LazyColumn(
        modifier = Modifier
            .fillMaxWidth()
            .weight(1f)
            .padding(top = 8.dp)
    ) {
        if (visible.isEmpty()) {
            // 呼叫存在但都被筛掉了：说清楚是筛选的结果，不是没有呼叫。
            item {
                Text(
                    stringResource(R.string.voip_no_matching_calls),
                    modifier = Modifier.padding(vertical = 8.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        items(visible, key = { it.callId }) { call ->
            VoipCallCard(call = call, onClick = { onOpenCall(call.callId) })
            HorizontalDivider()
        }
        if (state.unlinked.isNotEmpty()) {
            item {
                UnlinkedStreamsRow(count = state.unlinked.size, onClick = onOpenRtpStreams)
            }
        }
    }
}

/** 需求 1 的筛选：三个 [FilterChip]，谓词与标签颜色共用 [VoipCallState.bucket]。 */
@Composable
private fun FilterRow(selected: VoipCallFilter, onSelect: (VoipCallFilter) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(top = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        VoipCallFilter.entries.forEach { option ->
            FilterChip(
                selected = selected == option,
                onClick = { onSelect(option) },
                label = { Text(stringResource(option.labelRes), maxLines = 1) }
            )
        }
    }
}

/** 需求 2 的警告条：`tertiaryContainer` 是「需要注意但不是错误」的语义色。 */
@Composable
private fun TruncationBanner() {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Default.Warning, contentDescription = null)
            Text(
                stringResource(R.string.voip_sip_truncated_notice),
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

/** 需求 3 的一张呼叫卡片。整卡可点，把 `callId` 交给宿主（UI-02 的缝）。 */
@Composable
private fun VoipCallCard(call: VoipCall, onClick: () -> Unit) {
    val notApplicable = notApplicableText()
    val nameMissing = call.from.isBlank() || call.to.isBlank()

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick)
                .padding(horizontal = 12.dp, vertical = 8.dp)
        ) {
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
                VoipStatusBadge(call.state)
            }

            // 姓名缺失时补一行 Call-ID：真实标识，且不冒充主叫（见文件头 KDoc）。
            if (nameMissing && call.callId.isNotBlank()) {
                Text(
                    call.callId,
                    modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    stringResource(R.string.voip_call_start, formatVoipDecimal(call.startRel)),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    stringResource(
                        R.string.voip_call_duration,
                        call.durationMs?.let(::formatRtpPlayerTime) ?: notApplicable
                    ),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            call.streams.forEach { linked ->
                DirectionRow(linked = linked, notApplicable = notApplicable)
            }

            Text(
                stringResource(R.string.voip_call_stream_count, call.streams.size),
                modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

/**
 * 需求 3 的「每个方向的丢包与 MOS」一行。
 *
 * 丢包与 MOS 都取自**这条流自己**：MOS 是对 `stream.codec` + `stream.lostPct` 单独估算的，
 * 不是 [VoipCall.mos]（那只覆盖主方向）。丢包率不着色——阈值策略属于流列表，
 * 这里只把数字按方向摆出来，避免两处策略日后漂移。
 */
@Composable
private fun DirectionRow(linked: LinkedRtpStream, notApplicable: String) {
    val stream = linked.stream
    val mos = MosEstimator.estimate(
        codec = stream.codec,
        lossPercent = stream.lostPct,
        oneWayDelayMs = MosEstimator.defaultOneWayDelayMs()
    )
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            directionLabel(linked.direction),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            stringResource(R.string.voip_direction_loss, formatVoipDecimal(stream.lostPct)),
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
        // 有数值才标「估算」：MOS 是 E-model 期望值，不是实测值（MosEstimate.isEstimate）。
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

/** 需求 4 的底部「未关联 RTP 流 (N)」分组：点击整体进入 RTP 流列表页。 */
@Composable
private fun UnlinkedStreamsRow(count: Int, onClick: () -> Unit) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        tonalElevation = 2.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                stringResource(R.string.voip_unlinked_group, count),
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.labelLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Icon(
                Icons.AutoMirrored.Filled.ArrowForward,
                contentDescription = stringResource(R.string.voip_unlinked_open)
            )
        }
    }
}

// ---------------------------------------------------------------- 筛选桶

/**
 * 顶栏筛选的三个桶。
 *
 * 桶的归属只写一次（[VoipCallState.bucket]，已搬到 [VoipCallPresentation]），
 * [matches] 与状态标签颜色都从它派生，因此不可能出现「筛进已接通、标签却显示失败色」这种矛盾。
 */
private enum class VoipCallFilter(@StringRes val labelRes: Int) {
    ALL(R.string.voip_filter_all),
    ANSWERED(R.string.voip_filter_answered),
    FAILED(R.string.voip_filter_failed);

    fun matches(call: VoipCall): Boolean = when (this) {
        ALL -> true
        ANSWERED -> call.state.bucket() == VoipCallBucket.ANSWERED
        FAILED -> call.state.bucket() == VoipCallBucket.FAILED
    }
}

// ---------------------------------------------------------------- 预览夹具

@Preview(name = "VoIP calls · light", showBackground = true, widthDp = 360)
@Composable
private fun VoipCallsScreenLightPreview() {
    LayerAnalyzerTheme(darkTheme = false) {
        VoipCallsScreen(state = previewReadyState(), onLoad = {}, onBack = {})
    }
}

@Preview(name = "VoIP calls · empty", showBackground = true, widthDp = 360)
@Composable
private fun VoipCallsScreenEmptyPreview() {
    LayerAnalyzerTheme(darkTheme = false) {
        VoipCallsScreen(
            state = VoipCallsUiState.Ready(
                calls = emptyList(),
                unlinked = listOf(previewStream("s0")),
                sipTruncated = false,
                warnings = emptyList()
            ),
            onLoad = {},
            onBack = {}
        )
    }
}

@Preview(
    name = "VoIP calls · dark",
    showBackground = true,
    widthDp = 360,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
private fun VoipCallsScreenDarkPreview() {
    LayerAnalyzerTheme(darkTheme = true) {
        VoipCallsScreen(state = previewReadyState(), onLoad = {}, onBack = {})
    }
}

private fun previewReadyState(): VoipCallsUiState.Ready = VoipCallsUiState.Ready(
    calls = listOf(
        // from/to 为空：正好演示 NAT-04 缺位时的退路（未知主叫 → 未知被叫 + Call-ID）。
        VoipCall(
            callId = "3f2a91c0-8b4d-4e11-9f7a-1d2c3b4a5e60@10.0.0.1",
            from = "", to = "",
            state = VoipCallState.COMPLETED,
            startRel = 1.4, setupMs = 180L, ringMs = 62L, durationMs = 31_400L,
            sipFrames = listOf(12L, 14L, 20L, 812L), sdpFrames = listOf(12L, 14L),
            streams = listOf(
                LinkedRtpStream(previewStream("s0"), RtpStreamDirection.FORWARD, RtpLinkReason.SETUP_FRAME, "c1"),
                LinkedRtpStream(previewStream("s1"), RtpStreamDirection.REVERSE, RtpLinkReason.SDP_ADDRESS_PORT, "c2")
            ),
            mos = null
        ),
        VoipCall(
            callId = "call-2@example.org",
            from = "sip:alice@example.org", to = "sip:bob@example.net",
            state = VoipCallState.REJECTED,
            startRel = 12.0, setupMs = null, ringMs = 340L, durationMs = null,
            sipFrames = listOf(900L), sdpFrames = emptyList(),
            streams = emptyList(),
            mos = null
        )
    ),
    unlinked = listOf(previewStream("s9")),
    sipTruncated = true,
    warnings = emptyList()
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
