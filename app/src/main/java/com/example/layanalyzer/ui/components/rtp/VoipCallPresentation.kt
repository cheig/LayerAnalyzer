package com.example.layanalyzer.ui.components.rtp

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.data.RtpStreamDirection
import com.example.layanalyzer.data.VoipCallState
import java.util.Locale

/**
 * 呼叫页共用的文案、颜色与数字格式（RTP3-UI-02）。
 *
 * 「VoIP 呼叫」列表（[VoipCallsScreen]）与呼叫详情（[VoipCallDetailScreen]）必须用**同一套**
 * 状态文案、状态颜色、方向文案和数字格式，否则同一通呼叫在两个页面上会出现不同说法。
 * 这些 helper 因此从 `VoipCallsScreen.kt` 里搬到这里，两边都从这里取——单一来源。
 * 搬动没有改变列表页的任何可见行为。
 *
 * 颜色一律取自 `MaterialTheme.colorScheme` 的语义色（深色模式可读），
 * 每个用户可见字符串都走 `stringResource`。
 */

/** 顶栏筛选用的三个桶（[VoipCallsScreen] 的筛选芯片与状态标签颜色共用它）。 */
internal enum class VoipCallBucket { ANSWERED, FAILED, OTHER }

/**
 * 状态 → 桶。`COMPLETED` 算「已接通」（通话正常结束），`REJECTED` + `CANCELLED` 算「失败」，
 * 其余（`SETUP` / `RINGING` / `UNKNOWN`）只在「全部」下出现。
 */
internal fun VoipCallState.bucket(): VoipCallBucket = when (this) {
    VoipCallState.IN_CALL, VoipCallState.COMPLETED -> VoipCallBucket.ANSWERED
    VoipCallState.REJECTED, VoipCallState.CANCELLED -> VoipCallBucket.FAILED
    VoipCallState.SETUP, VoipCallState.RINGING, VoipCallState.UNKNOWN -> VoipCallBucket.OTHER
}

@StringRes
internal fun statusLabelRes(state: VoipCallState): Int = when (state) {
    VoipCallState.SETUP -> R.string.voip_status_setup
    VoipCallState.RINGING -> R.string.voip_status_ringing
    VoipCallState.IN_CALL -> R.string.voip_status_in_call
    VoipCallState.COMPLETED -> R.string.voip_status_completed
    VoipCallState.REJECTED -> R.string.voip_status_rejected
    VoipCallState.CANCELLED -> R.string.voip_status_cancelled
    VoipCallState.UNKNOWN -> R.string.voip_status_unknown
}

@Composable
internal fun statusLabel(state: VoipCallState): String = stringResource(statusLabelRes(state))

/**
 * 状态徽标（列表卡片与详情页概况区共用）。
 *
 * 与流列表的 `DecodableBadge` 同一手法：同色 15% 底 + 同色文字，深色模式下也够对比。
 */
@Composable
internal fun VoipStatusBadge(state: VoipCallState) {
    val color = statusColor(state)
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = color.copy(alpha = 0.15f),
        contentColor = color
    ) {
        Text(
            statusLabel(state),
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

/**
 * 状态标签颜色：接通绿、失败红、振铃黄、其它灰。
 *
 * 前提是 [bucket] 已经定好「接通 / 失败」，这里只补一条「振铃」的额外区分，
 * 于是筛选芯片选中的桶与状态颜色永远一致。
 */
@Composable
internal fun statusColor(state: VoipCallState): Color = when (state.bucket()) {
    VoipCallBucket.ANSWERED -> MaterialTheme.colorScheme.primary
    VoipCallBucket.FAILED -> MaterialTheme.colorScheme.error
    VoipCallBucket.OTHER -> when (state) {
        VoipCallState.RINGING -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
}

@Composable
internal fun directionLabel(direction: RtpStreamDirection): String = when (direction) {
    RtpStreamDirection.FORWARD -> stringResource(R.string.voip_direction_forward)
    RtpStreamDirection.REVERSE -> stringResource(R.string.voip_direction_reverse)
    RtpStreamDirection.UNKNOWN -> stringResource(R.string.voip_direction_unknown)
}

/** 数值缺失时的统一占位符（「不适用」）。 */
@Composable
internal fun notApplicableText(): String = stringResource(R.string.voip_not_applicable)

/**
 * 「主叫 → 被叫」标题。
 *
 * `from` / `to` 目前恒为空串（RTP3-NAT-04 的 `readRtpSetupInfo` 在本仓库尚未实现，
 * 见 `VoipCallsViewModel.fromToProvider` 的注释），空值一律显示本地化的「未知主叫」/「未知被叫」，
 * **绝不**拿 SDP 端点地址或 SSRC 顶替姓名——那是编造。
 */
@Composable
internal fun voipCallTitle(from: String, to: String): String = stringResource(
    R.string.voip_call_from_to,
    from.ifBlank { stringResource(R.string.voip_from_unknown) },
    to.ifBlank { stringResource(R.string.voip_to_unknown) }
)

/**
 * 相对秒。
 *
 * `startRel` 是相对抓包起点的秒数，理论上非负；真出现负值时夹到 0（时间轴比抓包起点还早的
 * 呼叫只可能是时间基准本身的误差，显示负数只会让人困惑）。格式沿用 RtpStreamsScreen 的
 * `formatVoipDecimal` 口径（`Locale.US`，小数点固定为 `.`）。
 */
internal fun formatVoipDecimal(value: Double): String =
    String.format(Locale.US, "%.1f", value.coerceAtLeast(0.0))

/** 毫秒数（`setupMs` / `ringMs` 之类），单位由 `voip_millis` 这个字符串资源给出。 */
@Composable
internal fun millisText(value: Long?): String =
    value?.let { stringResource(R.string.voip_millis, it) } ?: notApplicableText()
