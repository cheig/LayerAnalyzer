package com.example.layanalyzer.ui.components

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Stop
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.example.layanalyzer.R
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.SipCallSummary
import com.example.layanalyzer.model.RtpStreamSummary
import com.example.layanalyzer.model.RtcpStreamSummary
import com.example.layanalyzer.model.CoreSessionSummary
import java.util.Locale

/**
 * Horizontal inset shared by the whole screen.
 *
 * The rows used to be laid out edge to edge: on a 400dp phone the call ids
 * started ~1dp from the left edge and the failure code ended ~2dp from the
 * right edge, which reads as "content running off both sides". Every block of
 * this screen now sits inside this inset so text has a stable gutter.
 */
private val CommunicationContentPadding = 12.dp

/**
 * Full-screen SIP / SDP / RTP / RTCP workbench.
 *
 * Layout notes:
 * - the app-bar title is forced to a single line at `titleMedium`; at
 *   `titleLarge` the zh-CN title "SIP / SDP / RTP / RTCP 专项分析" wraps to two
 *   lines and eats a third of the header;
 * - the tab chips live in a [FlowRow] instead of a horizontally scrolling
 *   [Row]: the four zh-CN labels are wider than a phone, so the last chip
 *   ("核心网会话 N") used to be half visible with no affordance that it could be
 *   scrolled;
 * - the list rows inside [SipCallRow] / [RtpStreamRow] / [RtcpStreamRow] keep
 *   every long value on one ellipsised line and wrap their action buttons.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CommunicationScreen(
    state: CommunicationAnalysis,
    onRefresh: () -> Unit,
    onCancel: () -> Unit,
    onPacketClick: (Long) -> Unit,
    onApplyFilter: (String) -> Unit,
    onOpenRtpStreams: (() -> Unit)? = null,
    /**
     * Opens the full VoIP call list (RTP3-UI-01). Shown as a button above the SIP
     * call list in tab 0 — that is where a user looking at raw SIP calls expects
     * the "give me the calls, not the messages" next step. Null hides the entry,
     * so callers that do not wire it keep compiling unchanged.
     */
    onOpenVoipCalls: (() -> Unit)? = null,
    onBack: () -> Unit
) {
    BackHandler(onBack = onBack)
    var selectedTab by remember { mutableIntStateOf(0) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        stringResource(R.string.communication_analysis_title_compact),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        style = MaterialTheme.typography.titleMedium
                    )
                },
                navigationIcon = { IconButton(onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) } },
                actions = {
                    IconButton(if (state.isLoading) onCancel else onRefresh) {
                        Icon(if (state.isLoading) Icons.Default.Stop else Icons.Default.Refresh, stringResource(if (state.isLoading) R.string.cancel_analysis else R.string.refresh))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(horizontal = CommunicationContentPadding)
        ) {
            Text(stringResource(R.string.current_filter_scope), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            state.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            Spacer(Modifier.height(4.dp))
            CommunicationTabChips(state, selectedTab) { selectedTab = it }
            Spacer(Modifier.height(8.dp))
            if (state.isLoading) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else when (selectedTab) {
                0 -> SipCallList(state, onPacketClick, onApplyFilter, Modifier.weight(1f), onOpenVoipCalls)
                1 -> RtpStreamList(state, onPacketClick, onApplyFilter, Modifier.weight(1f), onOpenRtpStreams)
                2 -> RtcpStreamList(state, onPacketClick, onApplyFilter, Modifier.weight(1f))
                else -> CoreSessionList(state, onPacketClick, onApplyFilter, Modifier.weight(1f))
            }
        }
    }
}

@Composable
fun CommunicationDialog(
    state: CommunicationAnalysis,
    onRefresh: () -> Unit,
    onCancel: () -> Unit,
    onPacketClick: (Long) -> Unit,
    onApplyFilter: (String) -> Unit,
    onOpenRtpStreams: (() -> Unit)? = null,
    /** Opens the VoIP call list (RTP3-UI-01); see [CommunicationScreen]. */
    onOpenVoipCalls: (() -> Unit)? = null,
    onDismiss: () -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.communication_analysis_title)) },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) } },
        dismissButton = {
            TextButton(onClick = if (state.isLoading) onCancel else onRefresh) {
                Text(stringResource(if (state.isLoading) R.string.cancel_analysis else R.string.refresh))
            }
        },
        text = {
            Column(Modifier.widthIn(max = 760.dp)) {
                if (state.error != null) {
                    Text(state.error, color = MaterialTheme.colorScheme.error)
                }
                CommunicationTabChips(state, selectedTab) { selectedTab = it }
                Spacer(Modifier.height(8.dp))
                if (state.isLoading) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
                } else if (selectedTab == 0) {
                    SipCallList(state, onPacketClick, onApplyFilter, Modifier.heightIn(max = 440.dp), onOpenVoipCalls)
                } else if (selectedTab == 1) {
                    RtpStreamList(state, onPacketClick, onApplyFilter, Modifier.heightIn(max = 440.dp), onOpenRtpStreams)
                } else if (selectedTab == 2) {
                    RtcpStreamList(state, onPacketClick, onApplyFilter, Modifier.heightIn(max = 440.dp))
                } else {
                    CoreSessionList(state, onPacketClick, onApplyFilter, Modifier.heightIn(max = 440.dp))
                }
            }
        }
    )
}

/**
 * The four category chips.
 *
 * [FlowRow] rather than a scrolling [Row]: the zh-CN labels ("SIP 呼叫 23" /
 * "RTP 流 5" / "RTCP 流 0" / "核心网会话 0") together exceed a phone's width, so
 * in a scrolling row the selected chip could end up outside the viewport and
 * the user had no way to tell more entries existed. Wrapping keeps all four
 * reachable at any font scale.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CommunicationTabChips(
    state: CommunicationAnalysis,
    selectedTab: Int,
    onSelectTab: (Int) -> Unit
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        FilterChip(selectedTab == 0, { onSelectTab(0) }, label = { Text(stringResource(R.string.sip_calls_count, state.calls.size), maxLines = 1) })
        FilterChip(selectedTab == 1, { onSelectTab(1) }, label = { Text(stringResource(R.string.rtp_streams_count, state.streams.size), maxLines = 1) })
        FilterChip(selectedTab == 2, { onSelectTab(2) }, label = { Text(stringResource(R.string.rtcp_streams_count, state.rtcpStreams.size.toString()), maxLines = 1) })
        FilterChip(selectedTab == 3, { onSelectTab(3) }, label = { Text(stringResource(R.string.core_sessions_count, state.coreSessions.size), maxLines = 1) })
    }
}

/**
 * A single-line, non-shrinkable row of trailing actions.
 *
 * The previous plain [Row] gave each button its own intrinsic width, so a long
 * localised label ("应用会话过滤器", "应用 RTCP 过滤器") plus the "首帧 N" trailing
 * button could push past the right edge on narrow screens. [FlowRow] reflows the
 * second button onto its own line instead of clipping it.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun RowActions(content: @Composable () -> Unit) {
    FlowRow(
        modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        content()
    }
}

/**
 * Failure code as a filled badge rather than a bare trailing `Text`.
 *
 * Colour alone made it look like text that had been cut off at the screen edge;
 * as a badge it reads as a discrete status element and keeps a margin from the
 * edge because its own horizontal padding is inside the surface.
 */
@Composable
private fun FailureCodeBadge(code: Int) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        shape = MaterialTheme.shapes.small
    ) {
        Text(
            stringResource(R.string.call_failed_code, code),
            Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelMedium,
            maxLines = 1
        )
    }
}

@Composable
private fun CoreSessionList(
    state: CommunicationAnalysis,
    onPacketClick: (Long) -> Unit,
    onApplyFilter: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    if (state.coreSessions.isEmpty()) {
        Text(stringResource(R.string.no_core_messages), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        return
    }
    LazyColumn(modifier) {
        if (state.coreTruncated) item { Text(stringResource(R.string.core_results_truncated, state.coreTotal, state.coreMessages.size), color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.bodySmall) }
        items(state.coreSessions, key = { it.key }) { session ->
            CoreSessionRow(session, onPacketClick, onApplyFilter)
            HorizontalDivider()
        }
    }
}

@Composable
private fun CoreSessionRow(session: CoreSessionSummary, onPacketClick: (Long) -> Unit, onApplyFilter: (String) -> Unit) {
    val filter = if (session.correlationField.isBlank() || session.correlationValue.isBlank()) session.protocol.lowercase() else
        "${session.correlationField} == ${formatFilterValue(session.correlationValue)}"
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Text(session.protocol, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        Text(
            if (session.correlationValue.isBlank()) stringResource(R.string.unkeyed_session) else "${session.correlationField} = ${session.correlationValue}",
            Modifier.fillMaxWidth(),
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            style = MaterialTheme.typography.bodySmall
        )
        Text(stringResource(R.string.core_message_count, session.messages.size), style = MaterialTheme.typography.bodySmall)
        session.messages.map { it.outcome }.filter { it.isNotBlank() }.distinct().forEach { code ->
            Text(stringResource(R.string.outcome_code, code), Modifier.fillMaxWidth(), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        RowActions {
            session.firstFrame?.let { frame -> TextButton(onClick = { onPacketClick(frame) }) { Text(stringResource(R.string.first_frame, frame), maxLines = 1) } }
            Button(onClick = { onApplyFilter(filter) }) { Text(stringResource(R.string.apply_session_filter), maxLines = 1) }
        }
    }
}

@Composable
private fun SipCallList(
    state: CommunicationAnalysis,
    onPacketClick: (Long) -> Unit,
    onApplyFilter: (String) -> Unit,
    modifier: Modifier = Modifier,
    onOpenVoipCalls: (() -> Unit)? = null
) {
    // The entry sits above the empty check on purpose: a capture with no SIP
    // traffic at all is exactly when a user wants to know whether the VoIP view
    // has anything (RTP-only capture), so the button must not disappear with the
    // list. Same reasoning as the RTP tab's "open RTP stream analysis" button.
    onOpenVoipCalls?.let { open ->
        TextButton(onClick = open) {
            Text(stringResource(R.string.voip_calls_title))
        }
    }
    if (state.calls.isEmpty()) {
        Text(stringResource(R.string.no_sip_messages), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        return
    }
    LazyColumn(modifier) {
        if (state.sipTruncated) item { Text(stringResource(R.string.sip_results_truncated, state.sipTotal, state.sipMessages.size), color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.bodySmall) }
        items(state.calls, key = { it.callId }) { call ->
            SipCallRow(call, onPacketClick, onApplyFilter)
            HorizontalDivider()
        }
    }
}

@Composable
private fun SipCallRow(call: SipCallSummary, onPacketClick: (Long) -> Unit, onApplyFilter: (String) -> Unit) {
    val filter = if (call.callId.startsWith("unknown:")) "sip" else "sip.Call-ID == \"${call.callId.replace("\"", "\\\"")}\""
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            // weight(1f) lets the call id ellipsise before the failure badge is
            // squeezed; the badge is measured first, so it is never clipped.
            Text(
                call.callId,
                Modifier.weight(1f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Medium,
                style = MaterialTheme.typography.bodyMedium
            )
            call.failureCode?.let { code ->
                Spacer(Modifier.width(8.dp))
                FailureCodeBadge(code)
            }
        }
        Text(stringResource(R.string.call_message_duration, call.messages.size, formatSeconds(call.duration)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            call.messages.firstOrNull()?.let { "${it.source} → ${it.destination}" }.orEmpty(),
            Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        call.sdpMedia.forEach { sdp ->
            val unknown = stringResource(R.string.unknown)
            Text(
                stringResource(
                    R.string.sdp_media_summary,
                    sdp.mediaType.ifBlank { unknown },
                    sdp.connectionAddress.ifBlank { unknown },
                    sdp.mediaPort?.toString() ?: unknown,
                    sdp.mediaProtocol.ifBlank { unknown }
                ),
                Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (sdp.formats.isNotEmpty()) Text(stringResource(R.string.sdp_formats_summary, sdp.formats.joinToString()), Modifier.fillMaxWidth(), style = MaterialTheme.typography.labelSmall)
            if (sdp.codecs.isNotEmpty()) Text(stringResource(R.string.sdp_codecs_summary, sdp.codecs.joinToString()), Modifier.fillMaxWidth(), style = MaterialTheme.typography.labelSmall)
        }
        RowActions {
            call.firstFrame?.let { frame -> TextButton(onClick = { onPacketClick(frame) }) { Text(stringResource(R.string.first_frame, frame), maxLines = 1) } }
            Button(onClick = { onApplyFilter(filter) }) { Text(stringResource(R.string.apply_filter), maxLines = 1) }
        }
    }
}

@Composable
private fun RtcpStreamList(
    state: CommunicationAnalysis,
    onPacketClick: (Long) -> Unit,
    onApplyFilter: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    if (state.rtcpStreams.isEmpty()) {
        Text(stringResource(R.string.no_rtcp_messages), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        return
    }
    LazyColumn(modifier) {
        if (state.rtcpTruncated) item { Text(stringResource(R.string.rtcp_results_truncated, state.rtcpTotal.toString(), state.rtcpPackets.size.toString()), color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.bodySmall) }
        items(state.rtcpStreams, key = { it.key }) { stream ->
            RtcpStreamRow(stream, onPacketClick, onApplyFilter)
            HorizontalDivider()
        }
    }
}

@Composable
private fun RtcpStreamRow(stream: RtcpStreamSummary, onPacketClick: (Long) -> Unit, onApplyFilter: (String) -> Unit) {
    val filter = when {
        stream.reportedSsrc != null -> "rtcp && rtcp.ssrc.identifier == ${stream.reportedSsrc}"
        stream.senderSsrc != null -> "rtcp && rtcp.senderssrc == ${stream.senderSsrc}"
        else -> "rtcp"
    }
    val latest = stream.reports.lastOrNull()
    val unknown = stringResource(R.string.unknown)
    Column(Modifier.fillMaxWidth().clickable { stream.firstFrame?.let(onPacketClick) }.padding(vertical = 8.dp)) {
        Text(stringResource(R.string.rtcp_stream_heading, stream.reportedSsrc?.toString() ?: unknown, stream.senderSsrc?.toString() ?: unknown), Modifier.fillMaxWidth(), style = MaterialTheme.typography.labelLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text("${stream.source}:${stream.sourcePort ?: "?"} → ${stream.destination}:${stream.destinationPort ?: "?"}", Modifier.fillMaxWidth(), fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall)
        Text(
            stringResource(
                R.string.rtcp_report_summary,
                stream.reportCount.toString(),
                latest?.packetType?.toString() ?: unknown,
                latest?.fractionLostPercent?.let { String.format(Locale.US, "%.1f%%", it) } ?: unknown,
                latest?.cumulativeLost?.toString() ?: unknown,
                latest?.interarrivalJitter?.toString() ?: unknown
            ),
            Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.bodySmall,
            color = if ((latest?.cumulativeLost ?: 0) > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
        )
        RowActions {
            Button(onClick = { onApplyFilter(filter) }) { Text(stringResource(R.string.apply_rtcp_filter), maxLines = 1) }
        }
    }
}

@Composable
private fun RtpStreamList(
    state: CommunicationAnalysis,
    onPacketClick: (Long) -> Unit,
    onApplyFilter: (String) -> Unit,
    modifier: Modifier = Modifier,
    onOpenRtpStreams: (() -> Unit)? = null
) {
    onOpenRtpStreams?.let { open ->
        TextButton(onClick = open) {
            Text(stringResource(R.string.rtp_open_analysis))
        }
    }
    if (state.streams.isEmpty()) {
        Text(stringResource(R.string.no_rtp_messages), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        return
    }
    LazyColumn(modifier) {
        if (state.rtpTruncated) item { Text(stringResource(R.string.rtp_results_truncated, state.rtpTotal, state.rtpPackets.size), color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.bodySmall) }
        items(state.streams, key = { it.key }) { stream ->
            RtpStreamRow(stream, onPacketClick, onApplyFilter)
            HorizontalDivider()
        }
    }
}

@Composable
private fun RtpStreamRow(stream: RtpStreamSummary, onPacketClick: (Long) -> Unit, onApplyFilter: (String) -> Unit) {
    val filter = buildString {
        append("rtp")
        stream.ssrc?.let { append(" && rtp.ssrc == $it") }
        if (stream.source.isNotBlank()) append(" && ip.addr == \"${stream.source}\"")
    }
    Column(Modifier.fillMaxWidth().clickable { stream.firstFrame?.let(onPacketClick) }.padding(vertical = 8.dp)) {
        val unknown = stringResource(R.string.unknown)
        Text(stringResource(R.string.rtp_stream_heading, stream.ssrc?.toString() ?: unknown, stream.payloadType?.toString() ?: unknown), Modifier.fillMaxWidth(), style = MaterialTheme.typography.labelLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text("${stream.source}:${stream.sourcePort ?: "?"} → ${stream.destination}:${stream.destinationPort ?: "?"}", Modifier.fillMaxWidth(), fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.rtp_quality_summary, stream.packetCount, stream.lostPackets, stream.reorderedPackets, stream.duplicatePackets, stream.jitterMillis?.let(::formatSeconds) ?: unknown), Modifier.fillMaxWidth(), style = MaterialTheme.typography.bodySmall, color = if (stream.lostPackets > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
        RowActions {
            Button(onClick = { onApplyFilter(filter) }) { Text(stringResource(R.string.apply_stream_filter), maxLines = 1) }
        }
    }
}

private fun formatSeconds(value: Double): String = String.format(Locale.US, "%.3f", value)

private fun formatFilterValue(value: String): String =
    if (value.matches(Regex("(?:0x[0-9a-fA-F]+|\\d+)"))) value else "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""
