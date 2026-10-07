package com.example.layanalyzer.ui.components

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.example.layanalyzer.R
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ConversationStat
import com.example.layanalyzer.model.EndpointStat
import com.example.layanalyzer.model.IoBucket
import com.example.layanalyzer.model.PacketLengthBucket
import com.example.layanalyzer.model.ProtocolStat
import com.example.layanalyzer.model.ProtocolSummaryItem
import com.example.layanalyzer.model.RequestResponseTransaction
import com.example.layanalyzer.model.StatisticsUiState
import com.example.layanalyzer.viewmodel.formatFileSize
import java.util.Locale
import kotlin.math.max

private val StatisticsTabs = listOf("Protocol summary", "Conversations", "Endpoints", "I/O", "Lengths", "Protocols")
private val IoBuckets = listOf(0.1, 1.0, 5.0, 10.0, 60.0)

/**
 * Horizontal inset shared by the tab bodies.
 *
 * The bodies used to be laid out edge to edge (no gutter at all) while the chips
 * above them sat inside 8dp of padding, so every list read as if it were sliding
 * out of the screen on both sides.
 */
private val StatisticsContentPadding = 12.dp

/**
 * Full-screen statistics workbench.
 *
 * Layout notes:
 * - every tab body receives [Modifier.weight]/[Modifier.fillMaxSize] from this
 *   screen and fills the height that is actually left over. The bodies used to
 *   hard-code their own height (390dp for the conversations and endpoints
 *   lists, 460dp for the rest), which on a 890dp-tall phone left the last ~180dp
 *   of the window as bare background and cut the final list row in half: the
 *   list looked like it only occupied the middle of the screen. The fixed
 *   heights also overflowed on a landscape phone, where there is far less room
 *   than 390dp;
 * - the tab chips live in a [FlowRow] rather than a horizontally scrolling
 *   [Row]: the six labels together are wider than a 400dp phone, so the last
 *   chip was half cut off at the right edge with no affordance that the row
 *   could be scrolled.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun StatisticsScreen(
    state: StatisticsUiState,
    onRefresh: () -> Unit,
    onCancel: () -> Unit,
    onBucketChange: (Double) -> Unit,
    onPacketClick: (Long) -> Unit,
    onApplyFilter: (String) -> Unit,
    onExportTable: (String) -> Unit,
    onBack: () -> Unit
) {
    BackHandler(onBack = onBack)
    var selectedTab by remember { mutableIntStateOf(0) }
    var selectedConversation by remember { mutableStateOf<ConversationStat?>(null) }
    var selectedEndpoint by remember { mutableStateOf<EndpointStat?>(null) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.statistics)) },
                navigationIcon = { IconButton(onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) } },
                actions = {
                    if (selectedTab == 1 || selectedTab == 2) {
                        IconButton({ onExportTable(if (selectedTab == 1) "conversations" else "endpoints") }) {
                            Icon(Icons.Default.Download, stringResource(R.string.export_csv))
                        }
                    }
                    IconButton(if (state.isLoading) onCancel else onRefresh) {
                        Icon(if (state.isLoading) Icons.Default.Stop else Icons.Default.Refresh, stringResource(if (state.isLoading) R.string.cancel_analysis else R.string.refresh_statistics))
                    }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(horizontal = StatisticsContentPadding)
        ) {
            Text(stringResource(R.string.current_filter_scope), Modifier.padding(vertical = 4.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            StatisticsTabChips(selectedTab) { selectedTab = it }
            Spacer(Modifier.height(6.dp))
            Box(Modifier.fillMaxWidth().weight(1f)) {
                when {
                    state.isLoading -> LoadingStatistics()
                    state.error != null -> Text(state.error, Modifier.padding(vertical = 12.dp), color = MaterialTheme.colorScheme.error)
                    state.statistics == null -> Text(stringResource(R.string.no_statistics), Modifier.padding(vertical = 12.dp))
                    else -> StatisticsTabContent(
                        tabIndex = selectedTab,
                        statistics = state.statistics,
                        bucketSeconds = state.bucketSeconds,
                        onBucketChange = onBucketChange,
                        onPacketClick = onPacketClick,
                        onConversationClick = { selectedConversation = it },
                        onEndpointClick = { selectedEndpoint = it },
                        modifier = Modifier.fillMaxSize()
                    )
                }
            }
        }
    }
    selectedConversation?.let { conversation ->
        ConversationDetailDialog(conversation, onApplyFilter) { selectedConversation = null }
    }
    selectedEndpoint?.let { endpoint ->
        EndpointDetailDialog(endpoint, onApplyFilter) { selectedEndpoint = null }
    }
}

@Composable
fun StatisticsDialog(
    state: StatisticsUiState,
    onRefresh: () -> Unit,
    onCancel: () -> Unit,
    onBucketChange: (Double) -> Unit,
    onPacketClick: (Long) -> Unit,
    onApplyFilter: (String) -> Unit,
    onExportTable: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    var selectedConversation by remember { mutableStateOf<ConversationStat?>(null) }
    var selectedEndpoint by remember { mutableStateOf<EndpointStat?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            Row {
                if (selectedTab == 1 || selectedTab == 2) {
                    TextButton(onClick = { onExportTable(if (selectedTab == 1) "conversations" else "endpoints") }) { Text(stringResource(R.string.export_csv)) }
                }
                Button(onClick = onDismiss) {
                    Text(stringResource(R.string.close))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = if (state.isLoading) onCancel else onRefresh) {
                Text(stringResource(if (state.isLoading) R.string.cancel_analysis else R.string.refresh_statistics))
            }
        },
        title = { Text(stringResource(R.string.statistics)) },
        text = {
            Column(modifier = Modifier.widthIn(max = 760.dp)) {
                ScrollableTabRow(selectedTabIndex = selectedTab, edgePadding = 0.dp, modifier = Modifier.fillMaxWidth()) {
                    StatisticsTabs.forEachIndexed { index, label ->
                        Tab(
                            selected = selectedTab == index,
                            onClick = { selectedTab = index },
                            text = {
                                Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        )
                    }
                }
                Spacer(modifier = Modifier.height(12.dp))
                when {
                    state.isLoading -> LoadingStatistics()
                    state.error != null -> Text(state.error, color = MaterialTheme.colorScheme.error)
                    state.statistics == null -> Text(stringResource(R.string.no_statistics))
                    else -> StatisticsTabContent(
                        tabIndex = selectedTab,
                        statistics = state.statistics,
                        bucketSeconds = state.bucketSeconds,
                        onBucketChange = onBucketChange,
                        onPacketClick = onPacketClick,
                        onConversationClick = { selectedConversation = it },
                        onEndpointClick = { selectedEndpoint = it },
                        // A dialog body is wrap-content, so it has no leftover
                        // space to fill: it keeps an explicit ceiling instead.
                        modifier = Modifier.heightIn(max = 440.dp)
                    )
                }
            }
        }
    )
    selectedConversation?.let { conversation ->
        ConversationDetailDialog(
            conversation = conversation,
            onApplyFilter = onApplyFilter,
            onDismiss = { selectedConversation = null }
        )
    }
    selectedEndpoint?.let { endpoint ->
        EndpointDetailDialog(
            endpoint = endpoint,
            onApplyFilter = onApplyFilter,
            onDismiss = { selectedEndpoint = null }
        )
    }
}

/**
 * The six section chips.
 *
 * [FlowRow] rather than a horizontally scrolling [Row]: the labels are wider
 * than a 400dp phone, so in a scrolling row the selected chip could sit outside
 * the viewport and the user had no way to tell more entries existed (the same
 * remedy the SIP/SDP/RTP/RTCP workbench uses for its four chips).
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun StatisticsTabChips(selectedTab: Int, onSelectTab: (Int) -> Unit) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        StatisticsTabs.forEachIndexed { index, label ->
            FilterChip(selectedTab == index, { onSelectTab(index) }, label = { Text(label, maxLines = 1) })
        }
    }
}

@Composable
private fun LoadingStatistics() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(320.dp),
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator()
    }
}

@Composable
private fun StatisticsTabContent(
    tabIndex: Int,
    statistics: CaptureStatistics,
    bucketSeconds: Double,
    onBucketChange: (Double) -> Unit,
    onPacketClick: (Long) -> Unit,
    onConversationClick: (ConversationStat) -> Unit,
    onEndpointClick: (EndpointStat) -> Unit,
    /**
     * Sizing handed down by the host: the full-screen workbench passes
     * `fillMaxSize` so the body consumes the leftover height, the dialog passes
     * a `heightIn` ceiling. Bodies must not hard-code a height of their own.
     */
    modifier: Modifier = Modifier
) {
    when (tabIndex) {
        0 -> ProtocolHierarchyView(statistics, modifier)
        1 -> ConversationsView(statistics.conversations, onConversationClick, modifier)
        2 -> EndpointsView(statistics.endpoints, onEndpointClick, modifier)
        3 -> IoGraphView(statistics.ioGraph, bucketSeconds, onBucketChange, modifier)
        4 -> PacketLengthsView(statistics, modifier)
        else -> ProtocolSummariesView(statistics, onPacketClick, modifier)
    }
}

@Composable
private fun ProtocolHierarchyView(statistics: CaptureStatistics, modifier: Modifier = Modifier) {
    LazyColumn(modifier = modifier) {
        item {
            Text(
                "Flat protocol-column summary; this is not an Ethernet-to-application path tree.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            SummaryLine("Packets", statistics.packetCount.toString())
            SummaryLine("Bytes", statistics.byteCount.formatFileSize())
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
        }
        items(statistics.protocolHierarchy) { stat ->
            ProtocolRow(stat)
            HorizontalDivider()
        }
    }
}

@Composable
private fun ProtocolRow(stat: ProtocolStat) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(stat.name, modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.packet_percent, stat.packetPercent.formatPercent()), style = MaterialTheme.typography.bodySmall)
        }
        Spacer(modifier = Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { (stat.packetPercent / 100.0).toFloat().coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            "${stat.packetCount} packets  ${stat.byteCount.formatFileSize()}  ${stat.bytePercent.formatPercent()} bytes",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ConversationsView(
    conversations: List<ConversationStat>,
    onConversationClick: (ConversationStat) -> Unit,
    modifier: Modifier = Modifier
) {
    if (conversations.isEmpty()) {
        Text(stringResource(R.string.no_conversations), modifier = modifier)
        return
    }
    var query by remember { mutableStateOf("") }
    var sortBy by remember { mutableIntStateOf(0) }
    val visible = conversations.filter { conversation ->
        query.isBlank() || "${conversation.endpointA} ${conversation.endpointB} ${conversation.type}".contains(query, ignoreCase = true)
    }.let { rows -> when (sortBy) { 1 -> rows.sortedByDescending { it.bytes }; 2 -> rows.sortedByDescending { it.duration }; else -> rows.sortedByDescending { it.packets } } }
    Column(modifier = modifier) {
        OutlinedTextField(query, { query = it }, label = { Text(stringResource(R.string.filter)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(vertical = 6.dp)) {
            FilterChip(sortBy == 0, { sortBy = 0 }, label = { Text(stringResource(R.string.sort_packets)) })
            FilterChip(sortBy == 1, { sortBy = 1 }, label = { Text(stringResource(R.string.sort_bytes)) })
            FilterChip(sortBy == 2, { sortBy = 2 }, label = { Text(stringResource(R.string.sort_duration)) })
        }
        if (visible.isEmpty()) { Text(stringResource(R.string.no_matching_rows)); return }
        // The rows take whatever height the filter field and the sort chips
        // left over, rather than a fixed 390dp band.
        LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f)) {
        if (conversations.size > 300) {
            item { TruncationNotice("Showing the top 300 of ${conversations.size} conversations.") }
        }
        items(visible.take(300)) { conversation ->
            Column(modifier = Modifier.fillMaxWidth().clickable { onConversationClick(conversation) }.padding(vertical = 8.dp)) {
                Text(conversation.type, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                Text(
                    "${conversation.endpointALabel()} <-> ${conversation.endpointBLabel()}",
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall
                )
                Text(
                    "${conversation.packets} packets  ${conversation.bytes.formatFileSize()}  start ${conversation.startTime.formatSeconds()}s  duration ${conversation.duration.formatSeconds()}s  ${conversation.aToBPackets}-> / ${conversation.bToAPackets}<-",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            HorizontalDivider()
        }
        }
    }
}

@Composable
private fun EndpointsView(
    endpoints: List<EndpointStat>,
    onEndpointClick: (EndpointStat) -> Unit,
    modifier: Modifier = Modifier
) {
    if (endpoints.isEmpty()) {
        Text(stringResource(R.string.no_endpoints), modifier = modifier)
        return
    }
    var query by remember { mutableStateOf("") }
    var sortByBytes by remember { mutableStateOf(false) }
    val visible = endpoints.filter { endpoint -> query.isBlank() || "${endpoint.address} ${endpoint.type}".contains(query, ignoreCase = true) }
        .sortedByDescending { if (sortByBytes) it.bytes else it.packets.toLong() }
    Column(modifier = modifier) {
        OutlinedTextField(query, { query = it }, label = { Text(stringResource(R.string.filter)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        FilterChip(sortByBytes, { sortByBytes = !sortByBytes }, label = { Text(if (sortByBytes) stringResource(R.string.sort_bytes) else stringResource(R.string.sort_packets)) }, modifier = Modifier.padding(vertical = 6.dp))
        if (visible.isEmpty()) { Text(stringResource(R.string.no_matching_rows)); return }
        LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f)) {
        if (endpoints.size > 400) {
            item { TruncationNotice("Showing the top 400 of ${endpoints.size} endpoints.") }
        }
        items(visible.take(400)) { endpoint ->
            Row(
                modifier = Modifier.fillMaxWidth().clickable { onEndpointClick(endpoint) }.padding(vertical = 8.dp),
                verticalAlignment = Alignment.Top
            ) {
                Text(endpoint.type, modifier = Modifier.width(46.dp), color = MaterialTheme.colorScheme.primary)
                Column(modifier = Modifier.weight(1f)) {
                    Text(endpoint.label(), maxLines = 1, overflow = TextOverflow.Ellipsis, fontFamily = FontFamily.Monospace)
                    Text(
                        "${endpoint.packets} packets  ${endpoint.bytes.formatFileSize()}  sent ${endpoint.sentPackets}  received ${endpoint.receivedPackets}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            HorizontalDivider()
        }
        }
    }
}

@Composable
private fun ConversationDetailDialog(
    conversation: ConversationStat,
    onApplyFilter: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val filter = conversation.displayFilter()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.conversation_title, conversation.type)) },
        text = {
            Column {
                SummaryLine(stringResource(R.string.statistics_endpoint_a), conversation.endpointALabel())
                SummaryLine(stringResource(R.string.statistics_endpoint_b), conversation.endpointBLabel())
                SummaryLine(stringResource(R.string.statistics_frames), conversation.packets.toString())
                SummaryLine(stringResource(R.string.statistics_bytes), conversation.bytes.formatFileSize())
                SummaryLine(stringResource(R.string.statistics_duration), "${conversation.duration.formatSeconds()} s")
                SummaryLine(stringResource(R.string.statistics_direction), "${conversation.aToBPackets} A→B / ${conversation.bToAPackets} B→A")
                Spacer(Modifier.height(8.dp))
                Text(filter, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { Button(onClick = { onApplyFilter(filter) }) { Text(stringResource(R.string.apply_conversation_filter)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.return_action)) } }
    )
}

@Composable
private fun EndpointDetailDialog(
    endpoint: EndpointStat,
    onApplyFilter: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val filter = endpoint.displayFilter()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.endpoint_title, endpoint.type)) },
        text = {
            Column {
                SummaryLine(stringResource(R.string.statistics_address), endpoint.label())
                SummaryLine(stringResource(R.string.statistics_frames), endpoint.packets.toString())
                SummaryLine(stringResource(R.string.statistics_bytes), endpoint.bytes.formatFileSize())
                SummaryLine(stringResource(R.string.statistics_direction), "${endpoint.sentPackets} sent / ${endpoint.receivedPackets} received")
                Spacer(Modifier.height(8.dp))
                Text(filter, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { Button(onClick = { onApplyFilter(filter) }) { Text(stringResource(R.string.apply_endpoint_filter)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.return_action)) } }
    )
}

@Composable
private fun IoGraphView(
    buckets: List<IoBucket>,
    bucketSeconds: Double,
    onBucketChange: (Double) -> Unit,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier) {
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            IoBuckets.forEach { seconds ->
                FilterChip(
                    selected = bucketSeconds == seconds,
                    onClick = { onBucketChange(seconds) },
                    label = { Text(if (seconds < 1.0) "100 ms" else "${seconds.toInt()} s") }
                )
            }
        }
        Spacer(modifier = Modifier.height(10.dp))
        if (buckets.isEmpty()) {
            Text(stringResource(R.string.no_io_buckets))
            return
        }
        val maxPackets = max(1, buckets.maxOf { it.packets })
        val maxBytes = max(1L, buckets.maxOf { it.bytes })
        LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f)) {
            if (buckets.size > 300) {
                item { TruncationNotice("Showing the first 300 of ${buckets.size} time buckets.") }
            }
            items(buckets.take(300)) { bucket ->
                Column(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Text(
                        "${bucket.startTime.formatSeconds()}-${bucket.endTime.formatSeconds()}s  ${bucket.packets} packets  ${bucket.bytes.formatFileSize()}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    DualBar(
                        packetFraction = bucket.packets.toFloat() / maxPackets,
                        byteFraction = bucket.bytes.toFloat() / maxBytes
                    )
                }
            }
        }
    }
}

@Composable
private fun PacketLengthsView(statistics: CaptureStatistics, modifier: Modifier = Modifier) {
    LazyColumn(modifier = modifier) {
        item {
            SummaryLine("Minimum", "${statistics.packetLengths.min} bytes")
            SummaryLine("Maximum", "${statistics.packetLengths.max} bytes")
            SummaryLine("Average", "${statistics.packetLengths.average.formatSeconds()} bytes")
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
        }
        items(statistics.packetLengths.buckets) { bucket ->
            LengthBucketRow(bucket, statistics.packetCount)
            HorizontalDivider()
        }
    }
}

@Composable
private fun LengthBucketRow(bucket: PacketLengthBucket, totalPackets: Int) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Row {
            Text(bucket.label, modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.packet_count_label, bucket.packets), style = MaterialTheme.typography.bodySmall)
        }
        Spacer(modifier = Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { if (totalPackets > 0) bucket.packets.toFloat() / totalPackets else 0f },
            modifier = Modifier.fillMaxWidth()
        )
        Text(bucket.bytes.formatFileSize(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ProtocolSummariesView(
    statistics: CaptureStatistics,
    onPacketClick: (Long) -> Unit,
    modifier: Modifier = Modifier
) {
    val dnsTransactionsTitle = stringResource(R.string.dns_transactions)
    val httpTransactionsTitle = stringResource(R.string.http_transactions)
    val tcpSignalsTitle = stringResource(R.string.tcp_signals)
    LazyColumn(modifier = modifier) {
        transactionSection(dnsTransactionsTitle, statistics.dnsTransactions, onPacketClick)
        transactionSection(httpTransactionsTitle, statistics.httpTransactions, onPacketClick)
        summarySection("TLS", statistics.tlsSummaries, statistics.tlsSummaryTotal, onPacketClick)
        summarySection(tcpSignalsTitle, statistics.tcpSummaries, statistics.tcpSummaryTotal, onPacketClick)
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.transactionSection(
    title: String,
    transactions: List<RequestResponseTransaction>,
    onPacketClick: (Long) -> Unit
) {
    item {
        Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp, bottom = 4.dp))
    }
    if (transactions.isEmpty()) {
        item {
            Text(stringResource(R.string.no_transactions), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    } else {
        items(transactions, key = { "$title-${it.requestFrame}" }) { transaction ->
            RequestResponseRow(transaction, onPacketClick)
            HorizontalDivider()
        }
    }
}

@Composable
private fun RequestResponseRow(
    transaction: RequestResponseTransaction,
    onPacketClick: (Long) -> Unit
) {
    val responseFrame = transaction.responseFrame
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(transaction.protocol, modifier = Modifier.width(58.dp), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium)
            TextButton(onClick = { onPacketClick(transaction.requestFrame) }) {
                Text("#${transaction.requestFrame}")
            }
            Text("->", color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (responseFrame != null) {
                TextButton(onClick = { onPacketClick(responseFrame) }) {
                    Text("#$responseFrame")
                }
            } else {
                Text(stringResource(R.string.transaction_pending), modifier = Modifier.padding(horizontal = 12.dp), color = MaterialTheme.colorScheme.error)
            }
            transaction.responseTimeMillis?.let { elapsed ->
                Text(
                    String.format(Locale.US, "%.1f ms", elapsed),
                    modifier = Modifier.weight(1f),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
        Text(
            stringResource(R.string.endpoint_arrow, transaction.client, transaction.server),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(transaction.request, maxLines = 2, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall)
        Text(
            transaction.response ?: stringResource(R.string.no_response_captured),
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            style = MaterialTheme.typography.bodySmall,
            color = if (transaction.response == null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary
        )
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.summarySection(
    title: String,
    items: List<ProtocolSummaryItem>,
    total: Int,
    onPacketClick: (Long) -> Unit
) {
    item {
        Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp, bottom = 4.dp))
    }
    if (items.isEmpty()) {
        item {
            Text(stringResource(R.string.no_entries), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    } else {
        if (total > 80) {
            item {
                TruncationNotice(
                    "Showing 80 of $total matching frames${if (total > items.size) "; native analysis retained the first ${items.size}" else ""}."
                )
            }
        }
        items(items.take(80), key = { "${title}-${it.frameNumber}" }) { item ->
            ProtocolSummaryRow(item, onPacketClick)
            HorizontalDivider()
        }
    }
}

@Composable
private fun TruncationNotice(message: String) {
    Text(
        message,
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.tertiary
    )
}

@Composable
private fun ProtocolSummaryRow(item: ProtocolSummaryItem, onPacketClick: (Long) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onPacketClick(item.frameNumber) }
            .padding(vertical = 7.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("#${item.frameNumber}", modifier = Modifier.width(64.dp), style = MaterialTheme.typography.labelMedium)
            Text(item.protocol, modifier = Modifier.width(54.dp), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium)
            Text(stringResource(R.string.endpoint_arrow, item.source, item.destination), modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        }
        Text(item.summary, maxLines = 2, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun SummaryLine(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label, modifier = Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun DualBar(packetFraction: Float, byteFraction: Float) {
    val packetColor = MaterialTheme.colorScheme.primary
    val byteColor = MaterialTheme.colorScheme.tertiary
    Canvas(modifier = Modifier.fillMaxWidth().height(18.dp)) {
        drawFractionBar(packetFraction.coerceIn(0f, 1f), packetColor, top = 1f)
        drawFractionBar(byteFraction.coerceIn(0f, 1f), byteColor, top = size.height / 2f + 1f)
    }
}

private fun DrawScope.drawFractionBar(fraction: Float, color: Color, top: Float) {
    val barHeight = size.height / 2f - 2f
    drawRect(
        color = color.copy(alpha = 0.18f),
        topLeft = androidx.compose.ui.geometry.Offset(0f, top),
        size = Size(size.width, barHeight)
    )
    drawRect(
        color = color,
        topLeft = androidx.compose.ui.geometry.Offset(0f, top),
        size = Size(size.width * fraction, barHeight)
    )
}

private fun ConversationStat.endpointALabel(): String = if (portA == null) endpointA else "$endpointA:$portA"

private fun ConversationStat.endpointBLabel(): String = if (portB == null) endpointB else "$endpointB:$portB"

private fun EndpointStat.label(): String = if (port == null) address else "$address:$port"

private fun ConversationStat.displayFilter(): String {
    val addressField = when (type) {
        "IPv6" -> "ipv6.addr"
        "IPv4" -> "ip.addr"
        "Ethernet" -> "eth.addr"
        else -> "ip.addr"
    }
    val addresses = "$addressField == \"$endpointA\" && $addressField == \"$endpointB\""
    val transport = when (type) {
        "TCP" -> "tcp"
        "UDP" -> "udp"
        else -> null
    }
    return if (transport == null) addresses else {
        val ports = listOfNotNull(portA, portB).distinct()
        if (ports.isEmpty()) addresses else "$addresses && (${ports.joinToString(" || ") { "$transport.port == $it" }})"
    }
}

private fun EndpointStat.displayFilter(): String {
    val field = when (type) {
        "MAC" -> "eth.addr"
        "TCP", "UDP" -> if (address.contains(':')) "ipv6.addr" else "ip.addr"
        else -> if (address.contains(':')) "ipv6.addr" else "ip.addr"
    }
    val portPart = port?.let { " && ${type.lowercase()}.port == $it" }.orEmpty()
    return "$field == \"$address\"$portPart"
}

private fun Double.formatPercent(): String = String.format(Locale.US, "%.1f%%", this)

private fun Double.formatSeconds(): String = String.format(Locale.US, "%.3f", this)
