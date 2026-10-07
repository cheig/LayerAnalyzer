package com.example.layanalyzer.ui.components

import android.graphics.Paint
import android.graphics.Typeface
import android.content.res.Configuration
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.automirrored.filled.FactCheck
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.BookmarkBorder
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.EditNote
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Stream
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.model.ExportUiState
import com.example.layanalyzer.model.FollowStreamRecord
import com.example.layanalyzer.model.FollowStreamResult
import com.example.layanalyzer.model.PacketSummary
import com.example.layanalyzer.model.ProtocolNode
import com.example.layanalyzer.model.RtpStreamIdentity
import com.example.layanalyzer.viewmodel.PacketDetailState
import com.example.layanalyzer.viewmodel.PacketBytesViewerState
import com.example.layanalyzer.viewmodel.PacketNavigationState
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PacketDetailScreen(
    detailState: PacketDetailState?,
    isLoading: Boolean,
    selectedByteRange: IntRange?,
    selectedField: ProtocolNode?,
    navigationState: PacketNavigationState,
    followStream: FollowStreamResult?,
    isFollowingStream: Boolean,
    packetBytesViewer: PacketBytesViewerState?,
    exportState: ExportUiState,
    defaultTreeExpansionDepth: Int,
    appliedFilter: String,
    expertSeverity: String,
    isBookmarked: Boolean,
    workspaceNote: String,
    isEvidence: Boolean,
    onFieldSelected: (ProtocolNode) -> Unit,
    onByteSelected: (Int) -> Unit,
    onByteRangeSelected: (IntRange) -> Unit,
    onApplyFieldAsFilter: (String) -> Unit,
    onShowPacketBytes: (ProtocolNode) -> Unit = {},
    onDismissPacketBytesViewer: () -> Unit,
    onPrepareFieldFilter: (String) -> Unit,
    onFollowStream: (String) -> Unit,
    onExportPacketDetails: () -> Unit,
    onExportSelectedBytes: () -> Unit,
    onClearExportState: () -> Unit,
    onDismissFollowStream: () -> Unit,
    onStreamPacketClick: (Long) -> Unit,
    onPreviousPacket: () -> Unit,
    onNextPacket: () -> Unit,
    onToggleBookmark: () -> Unit,
    onSaveNote: (String) -> Unit,
    onToggleEvidence: () -> Unit,
    onAnalyzeRtpStream: (RtpStreamIdentity) -> Unit = {},
    onBack: () -> Unit
) {
    if (followStream != null) {
        FollowStreamScreen(followStream, onDismissFollowStream, onStreamPacketClick)
        return
    }

    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val snackbarHostState = remember { SnackbarHostState() }
    val snackbarScope = rememberCoroutineScope()
    var actionsExpanded by remember { mutableStateOf(false) }
    var showNoteDialog by remember { mutableStateOf(false) }
    val rtpIdentity = remember(detailState?.root) {
        RtpStreamIdentity.fromProtocolTree(detailState?.root)
    }

    LaunchedEffect(exportState.error, exportState.message) {
        (exportState.error ?: exportState.message)?.let { snackbarHostState.showSnackbar(it) }
    }
    LaunchedEffect(exportState.shareResult) {
        exportState.shareResult?.let {
            shareExportResult(context, it)
            onClearExportState()
        }
    }

    val configuration = LocalConfiguration.current
    // A phone in landscape has ~360dp of height. The summary band, tab row and
    // the 56dp packet navigation bar would leave only a couple of protocol tree
    // rows, so the chrome collapses and prev/next move into the single-line
    // title bar.
    val isCompactChrome = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE &&
        configuration.screenHeightDp < 600
    val detailTitle = detailState?.let { stringResource(R.string.packet_title, it.frameNumber) }
        ?: stringResource(R.string.packet_details)
    val compactTitle = if (navigationState.position >= 0 && navigationState.total > 0) {
        "$detailTitle · ${navigationState.position + 1} / ${navigationState.total}"
    } else {
        detailTitle
    }
    val topBarActions: @Composable RowScope.() -> Unit = {
        if (isCompactChrome) {
            IconButton(onClick = onPreviousPacket, enabled = navigationState.hasPrevious) {
                Icon(Icons.Default.KeyboardArrowUp, contentDescription = stringResource(R.string.previous_packet))
            }
            IconButton(onClick = onNextPacket, enabled = navigationState.hasNext) {
                Icon(Icons.Default.KeyboardArrowDown, contentDescription = stringResource(R.string.next_packet))
            }
        }
        if (detailState != null) {
            IconButton(onClick = onToggleBookmark) {
                Icon(
                    if (isBookmarked) Icons.Default.Bookmark else Icons.Default.BookmarkBorder,
                    contentDescription = stringResource(if (isBookmarked) R.string.remove_bookmark else R.string.bookmark_packet)
                )
            }
            Box {
                IconButton(onClick = { actionsExpanded = true }) {
                    Icon(Icons.Default.MoreVert, contentDescription = stringResource(R.string.packet_actions))
                }
                DropdownMenu(actionsExpanded, { actionsExpanded = false }) {
                    PacketActionItem(
                        if (isEvidence) R.string.remove_evidence else R.string.add_evidence,
                        { actionsExpanded = false; onToggleEvidence() },
                        Icons.AutoMirrored.Filled.FactCheck
                    )
                    PacketActionItem(R.string.edit_frame_note, { actionsExpanded = false; showNoteDialog = true }, Icons.Default.EditNote)
                    PacketActionItem(R.string.follow_tcp_stream, { actionsExpanded = false; onFollowStream("tcp") }, Icons.Default.Stream, !isFollowingStream)
                    PacketActionItem(R.string.follow_udp_stream, { actionsExpanded = false; onFollowStream("udp") }, Icons.Default.Stream, !isFollowingStream)
                    rtpIdentity?.let { identity ->
                        PacketActionItem(
                            R.string.rtp_analyze_stream,
                            { actionsExpanded = false; onAnalyzeRtpStream(identity) },
                            Icons.Default.Stream
                        )
                    }
                    HorizontalDivider()
                    PacketActionItem(R.string.export_details, { actionsExpanded = false; onExportPacketDetails() }, Icons.Default.Download, !exportState.isExporting)
                    PacketActionItem(R.string.export_hex, { actionsExpanded = false; onExportSelectedBytes() }, Icons.Default.Download, !exportState.isExporting)
                    if (selectedByteRange != null) {
                        PacketActionItem(R.string.copy_hex, {
                            actionsExpanded = false
                            clipboard.setText(AnnotatedString(detailState.bytes.selectedBytes(selectedByteRange).toHexText()))
                        }, Icons.Default.ContentCopy)
                        PacketActionItem(R.string.copy_ascii, {
                            actionsExpanded = false
                            clipboard.setText(AnnotatedString(detailState.bytes.selectedBytes(selectedByteRange).toAsciiText()))
                        }, Icons.Default.ContentCopy)
                    }
                }
            }
        }
    }

    Scaffold(
        topBar = {
            if (isCompactChrome) {
                CompactTopBar(
                    title = compactTitle,
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                        }
                    },
                    actions = topBarActions
                )
            } else {
                TopAppBar(
                    title = {
                        Text(
                            detailTitle,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                        }
                    },
                    actions = topBarActions
                )
            }
        },
        bottomBar = {
            if (!isCompactChrome) {
                PacketNavigationBar(navigationState, onPreviousPacket, onNextPacket)
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { paddingValues ->
        Box(Modifier.padding(paddingValues).fillMaxSize()) {
            when {
                isLoading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                detailState == null -> Text(stringResource(R.string.no_packet_selected), Modifier.align(Alignment.Center))
                else -> PacketDetailContent(
                    detailState,
                    selectedByteRange,
                    selectedField,
                    defaultTreeExpansionDepth,
                    appliedFilter,
                    expertSeverity,
                    onFieldSelected,
                    onByteSelected,
                    onByteRangeSelected,
                    onApplyFieldAsFilter,
                    onShowPacketBytes,
                    onPrepareFieldFilter,
                    compact = isCompactChrome
                )
            }
        }
    }

    if (packetBytesViewer != null && detailState != null) {
        PacketBytesDialog(
            state = packetBytesViewer,
            frameBytes = detailState.bytes,
            onDismiss = onDismissPacketBytesViewer,
            onCopied = {
                snackbarScope.launch { snackbarHostState.showSnackbar(context.getString(R.string.bytes_copied)) }
            },
            onSaved = {
                snackbarScope.launch { snackbarHostState.showSnackbar(context.getString(R.string.bytes_saved)) }
            },
            onSaveError = {
                snackbarScope.launch { snackbarHostState.showSnackbar(context.getString(R.string.error_save_bytes)) }
            }
        )
    }

    if (showNoteDialog && detailState != null) {
        var note by remember(detailState.frameNumber, workspaceNote) { mutableStateOf(workspaceNote) }
        AlertDialog(
            onDismissRequest = { showNoteDialog = false },
            title = { Text(stringResource(R.string.frame_note_title, detailState.frameNumber)) },
            text = { OutlinedTextField(note, { note = it.take(2000) }, label = { Text(stringResource(R.string.note_hint)) }, minLines = 3) },
            confirmButton = { Button({ onSaveNote(note); showNoteDialog = false }) { Text(stringResource(R.string.save)) } },
            dismissButton = { TextButton({ showNoteDialog = false }) { Text(stringResource(R.string.cancel)) } }
        )
    }
}

@Composable
private fun PacketActionItem(
    label: Int,
    onClick: () -> Unit,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    enabled: Boolean = true
) {
    DropdownMenuItem(
        text = { Text(stringResource(label)) },
        onClick = onClick,
        leadingIcon = { Icon(icon, contentDescription = null) },
        enabled = enabled
    )
}

@Composable
private fun PacketNavigationBar(
    state: PacketNavigationState,
    onPrevious: () -> Unit,
    onNext: () -> Unit
) {
    Surface(tonalElevation = 3.dp) {
        Row(
            Modifier.fillMaxWidth().height(56.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            IconButton(onPrevious, enabled = state.hasPrevious) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.previous_packet))
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    if (state.position >= 0) "${state.position + 1} / ${state.total}" else "- / ${state.total}",
                    style = MaterialTheme.typography.labelLarge,
                    fontFamily = FontFamily.Monospace
                )
                Text(stringResource(R.string.current_filter_scope), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            IconButton(onNext, enabled = state.hasNext) {
                Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = stringResource(R.string.next_packet))
            }
        }
    }
}

@Composable
private fun PacketDetailContent(
    detailState: PacketDetailState,
    selectedByteRange: IntRange?,
    selectedField: ProtocolNode?,
    defaultTreeExpansionDepth: Int,
    appliedFilter: String,
    expertSeverity: String,
    onFieldSelected: (ProtocolNode) -> Unit,
    onByteSelected: (Int) -> Unit,
    onByteRangeSelected: (IntRange) -> Unit,
    onApplyFieldAsFilter: (String) -> Unit,
    onShowPacketBytes: (ProtocolNode) -> Unit,
    onPrepareFieldFilter: (String) -> Unit,
    compact: Boolean = false
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    Column(Modifier.fillMaxSize()) {
        detailState.summary?.let { PacketSummaryBand(it, expertSeverity, compact) }
        TabRow(
            selectedTab,
            modifier = if (compact) Modifier.height(36.dp) else Modifier
        ) {
            Tab(selectedTab == 0, { selectedTab = 0 }, text = { Text(stringResource(R.string.dissection)) })
            Tab(selectedTab == 1, { selectedTab = 1 }, text = { Text(stringResource(R.string.bytes)) })
        }
        if (selectedField != null) {
            SelectedFieldBar(
                node = selectedField,
                appliedFilter = appliedFilter,
                onViewBytes = { selectedTab = 1 },
                onApplyFilter = onApplyFieldAsFilter,
                onPrepareFilter = onPrepareFieldFilter,
                compact = compact
            )
        }
        if (selectedTab == 0) {
            ProtocolTreeView(
                root = detailState.root,
                selectedNode = selectedField,
                defaultExpansionDepth = defaultTreeExpansionDepth,
                onFieldSelected = onFieldSelected,
                onApplyFieldAsFilter = onApplyFieldAsFilter,
                onShowPacketBytes = onShowPacketBytes,
                modifier = Modifier.weight(1f)
            )
        } else {
            HexAsciiView(
                bytes = detailState.bytes,
                selectedRange = selectedByteRange,
                selectedField = selectedField,
                onByteSelected = onByteSelected,
                onByteRangeSelected = onByteRangeSelected,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
private fun PacketSummaryBand(summary: PacketSummary, severity: String, compact: Boolean = false) {
    Column(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f))
            .padding(horizontal = 12.dp, vertical = if (compact) 3.dp else 7.dp),
        verticalArrangement = Arrangement.spacedBy(if (compact) 0.dp else 2.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            when (severity.lowercase()) {
                "error" -> Icon(Icons.Default.ErrorOutline, null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
                "warn" -> Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.tertiary, modifier = Modifier.size(18.dp))
            }
            Text(summary.time, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1f))
            Text(summary.protocol, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.labelMedium)
            Spacer(Modifier.width(10.dp))
            Text("${summary.length} B", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(
            "${summary.endpoint(true)}  ->  ${summary.endpoint(false)}",
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        // The info line duplicates much of the dissection tree, so the compact
        // landscape band drops it to keep rows for the tree itself.
        if (!compact) {
            Text(summary.info.ifBlank { "-" }, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun SelectedFieldBar(
    node: ProtocolNode,
    appliedFilter: String,
    onViewBytes: () -> Unit,
    onApplyFilter: (String) -> Unit,
    onPrepareFilter: (String) -> Unit,
    compact: Boolean = false
) {
    val clipboard = LocalClipboardManager.current
    val expression = remember(node) { node.asDisplayFilter() }
    var filterMenu by remember { mutableStateOf(false) }
    val rangeLabel = if (node.length > 0) stringResource(R.string.byte_range, node.start, node.start + node.length - 1) else stringResource(R.string.no_byte_range)
    val generatedLabel = stringResource(R.string.generated_field)
    val hiddenLabel = stringResource(R.string.hidden_field)
    Surface(color = MaterialTheme.colorScheme.secondaryContainer) {
        Row(
            Modifier.fillMaxWidth().height(if (compact) 40.dp else 52.dp).padding(start = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(node.filter ?: node.label, style = MaterialTheme.typography.labelMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    buildString {
                        append(rangeLabel)
                        if (node.generated) append(" · $generatedLabel")
                        if (node.hidden) append(" · $hiddenLabel")
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            TextButton(onViewBytes, enabled = node.length > 0) { Text(stringResource(R.string.view_bytes)) }
            Box {
                IconButton({ filterMenu = true }, enabled = expression != null) { Icon(Icons.Default.FilterAlt, stringResource(R.string.filter)) }
                DropdownMenu(filterMenu, { filterMenu = false }) {
                    expression?.let { fieldFilter ->
                        FilterCombinationItem(R.string.filter_replace, fieldFilter) { filterMenu = false; onApplyFilter(it) }
                        if (appliedFilter.isNotBlank()) {
                            FilterCombinationItem(R.string.filter_and, "($appliedFilter) && ($fieldFilter)") { filterMenu = false; onApplyFilter(it) }
                            FilterCombinationItem(R.string.filter_or, "($appliedFilter) || ($fieldFilter)") { filterMenu = false; onApplyFilter(it) }
                            FilterCombinationItem(R.string.filter_and_not, "($appliedFilter) && !($fieldFilter)") { filterMenu = false; onApplyFilter(it) }
                            FilterCombinationItem(R.string.filter_or_not, "($appliedFilter) || !($fieldFilter)") { filterMenu = false; onApplyFilter(it) }
                        }
                        HorizontalDivider()
                        FilterCombinationItem(R.string.prepare_filter, fieldFilter) { filterMenu = false; onPrepareFilter(it) }
                    }
                }
            }
            IconButton({
                clipboard.setText(AnnotatedString(listOfNotNull(node.filter, node.value).joinToString(" = ").ifBlank { node.label }))
            }) { Icon(Icons.Default.ContentCopy, stringResource(R.string.copy_field)) }
        }
    }
}

@Composable
private fun FilterCombinationItem(label: Int, expression: String, onSelect: (String) -> Unit) {
    DropdownMenuItem(
        text = {
            Column {
                Text(stringResource(label))
                Text(expression, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        },
        onClick = { onSelect(expression) }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FollowStreamScreen(
    result: FollowStreamResult,
    onBack: () -> Unit,
    onPacketClick: (Long) -> Unit
) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    var renderMode by remember { mutableStateOf(StreamRenderMode.Utf8) }
    var direction by remember { mutableStateOf(StreamDirection.Both) }
    var query by remember { mutableStateOf("") }
    var pendingExport by remember { mutableStateOf<String?>(null) }
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri: Uri? ->
        val text = pendingExport
        pendingExport = null
        if (uri != null && text != null) context.contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) }
    }
    val records = remember(result.records, direction, query, renderMode) {
        result.records.filter { record ->
            (direction == StreamDirection.Both || record.direction.equals(direction.nativeName, true)) &&
                (query.isBlank() || record.contentFor(renderMode).contains(query, true))
        }
    }
    val content = remember(records, renderMode) { records.toStreamContent(renderMode) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("${result.protocol.uppercase()} ${stringResource(R.string.stream_title, result.streamId)}") },
                navigationIcon = { IconButton(onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) } },
                actions = {
                    IconButton({ clipboard.setText(AnnotatedString(content)) }) { Icon(Icons.Default.ContentCopy, stringResource(R.string.copy)) }
                    IconButton({ pendingExport = content; exportLauncher.launch("${result.protocol}-stream-${result.streamId}.txt") }) { Icon(Icons.Default.Download, stringResource(R.string.export)) }
                }
            )
        }
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            Text(
                stringResource(if (result.directionKnown) R.string.stream_scope_known else R.string.stream_scope_unknown, result.scope),
                Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            result.records.firstOrNull()?.let { first ->
                Text("${first.source}  <->  ${first.destination}", Modifier.padding(horizontal = 12.dp), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Row(Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 8.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                StreamDirection.values().forEach { option ->
                    FilterChip(direction == option, { direction = option }, label = { Text(stringResource(option.label)) })
                }
                StreamRenderMode.values().forEach { option ->
                    FilterChip(renderMode == option, { renderMode = option }, label = { Text(option.label) })
                }
            }
            OutlinedTextField(
                query,
                { query = it },
                Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 4.dp),
                label = { Text(stringResource(R.string.search_stream)) },
                singleLine = true
            )
            if (!result.error.isNullOrBlank()) {
                Text(result.error, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(12.dp))
            } else {
                LazyColumn(Modifier.weight(1f)) {
                    items(records, key = { "${it.frameNumber}-${it.direction}" }) { record ->
                        Column(Modifier.fillMaxWidth().clickable { onPacketClick(record.frameNumber) }.padding(horizontal = 12.dp, vertical = 8.dp)) {
                            Text(
                                "#${record.frameNumber}  ${record.direction}  ${record.source} -> ${record.destination}  ${record.length} B",
                                style = MaterialTheme.typography.labelMedium,
                                color = if (record.direction.equals("client", true)) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(record.contentFor(renderMode), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        }
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}

private enum class StreamDirection(val label: Int, val nativeName: String) {
    Both(R.string.stream_both, ""),
    Client(R.string.stream_client, "client"),
    Server(R.string.stream_server, "server")
}

private enum class StreamRenderMode(val label: String) { Utf8("UTF-8"), Ascii("ASCII"), Hex("Hex") }

private fun FollowStreamRecord.contentFor(mode: StreamRenderMode): String = when (mode) {
    StreamRenderMode.Utf8 -> text
    StreamRenderMode.Ascii -> ascii
    StreamRenderMode.Hex -> hex
}

private fun List<FollowStreamRecord>.toStreamContent(mode: StreamRenderMode): String = joinToString("\n") {
    "#${it.frameNumber} ${it.direction} ${it.source} -> ${it.destination}\n${it.contentFor(mode)}"
}

@Composable
fun HexAsciiView(
    bytes: ByteArray,
    selectedRange: IntRange?,
    selectedField: ProtocolNode?,
    onByteSelected: (Int) -> Unit,
    onByteRangeSelected: (IntRange) -> Unit,
    modifier: Modifier = Modifier
) {
    val bytesPerRow = if (LocalConfiguration.current.screenWidthDp < 600) 8 else 16
    val hexCellWidth = if (bytesPerRow == 8) 23.dp else 24.dp
    val asciiCellWidth = if (bytesPerRow == 8) 14.dp else 16.dp
    val rowCount = (bytes.size + bytesPerRow - 1) / bytesPerRow
    val contentWidth = 16.dp + 64.dp + hexCellWidth * bytesPerRow + asciiCellWidth * bytesPerRow
    val listState = rememberLazyListState()
    val horizontalScroll = rememberScrollState()
    var offsetText by remember { mutableStateOf("") }
    val targetOffset = selectedRange?.first
    LaunchedEffect(targetOffset, bytesPerRow) {
        if (targetOffset != null && targetOffset in bytes.indices) {
            val targetRow = targetOffset / bytesPerRow
            val isVisible = listState.layoutInfo.visibleItemsInfo.any { it.index == targetRow }
            if (!isVisible) listState.animateScrollToItem(targetRow)
        }
    }
    Column(modifier) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                offsetText,
                { offsetText = it.filter { char -> char.isDigit() || char.lowercaseChar() in 'a'..'f' }.take(8) },
                Modifier.weight(1f),
                label = { Text(stringResource(R.string.jump_offset)) },
                singleLine = true,
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Go),
                keyboardActions = KeyboardActions(onGo = {
                    offsetText.toIntOrNull(16)?.takeIf { it in bytes.indices }?.let(onByteSelected)
                })
            )
            TextButton({ offsetText.toIntOrNull(16)?.takeIf { it in bytes.indices }?.let(onByteSelected) }) { Text(stringResource(R.string.go)) }
        }
        selectedField?.takeIf { it.length > 0 }?.let {
            Text(it.filter ?: it.label, Modifier.padding(horizontal = 10.dp, vertical = 2.dp), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Box(Modifier.fillMaxWidth().horizontalScroll(horizontalScroll).background(MaterialTheme.colorScheme.surfaceVariant)) {
            Row(Modifier.width(contentWidth).padding(horizontal = 8.dp, vertical = 5.dp)) {
                Text(stringResource(R.string.offset), Modifier.width(64.dp), style = MaterialTheme.typography.labelMedium)
                Text(stringResource(R.string.hex), Modifier.width(hexCellWidth * bytesPerRow), style = MaterialTheme.typography.labelMedium)
                Text(stringResource(R.string.ascii), Modifier.width(asciiCellWidth * bytesPerRow), style = MaterialTheme.typography.labelMedium)
            }
        }
        LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
            items(count = rowCount, key = { it }, contentType = { "hex-row" }) { rowIndex ->
                val offset = rowIndex * bytesPerRow
                HexAsciiRow(
                    allBytes = bytes,
                    offset = offset,
                    byteCount = minOf(bytesPerRow, bytes.size - offset),
                    bytesPerRow = bytesPerRow,
                    hexCellWidth = hexCellWidth,
                    asciiCellWidth = asciiCellWidth,
                    contentWidth = contentWidth,
                    selectedRange = selectedRange,
                    scrollState = horizontalScroll,
                    onByteSelected = onByteSelected,
                    onByteRangeSelected = onByteRangeSelected
                )
            }
        }
    }
}

@Composable
private fun HexAsciiRow(
    allBytes: ByteArray,
    offset: Int,
    byteCount: Int,
    bytesPerRow: Int,
    hexCellWidth: androidx.compose.ui.unit.Dp,
    asciiCellWidth: androidx.compose.ui.unit.Dp,
    contentWidth: androidx.compose.ui.unit.Dp,
    selectedRange: IntRange?,
    scrollState: androidx.compose.foundation.ScrollState,
    onByteSelected: (Int) -> Unit,
    onByteRangeSelected: (IntRange) -> Unit
) {
    val density = LocalDensity.current
    val textSize = with(density) { MaterialTheme.typography.bodySmall.fontSize.toPx() }
    val leftPaddingPx = with(density) { 8.dp.toPx() }
    val offsetWidthPx = with(density) { 64.dp.toPx() }
    val hexCellWidthPx = with(density) { hexCellWidth.toPx() }
    val asciiCellWidthPx = with(density) { asciiCellWidth.toPx() }
    val rowHeight = 26.dp
    val rowHeightPx = with(density) { rowHeight.toPx() }
    val textColor = MaterialTheme.colorScheme.onSurface.toArgb()
    val offsetColor = MaterialTheme.colorScheme.onSurfaceVariant.toArgb()
    val selectionColor = MaterialTheme.colorScheme.tertiaryContainer
    val currentOnByteSelected by rememberUpdatedState(onByteSelected)
    val currentOnByteRangeSelected by rememberUpdatedState(onByteRangeSelected)
    val textPaint = remember(textSize) {
        Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.MONOSPACE
            this.textSize = textSize
        }
    }

    fun byteIndexAt(viewportX: Float): Int? {
        val contentX = viewportX + scrollState.value
        val hexStart = leftPaddingPx + offsetWidthPx
        val asciiStart = hexStart + hexCellWidthPx * bytesPerRow
        val localIndex = when {
            contentX >= hexStart && contentX < hexStart + hexCellWidthPx * byteCount ->
                ((contentX - hexStart) / hexCellWidthPx).toInt()
            contentX >= asciiStart && contentX < asciiStart + asciiCellWidthPx * byteCount ->
                ((contentX - asciiStart) / asciiCellWidthPx).toInt()
            else -> return null
        }
        return offset + localIndex
    }

    Box(
        Modifier
            .fillMaxWidth()
            .pointerInput(offset, byteCount, hexCellWidthPx, asciiCellWidthPx) {
                detectTapGestures { position -> byteIndexAt(position.x)?.let(currentOnByteSelected) }
            }
            .pointerInput(offset, byteCount, hexCellWidthPx, asciiCellWidthPx) {
                var dragStartIndex: Int? = null
                detectHorizontalDragGestures(
                    onDragStart = { position ->
                        dragStartIndex = byteIndexAt(position.x)
                        dragStartIndex?.let { currentOnByteRangeSelected(it..it) }
                    },
                    onHorizontalDrag = { change, _ ->
                        val start = dragStartIndex ?: return@detectHorizontalDragGestures
                        byteIndexAt(change.position.x)?.let { end ->
                            currentOnByteRangeSelected(minOf(start, end)..maxOf(start, end))
                        }
                        change.consume()
                    },
                    onDragEnd = { dragStartIndex = null },
                    onDragCancel = { dragStartIndex = null }
                )
            }
            .horizontalScroll(scrollState)
    ) {
        Canvas(Modifier.width(contentWidth).height(rowHeight)) {
            val hexStart = leftPaddingPx + offsetWidthPx
            val asciiStart = hexStart + hexCellWidthPx * bytesPerRow
            val baseline = (rowHeightPx - (textPaint.descent() + textPaint.ascent())) / 2f

            repeat(byteCount) { index ->
                val absoluteIndex = offset + index
                if (selectedRange?.contains(absoluteIndex) == true) {
                    drawRect(
                        color = selectionColor,
                        topLeft = Offset(hexStart + index * hexCellWidthPx, 0f),
                        size = Size(hexCellWidthPx, rowHeightPx)
                    )
                    drawRect(
                        color = selectionColor,
                        topLeft = Offset(asciiStart + index * asciiCellWidthPx, 0f),
                        size = Size(asciiCellWidthPx, rowHeightPx)
                    )
                }
            }

            drawIntoCanvas { canvas ->
                textPaint.color = offsetColor
                canvas.nativeCanvas.drawText(offset.toHexOffset(), leftPaddingPx, baseline, textPaint)
                textPaint.color = textColor
                repeat(byteCount) { index ->
                    val value = allBytes[offset + index].toInt() and 0xff
                    canvas.nativeCanvas.drawText(
                        HEX_BYTE_LABELS[value],
                        hexStart + index * hexCellWidthPx,
                        baseline,
                        textPaint
                    )
                    canvas.nativeCanvas.drawText(
                        ASCII_BYTE_LABELS[value],
                        asciiStart + index * asciiCellWidthPx,
                        baseline,
                        textPaint
                    )
                }
            }
        }
    }
}

private val HEX_BYTE_LABELS = Array(256) { it.toString(16).uppercase().padStart(2, '0') }
private val ASCII_BYTE_LABELS = Array(256) { value -> if (value in 32..126) value.toChar().toString() else "." }

private fun Int.toHexOffset(): String = toString(16).uppercase().padStart(8, '0')

private fun PacketSummary.endpoint(sourceEndpoint: Boolean): String {
    val address = if (sourceEndpoint) source else destination
    val port = if (sourceEndpoint) sourcePort else destinationPort
    val formattedAddress = if (port != null && ':' in address && !address.startsWith("[")) "[$address]" else address
    return if (port == null) formattedAddress else "$formattedAddress:$port"
}

private fun ByteArray.selectedBytes(range: IntRange): List<Byte> {
    if (isEmpty()) return emptyList()
    val start = range.first.coerceIn(indices)
    val end = range.last.coerceIn(indices)
    return if (end < start) emptyList() else slice(start..end)
}

private fun List<Byte>.toHexText(): String = joinToString(" ") { "%02X".format(it.toInt() and 0xff) }
private fun List<Byte>.toAsciiText(): String = joinToString("") {
    val value = it.toInt() and 0xff
    if (value in 32..126) value.toChar().toString() else "."
}
