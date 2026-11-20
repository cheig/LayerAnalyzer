// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Download
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.model.ExportUiState
import com.example.layanalyzer.model.TlsFollowDirection
import com.example.layanalyzer.model.TlsFollowRecord
import com.example.layanalyzer.model.TlsFollowUnavailableReason
import com.example.layanalyzer.viewmodel.TlsFollowBanner
import com.example.layanalyzer.viewmodel.TlsFollowDirectionFilter
import com.example.layanalyzer.viewmodel.TlsFollowFormat
import com.example.layanalyzer.viewmodel.TlsFollowUiState
import com.example.layanalyzer.viewmodel.TlsFollowViewerState

/**
 * TLS-308 TLS follow viewer. Reuses no TCP/UDP code: it renders the dedicated [TlsFollowViewerState]
 * and always shows the connection scope, direction, truncation and incomplete limits. The bytes are a
 * plaintext byte stream, explicitly not presented as a single request. Export goes through the
 * bounded native file writer, never through a larger preview budget.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TlsFollowScreen(
    viewer: TlsFollowViewerState,
    exportState: ExportUiState,
    onDismiss: () -> Unit,
    onExport: () -> Unit,
    onCancelExport: () -> Unit,
    onClearExportState: () -> Unit
) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    var format by remember(viewer.frameNumber) { mutableStateOf(TlsFollowFormat.Utf8) }
    var direction by remember(viewer.frameNumber) { mutableStateOf(TlsFollowDirectionFilter.Both) }
    var query by remember(viewer.frameNumber) { mutableStateOf("") }

    LaunchedEffect(exportState.shareResult) {
        exportState.shareResult?.let {
            shareExportResult(context, it)
            onClearExportState()
        }
    }
    BackHandler { onDismiss() }

    val result = viewer.result
    var confirmExport by remember(viewer) { mutableStateOf(false) }
    val banner = remember(result) { TlsFollowUiState.banner(result) }
    if (confirmExport && banner.available && !exportState.isExporting) {
        SensitivePlaintextExportDialog(stringResource(R.string.tls_plaintext_export_stream_scope), {
            confirmExport = false
            onExport()
        }, { confirmExport = false })
    }
    val records = remember(result.records, direction, query, format) {
        TlsFollowUiState.filter(result.records, direction, query, format)
    }
    val copyContent = remember(records, format) {
        records.joinToString("\n") {
            "#${it.frameNumber} ${it.direction.wireName}\n${TlsFollowUiState.format(it.bytes, format)}"
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        stringResource(R.string.tls_follow_title, result.streamId?.toLong() ?: viewer.frameNumber),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                },
                actions = {
                    IconButton(
                        onClick = { clipboard.setText(AnnotatedString(copyContent)) },
                        enabled = records.isNotEmpty()
                    ) { Icon(Icons.Default.ContentCopy, stringResource(R.string.copy)) }
                    if (exportState.isExporting) {
                        Text(
                            stringResource(R.string.tls_follow_exporting),
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(end = 4.dp)
                        )
                        TextButton(onCancelExport) { Text(stringResource(R.string.cancel)) }
                    } else {
                        IconButton(onClick = { confirmExport = true }, enabled = banner.available) {
                            Icon(Icons.Default.Download, stringResource(R.string.tls_follow_export))
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            TlsFollowBanners(banner, exportState)
            if (banner.available) {
                Row(
                    Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    TlsFollowDirectionFilter.entries.forEach { option ->
                        FilterChip(direction == option, { direction = option }, label = { Text(stringResource(option.labelRes)) })
                    }
                    TlsFollowFormat.entries.forEach { option ->
                        FilterChip(format == option, { format = option }, label = { Text(option.label) })
                    }
                }
                OutlinedTextField(
                    query,
                    { query = it },
                    Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 4.dp),
                    label = { Text(stringResource(R.string.search_stream)) },
                    singleLine = true
                )
                LazyColumn(Modifier.weight(1f)) {
                    items(records, key = { "${it.frameNumber}-${it.direction.wireName}-${it.hashCode()}" }) { record ->
                        TlsFollowRecordRow(record, format)
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}

@Composable
private fun TlsFollowBanners(banner: TlsFollowBanner, exportState: ExportUiState) {
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        Text(
            stringResource(R.string.tls_follow_scope),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        if (!banner.available) {
            Text(
                stringResource(R.string.tls_follow_no_plaintext),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
            banner.unavailableReason?.let { reason ->
                Text(
                    stringResource(reason.promptRes()),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        if (!banner.directionKnown) {
            Text(
                stringResource(R.string.tls_follow_direction_unknown),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.tertiary
            )
        }
        if (banner.incomplete) {
            Text(
                stringResource(R.string.tls_follow_incomplete),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.tertiary
            )
        }
        if (banner.truncated) {
            Text(
                stringResource(R.string.tls_follow_truncated, TlsFollowUiState.previewLimit),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.tertiary
            )
        }
        Text(
            stringResource(R.string.tls_follow_byte_stream_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        exportState.message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        exportState.error?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun TlsFollowRecordRow(record: TlsFollowRecord, format: TlsFollowFormat) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
        Text(
            "#${record.frameNumber}  ${stringResource(record.direction.labelRes())}  ${record.byteLength} B",
            style = MaterialTheme.typography.labelMedium,
            color = if (record.direction == TlsFollowDirection.Client) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.tertiary
            },
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            TlsFollowUiState.format(record.bytes, format),
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall
        )
    }
}

private val TlsFollowDirectionFilter.labelRes: Int
    get() = when (this) {
        TlsFollowDirectionFilter.Both -> R.string.stream_both
        TlsFollowDirectionFilter.Client -> R.string.stream_client
        TlsFollowDirectionFilter.Server -> R.string.stream_server
    }

private fun TlsFollowDirection.labelRes(): Int = when (this) {
        TlsFollowDirection.Client -> R.string.stream_client
        TlsFollowDirection.Server -> R.string.stream_server
        TlsFollowDirection.Unknown -> R.string.stream_unknown
    }

private val TlsFollowFormat.label: String
    get() = when (this) {
        TlsFollowFormat.Utf8 -> "UTF-8"
        TlsFollowFormat.Ascii -> "ASCII"
        TlsFollowFormat.Hex -> "Hex"
    }

private fun TlsFollowUnavailableReason.promptRes(): Int = when (this) {
    TlsFollowUnavailableReason.NotTls -> R.string.tls_follow_prompt_not_tls
    TlsFollowUnavailableReason.SecretsNotConfigured -> R.string.tls_follow_prompt_no_secrets
    TlsFollowUnavailableReason.HandshakeIncomplete -> R.string.tls_follow_prompt_handshake_incomplete
    TlsFollowUnavailableReason.NoDecryptedApplicationData -> R.string.tls_follow_prompt_no_plaintext
    TlsFollowUnavailableReason.Unknown -> R.string.tls_follow_prompt_unavailable
}
