// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.layanalyzer.R
import com.example.layanalyzer.core.BytesFormatter
import com.example.layanalyzer.model.PacketBytesFormat
import com.example.layanalyzer.model.PacketDataSourceKind
import com.example.layanalyzer.viewmodel.PacketBytesSourceActions
import com.example.layanalyzer.viewmodel.PacketBytesViewerState
import com.example.layanalyzer.viewmodel.PacketDataSourceState

/** 内容区单次渲染字符上限：大帧防御性兜底，超出即截断并附尾注 */
private const val MAX_RENDER_CHARS = 256 * 1024

/**
 * TLS-307 source-aware byte window. The displayed bytes always come from the current data source
 * window ([state]); copy / format / export act on the source-relative selection (or, when browsing,
 * the loaded window), never on the raw frame bytes. A legacy detail with no native snapshot still
 * browses the raw frame bytes through [legacyFrameBytes] exactly as before.
 */
@Composable
fun PacketBytesDialog(
    viewer: PacketBytesViewerState,
    state: PacketDataSourceState,
    legacyFrameBytes: ByteArray,
    onDismiss: () -> Unit,
    onSwitchSource: (String) -> Unit,
    onCopied: () -> Unit = {},
    onSaved: () -> Unit = {},
    onSaveError: () -> Unit = {}
) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    var selectedFormat by remember(viewer) { mutableStateOf(PacketBytesFormat.HEX_DUMP) }

    val legacyRange = viewer.legacyRawRange
    val actionRange = remember(state, viewer) {
        if (legacyRange != null) legacyRange else PacketBytesSourceActions.actionRange(state, viewer.selectionAvailable)
    }
    val source = state.source
    // Action bytes come from the current source window; legacy details fall back to raw frame bytes.
    val slice = remember(actionRange, state.bytes, state.offset, legacyFrameBytes, legacyRange) {
        if (legacyRange != null) {
            val range = actionRange ?: return@remember ByteArray(0)
            BytesFormatter.sliceClamped(legacyFrameBytes, range.first, range.last - range.first + 1)
        } else {
            PacketBytesSourceActions.actionBytes(state, actionRange) ?: ByteArray(0)
        }
    }
    val actionsEnabled = actionRange != null
    val formatted = remember(selectedFormat, slice, actionsEnabled) {
        if (!actionsEnabled) null else runCatching { BytesFormatter.format(slice, selectedFormat) }.getOrNull()
    }
    val truncatedChars = ((formatted?.length ?: 0) - MAX_RENDER_CHARS).coerceAtLeast(0)
    val displayText = formatted?.let { text ->
        if (truncatedChars > 0) text.take(MAX_RENDER_CHARS) + "\n" + stringResource(R.string.bytes_truncated, truncatedChars) else text
    }

    var pendingSave by remember(viewer, state.analysis, state.sourceId) { mutableStateOf<String?>(null) }
    var confirmSave by remember(viewer, state.analysis, state.sourceId, actionRange, selectedFormat) { mutableStateOf(false) }
    val saveLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri: Uri? ->
        val text = pendingSave
        pendingSave = null
        if (uri != null && text != null) {
            val written = runCatching {
                context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(text.toByteArray()) } != null
            }.getOrDefault(false)
            if (written) onSaved() else {
                discardIncompleteBytesExport(context, uri)
                onSaveError()
            }
        } else if (uri != null) {
            // The source changed while SAF was open; never save a different source.
            discardIncompleteBytesExport(context, uri)
        }
    }

    val scrollState = rememberScrollState()
    // 只有 Hex 转储需要保住三栏列对齐走横向滚动，其余格式自动换行
    val isHexDump = selectedFormat == PacketBytesFormat.HEX_DUMP
    val horizontalScrollState = rememberScrollState()
    LaunchedEffect(selectedFormat) {
        scrollState.scrollTo(0)
        horizontalScrollState.scrollTo(0)
    }
    val sourceName = source?.let { stringResource(it.kind.labelRes).ifBlank { it.name } }
    val suggestedFileName = remember(viewer, sourceName) {
        val label = viewer.nodeLabel.replace(Regex("[\\\\/:*?\"<>|]"), "_").trim().take(40).ifBlank { "bytes" }
        val sourcePart = sourceName?.replace(Regex("[\\\\/:*?\"<>|]"), "_").orEmpty()
        "packet${viewer.frameNumber}_${sourcePart}_$label.txt".trim('_', '.', ' ')
    }
    if (confirmSave && displayText != null) {
        SensitivePlaintextExportDialog(stringResource(R.string.tls_plaintext_export_bytes_scope), {
            confirmSave = false
            pendingSave = displayText
            saveLauncher.launch(suggestedFileName)
        }, { confirmSave = false })
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            tonalElevation = 6.dp,
            modifier = Modifier.fillMaxWidth(0.95f).fillMaxHeight(0.85f)
        ) {
            Column(Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 16.dp)) {
                Text(
                    viewer.nodeLabel,
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                sourceName?.let {
                    Text(
                        stringResource(R.string.bytes_source_label, it),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                if (actionRange != null) {
                    Text(
                        stringResource(R.string.byte_range, actionRange.first + 1, actionRange.last + 1),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (source != null && source.truncated) {
                    Text(
                        stringResource(R.string.bytes_source_truncated, source.availableLength, source.byteLength),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                if (state.errorCode != null) {
                    Text(
                        stringResource(R.string.bytes_source_stale),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                if (legacyRange == null && state.sources.size > 1) {
                    LazyRow(
                        modifier = Modifier.padding(top = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(state.sources, key = { it.id }) { descriptor ->
                            FilterChip(
                                selected = descriptor.id == state.sourceId,
                                onClick = { onSwitchSource(descriptor.id) },
                                label = { Text(stringResource(descriptor.kind.labelRes).ifBlank { descriptor.name }, maxLines = 1) }
                            )
                        }
                    }
                }
                LazyRow(
                    modifier = Modifier.padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(PacketBytesFormat.entries) { format ->
                        FilterChip(
                            selected = selectedFormat == format,
                            onClick = { selectedFormat = format },
                            enabled = actionsEnabled,
                            label = { Text(stringResource(format.labelRes)) }
                        )
                    }
                }
                Box(
                    Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .verticalScroll(scrollState)
                        .then(if (isHexDump) Modifier.horizontalScroll(horizontalScrollState) else Modifier)
                ) {
                    when {
                        state.isLoading -> CircularProgressIndicator(Modifier.align(Alignment.Center).padding(12.dp))
                        !actionsEnabled -> Text(
                            stringResource(R.string.bytes_source_unavailable),
                            Modifier.padding(12.dp),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        displayText == null -> Text(
                            stringResource(R.string.bytes_format_error),
                            Modifier.padding(12.dp),
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        else -> Text(
                            displayText,
                            Modifier.padding(8.dp),
                            softWrap = !isHexDump,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                Row(
                    Modifier.fillMaxWidth().padding(top = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(
                        onClick = {
                            displayText?.let {
                                clipboard.setText(AnnotatedString(it))
                                onCopied()
                            }
                        },
                        enabled = displayText != null
                    ) { Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.copy)) }
                    IconButton(
                        onClick = {
                            if (displayText != null) {
                                if (source?.kind == PacketDataSourceKind.DecryptedTls) confirmSave = true
                                else {
                                    pendingSave = displayText
                                    saveLauncher.launch(suggestedFileName)
                                }
                            }
                        },
                        enabled = displayText != null
                    ) { Icon(Icons.Default.SaveAlt, contentDescription = stringResource(R.string.save)) }
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) }
                }
            }
        }
    }
}

private fun discardIncompleteBytesExport(context: android.content.Context, uri: Uri) {
    if (runCatching { DocumentsContract.deleteDocument(context.contentResolver, uri) }.getOrDefault(false)) return
    // Some document providers refuse deletion but allow truncation. Never log the URI/content.
    runCatching { context.contentResolver.openOutputStream(uri, "wt")?.use { it.flush() } }
}

internal val PacketDataSourceKind.labelRes: Int
    get() = when (this) {
        PacketDataSourceKind.RawFrame -> R.string.bytes_source_kind_raw_frame
        PacketDataSourceKind.Reassembled -> R.string.bytes_source_kind_reassembled
        PacketDataSourceKind.DecryptedTls -> R.string.bytes_source_kind_decrypted_tls
        PacketDataSourceKind.Derived -> R.string.bytes_source_kind_derived
        PacketDataSourceKind.Unknown -> R.string.bytes_source_kind_unknown
    }

private val PacketBytesFormat.labelRes: Int
    get() = when (this) {
        PacketBytesFormat.RAW -> R.string.bytes_format_raw
        PacketBytesFormat.ASCII -> R.string.bytes_format_ascii
        PacketBytesFormat.JSON -> R.string.bytes_format_json
        PacketBytesFormat.HEX_DUMP -> R.string.bytes_format_hex_dump
        PacketBytesFormat.UTF8 -> R.string.bytes_format_utf8
    }
