// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import android.net.Uri
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
import com.example.layanalyzer.viewmodel.PacketBytesViewerState

/** 内容区单次渲染字符上限：大帧防御性兜底，超出即截断并附尾注 */
private const val MAX_RENDER_CHARS = 256 * 1024

@Composable
fun PacketBytesDialog(
    state: PacketBytesViewerState,
    frameBytes: ByteArray,
    onDismiss: () -> Unit,
    onCopied: () -> Unit = {},
    onSaved: () -> Unit = {},
    onSaveError: () -> Unit = {}
) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    var selectedFormat by remember(state) { mutableStateOf(PacketBytesFormat.HEX_DUMP) }
    val slice = remember(state, frameBytes) {
        BytesFormatter.sliceClamped(frameBytes, state.start, state.endExclusive - state.start)
    }
    val formatted = remember(selectedFormat, slice) {
        runCatching { BytesFormatter.format(slice, selectedFormat) }.getOrNull()
    }
    val truncatedChars = ((formatted?.length ?: 0) - MAX_RENDER_CHARS).coerceAtLeast(0)
    val displayText = formatted?.let { text ->
        if (truncatedChars > 0) text.take(MAX_RENDER_CHARS) + "\n" + stringResource(R.string.bytes_truncated, truncatedChars) else text
    }

    var pendingSave by remember { mutableStateOf<String?>(null) }
    val saveLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri: Uri? ->
        val text = pendingSave
        pendingSave = null
        if (uri != null && text != null) {
            val written = runCatching {
                context.contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) } != null
            }.getOrDefault(false)
            if (written) onSaved() else onSaveError()
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
    val suggestedFileName = remember(state) {
        val label = state.nodeLabel.replace(Regex("[\\\\/:*?\"<>|]"), "_").trim().take(40).ifBlank { "bytes" }
        "packet${state.frameNumber}_${state.start}_$label.txt"
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
                    state.nodeLabel,
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    stringResource(R.string.byte_range, state.start + 1, state.endExclusive),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                LazyRow(
                    modifier = Modifier.padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(PacketBytesFormat.entries) { format ->
                        FilterChip(
                            selected = selectedFormat == format,
                            onClick = { selectedFormat = format },
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
                    if (displayText == null) {
                        Text(
                            stringResource(R.string.bytes_format_error),
                            Modifier.padding(12.dp),
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodyMedium
                        )
                    } else {
                        // Hex 转储关闭 softWrap 以保住偏移/hex/ASCII 三栏对齐，交给横向滚动；
                        // 其余格式开启 softWrap，超出屏宽自动折行，配合格式自身的换行符纵向滚动查看
                        Text(
                            displayText,
                            Modifier.padding(8.dp),
                            softWrap = isHexDump,
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
                                pendingSave = displayText
                                saveLauncher.launch(suggestedFileName)
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

private val PacketBytesFormat.labelRes: Int
    get() = when (this) {
        PacketBytesFormat.RAW -> R.string.bytes_format_raw
        PacketBytesFormat.ASCII -> R.string.bytes_format_ascii
        PacketBytesFormat.JSON -> R.string.bytes_format_json
        PacketBytesFormat.HEX_DUMP -> R.string.bytes_format_hex_dump
        PacketBytesFormat.UTF8 -> R.string.bytes_format_utf8
    }
