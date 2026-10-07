package com.example.layanalyzer.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DataArray
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.example.layanalyzer.R
import com.example.layanalyzer.model.ProtocolNode

@Immutable
private data class VisibleProtocolNode(
    val id: String,
    val node: ProtocolNode,
    val level: Int
)

@Composable
fun ProtocolTreeView(
    root: ProtocolNode,
    modifier: Modifier = Modifier,
    selectedNode: ProtocolNode?,
    defaultExpansionDepth: Int = 1,
    onFieldSelected: (ProtocolNode) -> Unit,
    onApplyFieldAsFilter: (String) -> Unit,
    onShowPacketBytes: (ProtocolNode) -> Unit = {}
) {
    val expanded = remember(root, defaultExpansionDepth) {
        mutableStateMapOf<String, Boolean>().apply {
            fun seed(node: ProtocolNode, id: String, level: Int): Boolean {
                var hasExceptionalField = node.severity.equals("error", true) || node.severity.equals("warn", true)
                node.children.forEachIndexed { index, child ->
                    if (seed(child, "$id.$index", level + 1)) hasExceptionalField = true
                }
                if (node.children.isNotEmpty()) {
                    this[id] = level < defaultExpansionDepth || hasExceptionalField
                }
                return hasExceptionalField
            }
            seed(root, "0", 0)
        }
    }
    val visibleNodes by remember(root, defaultExpansionDepth) {
        derivedStateOf {
            buildList {
                fun append(node: ProtocolNode, id: String, level: Int) {
                    add(VisibleProtocolNode(id, node, level))
                    if (expanded[id] == true) {
                        node.children.forEachIndexed { index, child -> append(child, "$id.$index", level + 1) }
                    }
                }
                append(root, "0", 0)
            }
        }
    }

    LazyColumn(modifier = modifier.fillMaxSize()) {
        items(visibleNodes, key = { it.id }, contentType = { "protocol-node" }) { visible ->
            ProtocolTreeRow(
                item = visible,
                expanded = expanded[visible.id] == true,
                selected = visible.node === selectedNode,
                onToggle = {
                    if (visible.node.children.isNotEmpty()) {
                        expanded[visible.id] = expanded[visible.id] != true
                    }
                },
                onSelect = { onFieldSelected(visible.node) },
                onApplyFieldAsFilter = onApplyFieldAsFilter,
                onShowPacketBytes = onShowPacketBytes
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ProtocolTreeRow(
    item: VisibleProtocolNode,
    expanded: Boolean,
    selected: Boolean,
    onToggle: () -> Unit,
    onSelect: () -> Unit,
    onApplyFieldAsFilter: (String) -> Unit,
    onShowPacketBytes: (ProtocolNode) -> Unit = {}
) {
    val node = item.node
    val isExceptional = node.severity.equals("error", true) || node.severity.equals("warn", true)
    var contextMenuExpanded by remember { mutableStateOf(false) }

    Box(Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(if (selected) MaterialTheme.colorScheme.secondaryContainer else Color.Transparent)
                .combinedClickable(
                    onClick = {
                        onToggle()
                        onSelect()
                    },
                    onLongClick = {
                        onSelect()
                        contextMenuExpanded = true
                    }
                )
                .padding(start = (item.level.coerceAtMost(3) * 12).dp, end = 8.dp, top = 5.dp, bottom = 5.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(28.dp)
                    .clickable(enabled = node.children.isNotEmpty(), onClick = onToggle),
                contentAlignment = Alignment.Center
            ) {
                if (node.children.isNotEmpty()) {
                    Icon(
                        if (expanded) Icons.Default.KeyboardArrowDown else Icons.AutoMirrored.Filled.KeyboardArrowRight,
                        contentDescription = stringResource(if (expanded) R.string.collapse else R.string.expand),
                        modifier = Modifier.size(18.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            if (item.level > 3) {
                Text("...", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
                Spacer(Modifier.width(4.dp))
            }
            Text(
                text = node.label,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = if (item.level <= 1 || isExceptional) FontWeight.SemiBold else FontWeight.Normal,
                color = severityColor(node.severity),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            node.value?.takeIf(String::isNotBlank)?.let { value ->
                Spacer(Modifier.width(8.dp))
                Text(
                    value,
                    modifier = Modifier.weight(0.55f, fill = false),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
        if (contextMenuExpanded) {
            val clipboard = LocalClipboardManager.current
            val filterExpression = remember(node.filter, node.filterValue, node.label) { node.asDisplayFilter() }
            val copyValue = remember(node.value, node.filterValue) { node.value ?: node.filterValue }
            DropdownMenu(
                expanded = true,
                onDismissRequest = { contextMenuExpanded = false }
            ) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.apply_as_filter)) },
                    leadingIcon = { Icon(Icons.Default.FilterAlt, contentDescription = null) },
                    enabled = filterExpression != null,
                    onClick = {
                        contextMenuExpanded = false
                        filterExpression?.let(onApplyFieldAsFilter)
                    }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.view_packet_bytes)) },
                    leadingIcon = { Icon(Icons.Default.DataArray, contentDescription = null) },
                    enabled = node.length > 0,
                    onClick = {
                        contextMenuExpanded = false
                        onShowPacketBytes(node)
                    }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.copy_field_value)) },
                    leadingIcon = { Icon(Icons.Default.ContentCopy, contentDescription = null) },
                    enabled = !copyValue.isNullOrEmpty(),
                    onClick = {
                        contextMenuExpanded = false
                        copyValue?.let { clipboard.setText(AnnotatedString(it)) }
                    }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.copy_field_description)) },
                    leadingIcon = { Icon(Icons.Default.Description, contentDescription = null) },
                    onClick = {
                        contextMenuExpanded = false
                        clipboard.setText(AnnotatedString(node.label))
                    }
                )
            }
        }
    }
}

@Composable
private fun severityColor(severity: String): Color = when (severity.lowercase()) {
    "warn" -> MaterialTheme.colorScheme.tertiary
    "error" -> MaterialTheme.colorScheme.error
    "note" -> MaterialTheme.colorScheme.primary
    else -> MaterialTheme.colorScheme.onSurface
}

fun ProtocolNode.asDisplayFilter(): String? {
    val field = filter?.trim()?.takeIf { it.isNotBlank() } ?: return null
    filterValue?.trim()?.takeIf { it.isNotBlank() }?.let { return "$field == $it" }
    val normalizedValue = label.substringAfterLast(":", missingDelimiterValue = "")
        .trim()
        .takeIf { it.isNotBlank() }
        ?.takeUnless { it.equals("true", true) || it.equals("false", true) }
        ?: return field
    return "$field == ${normalizedValue.asFilterValue()}"
}

private fun String.asFilterValue(): String {
    if (matches(Regex("-?\\d+(\\.\\d+)?")) || matches(Regex("0x[0-9a-fA-F]+"))) return this
    if (contains(":") && matches(Regex("[0-9a-fA-F:.]+"))) return this
    return "\"${replace("\\", "\\\\").replace("\"", "\\\"")}\""
}
