// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.model.ExportUiState
import com.example.layanalyzer.model.HttpObjectEntry
import com.example.layanalyzer.model.HttpObjectsState
import com.example.layanalyzer.viewmodel.formatFileSize

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HttpObjectsScreen(
    state: HttpObjectsState,
    exportState: ExportUiState,
    onRefresh: () -> Unit,
    onExport: (HttpObjectEntry) -> Unit,
    onExportAll: () -> Unit,
    onPacketClick: (Long) -> Unit,
    onBack: () -> Unit
) {
    BackHandler(onBack = onBack)
    var query by remember { mutableStateOf("") }
    val visibleObjects = remember(state.objects, query) {
        val needle = query.trim()
        if (needle.isBlank()) {
            state.objects
        } else {
            state.objects.filter { entry ->
                entry.filename.contains(needle, ignoreCase = true) ||
                    entry.hostname.contains(needle, ignoreCase = true) ||
                    entry.contentType.contains(needle, ignoreCase = true)
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.http_objects)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                },
                actions = {
                    TextButton(
                        onClick = onExportAll,
                        enabled = state.objects.isNotEmpty() && !state.isLoading && !exportState.isExporting
                    ) {
                        Text(stringResource(R.string.export_all))
                    }
                    IconButton(
                        onClick = onRefresh,
                        enabled = !state.isLoading && !exportState.isExporting
                    ) {
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
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text(stringResource(R.string.filter_http_objects)) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) }
            )
            when {
                state.isLoading -> CircularProgressIndicator(
                    modifier = Modifier.align(Alignment.CenterHorizontally).padding(top = 32.dp)
                )
                state.error != null -> Text(
                    state.error,
                    modifier = Modifier.padding(top = 16.dp),
                    color = MaterialTheme.colorScheme.error
                )
                !state.analyzed -> Text(
                    stringResource(R.string.http_objects_not_analyzed),
                    modifier = Modifier.padding(top = 16.dp)
                )
                state.objects.isEmpty() -> Text(
                    stringResource(R.string.no_http_objects),
                    modifier = Modifier.padding(top = 16.dp)
                )
                visibleObjects.isEmpty() -> Text(
                    stringResource(R.string.no_matching_http_objects),
                    modifier = Modifier.padding(top = 16.dp)
                )
                else -> LazyColumn(modifier = Modifier.fillMaxSize().padding(top = 8.dp)) {
                    items(visibleObjects, key = { it.id }) { entry ->
                        HttpObjectRow(
                            entry = entry,
                            exportEnabled = !exportState.isExporting,
                            onExport = onExport,
                            onPacketClick = onPacketClick
                        )
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}

@Composable
private fun HttpObjectRow(
    entry: HttpObjectEntry,
    exportEnabled: Boolean,
    onExport: (HttpObjectEntry) -> Unit,
    onPacketClick: (Long) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        TextButton(onClick = { onPacketClick(entry.frameNumber) }, modifier = Modifier.width(72.dp)) {
            Text("#${entry.frameNumber}")
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                entry.filename,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                listOf(entry.hostname, entry.contentType, entry.size.formatFileSize())
                    .filter { it.isNotBlank() }
                    .joinToString("  "),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontFamily = FontFamily.Monospace
            )
        }
        IconButton(onClick = { onExport(entry) }, enabled = exportEnabled) {
            Icon(
                Icons.Default.Download,
                contentDescription = stringResource(R.string.export_http_object, entry.filename),
                modifier = Modifier.size(22.dp)
            )
        }
    }
}
