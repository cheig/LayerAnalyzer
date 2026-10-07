// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.model.AnalysisJobPhase
import com.example.layanalyzer.model.AnalysisJobState

@Composable
fun AnalysisJobBanner(job: AnalysisJobState, onCancel: () -> Unit) {
    if (job.phase != AnalysisJobPhase.Running && job.phase != AnalysisJobPhase.Preparing) return
    Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(job.message ?: stringResource(R.string.analyzing), Modifier.weight(1f), style = MaterialTheme.typography.labelMedium)
            Text(job.scope.name, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            IconButton(onClick = onCancel) { Icon(Icons.Default.Stop, contentDescription = stringResource(R.string.cancel_analysis)) }
        }
        job.progress?.let { progress -> LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth()) }
            ?: LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
    }
}
