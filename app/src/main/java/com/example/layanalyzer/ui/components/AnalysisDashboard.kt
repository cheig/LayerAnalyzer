// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircleOutline
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.AssistChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.example.layanalyzer.R
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.AnalysisWorkspace
import com.example.layanalyzer.model.CaptureHealthSummary
import com.example.layanalyzer.model.HealthCard
import com.example.layanalyzer.model.HealthSeverity
import com.example.layanalyzer.model.ScenarioTemplate

@Composable
fun AnalysisDashboard(
    summary: CaptureHealthSummary,
    workspace: AnalysisWorkspace?,
    templates: List<ScenarioTemplate>,
    onRefresh: () -> Unit,
    onApplyFilter: (String) -> Unit,
    onToggleFavoriteFilter: (String) -> Unit,
    onPacketClick: (Long) -> Unit,
    onCollapse: () -> Unit
) {
    var selectedTemplate by remember { mutableStateOf<ScenarioTemplate?>(null) }
    Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.analysis_dashboard), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(scopeLabel(summary.scope), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            IconButton(onClick = onRefresh) {
                if (summary.isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Icon(Icons.Default.Refresh, contentDescription = stringResource(R.string.refresh_dashboard))
                }
            }
            IconButton(onClick = onCollapse) { Icon(Icons.Default.Close, contentDescription = stringResource(R.string.collapse_dashboard)) }
        }
        if (summary.error != null) {
            Text(summary.error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        if (summary.cards.isNotEmpty()) {
            AnalyzerCard(Modifier.fillMaxWidth()) {
                Row(Modifier.horizontalScroll(rememberScrollState()).height(IntrinsicSize.Min)) {
                    summary.cards.forEachIndexed { index, card ->
                        if (index > 0) {
                            VerticalDivider(
                                modifier = Modifier.fillMaxHeight().padding(vertical = AnalyzerSpacing.CardPadding),
                                color = MaterialTheme.colorScheme.outlineVariant
                            )
                        }
                        HealthCardView(card, onPacketClick, onApplyFilter)
                    }
                }
            }
        } else if (summary.isLoading) {
            Text(stringResource(R.string.analyzing), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(12.dp))
        }
        if (templates.isNotEmpty()) {
            Spacer(Modifier.height(6.dp))
            Text(stringResource(R.string.scenario_templates), style = MaterialTheme.typography.labelLarge)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                templates.forEach { template ->
                    FilterChip(
                        selected = selectedTemplate?.id == template.id,
                        onClick = { selectedTemplate = if (selectedTemplate?.id == template.id) null else template },
                        label = { Text(template.title) }
                    )
                }
            }
            selectedTemplate?.let { template ->
                Text(template.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    template.steps.forEach { step ->
                        AssistChip(onClick = { onApplyFilter(step.filter) }, label = { Text(step.title) })
                    }
                }
            }
        }
        workspace?.let { current ->
            if (current.filterHistory.isNotEmpty()) {
                Text(stringResource(R.string.recent_filters), style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 4.dp))
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    current.filterHistory.take(8).forEach { filter ->
                        AssistChip(
                            onClick = { onApplyFilter(filter) },
                            label = { Text(filter, maxLines = 1) },
                            leadingIcon = {
                                IconButton(onClick = { onToggleFavoriteFilter(filter) }) {
                                    Icon(if (filter in current.favoriteFilters) Icons.Default.Star else Icons.Default.StarBorder, contentDescription = stringResource(R.string.favorite_filter))
                                }
                            }
                        )
                    }
                }
            }
            if (current.filterHistory.isNotEmpty() || current.evidenceFrames.isNotEmpty()) {
                Text(
                    stringResource(R.string.workspace_summary, current.evidenceFrames.size, current.filterHistory.size, current.favoriteFilters.size),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }
    }
}

@Composable
private fun HealthCardView(card: HealthCard, onPacketClick: (Long) -> Unit, onApplyFilter: (String) -> Unit) {
    val color = when (card.severity) {
        HealthSeverity.Error -> MaterialTheme.colorScheme.error
        HealthSeverity.Warning -> MaterialTheme.colorScheme.tertiary
        HealthSeverity.Notice -> MaterialTheme.colorScheme.onSurfaceVariant
        HealthSeverity.Healthy -> MaterialTheme.colorScheme.primary
    }
    val icon = when (card.severity) {
        HealthSeverity.Error -> Icons.Default.ErrorOutline
        HealthSeverity.Warning -> Icons.Default.WarningAmber
        HealthSeverity.Notice -> Icons.Default.Info
        HealthSeverity.Healthy -> Icons.Default.CheckCircleOutline
    }
    val status = stringResource(
        when (card.severity) {
            HealthSeverity.Error -> R.string.agent_severity_error
            HealthSeverity.Warning -> R.string.agent_severity_warning
            HealthSeverity.Notice -> R.string.agent_severity_notice
            HealthSeverity.Healthy -> R.string.health_no_issues
        }
    )
    Column(
        modifier = Modifier.width(192.dp).padding(AnalyzerSpacing.CardPadding),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Icon(icon, contentDescription = status, tint = color, modifier = Modifier.size(18.dp))
            Text(
                card.title,
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Text(card.value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Medium)
        Text(
            card.detail,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 3,
            overflow = TextOverflow.Ellipsis
        )
        if (card.truncated) {
            Text(
                stringResource(R.string.result_truncated, card.returned, card.total),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.tertiary
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            card.frameNumber?.let { frame ->
                TextButton(onClick = { onPacketClick(frame) }, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.view_frame, frame))
                }
            }
            card.filter?.let { filter ->
                if (card.frameNumber == null) {
                    TextButton(onClick = { onApplyFilter(filter) }) {
                        Text(stringResource(R.string.generate_filter))
                    }
                } else {
                    IconButton(onClick = { onApplyFilter(filter) }) {
                        Icon(
                            Icons.Default.FilterAlt,
                            contentDescription = stringResource(R.string.generate_filter),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun scopeLabel(scope: AnalysisScope): String = stringResource(when (scope) {
    AnalysisScope.CompleteFile -> R.string.scope_complete_file
    AnalysisScope.CurrentFilter -> R.string.scope_current_filter
    AnalysisScope.CurrentSession -> R.string.scope_current_session
    AnalysisScope.RecentCapture -> R.string.scope_recent_capture
})
