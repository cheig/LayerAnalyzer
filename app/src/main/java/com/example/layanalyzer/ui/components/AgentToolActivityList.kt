package com.example.layanalyzer.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AgentToolActivityStatus

/**
 * The audit trail of one Agent run.
 *
 * Everything rendered here is already public by construction: AI-06 builds an
 * [AgentToolActivity] from the tool *definition* and its provenance counters, so
 * an argument summary is a list of parameter names rather than their values.
 * That matters because a value can hold a Call-ID or a host name — this screen
 * must not become the place capture identifiers leak into a screenshot.  Model
 * reasoning and request bodies never reach this layer at all.
 */
@Composable
fun AgentToolActivityList(
    activities: List<AgentToolActivity>,
    modelInteractions: List<AgentModelInteraction> = emptyList(),
    onOpenModelInteraction: (AgentModelInteraction) -> Unit = {},
    modifier: Modifier = Modifier
) {
    if (activities.isEmpty() && modelInteractions.isEmpty()) return

    var expanded by rememberSaveable { mutableStateOf(false) }
    val interactionPlacements = placeModelInteractions(activities, modelInteractions)
    val visibleStepCount = activities.size + interactionPlacements.unassigned.size
    Column(modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(
                    R.string.agent_tool_activity_count,
                    visibleStepCount
                ),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f)
            )
            IconButton(
                onClick = { expanded = !expanded }
            ) {
                Icon(
                    imageVector = if (expanded) {
                        Icons.Default.ExpandLess
                    } else {
                        Icons.Default.ExpandMore
                    },
                    contentDescription = stringResource(
                        if (expanded) R.string.collapse else R.string.expand
                    ),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        if (expanded) {
            activities.forEach { activity ->
                AgentToolActivityRow(
                    activity = activity,
                    modelInteractions = interactionPlacements.byToolCallId[activity.toolCallId].orEmpty(),
                    onOpenModelInteraction = onOpenModelInteraction
                )
            }
            interactionPlacements.unassigned.forEach { indexed ->
                AgentModelInteractionRow(
                    interaction = indexed.interaction,
                    position = indexed.position,
                    onOpen = { onOpenModelInteraction(indexed.interaction) }
                )
            }
        }
    }
}

@Composable
internal fun AgentToolActivityRow(
    activity: AgentToolActivity,
    modelInteractions: List<IndexedModelInteraction> = emptyList(),
    onOpenModelInteraction: (AgentModelInteraction) -> Unit = {}
) {
    // Saved so expanding a step survives rotation; keyed by the tool call so
    // rows cannot inherit each other's expansion.
    var expanded by rememberSaveable(activity.toolCallId) { mutableStateOf(false) }
    val toolLabel = agentToolDisplayName(activity.toolName)
    val statusLabel = agentToolStatusLabel(activity.status)
    val arguments = activity.argumentsSummary.trim()
    val canExpand = arguments.isNotEmpty()

    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .let { if (canExpand) it.clickable { expanded = !expanded } else it }
                .padding(horizontal = 12.dp, vertical = 9.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                AgentToolStatusIcon(activity.status)
                Spacer(Modifier.width(9.dp))
                Column(Modifier.weight(1f)) {
                    // One description for the whole row: TalkBack should read
                    // "Expert information, Succeeded" as a unit rather than
                    // stepping through an icon, a name and a chip separately.
                    // The text itself stays in the tree — clearing it would hide
                    // the tool name from every semantics consumer, not just the
                    // screen reader this description is for.
                    Text(
                        text = toolLabel,
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.semantics {
                            contentDescription = "$toolLabel, $statusLabel"
                        }
                    )
                    AgentToolMetrics(activity)
                }
                Text(
                    text = statusLabel,
                    style = MaterialTheme.typography.labelSmall,
                    color = agentToolStatusColor(activity.status),
                    modifier = Modifier.clearAndSetSemantics {}
                )
                if (canExpand) {
                    Icon(
                        imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = stringResource(if (expanded) R.string.collapse else R.string.expand),
                        modifier = Modifier
                            .padding(start = 4.dp)
                            .size(18.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            if (canExpand && expanded) {
                Spacer(Modifier.height(6.dp))
                Text(
                    text = stringResource(R.string.agent_tool_arguments, arguments),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            activity.error?.let { error ->
                Spacer(Modifier.height(6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Default.ErrorOutline,
                        contentDescription = null,
                        Modifier.size(15.dp),
                        tint = MaterialTheme.colorScheme.error
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        text = "${error.code.name} · ${error.userMessage}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }

            if (modelInteractions.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                modelInteractions.forEach { indexed ->
                    AgentModelInteractionRow(
                        interaction = indexed.interaction,
                        position = indexed.position,
                        onOpen = { onOpenModelInteraction(indexed.interaction) },
                        embedded = true
                    )
                }
            }
        }
    }
}

internal data class IndexedModelInteraction(
    val position: Int,
    val interaction: AgentModelInteraction
)

internal data class AgentModelInteractionPlacements(
    val byToolCallId: Map<String, List<IndexedModelInteraction>>,
    val unassigned: List<IndexedModelInteraction>
)

/**
 * Places each exchange once. Tool-call responses belong to their first visible
 * call. A failed retry follows the later successful attempt in the same turn;
 * only a terminal exchange falls back to the last step already shown.
 */
internal fun placeModelInteractions(
    activities: List<AgentToolActivity>,
    interactions: List<AgentModelInteraction>
): AgentModelInteractionPlacements {
    val activityIds = activities.mapTo(linkedSetOf()) { it.toolCallId }
    val byToolCallId = linkedMapOf<String, MutableList<IndexedModelInteraction>>()
    val unassigned = mutableListOf<IndexedModelInteraction>()
    val directTargets = interactions.map { interaction ->
        (interaction.response as? AgentModelResponse.ToolCalls)
            ?.calls
            ?.firstOrNull { it.toolCallId in activityIds }
            ?.toolCallId
    }

    interactions.forEachIndexed { index, interaction ->
        val indexed = IndexedModelInteraction(index + 1, interaction)
        val retryTarget = if (interaction.response is AgentModelResponse.Failure) {
            interactions.indices
                .drop(index + 1)
                .firstOrNull { candidateIndex ->
                    val candidate = interactions[candidateIndex]
                    candidate.turn == interaction.turn &&
                        candidate.attempt > interaction.attempt &&
                        directTargets[candidateIndex] != null
                }
                ?.let(directTargets::get)
        } else {
            null
        }
        val targetToolCallId = directTargets[index]
            ?: retryTarget
            ?: activities.lastOrNull()?.toolCallId

        if (targetToolCallId == null) {
            unassigned += indexed
        } else {
            byToolCallId.getOrPut(targetToolCallId) { mutableListOf() } += indexed
        }
    }

    return AgentModelInteractionPlacements(byToolCallId, unassigned)
}

/** returned/total, truncation and duration — the auditable part of a step. */
@Composable
private fun AgentToolMetrics(activity: AgentToolActivity) {
    val parts = mutableListOf<String>()
    if (activity.totalCount > 0 || activity.returnedCount > 0) {
        parts += stringResource(
            R.string.agent_tool_counts,
            activity.returnedCount,
            activity.totalCount
        )
    }
    if (activity.truncated) parts += stringResource(R.string.agent_tool_truncated)
    if (activity.sampled) parts += stringResource(R.string.agent_tool_sampled)
    if (activity.resultBytes > 0) {
        parts += stringResource(R.string.agent_tool_result_bytes, activity.resultBytes)
    }
    parts += stringResource(R.string.agent_tool_scope, activity.scope.name)
    activity.queryMode?.takeIf(String::isNotBlank)?.let { queryMode ->
        parts += stringResource(R.string.agent_tool_query_mode, queryMode)
    }
    // AgentToolActivity carries timestamps rather than a duration, so a step
    // that is still running simply has nothing to show yet.
    val completedAt = activity.completedAtMillis
    if (completedAt != null && activity.startedAtMillis > 0L && completedAt >= activity.startedAtMillis) {
        parts += stringResource(R.string.agent_tool_duration, completedAt - activity.startedAtMillis)
    }
    if (parts.isEmpty()) return
    Text(
        text = parts.joinToString(" · "),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@Composable
private fun AgentToolStatusIcon(status: AgentToolActivityStatus) {
    when (status) {
        AgentToolActivityStatus.Running ->
            CircularProgressIndicator(Modifier.size(15.dp), strokeWidth = 2.dp)
        AgentToolActivityStatus.Queued ->
            Icon(Icons.Default.Schedule, null, Modifier.size(17.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
        AgentToolActivityStatus.Succeeded ->
            Icon(Icons.Default.CheckCircle, null, Modifier.size(17.dp), tint = agentToolStatusColor(status))
        AgentToolActivityStatus.Failed ->
            Icon(Icons.Default.ErrorOutline, null, Modifier.size(17.dp), tint = MaterialTheme.colorScheme.error)
        AgentToolActivityStatus.Cancelled ->
            Icon(Icons.Default.Close, null, Modifier.size(17.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
        AgentToolActivityStatus.Unknown ->
            Icon(Icons.Default.Schedule, null, Modifier.size(17.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun agentToolStatusColor(status: AgentToolActivityStatus): Color = when (status) {
    // Not colorScheme.primary: on a surfaceVariant card in dark mode the
    // primary tone sits too close to the container to read as "succeeded".
    AgentToolActivityStatus.Succeeded -> MaterialTheme.colorScheme.tertiary
    AgentToolActivityStatus.Failed -> MaterialTheme.colorScheme.error
    else -> MaterialTheme.colorScheme.onSurfaceVariant
}

@Composable
fun agentToolStatusLabel(status: AgentToolActivityStatus): String = stringResource(
    when (status) {
        AgentToolActivityStatus.Queued -> R.string.agent_tool_status_queued
        AgentToolActivityStatus.Running -> R.string.agent_tool_status_running
        AgentToolActivityStatus.Succeeded -> R.string.agent_tool_status_succeeded
        AgentToolActivityStatus.Failed -> R.string.agent_tool_status_failed
        AgentToolActivityStatus.Cancelled -> R.string.agent_tool_status_cancelled
        AgentToolActivityStatus.Unknown -> R.string.agent_tool_status_unknown
    }
)

/**
 * Localised name for a whitelisted tool.
 *
 * An unknown name falls through to the raw identifier rather than to a generic
 * "step": if the registry gains a tool before this mapping does, the trace
 * should still say which one ran.
 */
@Composable
fun agentToolDisplayName(toolName: String): String = when (toolName) {
    "get_capture_overview" -> stringResource(R.string.agent_tool_capture_overview)
    "get_expert_info" -> stringResource(R.string.agent_tool_expert_info)
    "validate_display_filter" -> stringResource(R.string.agent_tool_validate_filter)
    "query_packet_field_aggregate" -> "Packet field aggregate"
    else -> toolName.ifBlank { stringResource(R.string.agent_tool_status_unknown) }
}
