// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.example.layanalyzer.R
import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.ai.tools.AgentResultTruncator
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentTokenUsage
import androidx.compose.ui.res.stringResource
import java.util.Locale

/** Compact entry point for the full request/response transcript. */
@Composable
fun AgentModelInteractionList(
    interactions: List<AgentModelInteraction>,
    onOpen: (AgentModelInteraction) -> Unit,
    modifier: Modifier = Modifier
) {
    if (interactions.isEmpty()) return

    Column(modifier.fillMaxWidth()) {
        Text(
            text = stringResource(R.string.agent_model_interactions_count, interactions.size),
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(4.dp))
        interactions.forEachIndexed { index, interaction ->
            AgentModelInteractionRow(
                interaction = interaction,
                position = index + 1,
                onOpen = { onOpen(interaction) }
            )
        }
    }
}

@Composable
internal fun AgentModelInteractionRow(
    interaction: AgentModelInteraction,
    position: Int,
    onOpen: () -> Unit,
    embedded: Boolean = false
) {
    if (embedded) {
        AgentModelInteractionRowContent(
            interaction = interaction,
            position = position,
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onOpen)
                .padding(horizontal = 4.dp, vertical = 8.dp)
        )
        return
    }

    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
            .clickable(onClick = onOpen)
    ) {
        AgentModelInteractionRowContent(
            interaction = interaction,
            position = position,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
        )
    }
}

@Composable
private fun AgentModelInteractionRowContent(
    interaction: AgentModelInteraction,
    position: Int,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.agent_model_interaction_step, position),
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = stringResource(
                    R.string.agent_model_interaction_turn,
                    interaction.turn ?: 0,
                    interaction.attempt
                ) + " · " + responseKindLabel(interaction.response),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            AgentModelInteractionMetrics(interaction)
        }
        Spacer(Modifier.width(8.dp))
        Icon(
            imageVector = Icons.AutoMirrored.Filled.ArrowForward,
            contentDescription = stringResource(R.string.agent_model_interaction_view),
            modifier = Modifier.size(18.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

/** Large, scrollable modal for one exact normalized model exchange. */
@Composable
fun AgentModelInteractionDialog(
    interaction: AgentModelInteraction,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Surface(
            modifier = Modifier
                .fillMaxWidth(0.96f)
                .fillMaxHeight(0.9f)
                .widthIn(max = 720.dp),
            shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
            tonalElevation = 6.dp
        ) {
            Column(Modifier.fillMaxWidth().fillMaxHeight()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 16.dp, end = 4.dp, top = 8.dp, bottom = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.agent_model_interaction_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            text = stringResource(
                                R.string.agent_model_interaction_turn,
                                interaction.turn ?: 0,
                                interaction.attempt
                            ),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = stringResource(R.string.close)
                        )
                    }
                }
                HorizontalDivider()

                LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    item(key = "timing-title") {
                        InteractionSectionTitle(
                            text = stringResource(R.string.agent_model_interaction_timing)
                        )
                    }
                    item(key = "timing") {
                        AgentModelTimingCard(interaction)
                    }

                    item(key = "usage-title") {
                        InteractionSectionTitle(
                            text = stringResource(R.string.agent_model_interaction_usage)
                        )
                    }
                    item(key = "usage") {
                        AgentModelUsageCard(interaction.response.usage)
                    }

                    item(key = "request-title") {
                        InteractionSectionTitle(
                            text = stringResource(R.string.agent_model_interaction_request)
                        )
                    }

                    interaction.request.messages.forEachIndexed { index, message ->
                        item(key = "request-message-$index") {
                            AgentTranscriptMessage(
                                message = message,
                                blockKey = "${interaction.id}-message-$index"
                            )
                        }
                    }

                    if (interaction.request.toolDefinitions.isNotEmpty()) {
                        item(key = "tool-definitions-title") {
                            InteractionSectionTitle(
                                text = stringResource(R.string.agent_model_interaction_tools)
                            )
                        }
                        item(key = "tool-definitions") {
                            AgentCodeBlock(
                                text = formatToolDefinitions(interaction),
                                blockKey = "${interaction.id}-tools"
                            )
                        }
                    }

                    interaction.request.responseSchema?.let { schema ->
                        item(key = "response-schema-title") {
                            InteractionSectionTitle(
                                text = stringResource(R.string.agent_model_interaction_schema)
                            )
                        }
                        item(key = "response-schema") {
                            AgentCodeBlock(
                                text = formatJson(schema),
                                blockKey = "${interaction.id}-schema"
                            )
                        }
                    }

                    item(key = "response-title") {
                        InteractionSectionTitle(
                            text = stringResource(R.string.agent_model_interaction_response)
                        )
                    }
                    item(key = "response") {
                        AgentCodeBlock(
                            text = formatResponse(interaction.response),
                            blockKey = "${interaction.id}-response"
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun AgentModelInteractionMetrics(interaction: AgentModelInteraction) {
    val timing = modelInteractionTimingBreakdown(interaction)
    timing.responseDurationMillis?.let { responseDuration ->
        Text(
            text = stringResource(
                R.string.agent_model_interaction_timing_summary,
                formatAgentDurationMillis(responseDuration),
                timing.timeToFirstTokenMillis
                    ?.let(::formatAgentDurationMillis)
                    ?: stringResource(R.string.agent_model_interaction_metric_unavailable)
            ),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }

    val usage = interaction.response.usage
    Text(
        text = if (usage == null) {
            stringResource(R.string.agent_model_interaction_token_summary_unavailable)
        } else {
            val breakdown = modelInteractionUsageBreakdown(usage)
            stringResource(
                R.string.agent_model_interaction_token_summary,
                formatAgentTokenCount(breakdown.totalInputTokens),
                formatAgentTokenCount(breakdown.cachedInputTokens),
                formatAgentTokenCount(breakdown.outputTokens)
            )
        },
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@Composable
private fun AgentModelTimingCard(interaction: AgentModelInteraction) {
    val timing = modelInteractionTimingBreakdown(interaction)
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 11.dp, vertical = 9.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            AgentModelUsageRow(
                label = stringResource(R.string.agent_model_interaction_response_duration),
                value = timing.responseDurationMillis
                    ?.let(::formatAgentDurationMillis)
                    ?: stringResource(R.string.agent_model_interaction_metric_unavailable)
            )
            AgentModelUsageRow(
                label = stringResource(R.string.agent_model_interaction_time_to_first_token),
                value = timing.timeToFirstTokenMillis
                    ?.let(::formatAgentDurationMillis)
                    ?: stringResource(R.string.agent_model_interaction_metric_unavailable)
            )
        }
    }
}

@Composable
private fun AgentModelUsageCard(usage: AgentTokenUsage?) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        if (usage == null) {
            Text(
                text = stringResource(R.string.agent_model_interaction_usage_unavailable),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(10.dp)
            )
        } else {
            val breakdown = modelInteractionUsageBreakdown(usage)
            Column(
                modifier = Modifier.padding(horizontal = 11.dp, vertical = 9.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                AgentModelUsageRow(
                    label = stringResource(R.string.agent_model_interaction_usage_total_input),
                    value = formatAgentTokenCount(breakdown.totalInputTokens)
                )
                AgentModelUsageRow(
                    label = stringResource(R.string.agent_model_interaction_usage_uncached_input),
                    value = formatAgentTokenCount(breakdown.uncachedInputTokens)
                )
                AgentModelUsageRow(
                    label = stringResource(R.string.agent_model_interaction_usage_cache_read),
                    value = formatAgentTokenCount(breakdown.cachedInputTokens)
                )
                AgentModelUsageRow(
                    label = stringResource(R.string.agent_model_interaction_usage_cache_creation),
                    value = formatAgentTokenCount(breakdown.cacheCreationTokens)
                )
                AgentModelUsageRow(
                    label = stringResource(R.string.agent_model_interaction_usage_output),
                    value = formatAgentTokenCount(breakdown.outputTokens)
                )
                AgentModelUsageRow(
                    label = stringResource(R.string.agent_model_interaction_usage_cache_hit_rate),
                    value = formatAgentCacheHitRate(
                        cachedInputTokens = breakdown.cachedInputTokens,
                        totalInputTokens = breakdown.totalInputTokens
                    )
                )
            }
        }
    }
}

@Composable
private fun AgentModelUsageRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f)
        )
        Spacer(Modifier.width(12.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium
        )
    }
}

internal data class AgentModelUsageBreakdown(
    val totalInputTokens: Int,
    val uncachedInputTokens: Int,
    val cachedInputTokens: Int,
    val cacheCreationTokens: Int,
    val outputTokens: Int
)

internal data class AgentModelTimingBreakdown(
    val responseDurationMillis: Long?,
    val timeToFirstTokenMillis: Long?
)

internal fun modelInteractionTimingBreakdown(
    interaction: AgentModelInteraction
): AgentModelTimingBreakdown = AgentModelTimingBreakdown(
    responseDurationMillis = interaction.responseDurationMillis,
    timeToFirstTokenMillis = interaction.timeToFirstTokenMillis
)

internal fun formatAgentDurationMillis(durationMillis: Long): String {
    val value = durationMillis.coerceAtLeast(0L)
    if (value < 1_000L) return "$value ms"
    val roundedTenths = (value + 50L) / 100L
    return if (roundedTenths % 10L == 0L) {
        "${roundedTenths / 10L} s"
    } else {
        "${roundedTenths / 10L}.${roundedTenths % 10L} s"
    }
}

internal fun modelInteractionUsageBreakdown(usage: AgentTokenUsage): AgentModelUsageBreakdown {
    val totalInput = usage.inputTokens.coerceAtLeast(0)
    val cachedInput = usage.cachedInputTokens.coerceIn(0, totalInput)
    val cacheCreation = usage.cacheCreationTokens.coerceIn(0, totalInput - cachedInput)
    return AgentModelUsageBreakdown(
        totalInputTokens = totalInput,
        uncachedInputTokens = totalInput - cachedInput - cacheCreation,
        cachedInputTokens = cachedInput,
        cacheCreationTokens = cacheCreation,
        outputTokens = usage.outputTokens.coerceAtLeast(0)
    )
}

internal fun formatAgentCacheHitRate(
    cachedInputTokens: Int,
    totalInputTokens: Int
): String {
    val total = totalInputTokens.coerceAtLeast(0)
    if (total == 0) return "0.0%"
    val cached = cachedInputTokens.coerceIn(0, total)
    return String.format(Locale.ROOT, "%.1f%%", cached.toDouble() * 100.0 / total.toDouble())
}

@Composable
private fun InteractionSectionTitle(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.primary
    )
}

@Composable
private fun AgentTranscriptMessage(message: AgentModelMessage, blockKey: String) {
    val role = transcriptRoleLabel(message)
    val body = formatMessage(message)
    Surface(
        color = when (message.role) {
            AgentModelMessageRole.User -> MaterialTheme.colorScheme.primaryContainer
            AgentModelMessageRole.Tool -> MaterialTheme.colorScheme.tertiaryContainer
            AgentModelMessageRole.System -> MaterialTheme.colorScheme.surfaceVariant
            else -> MaterialTheme.colorScheme.secondaryContainer
        },
        shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(horizontal = 11.dp, vertical = 9.dp)) {
            Text(
                text = role,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Medium
            )
            Spacer(Modifier.height(5.dp))
            CollapsibleMonospaceBody(
                text = body.ifBlank {
                    stringResource(R.string.agent_model_interaction_no_content)
                },
                blockKey = blockKey
            )
            if (message.untrustedCaptureData) {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.agent_capture_derived),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun transcriptRoleLabel(message: AgentModelMessage): String = when (message.role) {
    AgentModelMessageRole.User -> stringResource(R.string.agent_role_you)
    AgentModelMessageRole.Assistant -> stringResource(R.string.agent_role_assistant)
    AgentModelMessageRole.Tool -> message.toolName
        ?.takeIf { it.isNotBlank() }
        ?.let { toolName -> agentToolDisplayName(toolName) }
        ?: stringResource(R.string.agent_role_tool)
    AgentModelMessageRole.System -> stringResource(R.string.agent_role_system)
    AgentModelMessageRole.Unknown -> stringResource(R.string.agent_role_system)
}

private fun formatMessage(message: AgentModelMessage): String = buildString {
    message.content.takeIf { it.isNotBlank() }?.let { append(it) }
    message.structuredContent?.let { structured ->
        if (isNotEmpty()) appendLine().appendLine()
        append("structuredContent:\n")
        append(formatJson(structured))
    }
    message.toolResult?.let { result ->
        if (isNotEmpty()) appendLine().appendLine()
        append("toolResult:\n")
        append(AgentJsonCodec.encodeToolResult(result))
    }
    if (message.toolCalls.isNotEmpty()) {
        if (isNotEmpty()) appendLine().appendLine()
        append("toolCalls:\n")
        append(
            formatJson(
                mapOf(
                    "toolCalls" to message.toolCalls.map { call ->
                        mapOf(
                            "toolCallId" to call.toolCallId,
                            "toolName" to call.toolName,
                            "arguments" to call.arguments,
                            "responseItemId" to call.responseItemId
                        )
                    }
                )
            )
        )
    }
}

private fun formatToolDefinitions(interaction: AgentModelInteraction): String = formatJson(
    mapOf(
        "tools" to interaction.request.toolDefinitions.map { tool ->
            mapOf(
                "name" to tool.name,
                "description" to tool.description,
                "inputSchema" to tool.inputSchema,
                "sensitivity" to tool.sensitivity.name,
                "defaultTimeoutMillis" to tool.defaultTimeoutMillis,
                "version" to tool.version
            )
        }
    )
)

private fun formatResponse(response: AgentModelResponse): String = when (response) {
    is AgentModelResponse.ToolCalls -> formatJson(
        mapOf(
            "type" to "tool_calls",
            "toolCalls" to response.calls.map { call ->
                mapOf(
                    "toolCallId" to call.toolCallId,
                    "toolName" to call.toolName,
                    "arguments" to call.arguments,
                    "responseItemId" to call.responseItemId
                )
            }
        )
    )
    is AgentModelResponse.Final -> response.rawJson
        ?: response.report?.let(AgentJsonCodec::encodeReport)
        ?: "{}"
    is AgentModelResponse.Refusal -> formatJson(
        mapOf(
            "type" to "refusal",
            "reason" to response.reason,
            "error" to response.error?.let(::formatError)
        )
    )
    is AgentModelResponse.Failure -> formatJson(
        mapOf(
            "type" to "failure",
            "error" to formatError(response.error)
        )
    )
}

private fun formatError(error: com.example.layanalyzer.model.AgentError): Map<String, Any?> = mapOf(
    "code" to error.code.name,
    "userMessage" to error.userMessage,
    "retryable" to error.retryable,
    "details" to error.details
)

private fun formatJson(value: Map<String, Any?>): String =
    AgentResultTruncator.encode(value)

@Composable
private fun AgentCodeBlock(text: String, blockKey: String) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        CollapsibleMonospaceBody(
            text = text,
            blockKey = blockKey,
            modifier = Modifier.padding(10.dp)
        )
    }
}

/**
 * Long transcript bodies are collapsed to a preview until tapped, and even when
 * expanded they stay inside a fixed viewport that scrolls on its own. Without the
 * cap, one large system prompt or tool result pushes every later section far down
 * the dialog's own scroll.
 */
@Composable
private fun CollapsibleMonospaceBody(
    text: String,
    blockKey: String,
    modifier: Modifier = Modifier
) {
    val lineCount = remember(text) { text.count { it == '\n' } + 1 }
    // Native JSON blocks arrive as one very long line, so lines alone cannot tell
    // a small block from a 20KB one. Characters catch what newlines miss.
    val isLong = lineCount > COLLAPSE_LINE_THRESHOLD || text.length > COLLAPSE_CHAR_THRESHOLD
    // Saved so an opened section survives rotation; keyed per block so sections
    // cannot inherit each other's expansion state. Long blocks start collapsed;
    // short ones start open but stay collapsible.
    var expanded by rememberSaveable(blockKey) { mutableStateOf(!isLong) }

    Column(modifier) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded }
                .padding(bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = if (lineCount > 1) {
                    stringResource(R.string.agent_model_interaction_lines, lineCount)
                } else {
                    stringResource(R.string.agent_model_interaction_chars, text.length)
                },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f)
            )
            Text(
                text = stringResource(if (expanded) R.string.collapse else R.string.expand),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary
            )
            Icon(
                imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                contentDescription = null,
                modifier = Modifier
                    .padding(start = 2.dp)
                    .size(16.dp),
                tint = MaterialTheme.colorScheme.primary
            )
        }

        val bodyModifier = if (expanded && isLong) {
            // Bounded height keeps this nested scroll legal inside the dialog's LazyColumn.
            Modifier
                .fillMaxWidth()
                .heightIn(max = EXPANDED_BLOCK_MAX_HEIGHT)
                .verticalScroll(rememberScrollState())
        } else {
            Modifier.fillMaxWidth()
        }

        SelectionContainer {
            Text(
                text = text,
                modifier = bodyModifier,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = if (expanded) Int.MAX_VALUE else COLLAPSED_PREVIEW_LINES,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

private const val COLLAPSE_LINE_THRESHOLD = 8
private const val COLLAPSE_CHAR_THRESHOLD = 400
private const val COLLAPSED_PREVIEW_LINES = 3
private val EXPANDED_BLOCK_MAX_HEIGHT = 260.dp

@Composable
private fun responseKindLabel(response: AgentModelResponse): String = when (response) {
    is AgentModelResponse.ToolCalls ->
        stringResource(R.string.agent_model_interaction_response_tool_calls)
    is AgentModelResponse.Final ->
        stringResource(R.string.agent_model_interaction_response_final)
    is AgentModelResponse.Refusal ->
        stringResource(R.string.agent_model_interaction_response_refusal)
    is AgentModelResponse.Failure ->
        stringResource(R.string.agent_model_interaction_response_failure)
}
