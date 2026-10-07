// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.FactCheck
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentFindingTimelineEvent

/**
 * Read-only rendering of one validated finding.
 *
 * A report can only propose evidence.  The optional callbacks are user actions
 * owned by the screen host, where capture/session validation happens before any
 * navigation or workspace write.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun AgentFindingCard(
    finding: AgentFinding,
    onFrameClick: (Long) -> Unit,
    onEvidenceClick: ((AgentEvidence) -> Unit)? = null,
    onSaveToWorkspace: (() -> Unit)? = null,
    /**
     * Optional jump target for a related-signal chip (agent-report-2). The
     * destination screen does not exist yet, so callers keep it null and the
     * chips stay display-only.
     */
    onSignalClick: ((String) -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val severityLabel = agentSeverityLabel(finding.severity)
    val confidenceLabel = agentConfidenceLabel(finding.confidence)
    val primaryEvidence = finding.evidence.firstOrNull {
        it.frameNumber != null || !it.displayFilter.isNullOrBlank()
    } ?: finding.evidence.firstOrNull()
    val hasDetails = finding.timeline.isNotEmpty() ||
        finding.evidence.size > 1 ||
        finding.alternatives.isNotEmpty() ||
        finding.recommendations.isNotEmpty()
    var detailsExpanded by rememberSaveable(finding.id.ifBlank { finding.title }) {
        mutableStateOf(false)
    }
    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(Modifier.padding(13.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                agentFindingHeaderBadges(finding).forEachIndexed { index, badge ->
                    if (index > 0) Spacer(Modifier.width(8.dp))
                    when (badge) {
                        AgentFindingHeaderBadge.Severity -> AgentSeverityBadge(finding.severity)
                        is AgentFindingHeaderBadge.Polarity -> AgentPolarityBadge(badge.polarity)
                        is AgentFindingHeaderBadge.Hypothesis -> AgentHypothesisChip(badge.hypothesisId)
                    }
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    text = finding.title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f)
                )
            }
            // Severity and confidence are read together; a screen reader that
            // announced only the title would drop exactly the qualifiers that
            // tell the user how much to trust the conclusion.
            Spacer(Modifier.height(4.dp))
            Text(
                text = "$severityLabel · $confidenceLabel",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.semantics { contentDescription = "$severityLabel, $confidenceLabel" }
            )

            if (finding.conclusion.isNotBlank()) {
                Spacer(Modifier.height(8.dp))
                AgentMarkdownText(finding.conclusion)
            }

            if (detailsExpanded) {
                AgentFindingTimeline(finding.timeline, onFrameClick)
            }

            if (finding.evidence.isNotEmpty()) {
                Spacer(Modifier.height(10.dp))
                AgentSectionLabel(stringResource(R.string.agent_report_evidence))
                Spacer(Modifier.height(4.dp))
                val visibleEvidence = if (detailsExpanded) {
                    finding.evidence
                } else {
                    listOfNotNull(primaryEvidence)
                }
                AgentEvidenceRow(visibleEvidence, onFrameClick, onEvidenceClick)
                if (!detailsExpanded && finding.evidence.size > visibleEvidence.size) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = stringResource(
                            R.string.agent_finding_more_evidence,
                            finding.evidence.size - visibleEvidence.size
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // agent-report-2: host overview signals the finding relates to.
            // The jump target does not exist yet, so chips are display-only
            // unless a host supplies onSignalClick.
            if (agentFindingRelatedSignals(finding).isNotEmpty()) {
                Spacer(Modifier.height(10.dp))
                AgentSectionLabel(stringResource(R.string.agent_finding_related_signals))
                Spacer(Modifier.height(4.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    agentFindingRelatedSignals(finding).forEach { signalId ->
                        AgentSignalChip(signalId, onSignalClick)
                    }
                }
            }

            if (hasDetails || onSaveToWorkspace != null) {
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    if (hasDetails) {
                        TextButton(onClick = { detailsExpanded = !detailsExpanded }) {
                            Text(
                                stringResource(
                                    if (detailsExpanded) {
                                        R.string.agent_finding_details_hide
                                    } else {
                                        R.string.agent_finding_details_show
                                    }
                                )
                            )
                            Spacer(Modifier.width(4.dp))
                            Icon(
                                imageVector = if (detailsExpanded) {
                                    Icons.Default.ExpandLess
                                } else {
                                    Icons.Default.ExpandMore
                                },
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                    if (onSaveToWorkspace != null) {
                        TextButton(onClick = onSaveToWorkspace) {
                            Text(stringResource(R.string.agent_save_to_workspace))
                        }
                    }
                }
            }

            if (detailsExpanded) {
                AgentBulletSection(stringResource(R.string.agent_report_alternatives), finding.alternatives)
                AgentBulletSection(stringResource(R.string.agent_report_recommendations), finding.recommendations)
            }
        }
    }
}

/** A reusable, frame-linked phase timeline for structured diagnostic findings. */
@Composable
fun AgentFindingTimeline(
    events: List<AgentFindingTimelineEvent>,
    onFrameClick: (Long) -> Unit,
    modifier: Modifier = Modifier
) {
    if (events.isEmpty()) return
    Spacer(Modifier.height(10.dp))
    Column(modifier) {
        AgentSectionLabel(stringResource(R.string.agent_report_timeline))
        events.forEach { event ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 6.dp),
                verticalAlignment = Alignment.Top
            ) {
                Surface(
                    color = MaterialTheme.colorScheme.primary,
                    shape = RoundedCornerShape(4.dp),
                    modifier = Modifier
                        .padding(top = 6.dp)
                        .size(8.dp)
                ) {}
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(event.stage, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
                    if (event.detail.isNotBlank()) {
                        Text(
                            event.detail,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    event.elapsedMillis?.let { elapsed ->
                        Text(
                            text = "${elapsed} ms",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                event.frameNumber?.takeIf { it > 0L }?.let { frame ->
                    TextButton(onClick = { onFrameClick(frame) }) {
                        Text(stringResource(R.string.agent_evidence_frame, frame))
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AgentEvidenceRow(
    evidence: List<AgentEvidence>,
    onFrameClick: (Long) -> Unit,
    onEvidenceClick: ((AgentEvidence) -> Unit)?
) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        evidence.forEach { item -> AgentEvidenceChip(item, onFrameClick, onEvidenceClick) }
    }
}

/**
 * A single citation.
 *
 * Frame and display-filter citations are actionable only when a host callback
 * is supplied. The host repeats session and source-call checks before acting.
 */
@Composable
fun AgentEvidenceChip(
    evidence: AgentEvidence,
    onFrameClick: (Long) -> Unit,
    onEvidenceClick: ((AgentEvidence) -> Unit)? = null
) {
    val frame = evidence.frameNumber?.takeIf { it > 0L }
    val filter = evidence.displayFilter?.takeIf { it.isNotBlank() }
    val label = agentEvidenceLabel(evidence)
    // Resolved before the semantics lambda: that block is not a composable
    // scope, so stringResource cannot be called from inside it.
    val openLabel = frame?.let { stringResource(R.string.agent_evidence_open_frame, it) }

    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        shape = RoundedCornerShape(7.dp),
        modifier = if (frame != null || (filter != null && onEvidenceClick != null)) {
            Modifier
                .clickable {
                    onEvidenceClick?.invoke(evidence) ?: frame?.let(onFrameClick)
                }
                .semantics { contentDescription = openLabel ?: label }
        } else {
            Modifier
        }
    ) {
        Row(
            Modifier.padding(horizontal = 8.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = when (evidence.type) {
                    AgentEvidenceType.DisplayFilter -> Icons.Default.FilterAlt
                    AgentEvidenceType.Frame, AgentEvidenceType.Packet -> Icons.AutoMirrored.Filled.FactCheck
                    else -> Icons.Default.Info
                },
                contentDescription = null,
                modifier = Modifier.size(14.dp),
                tint = MaterialTheme.colorScheme.onSecondaryContainer
            )
            Spacer(Modifier.width(5.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                fontFamily = if (frame != null) FontFamily.Monospace else FontFamily.Default,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )
        }
    }
}

/**
 * Truncation, missing packets, scope and budget stops.
 *
 * Rendered in an error-tinted container rather than as plain body text: a
 * limitation is the reason a conclusion may be wrong, and it should not read as
 * a footnote under a confident-looking report.
 */
@Composable
fun AgentLimitationCard(limitations: List<String>, modifier: Modifier = Modifier) {
    if (limitations.isEmpty()) return
    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
    ) {
        Column(Modifier.padding(13.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.ErrorOutline,
                    contentDescription = null,
                    Modifier.size(17.dp),
                    tint = MaterialTheme.colorScheme.onErrorContainer
                )
                Spacer(Modifier.width(7.dp))
                Text(
                    text = stringResource(R.string.agent_report_limitations),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            limitations.forEach { limitation ->
                Spacer(Modifier.height(5.dp))
                AgentMarkdownText(
                    markdown = limitation,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    listItem = true
                )
            }
        }
    }
}

@Composable
fun AgentSeverityBadge(severity: AgentFindingSeverity) {
    val label = agentSeverityLabel(severity)
    Surface(
        color = agentSeverityContainerColor(severity),
        shape = RoundedCornerShape(6.dp),
        // The card already announces "severity, confidence" as one phrase, so
        // this badge stays silent instead of repeating it.
        modifier = Modifier.clearAndSetSemantics {}
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Medium,
            color = agentSeverityContentColor(severity),
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp)
        )
    }
}

/**
 * agent-report-2 polarity of the finding's core claim.
 *
 * Rendered only for declared polarities ([AgentFindingPolarity.Unknown] is
 * undeclared and stays invisible), mirroring the exporter's emit-only-when-
 * non-default rule.
 */
@Composable
fun AgentPolarityBadge(polarity: AgentFindingPolarity) {
    val label = agentPolarityLabel(polarity)
    Surface(
        color = agentPolarityContainerColor(polarity),
        shape = RoundedCornerShape(6.dp),
        // The card is announced as one phrase, so the badge stays silent
        // exactly like the severity badge.
        modifier = Modifier.clearAndSetSemantics {}
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Medium,
            color = agentPolarityContentColor(polarity),
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp)
        )
    }
}

/** Compact reference to the plan hypothesis this finding is tied to. */
@Composable
private fun AgentHypothesisChip(hypothesisId: String) {
    // Resolved before the semantics lambda: that block is not a composable
    // scope, so stringResource cannot be called from inside it.
    val chipDescription = stringResource(R.string.agent_finding_hypothesis, hypothesisId)
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = RoundedCornerShape(6.dp),
        modifier = Modifier.semantics { contentDescription = chipDescription }
    ) {
        Text(
            text = hypothesisId,
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp)
        )
    }
}

/**
 * A host overview signal the finding relates to (agent-report-2).
 *
 * Clickable only when the host supplies a jump callback; the destination
 * screen does not exist yet, so the chip is display-only by default.
 */
@Composable
private fun AgentSignalChip(signalId: String, onSignalClick: ((String) -> Unit)?) {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        shape = RoundedCornerShape(7.dp),
        modifier = if (onSignalClick != null) {
            Modifier
                .clickable { onSignalClick(signalId) }
                .semantics { contentDescription = signalId }
        } else {
            Modifier
        }
    ) {
        Row(
            Modifier.padding(horizontal = 8.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Info,
                contentDescription = null,
                modifier = Modifier.size(14.dp),
                tint = MaterialTheme.colorScheme.onSecondaryContainer
            )
            Spacer(Modifier.width(5.dp))
            Text(
                text = signalId,
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )
        }
    }
}

@Composable
private fun AgentBulletSection(title: String, items: List<String>) {
    if (items.isEmpty()) return
    Spacer(Modifier.height(10.dp))
    Column {
        AgentSectionLabel(title)
        items.forEach { item ->
            Spacer(Modifier.height(6.dp))
            AgentMarkdownText(item, style = MaterialTheme.typography.bodySmall, listItem = true)
        }
    }
}

@Composable
internal fun AgentSectionLabel(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.labelMedium,
        fontWeight = FontWeight.Medium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@Composable
private fun agentEvidenceLabel(evidence: AgentEvidence): String {
    evidence.frameNumber?.let { return stringResource(R.string.agent_evidence_frame, it) }
    evidence.displayFilter?.takeIf { it.isNotBlank() }?.let {
        return stringResource(R.string.agent_evidence_filter, it)
    }
    val metric = evidence.metric?.takeIf { it.isNotBlank() }
    if (metric != null) {
        return stringResource(R.string.agent_evidence_metric, metric, evidence.observedValue.orEmpty())
    }
    evidence.field?.takeIf { it.isNotBlank() }?.let {
        return stringResource(R.string.agent_evidence_field, it)
    }
    return evidence.observation.ifBlank { stringResource(R.string.agent_report_evidence) }
}

@Composable
fun agentSeverityLabel(severity: AgentFindingSeverity): String = stringResource(
    when (severity) {
        AgentFindingSeverity.Info -> R.string.agent_severity_info
        AgentFindingSeverity.Notice -> R.string.agent_severity_notice
        AgentFindingSeverity.Warning -> R.string.agent_severity_warning
        AgentFindingSeverity.Error -> R.string.agent_severity_error
        AgentFindingSeverity.Critical -> R.string.agent_severity_critical
        AgentFindingSeverity.Unknown -> R.string.agent_severity_unknown
    }
)

@Composable
fun agentConfidenceLabel(confidence: AgentConfidence): String = stringResource(
    when (confidence) {
        AgentConfidence.Low -> R.string.agent_confidence_low
        AgentConfidence.Medium -> R.string.agent_confidence_medium
        AgentConfidence.High -> R.string.agent_confidence_high
        AgentConfidence.Unknown -> R.string.agent_confidence_unknown
    }
)

@Composable
fun agentPolarityLabel(polarity: AgentFindingPolarity): String = stringResource(
    when (polarity) {
        AgentFindingPolarity.Positive -> R.string.agent_finding_polarity_positive
        AgentFindingPolarity.Negative -> R.string.agent_finding_polarity_negative
        AgentFindingPolarity.Neutral, AgentFindingPolarity.Unknown ->
            R.string.agent_finding_polarity_neutral
    }
)

/**
 * Severity colours come from the theme's container roles rather than fixed
 * values so they keep their contrast in dark mode.
 */
@Composable
private fun agentSeverityContainerColor(severity: AgentFindingSeverity): Color = when (severity) {
    AgentFindingSeverity.Critical, AgentFindingSeverity.Error -> MaterialTheme.colorScheme.errorContainer
    AgentFindingSeverity.Warning -> MaterialTheme.colorScheme.tertiaryContainer
    AgentFindingSeverity.Notice, AgentFindingSeverity.Info -> MaterialTheme.colorScheme.secondaryContainer
    AgentFindingSeverity.Unknown -> MaterialTheme.colorScheme.surfaceVariant
}

@Composable
private fun agentSeverityContentColor(severity: AgentFindingSeverity): Color = when (severity) {
    AgentFindingSeverity.Critical, AgentFindingSeverity.Error -> MaterialTheme.colorScheme.onErrorContainer
    AgentFindingSeverity.Warning -> MaterialTheme.colorScheme.onTertiaryContainer
    AgentFindingSeverity.Notice, AgentFindingSeverity.Info -> MaterialTheme.colorScheme.onSecondaryContainer
    AgentFindingSeverity.Unknown -> MaterialTheme.colorScheme.onSurfaceVariant
}

/**
 * Declared polarities render a badge; [AgentFindingPolarity.Unknown] means the
 * model left the claim's direction undeclared and stays invisible, mirroring
 * the exporter's emit-only-when-non-default rule.
 */
internal fun AgentFindingPolarity.shouldRenderBadge(): Boolean = this != AgentFindingPolarity.Unknown

/**
 * One slot in the finding card's header row, left to right.
 *
 * The severity badge is always present and always first; the polarity badge
 * and the hypothesis reference chip appear only when the finding declares
 * them (agent-report-2 defaults stay invisible).
 */
internal sealed interface AgentFindingHeaderBadge {
    /** The severity badge, always the first header item. */
    object Severity : AgentFindingHeaderBadge

    /** The polarity badge; only present for declared polarities. */
    data class Polarity(val polarity: AgentFindingPolarity) : AgentFindingHeaderBadge

    /** The hypothesis reference chip; only present when a hypothesis id is set. */
    data class Hypothesis(val hypothesisId: String) : AgentFindingHeaderBadge
}

internal fun agentFindingHeaderBadges(finding: AgentFinding): List<AgentFindingHeaderBadge> {
    val badges = mutableListOf<AgentFindingHeaderBadge>(AgentFindingHeaderBadge.Severity)
    if (finding.polarity.shouldRenderBadge()) {
        badges += AgentFindingHeaderBadge.Polarity(finding.polarity)
    }
    finding.hypothesisId?.let { badges += AgentFindingHeaderBadge.Hypothesis(it) }
    return badges
}

/** Related-signal chips under the evidence section; empty hides the whole section. */
internal fun agentFindingRelatedSignals(finding: AgentFinding): List<String> = finding.relatedSignals

/** Polarity colours reuse the theme's container roles, like severity. */
@Composable
private fun agentPolarityContainerColor(polarity: AgentFindingPolarity): Color = when (polarity) {
    AgentFindingPolarity.Positive -> MaterialTheme.colorScheme.tertiaryContainer
    AgentFindingPolarity.Negative -> MaterialTheme.colorScheme.errorContainer
    AgentFindingPolarity.Neutral, AgentFindingPolarity.Unknown -> MaterialTheme.colorScheme.surfaceVariant
}

@Composable
private fun agentPolarityContentColor(polarity: AgentFindingPolarity): Color = when (polarity) {
    AgentFindingPolarity.Positive -> MaterialTheme.colorScheme.onTertiaryContainer
    AgentFindingPolarity.Negative -> MaterialTheme.colorScheme.onErrorContainer
    AgentFindingPolarity.Neutral, AgentFindingPolarity.Unknown -> MaterialTheme.colorScheme.onSurfaceVariant
}
