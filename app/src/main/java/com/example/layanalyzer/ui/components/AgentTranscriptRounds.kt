package com.example.layanalyzer.ui.components

import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentTokenUsage
import com.example.layanalyzer.model.isHostConfirmedToolResult

/**
 * One "asked question" as the round-accordion renders it.
 *
 * Derived purely from the visible transcript; nothing here is persisted. [key]
 * is the round-opening User message id, which is stable across save/resume
 * because message ids embed the cross-process run id, so it doubles as the
 * LazyColumn key and the [androidx.compose.runtime.saveable.Saver] payload for
 * the expanded-round state.
 */
data class AgentTranscriptRound(
    val key: String,
    val question: String,
    /** Every visible message of this round, including the opening User bubble. */
    val messages: List<AgentConversationItem>,
    val startedAtMillis: Long,
    /** The report the round's conclusion bubble carried, if it reached one. */
    val report: AgentReport?
)

/**
 * Group the visible transcript into rounds and place [currentReport].
 *
 * A User message opens a round; everything after it belongs to that round until
 * the next User message. Tool bubbles are filtered here so the round grouping
 * and the screen share one definition of "visible"; the ViewModel keeps Tool
 * rows for the model/context contract, the screen never renders them.
 *
 * [currentReport] is `uiState.report`. When some round's embedded report equals
 * it the report is already carried by a conclusion bubble and nothing happens.
 * Otherwise a non-empty round list takes it onto the last round — that covers
 * partial reports (whose round ends in an Error bubble) and archives whose
 * bubble report failed to decode. An empty round list means the archive holds
 * no messages at all (pre-schema-3 saves): the report goes back to the caller,
 * which renders it in the main-area fallback.
 */
internal fun buildTranscriptRounds(
    visibleMessages: List<AgentConversationItem>,
    currentReport: AgentReport? = null
): List<AgentTranscriptRound> {
    val messages = visibleMessages.filterNot { it.role == AgentConversationRole.Tool }
    if (messages.isEmpty()) return emptyList()

    val groups = mutableListOf<MutableList<AgentConversationItem>>()
    for (message in messages) {
        // Messages before the first User bubble should not exist (a run always
        // emits its question first); if one ever does, keep it in a defensive
        // leading round rather than dropping the content.
        if (message.role == AgentConversationRole.User || groups.isEmpty()) {
            groups += mutableListOf(message)
        } else {
            groups.last() += message
        }
    }

    val rounds = groups.mapIndexed { index, messages ->
        val first = messages.first()
        AgentTranscriptRound(
            key = first.id.ifBlank { "round-${index + 1}" },
            question = first.content,
            messages = messages.toList(),
            startedAtMillis = first.createdAtMillis,
            report = messages.lastOrNull { it.report != null }?.report
        )
    }

    if (currentReport != null && rounds.none { it.report == currentReport }) {
        val last = rounds.last()
        return rounds.dropLast(1) + last.copy(report = currentReport)
    }
    return rounds
}

/**
 * Reports of earlier rounds that no part of the round list carries: not
 * embedded in any round and not the current report. These are the orphans the
 * archive fallback keeps reachable — typically a retry's archived report whose
 * transcript was cleared with it.
 */
internal fun orphanArchivedRounds(
    rounds: List<AgentTranscriptRound>,
    currentReport: AgentReport?,
    pastReports: List<com.example.layanalyzer.model.AgentConversationRound>
): List<com.example.layanalyzer.model.AgentConversationRound> = pastReports.filterNot { archived ->
    archived.report == currentReport || rounds.any { it.report == archived.report }
}

// ----------------------------------------------------------------- item plan

/** Composable type of one plan entry; the LazyColumn's `contentType`. */
internal enum class AgentListItemKind {
    Scope,
    Model,
    ScenarioPackage,
    GatewayAccount,
    InterruptedJob,
    Suggestions,
    RoundHeader,
    RoundMessage,
    ReportHeader,
    ReportPartialNotice,
    ReportNoFindings,
    ReportFindingsTitle,
    ReportFinding,
    ReportLimitations,
    ReportNextSteps,
    ToolActivity,
    Phase,
    Error,
    PartialReportWarning,
    CompletionWarning,
    TokenUsage,
    Cancelled,
    SingleSummaryMode,
    ReportCoverage
}

/**
 * One LazyColumn entry, described as data.
 *
 * [agentListItemPlan] is the single source of truth for what the Agent screen
 * renders and in which order; the screen's LazyColumn is a dumb dispatcher over
 * this list. Scroll positioning looks the report anchor up here instead of
 * mirroring item counts by hand — the hand mirror is exactly what drifted
 * whenever a conditional item type was added without updating the counter.
 */
internal sealed interface AgentListItemSpec {
    val key: String
    val kind: AgentListItemKind
}

internal object AgentScopeSpec : AgentListItemSpec {
    override val key = "scope"
    override val kind = AgentListItemKind.Scope
}

internal object AgentModelSpec : AgentListItemSpec {
    override val key = "model"
    override val kind = AgentListItemKind.Model
}

internal object AgentScenarioPackageSpec : AgentListItemSpec {
    override val key = "scenario-package"
    override val kind = AgentListItemKind.ScenarioPackage
}

internal object AgentGatewayAccountSpec : AgentListItemSpec {
    override val key = "gateway-account"
    override val kind = AgentListItemKind.GatewayAccount
}

internal data class AgentInterruptedJobSpec(private val runId: String) : AgentListItemSpec {
    override val key = "interrupted-job-$runId"
    override val kind = AgentListItemKind.InterruptedJob
}

internal object AgentSuggestionsSpec : AgentListItemSpec {
    override val key = "suggestions"
    override val kind = AgentListItemKind.Suggestions
}

internal data class AgentRoundHeaderSpec(
    val round: AgentTranscriptRound,
    /** 1-based round number for the title. */
    val ordinal: Int,
    val expanded: Boolean,
    /** True for the last round while a run is in flight; it is not "interrupted". */
    val running: Boolean
) : AgentListItemSpec {
    override val key = "round-${round.key}"
    override val kind = AgentListItemKind.RoundHeader
}

internal data class AgentRoundMessageSpec(val message: AgentConversationItem) : AgentListItemSpec {
    override val key = message.id
    override val kind = AgentListItemKind.RoundMessage
}

internal data class AgentReportHeaderSpec(
    override val key: String,
    val report: AgentReport
) : AgentListItemSpec {
    override val kind = AgentListItemKind.ReportHeader
}

internal data class AgentReportPartialNoticeSpec(override val key: String) : AgentListItemSpec {
    override val kind = AgentListItemKind.ReportPartialNotice
}

internal data class AgentReportNoFindingsSpec(override val key: String) : AgentListItemSpec {
    override val kind = AgentListItemKind.ReportNoFindings
}

internal data class AgentReportFindingsTitleSpec(override val key: String) : AgentListItemSpec {
    override val kind = AgentListItemKind.ReportFindingsTitle
}

internal data class AgentReportFindingSpec(
    override val key: String,
    val finding: com.example.layanalyzer.model.AgentFinding,
    /** The report this finding belongs to; callbacks capture it. */
    val report: AgentReport,
    /** Historical rounds read: no save-to-workspace, no frame navigation. */
    val readOnly: Boolean
) : AgentListItemSpec {
    override val kind = AgentListItemKind.ReportFinding
}

internal data class AgentReportLimitationsSpec(
    override val key: String,
    val limitations: List<String>
) : AgentListItemSpec {
    override val kind = AgentListItemKind.ReportLimitations
}

internal data class AgentReportNextStepsSpec(
    override val key: String,
    val steps: List<String>
) : AgentListItemSpec {
    override val kind = AgentListItemKind.ReportNextSteps
}

/**
 * EVL-UI-07: the report's evidence-coverage badge, always emitted so a clean
 * round still shows "N / N frames cited". [readOnly] mirrors the report's
 * read-only flag and downgrades the uncited-frame chips to plain text;
 * [ReportCoverageBadge.from] suppresses the section when the run record and the
 * host limitation cannot be reconciled.
 */
internal data class AgentReportCoverageSpec(
    override val key: String,
    val report: AgentReport,
    val readOnly: Boolean
) : AgentListItemSpec {
    override val kind = AgentListItemKind.ReportCoverage
}

internal object AgentToolActivitySpec : AgentListItemSpec {
    override val key = "tool-activity"
    override val kind = AgentListItemKind.ToolActivity
}

internal object AgentPhaseSpec : AgentListItemSpec {
    override val key = "phase"
    override val kind = AgentListItemKind.Phase
}

internal data class AgentErrorSpec(val error: AgentError) : AgentListItemSpec {
    override val key = "error"
    override val kind = AgentListItemKind.Error
}

internal object AgentPartialReportWarningSpec : AgentListItemSpec {
    override val key = "partial-report-warning"
    override val kind = AgentListItemKind.PartialReportWarning
}

internal data class AgentCompletionWarningSpec(val message: String) : AgentListItemSpec {
    override val key = "completion-warning"
    override val kind = AgentListItemKind.CompletionWarning
}

internal data class AgentTokenUsageSpec(val usage: AgentTokenUsage) : AgentListItemSpec {
    override val key = "token-usage"
    override val kind = AgentListItemKind.TokenUsage
}

internal object AgentCancelledSpec : AgentListItemSpec {
    override val key = "cancelled"
    override val kind = AgentListItemKind.Cancelled
}

internal object AgentSingleSummaryModeSpec : AgentListItemSpec {
    override val key = "single-summary-mode"
    override val kind = AgentListItemKind.SingleSummaryMode
}

/**
 * A report's sections as plan entries, one finding per entry so a long report
 * still composes only the cards on screen.
 *
 * [keyPrefix] namespaces the section keys — the round accordion embeds one
 * report per expanded round and the main-area fallback renders at most one, so
 * the prefix keeps LazyColumn keys unique across both shapes. [readOnly] marks
 * a historical round's report: copy/export stay, saving findings and jumping to
 * frames do not.
 */
internal fun agentReportSpecs(
    report: AgentReport,
    keyPrefix: String,
    readOnly: Boolean
): List<AgentListItemSpec> {
    // Host-confirmed tool results are audit bookkeeping, not analysis: the step
    // trace already shows them, and the findings list keeps only conclusions.
    val visibleFindings = report.findings.filterNot { it.isHostConfirmedToolResult }
    val specs = mutableListOf<AgentListItemSpec>()
    specs += AgentReportHeaderSpec("$keyPrefix-header", report)
    if (report.completeness == AgentReportCompleteness.Partial ||
        report.completeness == AgentReportCompleteness.Incomplete
    ) {
        specs += AgentReportPartialNoticeSpec("$keyPrefix-partial")
    }
    if (visibleFindings.isEmpty()) {
        specs += AgentReportNoFindingsSpec("$keyPrefix-no-findings")
    } else {
        specs += AgentReportFindingsTitleSpec("$keyPrefix-findings-title")
        visibleFindings.forEachIndexed { index, finding ->
            specs += AgentReportFindingSpec(
                key = "$keyPrefix-finding-$index-${finding.id.ifBlank { finding.title }}",
                finding = finding,
                report = report,
                readOnly = readOnly
            )
        }
    }
    if (report.limitations.isNotEmpty()) {
        specs += AgentReportLimitationsSpec("$keyPrefix-limitations", report.limitations)
    }
    if (report.recommendedNextSteps.isNotEmpty()) {
        specs += AgentReportNextStepsSpec("$keyPrefix-next-steps", report.recommendedNextSteps)
    }
    // Unconditional: a clean run that cited every flagged frame still shows
    // "N / N frames cited". The section renders nothing when the badge cannot
    // be reconciled with the host limitation.
    specs += AgentReportCoverageSpec("$keyPrefix-coverage", report, readOnly)
    return specs
}

/**
 * Everything the Agent screen's LazyColumn renders, from the scope card down to
 * the current report, in order.
 *
 * The plan covers every conditional entry type — including interrupted-job and
 * partial-report-warning, the two whose omission from the old hand mirror
 * caused the drift — so an index derived from it can never disagree with what
 * is on screen. Rounds render as headers; the single expanded round also emits
 * its messages (conclusion bubbles hidden — their text duplicates the report)
 * and its embedded report. When no round exists, [fallbackReport] renders as
 * the main-area report, preserving the pre-accordion layout for very old
 * archives.
 */
internal fun agentListItemPlan(
    rounds: List<AgentTranscriptRound>,
    expandedRoundKey: String?,
    fallbackReport: AgentReport?,
    showScenarioPackage: Boolean,
    showGatewayAccount: Boolean,
    interruptedJobRunId: String?,
    showSuggestions: Boolean,
    hasToolActivity: Boolean,
    isRunning: Boolean,
    error: AgentError?,
    showPartialReportWarning: Boolean,
    completionWarningMessage: String?,
    tokenUsage: AgentTokenUsage?,
    isCancelled: Boolean,
    singleSummaryMode: Boolean
): List<AgentListItemSpec> {
    val plan = mutableListOf<AgentListItemSpec>()
    plan += AgentScopeSpec
    plan += AgentModelSpec
    if (showScenarioPackage) plan += AgentScenarioPackageSpec
    if (showGatewayAccount) plan += AgentGatewayAccountSpec
    if (interruptedJobRunId != null) plan += AgentInterruptedJobSpec(interruptedJobRunId)
    if (showSuggestions) plan += AgentSuggestionsSpec

    rounds.forEachIndexed { index, round ->
        val isLatest = index == rounds.lastIndex
        plan += AgentRoundHeaderSpec(
            round = round,
            ordinal = index + 1,
            expanded = round.key == expandedRoundKey,
            running = isRunning && isLatest
        )
        if (round.key == expandedRoundKey) {
            round.messages.forEach { message ->
                // The conclusion bubble's text duplicates the embedded report
                // header, so the bubble is dropped when a report follows it.
                if (message.report == null) {
                    plan += AgentRoundMessageSpec(message)
                }
            }
            round.report?.let { report ->
                plan += agentReportSpecs(
                    report = report,
                    keyPrefix = "report-${round.key}",
                    readOnly = !isLatest
                )
            }
        }
    }

    if (hasToolActivity) plan += AgentToolActivitySpec
    if (isRunning) plan += AgentPhaseSpec
    if (error != null) plan += AgentErrorSpec(error)
    if (showPartialReportWarning) plan += AgentPartialReportWarningSpec
    if (completionWarningMessage != null) plan += AgentCompletionWarningSpec(completionWarningMessage)
    if (tokenUsage != null) plan += AgentTokenUsageSpec(tokenUsage)
    if (isCancelled) plan += AgentCancelledSpec
    if (singleSummaryMode) plan += AgentSingleSummaryModeSpec

    if (rounds.isEmpty() && fallbackReport != null) {
        plan += agentReportSpecs(report = fallbackReport, keyPrefix = "report", readOnly = false)
    }
    return plan
}

/** The LazyColumn key of the current report's header, null when none is shown. */
internal val List<AgentListItemSpec>.reportAnchorKey: String?
    get() = filterIsInstance<AgentReportHeaderSpec>().firstOrNull()?.key
