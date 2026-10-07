// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

/**
 * JSON-compatible object used at the boundary between the host and an Agent.
 *
 * The type deliberately does not expose JSONObject.  Implementations may use
 * maps/lists internally, while [com.example.layanalyzer.ai.serialization.AgentJsonCodec]
 * owns the wire representation.
 */
typealias AgentJsonObject = Map<String, Any?>

typealias AgentJsonArray = List<Any?>

/** Lifecycle phases exposed by the Agent UI and orchestration layer. */
enum class AgentRunPhase {
    Idle,
    Preparing,
    /** The bounded evidence-gathering part of a run. */
    Investigating,
    WaitingForModel,
    RunningTool,
    /** A no-tools request that must turn existing evidence into a report. */
    Finalizing,
    /** The single, narrow correction request after report validation. */
    Revising,
    ValidatingReport,
    Completed,
    Failed,
    /** A terminal model failure for which the host retained a partial report. */
    FailedWithPartialReport,
    Cancelled
}

/** How much of the requested analysis was completed. */
enum class AgentReportCompleteness {
    Complete,
    Partial,
    Incomplete,
    Unknown
}

/** Whether a run used the full tool loop or the bounded one-shot fallback. */
enum class AgentAnalysisMode {
    FullAgent,
    SingleSummary
}

/** User-facing impact of a finding.  Unknown is intentionally non-assertive. */
enum class AgentFindingSeverity {
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Unknown
}

/** Declared polarity of a finding's core claim; `Unknown` means undeclared. */
enum class AgentFindingPolarity {
    Positive,
    Negative,
    Neutral,
    Unknown
}

/** Confidence assigned to a conclusion after evidence validation. */
enum class AgentConfidence {
    Low,
    Medium,
    High,
    Unknown
}

/** Controls which classes of capture data may be sent to a model. */
enum class AgentPrivacyMode {
    LocalOnly,
    RedactedMetadata,
    UnredactedMetadata,
    SelectedPayload,
    Unknown
}

/** Sensitivity of a value returned by a local analysis tool. */
enum class AgentDataSensitivity {
    Aggregate,
    Metadata,
    Identifier,
    Payload,
    Credential,
    Unknown
}

/** Stable, provider-neutral error identifiers used across the Agent stack. */
enum class AgentErrorCode {
    NO_CAPTURE,
    SESSION_CHANGED,
    FILTER_CONFLICT,
    INVALID_TOOL_ARGUMENTS,
    INVALID_DISPLAY_FILTER,
    TOOL_TIMEOUT,
    TOOL_RESULT_TOO_LARGE,
    MODEL_AUTH_FAILED,
    MODEL_RATE_LIMITED,
    MODEL_UNAVAILABLE,
    MODEL_INPUT_CONTEXT_LIMIT,
    MODEL_OUTPUT_TRUNCATED,
    MODEL_RESPONSE_TOO_LARGE,
    MODEL_RESPONSE_MALFORMED,
    MODEL_TIMEOUT,
    PRIVACY_BLOCKED,
    MAX_STEPS_REACHED,
    CONTEXT_LIMIT,
    CANCELLED,
    INTERNAL_ERROR
}

/**
 * Structured error safe to display and log after normal redaction.
 *
 * [details] is deliberately an untyped, JSON-compatible map so callers can
 * report safe values such as a field path or a limit.  Callers must never put
 * exception messages, stack traces, credentials, or packet payloads here.
 */
data class AgentError(
    val code: AgentErrorCode,
    val userMessage: String,
    val retryable: Boolean = false,
    val details: AgentJsonObject = emptyMap()
)

/** Immutable identity and scope captured when an Agent run starts. */
data class AgentCaptureSnapshot(
    val sessionHandle: Long = 0L,
    val fileFingerprint: String = "",
    val frameCount: Int = 0,
    val displayFilter: String = "",
    val scope: AnalysisScope = AnalysisScope.CompleteFile,
    val startedAtMillis: Long = 0L,
    /** Generation of the owning Agent run. */
    val analysisGeneration: Long = 0L,
    /** Shared native-session generation published by CaptureSessionCoordinator. */
    val sessionGeneration: Long = 0L,
    /** Explicit alias retained when session and Agent generations differ. */
    val agentGeneration: Long = analysisGeneration,
    /**
     * Version of the dissection-affecting configuration (Decode As, name
     * resolution) in force when this snapshot was taken.  Part of the AI-24
     * deterministic tool cache key.
     */
    val analysisConfigVersion: Int = 1,
    /**
     * EVL-CONTEXT-04: size of the evidence set the `displayFilterOverride`
     * was compiled from, recorded at submission time.  Null — every path
     * without an override — keeps the report page silent about the analysis
     * scope; no count is ever invented here.
     */
    val evidenceFrameCount: Int? = null
) {
    /** Compatibility constructor matching the coordinator's shorter vocabulary. */
    constructor(
        sessionHandle: Long,
        fingerprint: String,
        frameCount: Int,
        displayFilter: String,
        scope: AnalysisScope,
        generation: Long
    ) : this(
        sessionHandle = sessionHandle,
        fileFingerprint = fingerprint,
        frameCount = frameCount,
        displayFilter = displayFilter,
        scope = scope,
        startedAtMillis = 0L,
        analysisGeneration = generation,
        sessionGeneration = generation,
        agentGeneration = generation
    )

    /** Alias used by newer coordination code. */
    val captureFingerprint: String
        get() = fileFingerprint

    val fingerprint: String
        get() = fileFingerprint

    /** Alias used by the session coordinator. */
    val generation: Long
        get() = sessionGeneration.takeIf { it > 0L } ?: analysisGeneration

    val agentRunGeneration: Long
        get() = agentGeneration.takeIf { it > 0L } ?: analysisGeneration
}

/**
 * Decide the display filter an Agent run's [AgentCaptureSnapshot] is framed
 * with (EVL-CONTEXT-03).
 *
 * [override] is the `displayFilterOverride` an evidence-workflow submission
 * ("analyze with this evidence") passes down the pipeline; [sessionFilter] is
 * the capture session's currently applied filter.  A null, blank, or
 * whitespace-only override keeps [sessionFilter], so every existing caller
 * that passes no override behaves exactly as before.  A usable override is
 * trimmed and replaces [sessionFilter] wholesale — the [AnalysisScope] is
 * deliberately untouched; the override widens or narrows the packet view, not
 * the scope mechanism.
 *
 * Contract the caller must honour: the override has already passed
 * `validateDisplayFilter` (the same NativeEngine validation the session's
 * applied filter went through when it was applied) before it reaches a run.
 * The agent deliberately does not run a second validation path; an invalid
 * override fails at the first tool read, exactly like any other filter
 * mismatch between the session and the engine.
 */
internal fun resolveDisplayFilter(sessionFilter: String, override: String?): String =
    override?.trim()?.takeIf { it.isNotEmpty() } ?: sessionFilter

/**
 * Pure decisions for the evidence-override UI consistency contract
 * (EVL-CONTEXT-04).
 *
 * An evidence-workflow submission frames its run with a
 * `displayFilterOverride` compiled from the workspace evidence set.  Two
 * things must stay in step with that override: the packet list the user
 * looks at, and the report they get back.  Both decisions are pure so they
 * can be unit-tested without a ViewModel harness.
 */
object AgentEvidenceScope {

    /**
     * The frame count the report page renders as "Analysis scope: evidence
     * set (N frames)", or null when the line must be hidden.
     *
     * The line is shown only when the run actually carried a usable override
     * *and* a positive frame count was recorded at submission time.  A null
     * or blank override (no evidence workflow), a missing count, or a zero
     * count (empty evidence set cannot start a run) all hide the line — the
     * label never invents a number.
     */
    fun reportFrameCount(displayFilterOverride: String?, evidenceFrameCount: Int?): Int? {
        val override = displayFilterOverride?.trim().orEmpty()
        if (override.isEmpty()) return null
        val count = evidenceFrameCount ?: return null
        return count.takeIf { it > 0 }
    }

    /**
     * Whether the packet list must be re-framed to [displayFilterOverride]
     * when the run starts, so what the user sees matches what the agent
     * analyzes.
     *
     * Only a usable override triggers an application, and only when it
     * differs from [appliedDisplayFilter] — re-applying an identical filter
     * would churn the visible list and the filter history for no change.
     * The caller applies the result through the normal `applyDisplayFilter`
     * path; any failure surfaces that path's existing error handling, never
     * a silent pretend-applied state.
     */
    fun shouldApplyOverrideToPacketList(
        displayFilterOverride: String?,
        appliedDisplayFilter: String?
    ): Boolean {
        val override = displayFilterOverride?.trim().orEmpty()
        if (override.isEmpty()) return false
        val applied = appliedDisplayFilter?.trim().orEmpty()
        return override != applied
    }
}

/**
 * Host-owned description of every layer that may remove tool-result data.
 * Counts describe the payload actually returned to the model; continuation is
 * intentionally short and contains only safe paging/read hints.
 */
data class AgentTruncationInfo(
    val sourceTruncated: Boolean = false,
    val quotaTruncated: Boolean = false,
    val payloadTruncated: Boolean = false,
    val contextCompacted: Boolean = false,
    val returned: Long = 0L,
    val total: Long = 0L,
    val omittedFrames: List<Long> = emptyList(),
    val omittedPaths: List<String> = emptyList(),
    val continuation: AgentJsonObject? = null
) {
    val truncated: Boolean
        get() = sourceTruncated || quotaTruncated || payloadTruncated || contextCompacted
}

/**
 * Audit/provenance information attached to every local tool result.
 * localSessionReference must be a non-exportable, already-hashed reference;
 * never place a native pointer or a file path in this object.
 */
data class AgentProvenance(
    val captureFingerprint: String = "",
    val localSessionReference: String? = null,
    val scope: AnalysisScope = AnalysisScope.CompleteFile,
    val displayFilter: String = "",
    val toolName: String = "",
    val toolVersion: String = "1",
    val normalizedArgumentsHash: String = "",
    val generatedAtMillis: Long = 0L,
    val returnedCount: Long = 0L,
    val totalCount: Long = 0L,
    val truncated: Boolean = false,
    val durationMillis: Long = 0L,
    /** Native Scoped Query or legacy Filter Lease, when applicable. */
    val queryMode: String? = null,
    val truncation: AgentTruncationInfo = AgentTruncationInfo()
) {
    /** Alias retained for callers that use the term session reference. */
    val sessionReference: String?
        get() = localSessionReference
}

/** Provenance for a complete report, including model/playbook versions. */
data class AgentReportProvenance(
    val captureFingerprint: String = "",
    val scope: AnalysisScope = AnalysisScope.CompleteFile,
    val displayFilter: String = "",
    val modelId: String = "",
    val promptVersion: String = "",
    val playbookVersion: String? = null,
    val generatedAtMillis: Long = 0L,
    val toolCallIds: List<String> = emptyList(),
    val agentVersion: String? = null,
    val startedAtMillis: Long? = null,
    val completedAtMillis: Long? = null,
    /**
     * EVL-CONTEXT-04: number of frames in the evidence set the run's
     * `displayFilter` override was compiled from, or null when the run was
     * not framed by an evidence override.  Rendered by the report page as
     * "Analysis scope: evidence set (N frames)".
     */
    val evidenceFrameCount: Int? = null
) {
    val analysisScope: AnalysisScope
        get() = scope
}

/** A provider-neutral request for one whitelisted local tool. */
data class AgentToolCall(
    val toolCallId: String = "",
    val toolName: String = "",
    val arguments: AgentJsonObject = emptyMap(),
    /** Optional provider response-item id required when replaying Responses output. */
    val responseItemId: String? = null
) {
    /** Common short aliases used by model adapters. */
    val id: String
        get() = toolCallId

    val name: String
        get() = toolName
}

/** Public tool definition supplied to a model. */
data class AgentToolDefinition(
    val name: String,
    val description: String = "",
    val inputSchema: AgentJsonObject = emptyMap(),
    val sensitivity: AgentDataSensitivity = AgentDataSensitivity.Metadata,
    val defaultTimeoutMillis: Long = 30_000L,
    val version: String = "1"
)

/** State shown for an individual tool activity in the UI. */
enum class AgentToolActivityStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Unknown
}

/** Public, redacted summary of one tool invocation. */
data class AgentToolActivity(
    val toolCallId: String = "",
    val toolName: String = "",
    val status: AgentToolActivityStatus = AgentToolActivityStatus.Queued,
    val argumentsSummary: String = "",
    val startedAtMillis: Long = 0L,
    val completedAtMillis: Long? = null,
    val returnedCount: Long = 0L,
    val totalCount: Long = 0L,
    val truncated: Boolean = false,
    val resultBytes: Int = 0,
    val scope: AnalysisScope = AnalysisScope.CompleteFile,
    val queryMode: String? = null,
    val sampled: Boolean = false,
    val error: AgentError? = null
) {
    val id: String
        get() = toolCallId

    val state: AgentToolActivityStatus
        get() = status
}

/** Host-visible plan declared before capture analysis starts. */
data class AgentAnalysisPlan(
    val goal: String,
    val steps: List<AgentAnalysisPlanStep>
)

data class AgentAnalysisPlanStep(
    val tool: String,
    val purpose: String,
    /**
     * Playbook check this step promises to cover, matched against
     * `AgentPlaybookCheck.id` (OPT-VAL-01-02).  Empty when the step declares
     * no check — the default every plan produced before this field keeps, so
     * an empty value simply makes the run unattributable for the check-
     * coverage gate instead of failing anything.
     */
    val checkId: String = ""
)

/** Result returned by a local tool after policy and provenance processing. */
data class AgentToolResult(
    val toolCallId: String = "",
    val toolName: String = "",
    val success: Boolean = true,
    val data: AgentJsonObject? = null,
    val error: AgentError? = null,
    val truncated: Boolean = false,
    val sensitivity: AgentDataSensitivity = AgentDataSensitivity.Aggregate,
    val provenance: AgentProvenance = AgentProvenance(),
    val durationMillis: Long = provenance.durationMillis,
    val returnedCount: Long = provenance.returnedCount,
    val totalCount: Long = provenance.totalCount,
    val queryMode: String? = null,
    /** UTF-8 size of the structured payload actually handed to the model. */
    val resultBytes: Int = 0,
    val truncation: AgentTruncationInfo = AgentTruncationInfo()
)

/** The kind of source an evidence item points at. */
enum class AgentEvidenceType {
    Frame,
    Packet,
    Field,
    Statistic,
    DisplayFilter,
    ExpertInfo,
    Transaction,
    Timeline,
    Observation,
    Unknown
}

/**
 * A verifiable observation cited by a finding.  sourceToolCallId is required
 * by the protocol; an empty value is retained during decoding so the later
 * EvidenceValidator can reject it with a useful limitation instead of making
 * JSON parsing crash.
 */
data class AgentEvidence(
    val type: AgentEvidenceType = AgentEvidenceType.Unknown,
    val frameNumber: Long? = null,
    val displayFilter: String? = null,
    val field: String? = null,
    val observation: String = "",
    val sourceToolCallId: String,
    val metric: String? = null,
    val observedValue: String? = null,
    val timeRangeStartMillis: Long? = null,
    val timeRangeEndMillis: Long? = null
)

/** A compact, frame-linked phase in a structured finding timeline. */
data class AgentFindingTimelineEvent(
    val stage: String = "",
    val frameNumber: Long? = null,
    val detail: String = "",
    val elapsedMillis: Long? = null
)

/** One diagnosed issue and its alternatives/recommendations. */
data class AgentFinding(
    val id: String = "",
    val title: String = "",
    val severity: AgentFindingSeverity = AgentFindingSeverity.Unknown,
    val confidence: AgentConfidence = AgentConfidence.Unknown,
    val conclusion: String = "",
    val evidence: List<AgentEvidence> = emptyList(),
    val alternatives: List<String> = emptyList(),
    val recommendations: List<String> = emptyList(),
    val timeline: List<AgentFindingTimelineEvent> = emptyList(),
    /** Declared polarity of the core claim (agent-report-2); `Unknown` when undeclared. */
    val polarity: AgentFindingPolarity = AgentFindingPolarity.Unknown,
    /** Tool call ids that checked counter-evidence against this conclusion (agent-report-2). */
    val counterEvidenceChecked: List<String> = emptyList(),
    /** Plan hypothesis id this finding is tied to (agent-report-2). */
    val hypothesisId: String? = null,
    /** Host overview signal ids (signalId) this finding relates to (agent-report-2). */
    val relatedSignals: List<String> = emptyList()
)

/** Prefix of host-authored bookkeeping findings that record an uncited tool result. */
const val HOST_CONFIRMED_FINDING_PREFIX = "host-confirmed-"

/**
 * A host-authored bookkeeping finding that records a successful tool call the
 * model's text did not cite.  It restates a tool result rather than an analysis
 * conclusion, so the UI hides it from the findings list; the underlying report
 * data and exports still retain it for audit.
 */
val AgentFinding.isHostConfirmedToolResult: Boolean
    get() = id.startsWith(HOST_CONFIRMED_FINDING_PREFIX)

/** Locally validated conclusion from the immediately preceding Agent turn. */
data class AgentPriorContext(
    val priorQuestion: String,
    val priorSummary: String,
    val priorFindings: List<PriorFinding>
) {
    data class PriorFinding(
        val title: String,
        val conclusion: String,
        val evidenceToolCallIds: List<String>,
        val frameNumbers: List<Long>
    )

    companion object {
        fun from(priorQuestion: String, report: AgentReport): AgentPriorContext =
            AgentPriorContext(
                priorQuestion = priorQuestion,
                priorSummary = report.summary,
                priorFindings = report.findings.map { finding ->
                    PriorFinding(
                        title = finding.title,
                        conclusion = finding.conclusion,
                        evidenceToolCallIds = finding.evidence
                            .map { it.sourceToolCallId }
                            .filter { it.isNotBlank() }
                            .distinct(),
                        frameNumbers = finding.evidence
                            .mapNotNull { it.frameNumber }
                            .distinct()
                    )
                }
            )
    }
}

/**
 * One user-question part and whether the report addressed it (agent-report-2).
 *
 * [findingIds] references the findings that answer [questionPart]; an empty
 * list with [addressed]=false marks a part the report could not cover.
 */
data class AgentQuestionAlignment(
    val questionPart: String = "",
    val addressed: Boolean = false,
    val findingIds: List<String> = emptyList()
)

/** Structured, evidence-first output of an Agent run. */
data class AgentReport(
    val summary: String = "",
    val findings: List<AgentFinding> = emptyList(),
    val limitations: List<String> = emptyList(),
    val recommendedNextSteps: List<String> = emptyList(),
    val provenance: AgentReportProvenance = AgentReportProvenance(),
    val completeness: AgentReportCompleteness = AgentReportCompleteness.Unknown,
    /**
     * User-question decomposition aligned to the answer (agent-report-2).
     * Each entry maps one question part to the findings that address it; the
     * host validates the count (<= 4) and the reference integrity.
     */
    val questionAlignment: List<AgentQuestionAlignment> = emptyList()
)

/** Provider-neutral roles used in the visible conversation transcript. */
enum class AgentConversationRole {
    User,
    Assistant,
    Tool,
    System,
    Error,
    Unknown
}

/** A redacted transcript item shown by the Agent screen. */
data class AgentConversationItem(
    val id: String = "",
    val role: AgentConversationRole = AgentConversationRole.Unknown,
    val content: String = "",
    val createdAtMillis: Long = 0L,
    val toolCallId: String? = null,
    val toolName: String? = null,
    val untrustedCaptureData: Boolean = false,
    val error: AgentError? = null,
    val report: AgentReport? = null
) {
    val text: String
        get() = content
}

/** Roles accepted by the model boundary; vendor-specific roles stay outside. */
enum class AgentModelMessageRole {
    System,
    User,
    Assistant,
    Tool,
    Unknown
}

typealias AgentMessageRole = AgentModelMessageRole

typealias AgentModelRole = AgentModelMessageRole

/** Provider-neutral prompt cache hint. Unsupported adapters ignore it. */
data class CacheControl(
    val type: String = EPHEMERAL
) {
    init {
        require(type == EPHEMERAL) { "Unsupported cache control type: $type" }
    }

    companion object {
        const val EPHEMERAL: String = "ephemeral"
    }
}

/**
 * A model message.  Tool results should be created with [fromToolResult],
 * which forces untrustedCaptureData=true.  System and product context remain
 * false by default.
 */
data class AgentModelMessage(
    val role: AgentModelMessageRole,
    val content: String = "",
    val toolCallId: String? = null,
    val toolName: String? = null,
    val toolCalls: List<AgentToolCall> = emptyList(),
    val untrustedCaptureData: Boolean = false,
    val structuredContent: AgentJsonObject? = null,
    val toolResult: AgentToolResult? = null,
    val cacheControl: CacheControl? = null,
    /**
     * Opaque continuation state returned by some thinking-mode providers. It is
     * replayed only on assistant messages and never merged into visible report
     * content. Saved private model-interaction traces retain it so a serialized
     * message cannot silently lose provider-required continuation state.
     */
    val reasoningContent: String? = null
) {
    fun withCacheBreakpoint(): AgentModelMessage = copy(cacheControl = CacheControl())

    companion object {
        fun system(content: String, cacheable: Boolean = false): AgentModelMessage =
            AgentModelMessage(
                role = AgentModelMessageRole.System,
                content = content,
                cacheControl = CacheControl().takeIf { cacheable }
            )

        fun user(content: String): AgentModelMessage =
            AgentModelMessage(AgentModelMessageRole.User, content)

        fun assistant(
            content: String = "",
            toolCalls: List<AgentToolCall> = emptyList(),
            reasoningContent: String? = null
        ): AgentModelMessage =
            AgentModelMessage(
                role = AgentModelMessageRole.Assistant,
                content = content,
                toolCalls = toolCalls,
                reasoningContent = reasoningContent
            )

        /** Convert a local result without allowing callers to clear its trust marker. */
        fun fromToolResult(
            result: AgentToolResult,
            content: String = ""
        ): AgentModelMessage = AgentModelMessage(
            role = AgentModelMessageRole.Tool,
            content = content,
            toolCallId = result.toolCallId,
            toolName = result.toolName,
            untrustedCaptureData = true,
            structuredContent = result.toModelPayload(),
            toolResult = result.copy(
                // The capture fingerprint is a local cache/session key. It is
                // intentionally removed from the model-bound copy; exposing it
                // alongside aliases would make the alias salt guessable.
                provenance = result.provenance.copy(
                    captureFingerprint = "",
                    localSessionReference = null
                )
            )
        )
    }
}

/** Request passed to any local, cloud, or test model client. */
data class AgentModelRequest(
    val requestId: String,
    val messages: List<AgentModelMessage> = emptyList(),
    val toolDefinitions: List<AgentToolDefinition> = emptyList(),
    val responseSchema: AgentJsonObject? = null,
    val timeoutMillis: Long = 120_000L,
    val maxOutputTokens: Int = 0,
    /** Sent to a gateway as a policy label; it is not a provider type. */
    val privacyMode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata
)

/**
 * Normalized token counts for one model request.
 *
 * [inputTokens] is the total input processed by the provider. Cached reads are
 * included in that total and also reported separately so shared budgeting can
 * apply a discount without depending on provider-specific usage semantics.
 */
data class AgentTokenUsage(
    val inputTokens: Int = 0,
    val outputTokens: Int = 0,
    val cachedInputTokens: Int = 0,
    val cacheCreationTokens: Int = 0
) {
    /** Provider input that was neither read from nor written to the prompt cache. */
    val uncachedInputTokens: Int
        get() {
            val total = inputTokens.coerceAtLeast(0)
            val cached = cachedInputTokens.coerceIn(0, total)
            val creation = cacheCreationTokens.coerceIn(0, total - cached)
            return total - cached - creation
        }

    val billableInputTokens: Int
        get() = (inputTokens - cachedInputTokens).coerceAtLeast(0)

    operator fun plus(other: AgentTokenUsage): AgentTokenUsage = AgentTokenUsage(
        inputTokens = saturatedAdd(inputTokens, other.inputTokens),
        outputTokens = saturatedAdd(outputTokens, other.outputTokens),
        cachedInputTokens = saturatedAdd(cachedInputTokens, other.cachedInputTokens),
        cacheCreationTokens = saturatedAdd(cacheCreationTokens, other.cacheCreationTokens)
    )

    private fun saturatedAdd(first: Int, second: Int): Int =
        (first.coerceAtLeast(0).toLong() + second.coerceAtLeast(0).toLong())
            .coerceAtMost(Int.MAX_VALUE.toLong())
            .toInt()
}

/** Closed response vocabulary shared by all model adapters. */
sealed class AgentModelResponse {
    abstract val usage: AgentTokenUsage?

    data class ToolCalls(
        val calls: List<AgentToolCall>,
        override val usage: AgentTokenUsage? = null,
        /** Assistant text returned alongside the tool calls, if any. */
        val assistantContent: String = "",
        /** Provider continuation state required when replaying this assistant turn. */
        val reasoningContent: String? = null
    ) : AgentModelResponse()

    data class Final(
        val report: AgentReport? = null,
        val reportJson: String? = null,
        val json: String? = null,
        override val usage: AgentTokenUsage? = null,
        /** Provider continuation state retained only if the host requests a revision. */
        val reasoningContent: String? = null
    ) : AgentModelResponse() {
        constructor(report: AgentReport) : this(report, null, null)

        constructor(reportJson: String) : this(null, reportJson, reportJson)

        val rawJson: String?
            get() = reportJson ?: json
    }

    data class Refusal(
        val reason: String,
        val error: AgentError? = null,
        override val usage: AgentTokenUsage? = null
    ) : AgentModelResponse()

    data class Failure(
        val error: AgentError,
        override val usage: AgentTokenUsage? = null
    ) : AgentModelResponse()
}

/**
 * One model request and its normalized response, retained for inspection on
 * the analysis screen and in resumable saved conversations. Diagnostics still
 * receive only bounded attributes rather than these potentially large bodies.
 */
data class AgentModelInteraction(
    val id: String,
    val turn: Int? = null,
    val attempt: Int = 1,
    val request: AgentModelRequest,
    val response: AgentModelResponse,
    val startedAtMillis: Long = 0L,
    /**
     * Time of the first content-bearing streaming event. Text and tool-call
     * deltas both count because an Agent turn may respond only with a tool call.
     * Null means the provider/client did not expose incremental output.
     */
    val firstTokenAtMillis: Long? = null,
    val completedAtMillis: Long = 0L
) {
    /** End-to-end time from dispatch until the normalized response completed. */
    val responseDurationMillis: Long?
        get() = completedAtMillis
            .takeIf { startedAtMillis > 0L && it >= startedAtMillis }
            ?.minus(startedAtMillis)

    /** Time from dispatch until the first content-bearing streaming event. */
    val timeToFirstTokenMillis: Long?
        get() = firstTokenAtMillis
            ?.takeIf { first ->
                startedAtMillis > 0L &&
                    first >= startedAtMillis &&
                    (completedAtMillis <= 0L || first <= completedAtMillis)
            }
            ?.minus(startedAtMillis)
}

    /** Complete UI state for one protocol-analysis Agent session. */
data class ProtocolAgentUiState(
    val phase: AgentRunPhase = AgentRunPhase.Idle,
    /** Cross-process conversation key; the saved-history primary id. */
    val conversationId: String? = null,
    /** The run currently (or most recently) driving this state. */
    val runId: String? = null,
    val messages: List<AgentConversationItem> = emptyList(),
    /** Full model exchanges backing the live or restored analysis-step details. */
    val modelInteractions: List<AgentModelInteraction> = emptyList(),
    val activeTool: AgentToolActivity? = null,
    val completedSteps: Int = 0,
    val maxSteps: Int = 48,
    val report: AgentReport? = null,
    /**
     * Reports of earlier rounds of this conversation, oldest first.  A
     * follow-up that commits a new report archives the one on screen here so
     * every round stays reachable; a retry blanks it together with the failed
     * attempt's transcript.
     */
    val pastReports: List<AgentConversationRound> = emptyList(),
    val privacyMode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata,
    val error: AgentError? = null,
    /** A completed run may still be incomplete; keep its host stop reason visible. */
    val completionWarning: AgentError? = null,
    val toolActivities: List<AgentToolActivity> = emptyList(),
    val analysisMode: AgentAnalysisMode = AgentAnalysisMode.FullAgent,
    /** Provider-reported totals for the most recent run; null when unavailable. */
    val tokenUsage: AgentTokenUsage? = null,
    /** Current incremental assistant text; cleared when the request completes. */
    val streamingText: String = "",
    val analysisPlan: AgentAnalysisPlan? = null,
    /** Number of declared plan steps whose matching tool call has completed. */
    val completedPlanSteps: Int = 0,
    /**
     * A refused action — a blank question, a second concurrent submit — that the
     * UI shows once and dismisses.  Kept apart from [error] so rejecting a
     * submit never overwrites the error of the run that is still on screen.
     */
    val transientError: AgentError? = null,
    /** A follow-up is about to run under a filter the user changed in between. */
    val scopeChanged: Boolean = false
) {
    val isRunning: Boolean
        get() = phase == AgentRunPhase.Preparing ||
            phase == AgentRunPhase.Investigating ||
            phase == AgentRunPhase.WaitingForModel ||
            phase == AgentRunPhase.RunningTool ||
            phase == AgentRunPhase.Finalizing ||
            phase == AgentRunPhase.Revising ||
            phase == AgentRunPhase.ValidatingReport

    /** Whether a follow-up may be sent against the conversation on screen. */
    val canContinue: Boolean
        get() = !isRunning && messages.isNotEmpty()
}

/**
 * A validated, user-owned proposal to apply a display-filter citation.
 *
 * The Agent can create this state but cannot apply it.  Only the UI's explicit
 * confirmation calls the shared capture-session coordinator.
 */
data class AgentFilterPreviewState(
    val evidence: AgentEvidence,
    val captureFingerprint: String,
    val currentFilter: String,
    val suggestedFilter: String,
    val currentScope: AnalysisScope,
    val suggestedScope: AnalysisScope,
    val isValidating: Boolean = true,
    val error: AgentError? = null
) {
    val canApply: Boolean
        get() = !isValidating && error == null && suggestedFilter.isNotBlank()
}

/** Convenient conversion used by AgentLoop when appending local results. */
fun AgentToolResult.asModelMessage(content: String = ""): AgentModelMessage =
    AgentModelMessage.fromToolResult(this, content)

/**
 * Alias used by the Agent loop design.  The argument is accepted for source
 * compatibility, but capture-derived tool data is always marked untrusted.
 */
@Suppress("UNUSED_PARAMETER")
fun AgentToolResult.asToolMessage(
    untrusted: Boolean = true,
    content: String = ""
): AgentModelMessage = AgentModelMessage.fromToolResult(this, content).copy(
    untrustedCaptureData = true
)

/**
 * Build the structured tool payload without exporting the local session
 * reference.  The latter is useful for host-side auditing but must never be
 * sent to a model, even when a caller uses this convenience conversion.
 */
private fun AgentToolResult.toModelPayload(): AgentJsonObject = buildMap {
    put("toolCallId", toolCallId)
    put("toolName", toolName)
    put("success", success)
    put("data", data)
    put("error", error?.let {
        mapOf(
            "code" to it.code.name,
            "userMessage" to it.userMessage,
            "retryable" to it.retryable,
            "details" to it.details
        )
    })
    put("truncated", truncated)
    put("sensitivity", sensitivity.name)
    put("durationMillis", durationMillis)
    put("returnedCount", returnedCount)
    put("totalCount", totalCount)
    put("queryMode", queryMode)
    if (truncation.truncated || truncation.omittedFrames.isNotEmpty() ||
        truncation.omittedPaths.isNotEmpty() || truncation.continuation != null) put("truncation", mapOf(
        "sourceTruncated" to truncation.sourceTruncated,
        "quotaTruncated" to truncation.quotaTruncated,
        "payloadTruncated" to truncation.payloadTruncated,
        "contextCompacted" to truncation.contextCompacted,
        "returned" to truncation.returned,
        "total" to truncation.total,
        "omittedFrames" to truncation.omittedFrames,
        "omittedPaths" to truncation.omittedPaths,
        "continuation" to truncation.continuation
    ))
    put("resultBytes", resultBytes)
    put("provenance", mapOf(
        "scope" to provenance.scope.name,
        "displayFilter" to provenance.displayFilter,
        "toolName" to provenance.toolName,
        "toolVersion" to provenance.toolVersion,
        "normalizedArgumentsHash" to provenance.normalizedArgumentsHash,
        "generatedAtMillis" to provenance.generatedAtMillis,
        "returnedCount" to provenance.returnedCount,
        "totalCount" to provenance.totalCount,
        "truncated" to provenance.truncated,
        "durationMillis" to provenance.durationMillis,
        "queryMode" to provenance.queryMode,
        "truncation" to mapOf(
            "sourceTruncated" to provenance.truncation.sourceTruncated,
            "quotaTruncated" to provenance.truncation.quotaTruncated,
            "payloadTruncated" to provenance.truncation.payloadTruncated,
            "contextCompacted" to provenance.truncation.contextCompacted,
            "returned" to provenance.truncation.returned,
            "total" to provenance.truncation.total,
            "omittedFrames" to provenance.truncation.omittedFrames,
            "omittedPaths" to provenance.truncation.omittedPaths,
            "continuation" to provenance.truncation.continuation
        )
    ))
}
