package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import kotlin.math.roundToLong
import kotlin.random.Random

/** Host-side hints used to decide whether a detail read can use a wider batch. */
data class AgentDetailRequest(
    val fieldCount: Int = 0,
    val fieldNameChars: Int = 0,
    val includeDisplayValue: Boolean = true,
    val compact: Boolean = false,
    val estimatedValueWidth: Int = 0
)

/** The frame grant chosen before a detail-reading tool starts native work. */
data class AgentDetailFrameGrant(
    val limit: Int,
    val reason: String
)

/** Host-owned generation stages; no normal request uses the context reserve directly. */
enum class AgentModelRequestStage {
    PlanDeclaration,
    ToolSelection,
    FinalReport,
    Revision,
    ForcedSummary
}

object AgentOutputBudget {
    /** Conservative grants for clients that do not advertise a wider output window. */
    const val PLAN_DECLARATION_TOKENS = 2_048
    const val TOOL_SELECTION_TOKENS = 4_096
    const val FINAL_REPORT_TOKENS = 8_192
    const val REVISION_TOKENS = 4_096
    /**
     * The forced summary is a recovery hand-off, not a second full report.
     * Keeping this independently bounded prevents a large context from
     * producing another long response after the normal run has already hit a
     * limit.  The prompt also asks for a compact report with at most five
     * findings.
     */
    const val FORCED_SUMMARY_TOKENS = 4_096

    /** Wider grants for reasoning models whose declared output window exceeds the fallback. */
    const val WIDE_PLAN_DECLARATION_TOKENS = 8_192
    const val WIDE_TOOL_SELECTION_TOKENS = 32_768
    const val WIDE_FINAL_REPORT_TOKENS = 65_536
    const val WIDE_REVISION_TOKENS = 16_384
    /** Even wide-context models use the same bounded recovery generation. */
    const val WIDE_FORCED_SUMMARY_TOKENS = FORCED_SUMMARY_TOKENS

    fun tokens(stage: AgentModelRequestStage, modelOutputLimit: Int = 0): Int {
        val wideOutput = modelOutputLimit > FINAL_REPORT_TOKENS
        return when (stage) {
            AgentModelRequestStage.PlanDeclaration ->
                if (wideOutput) WIDE_PLAN_DECLARATION_TOKENS else PLAN_DECLARATION_TOKENS
            AgentModelRequestStage.ToolSelection ->
                if (wideOutput) WIDE_TOOL_SELECTION_TOKENS else TOOL_SELECTION_TOKENS
            AgentModelRequestStage.FinalReport ->
                if (wideOutput) WIDE_FINAL_REPORT_TOKENS else FINAL_REPORT_TOKENS
            AgentModelRequestStage.Revision ->
                if (wideOutput) WIDE_REVISION_TOKENS else REVISION_TOKENS
            AgentModelRequestStage.ForcedSummary ->
                if (wideOutput) WIDE_FORCED_SUMMARY_TOKENS else FORCED_SUMMARY_TOKENS
        }
    }
}

/**
 * Host-owned execution budget for one Agent run.
 *
 * Every value is calculated by the app.  A model may only narrow a budget
 * through [narrowedTo]; it can never widen one, and it can never supply a
 * policy object of its own.
 */
data class AgentPolicy(
    /** Rollback switch for host-provided Analysis Bootstrap evidence. */
    val analysisBootstrapEnabled: Boolean = true,
    /** Normal tool-call budget. A separate per-request/step timeout remains authoritative. */
    val maxSteps: Int = 48,
    /**
     * Maximum wall-clock duration of one remote model request.
     *
     * Independent of [DEFAULT_MAX_STEP_TIMEOUT_MILLIS]: reasoning models think
     * for minutes before their first token, and streaming keeps the connection
     * alive while they do, so a model request legitimately needs a much larger
     * ceiling than one local tool step.
     */
    val maxModelRequestTimeoutMillis: Long = DEFAULT_MAX_MODEL_REQUEST_TIMEOUT_MILLIS,
    val maxSummaryFramesPerCall: Int = 100,
    val maxDetailFramesPerCall: Int = 16,
    val maxDetailFramesPerSession: Int = 48,
    val maxToolResultBytes: Int = 32 * 1024,
    /** Experimental ceiling for compact, field-aware detail requests. */
    val maxDynamicDetailFramesPerCall: Int = 24,
    /** Rollback switch for the experimental dynamic detail grant. */
    val dynamicDetailFramesEnabled: Boolean = true,
    /**
     * Rollback switch for shape-changing tool results.
     *
     * When false, a tool that would otherwise return a distribution summary or a
     * depth-narrowed projection returns its full shape and lets
     * [maxToolResultBytes] trimming cut it, which is the pre-narrowing behaviour.
     */
    val evidenceNarrowingEnabled: Boolean = true,
    /** Independent byte ceilings for detail results. */
    val maxDetailResultBytesPerCall: Int = maxToolResultBytes,
    val maxDetailResultBytesPerSession: Long =
        maxDetailResultBytesPerCall.toLong() * maxSteps,
    val maxConcurrentSessions: Int = 1,
    val allowPayload: Boolean = false,
    /** Field projections requested in a single get_packet_fields style call. */
    val maxFieldsPerCall: Int = 32,
    /** Upper bound applied to one AgentToolDefinition execution. */
    val maxToolTimeoutMillis: Long = DEFAULT_MAX_STEP_TIMEOUT_MILLIS,
    /** Accumulated tool-result bytes for the whole run. */
    val maxTotalResultBytes: Long = maxToolResultBytes.toLong() * maxSteps,
    /** Structural limits applied to model-supplied arguments. */
    val maxArgumentDepth: Int = 8,
    val maxArgumentStringLength: Int = 2048,
    val maxArgumentArrayItems: Int = 512,
    val maxArgumentProperties: Int = 64,
    /**
     * Rejected argument sets the model may retry before the host ends the run.
     * A model that keeps submitting invalid arguments would otherwise burn the
     * turn ceiling without ever spending a step.
     */
    val maxInvalidArgumentRetries: Int = 3,
    /** Number of additional attempts allowed after a retryable model failure. */
    val maxModelRetries: Int = DEFAULT_MAX_MODEL_RETRIES,
    /** Whole-run logical request budget. Retry attempts do not consume it. */
    val maxModelRequests: Int = DEFAULT_MAX_MODEL_REQUESTS,
    /** Delegate wall clock and local logical request/step budgets preserve parent finalization capacity. */
    val maxDelegatedInvestigationTimeoutMillis: Long = DEFAULT_MAX_DELEGATED_TIMEOUT_MILLIS,
    val maxDelegatedModelRequests: Int = DEFAULT_MAX_DELEGATED_MODEL_REQUESTS,
    val maxDelegatedSteps: Int = DEFAULT_MAX_DELEGATED_STEPS,
    val reservedParentModelRequests: Int = DEFAULT_RESERVED_PARENT_MODEL_REQUESTS,
    /** Consecutive identical tool queries allowed before a final-summary handoff. */
    val maxConsecutiveIdenticalToolCalls: Int = 3,
    /** Evidence rejections required before the model gets one report revision turn. */
    val minRejectionsForRevision: Int = 2,
    /**
     * Extra tool-call turns granted once, after the declared plan completes,
     * when the run still holds truncated evidence with a usable continuation.
     * Zero disables the grant and restores the hard plan-completion stop.
     */
    val maxPlanGapFillTurns: Int = DEFAULT_MAX_PLAN_GAP_FILL_TURNS,
    /** Weighted provider input tokens across a run; zero leaves the dimension unlimited. */
    val maxCumulativeInputTokens: Long = 0L,
    /** Provider output tokens across a run; zero leaves the dimension unlimited. */
    val maxCumulativeOutputTokens: Long = 0L,
    /**
     * Model turns a run may last.  Invalid arguments, empty tool-call lists and
     * initial-tool nudges consume turns without ever consuming a step, so the
     * ceiling lives above the step budget — it guards a wedged loop, not work.
     */
    val maxTurns: Int = maxSteps * 2 + 2,
    /**
     * Independent Critic review requests for the run.
     *
     * Zero disables the Critic stage; a later task charges these requests
     * against [maxModelRequests] through the logical request count.
     */
    val maxCriticRequests: Int = DEFAULT_MAX_CRITIC_REQUESTS,
    /**
     * Tool steps a revision turn may spend repairing rejected findings.
     *
     * Zero disables the repair window and restores the zero-tool revision
     * behaviour.
     */
    val maxRevisionRepairSteps: Int = DEFAULT_MAX_REVISION_REPAIR_STEPS,
    /** Bounded append-mode replans per run; zero disables replanning. */
    val maxReplans: Int = DEFAULT_MAX_REPLANS,
    /**
     * Escape valve for the playbook check-coverage gate.
     *
     * When true, a playbook-hit run must cover every declared check before its
     * report is accepted.  When false, the pre-gate behaviour is restored.
     */
    val enforcePlaybookCheckCoverage: Boolean = true,
    /**
     * Quick direct-through effort tier for small, self-contained questions.
     *
     * When false, every run takes the full-analysis path.
     */
    val quickModeEnabled: Boolean = true,
    /**
     * Independent self-consistency inferences for high-severity findings.
     *
     * Zero disables the re-check.
     */
    val maxSelfConsistencyRequests: Int = DEFAULT_MAX_SELF_CONSISTENCY_REQUESTS,
    /**
     * Consecutive successful tool calls that add no new ledger data before the
     * host nudges the model to change strategy.  Zero disables the nudge.
     */
    val maxConsecutiveNonProductiveToolCalls: Int =
        DEFAULT_MAX_CONSECUTIVE_NON_PRODUCTIVE_TOOL_CALLS,
    /**
     * Sub-investigations a run may dispatch in parallel.
     *
     * Native access stays serialized by the session coordinator, so only the
     * orchestration overlaps.
     */
    val maxConcurrentDelegations: Int = 2,
    /**
     * Rollback switch for OPT-VAL-07 precise truncation downgrading.
     *
     * When true, [EvidenceValidator] only caps a finding's confidence for
     * truncation when the truncation can affect that conclusion (negative or
     * aggregate assertions, citations outside the returned subset, or evidence
     * resting entirely on incomplete sources); a fully returned-subset-bound
     * citation keeps its confidence and gains a limitation instead.
     * When false, the pre-OPT-VAL-07 behaviour is restored: any cited source
     * that is not complete lowers the cap by one level.
     */
    val preciseTruncationDowngrade: Boolean = true,
    /**
     * Rollback switch for OPT-VAL-04-02 polarity-driven negative validation.
     *
     * When true, [EvidenceValidator] triggers the filter/time-range/complete/
     * zero-match requirements from the finding's declared polarity: a finding
     * that declares `Negative` and grounds its absence claim in at least one
     * fully qualified citation has every citation it rests on reviewed under
     * the same standard; findings whose polarity is undeclared (`Unknown` —
     * old reports or unavailable structured output) keep the legacy per-
     * observation marker path unchanged, and `Positive`/`Neutral` findings
     * are no longer triggered by marker text at all.
     * When false, the pre-OPT-VAL-04 behaviour is restored: the marker table
     * triggers the requirements per observation, whatever the polarity says.
     */
    val findingPolarityNegativeValidation: Boolean = true,
    /**
     * Escape valve for the OPT-VAL-02-03 signal-coverage rule (design §5.2).
     *
     * When true, a report must address every host-enumerated baseline
     * signal — through some finding's `relatedSignals`, some model-authored
     * limitation naming the signal id, or the Critic's disposition record —
     * and an attributable submit that leaves one unaddressed is refused
     * exactly once by the same gate that refuses uncovered playbook checks,
     * while every signal the final report still ignores gains a
     * host-authored limitation.
     * When false, the rule is fully inert: no refusals, no signal-gap
     * limitations, and the `signalCoverageGaps` metric stays 0 — the
     * pre-OPT-VAL-02 behaviour end to end.
     */
    val enforceSignalCoverage: Boolean = true,
    /**
     * Escape valve for the OPT-VAL-03-01 question-alignment rule (design §5.3).
     *
     * When true, the host verifies every `questionAlignment` entry of a
     * report against the findings that survive evidence validation: a
     * referenced finding must still exist, and an entry claiming its question
     * part was addressed must stand on at least one surviving citation. A
     * violating entry is removed and rejected with reason
     * `alignment_dangling_reference` (shared channel with citation
     * rejections: it narrates a limitation and can buy a revision turn), and
     * a structured-output run whose report declares no entries at all gains
     * one host-authored limitation — a missing field is never a rejection.
     * When false, the rule is fully inert: no entry removals, no alignment
     * rejections, no missing-field limitation, and the `alignmentFailures`
     * metric stays 0 — the pre-OPT-VAL-03 behaviour end to end.
     */
    val enforceQuestionAlignment: Boolean = true
) {
    init {
        require(maxSteps > 0) { "maxSteps must be positive." }
        require(maxModelRequestTimeoutMillis > 0L) {
            "maxModelRequestTimeoutMillis must be positive."
        }
        require(maxModelRequestTimeoutMillis <= MAX_MODEL_REQUEST_TIMEOUT_MILLIS) {
            "maxModelRequestTimeoutMillis must not exceed the " +
                "${MAX_MODEL_REQUEST_TIMEOUT_MILLIS / 1000}-second model request ceiling."
        }
        require(maxToolTimeoutMillis > 0L) { "maxToolTimeoutMillis must be positive." }
        require(maxToolTimeoutMillis <= DEFAULT_MAX_STEP_TIMEOUT_MILLIS) {
            "maxToolTimeoutMillis must not exceed the 120-second step ceiling."
        }
        require(maxToolResultBytes >= MIN_RESULT_BYTES) { "maxToolResultBytes is too small." }
        require(maxSummaryFramesPerCall > 0) { "maxSummaryFramesPerCall must be positive." }
        require(maxDetailFramesPerCall > 0) { "maxDetailFramesPerCall must be positive." }
        require(maxDetailFramesPerSession > 0) {
            "maxDetailFramesPerSession must be positive."
        }
        require(maxDynamicDetailFramesPerCall > 0) {
            "maxDynamicDetailFramesPerCall must be positive."
        }
        require(maxDetailResultBytesPerCall >= MIN_RESULT_BYTES) {
            "maxDetailResultBytesPerCall is too small."
        }
        require(maxDetailResultBytesPerSession >= maxDetailResultBytesPerCall) {
            "maxDetailResultBytesPerSession must cover one detail result."
        }
        require(maxInvalidArgumentRetries > 0) { "maxInvalidArgumentRetries must be positive." }
        require(maxModelRetries in 0..MAX_MODEL_RETRIES) {
            "maxModelRetries must be between 0 and $MAX_MODEL_RETRIES."
        }
        require(maxModelRequests > 0) { "maxModelRequests must be positive." }
        require(maxModelRequests <= MAX_MODEL_REQUESTS) {
            "maxModelRequests must not exceed the host safety ceiling."
        }
        require(maxDelegatedInvestigationTimeoutMillis > 0L &&
            maxDelegatedInvestigationTimeoutMillis <= MAX_DELEGATED_TIMEOUT_MILLIS) {
            "maxDelegatedInvestigationTimeoutMillis must be within the host delegate ceiling."
        }
        require(maxDelegatedModelRequests > 0) { "maxDelegatedModelRequests must be positive." }
        require(maxDelegatedSteps > 0) { "maxDelegatedSteps must be positive." }
        require(reservedParentModelRequests > 0 && reservedParentModelRequests <= maxModelRequests) {
            "reservedParentModelRequests must preserve part of the model request budget."
        }
        require(maxConsecutiveIdenticalToolCalls > 0) {
            "maxConsecutiveIdenticalToolCalls must be positive."
        }
        require(minRejectionsForRevision > 0) { "minRejectionsForRevision must be positive." }
        require(maxPlanGapFillTurns >= 0) { "maxPlanGapFillTurns must not be negative." }
        require(maxCumulativeInputTokens >= 0L) {
            "maxCumulativeInputTokens must not be negative."
        }
        require(maxCumulativeOutputTokens >= 0L) {
            "maxCumulativeOutputTokens must not be negative."
        }
        require(maxTurns > 0) { "maxTurns must be positive." }
        require(maxCriticRequests in 0..MAX_CRITIC_REQUESTS) {
            "maxCriticRequests must be between 0 and $MAX_CRITIC_REQUESTS."
        }
        require(maxRevisionRepairSteps in 0..MAX_REVISION_REPAIR_STEPS) {
            "maxRevisionRepairSteps must be between 0 and $MAX_REVISION_REPAIR_STEPS."
        }
        require(maxReplans in 0..MAX_REPLANS) {
            "maxReplans must be between 0 and $MAX_REPLANS."
        }
        require(maxSelfConsistencyRequests in 0..MAX_SELF_CONSISTENCY_REQUESTS) {
            "maxSelfConsistencyRequests must be between 0 and $MAX_SELF_CONSISTENCY_REQUESTS."
        }
        require(maxConsecutiveNonProductiveToolCalls >= 0) {
            "maxConsecutiveNonProductiveToolCalls must not be negative."
        }
        require(maxConcurrentDelegations in 1..MAX_CONCURRENT_DELEGATIONS) {
            "maxConcurrentDelegations must be between 1 and $MAX_CONCURRENT_DELEGATIONS."
        }
    }

    /**
     * Keep per-request and per-tool ceilings independent of capture size.
     *
     * A run has no wall-clock deadline: large captures may use more model/tool
     * turns, while each individual request or step remains bounded by its own
     * timeout in this policy.
     */
    fun adaptiveForCapture(@Suppress("UNUSED_PARAMETER") frameCount: Int): AgentPolicy = this

    /**
     * Element-wise intersection of two budgets.  Used when a caller (never the
     * model itself) wants a stricter run, for example a quick preflight check.
     */
    fun narrowedTo(other: AgentPolicy): AgentPolicy = AgentPolicy(
        analysisBootstrapEnabled = analysisBootstrapEnabled && other.analysisBootstrapEnabled,
        maxSteps = minOf(maxSteps, other.maxSteps),
        maxModelRequestTimeoutMillis = minOf(
            maxModelRequestTimeoutMillis,
            other.maxModelRequestTimeoutMillis
        ),
        maxSummaryFramesPerCall = minOf(maxSummaryFramesPerCall, other.maxSummaryFramesPerCall),
        maxDetailFramesPerCall = minOf(maxDetailFramesPerCall, other.maxDetailFramesPerCall),
        maxDetailFramesPerSession = minOf(maxDetailFramesPerSession, other.maxDetailFramesPerSession),
        maxToolResultBytes = minOf(maxToolResultBytes, other.maxToolResultBytes),
        maxDynamicDetailFramesPerCall = minOf(
            maxDynamicDetailFramesPerCall,
            other.maxDynamicDetailFramesPerCall
        ),
        dynamicDetailFramesEnabled = dynamicDetailFramesEnabled && other.dynamicDetailFramesEnabled,
        evidenceNarrowingEnabled = evidenceNarrowingEnabled && other.evidenceNarrowingEnabled,
        maxDetailResultBytesPerCall = minOf(
            maxDetailResultBytesPerCall,
            other.maxDetailResultBytesPerCall
        ),
        maxDetailResultBytesPerSession = minOf(
            maxDetailResultBytesPerSession,
            other.maxDetailResultBytesPerSession
        ),
        maxConcurrentSessions = minOf(maxConcurrentSessions, other.maxConcurrentSessions),
        allowPayload = allowPayload && other.allowPayload,
        maxFieldsPerCall = minOf(maxFieldsPerCall, other.maxFieldsPerCall),
        maxToolTimeoutMillis = minOf(maxToolTimeoutMillis, other.maxToolTimeoutMillis),
        maxTotalResultBytes = minOf(maxTotalResultBytes, other.maxTotalResultBytes),
        maxArgumentDepth = minOf(maxArgumentDepth, other.maxArgumentDepth),
        maxArgumentStringLength = minOf(maxArgumentStringLength, other.maxArgumentStringLength),
        maxArgumentArrayItems = minOf(maxArgumentArrayItems, other.maxArgumentArrayItems),
        maxArgumentProperties = minOf(maxArgumentProperties, other.maxArgumentProperties),
        maxInvalidArgumentRetries = minOf(maxInvalidArgumentRetries, other.maxInvalidArgumentRetries),
        maxModelRetries = minOf(maxModelRetries, other.maxModelRetries),
        maxModelRequests = minOf(maxModelRequests, other.maxModelRequests),
        maxDelegatedInvestigationTimeoutMillis = minOf(
            maxDelegatedInvestigationTimeoutMillis,
            other.maxDelegatedInvestigationTimeoutMillis
        ),
        maxDelegatedModelRequests = minOf(maxDelegatedModelRequests, other.maxDelegatedModelRequests),
        maxDelegatedSteps = minOf(maxDelegatedSteps, other.maxDelegatedSteps),
        reservedParentModelRequests = minOf(
            maxOf(reservedParentModelRequests, other.reservedParentModelRequests),
            (minOf(maxModelRequests, other.maxModelRequests) - 1).coerceAtLeast(1)
        ),
        maxConsecutiveIdenticalToolCalls = minOf(
            maxConsecutiveIdenticalToolCalls,
            other.maxConsecutiveIdenticalToolCalls
        ),
        minRejectionsForRevision = minOf(
            minRejectionsForRevision,
            other.minRejectionsForRevision
        ),
        maxPlanGapFillTurns = minOf(maxPlanGapFillTurns, other.maxPlanGapFillTurns),
        maxCumulativeInputTokens = narrowerOptionalLimit(
            maxCumulativeInputTokens,
            other.maxCumulativeInputTokens
        ),
        maxCumulativeOutputTokens = narrowerOptionalLimit(
            maxCumulativeOutputTokens,
            other.maxCumulativeOutputTokens
        ),
        maxTurns = minOf(maxTurns, other.maxTurns),
        maxCriticRequests = minOf(maxCriticRequests, other.maxCriticRequests),
        maxRevisionRepairSteps = minOf(
            maxRevisionRepairSteps,
            other.maxRevisionRepairSteps
        ),
        maxReplans = minOf(maxReplans, other.maxReplans),
        enforcePlaybookCheckCoverage =
            enforcePlaybookCheckCoverage && other.enforcePlaybookCheckCoverage,
        quickModeEnabled = quickModeEnabled && other.quickModeEnabled,
        maxSelfConsistencyRequests = minOf(
            maxSelfConsistencyRequests,
            other.maxSelfConsistencyRequests
        ),
        maxConsecutiveNonProductiveToolCalls = minOf(
            maxConsecutiveNonProductiveToolCalls,
            other.maxConsecutiveNonProductiveToolCalls
        ),
        maxConcurrentDelegations = minOf(
            maxConcurrentDelegations,
            other.maxConcurrentDelegations
        ),
        preciseTruncationDowngrade =
            preciseTruncationDowngrade && other.preciseTruncationDowngrade,
        findingPolarityNegativeValidation =
            findingPolarityNegativeValidation && other.findingPolarityNegativeValidation,
        enforceSignalCoverage =
            enforceSignalCoverage && other.enforceSignalCoverage,
        enforceQuestionAlignment =
            enforceQuestionAlignment && other.enforceQuestionAlignment
    )

    internal fun inputTokenBudgetDescription(): String =
        maxCumulativeInputTokens.takeIf { it > 0L }?.toString() ?: "unlimited"

    internal fun outputTokenBudgetDescription(): String =
        maxCumulativeOutputTokens.takeIf { it > 0L }?.toString() ?: "unlimited"

    /** Decide the per-call grant without looking at capture-derived values. */
    fun detailFrameGrant(request: AgentDetailRequest?): AgentDetailFrameGrant {
        val baseline = maxDetailFramesPerCall
        if (!dynamicDetailFramesEnabled || request == null) {
            return AgentDetailFrameGrant(baseline, "default_projection")
        }

        val shortProjection = !request.includeDisplayValue &&
            request.fieldCount in 1..2 &&
            request.fieldNameChars <= MAX_DYNAMIC_FIELD_NAME_CHARS &&
            request.estimatedValueWidth <= MAX_DYNAMIC_VALUE_WIDTH
        val eligible = request.compact || shortProjection
        // A projection so wide that a full batch cannot fit the per-call byte
        // budget would be trimmed to nothing by the generic byte cut. Granting
        // fewer frames up front returns *complete* rows, charges only what is
        // read, and leaves the rest in omittedFrames for a follow-up call.
        val byteFit = detailByteFit(request)
        if (!eligible) {
            return if (byteFit < baseline) {
                AgentDetailFrameGrant(byteFit, "byte_fitted_projection")
            } else {
                AgentDetailFrameGrant(baseline, "wide_projection")
            }
        }

        // maxDetailFramesPerCall remains a hard compatibility ceiling when a
        // caller supplied a stricter legacy value. The default 16-frame policy
        // may use the experimental dynamic ceiling.
        val ceiling = if (baseline == DEFAULT_DETAIL_FRAMES_PER_CALL) {
            maxDynamicDetailFramesPerCall
        } else {
            minOf(baseline, maxDynamicDetailFramesPerCall)
        }
        val limit = ceiling.coerceAtMost(maxDetailFramesPerSession)
        if (byteFit < limit) {
            return AgentDetailFrameGrant(byteFit, "byte_fitted_projection")
        }
        return AgentDetailFrameGrant(
            limit = limit,
            reason = if (request.compact) "compact_projection" else "dynamic_short_projection"
        )
    }

    /**
     * Frames whose complete projections fit the per-call detail byte budget,
     * with headroom for the payload envelope and redaction aliases.  The width
     * estimate is deliberately generous per field: an occurrence repeats the
     * field name and may carry both a raw and a display value.
     */
    private fun detailByteFit(request: AgentDetailRequest): Int {
        val fieldCount = request.fieldCount.coerceAtLeast(1)
        val nameChars = request.fieldNameChars.takeIf { it > 0 }
            ?: (fieldCount * DEFAULT_FIELD_NAME_CHARS)
        val valueWidth = when {
            request.estimatedValueWidth > 0 -> request.estimatedValueWidth
            request.includeDisplayValue -> WIDE_VALUE_WIDTH_BYTES
            else -> RAW_VALUE_WIDTH_BYTES
        }
        val perFrame = FRAME_ROW_OVERHEAD_BYTES + nameChars +
            fieldCount * (valueWidth + FIELD_ENTRY_OVERHEAD_BYTES)
        val rowBudget = maxDetailResultBytesPerCall.toLong() * 3L / 4L
        return (rowBudget / perFrame).toInt().coerceIn(1, maxDetailFramesPerSession)
    }

    companion object {
        const val DEFAULT_MAX_STEP_TIMEOUT_MILLIS = 120_000L
        /**
         * One remote model request may take far longer than one tool step: a
         * reasoning model can think for minutes before emitting anything, and
         * the transport no longer imposes its own whole-call deadline on a
         * streaming response. The ceiling still exists so a hung provider
         * eventually releases the run.
         */
        const val DEFAULT_MAX_MODEL_REQUEST_TIMEOUT_MILLIS = 300_000L
        const val MAX_MODEL_REQUEST_TIMEOUT_MILLIS = 600_000L
        const val DEFAULT_MAX_MODEL_REQUESTS = 24
        const val MAX_MODEL_REQUESTS = 64
        const val DEFAULT_MAX_DELEGATED_TIMEOUT_MILLIS = 15 * 60_000L
        const val MAX_DELEGATED_TIMEOUT_MILLIS = 15 * 60_000L
        const val DEFAULT_MAX_DELEGATED_MODEL_REQUESTS = 6
        const val DEFAULT_MAX_DELEGATED_STEPS = 16
        const val DEFAULT_RESERVED_PARENT_MODEL_REQUESTS = 1
        const val DEFAULT_MAX_PLAN_GAP_FILL_TURNS = 4
        /** Default Critic review requests; zero disables the Critic stage. */
        const val DEFAULT_MAX_CRITIC_REQUESTS = 1
        const val MAX_CRITIC_REQUESTS = 4
        /** Default revision-turn tool steps; zero restores zero-tool revisions. */
        const val DEFAULT_MAX_REVISION_REPAIR_STEPS = 3
        const val MAX_REVISION_REPAIR_STEPS = 8
        /** Default append-mode replans per run; zero disables replanning. */
        const val DEFAULT_MAX_REPLANS = 1
        const val MAX_REPLANS = 2
        /** Default high-severity self-consistency inferences; zero disables them. */
        const val DEFAULT_MAX_SELF_CONSISTENCY_REQUESTS = 2
        const val MAX_SELF_CONSISTENCY_REQUESTS = 4
        /** Default non-productive calls before a nudge; zero disables the nudge. */
        const val DEFAULT_MAX_CONSECUTIVE_NON_PRODUCTIVE_TOOL_CALLS = 4
        /** Hard ceiling for parallel sub-investigations; native stays serialized. */
        const val MAX_CONCURRENT_DELEGATIONS = 4
        private const val MIN_RESULT_BYTES = 256
        const val DEFAULT_MAX_MODEL_RETRIES = 3
        const val MAX_MODEL_RETRIES = 8
        const val DEFAULT_DETAIL_FRAMES_PER_CALL = 16
        private const val MAX_DYNAMIC_FIELD_NAME_CHARS = 240
        private const val MAX_DYNAMIC_VALUE_WIDTH = 256
        private const val DEFAULT_FIELD_NAME_CHARS = 16
        private const val FRAME_ROW_OVERHEAD_BYTES = 120
        private const val FIELD_ENTRY_OVERHEAD_BYTES = 48
        private const val RAW_VALUE_WIDTH_BYTES = 96
        private const val WIDE_VALUE_WIDTH_BYTES = 192

        private val MODEL_RETRY_DELAYS_MILLIS = longArrayOf(500L, 1_000L, 2_000L, 4_000L)
        private val RATE_LIMIT_RETRY_DELAYS_MILLIS =
            longArrayOf(2_000L, 5_000L, 15_000L, 30_000L)
        private val FAST_RETRY_DELAYS_MILLIS = longArrayOf(200L, 500L, 1_000L, 2_000L)

        private fun narrowerOptionalLimit(first: Long, second: Long): Long = when {
            first == 0L -> second
            second == 0L -> first
            else -> minOf(first, second)
        }

        /** Delay before retry number 1, 2, 3, ...; the last value is sticky. */
        @Deprecated("Use retryDelayMillis(retryNumber, error) for classified retries.")
        fun modelRetryDelayMillis(retryNumber: Int): Long {
            require(retryNumber > 0) { "retryNumber must be positive." }
            return MODEL_RETRY_DELAYS_MILLIS[
                (retryNumber - 1).coerceAtMost(MODEL_RETRY_DELAYS_MILLIS.lastIndex)
            ]
        }

        /** Classified retry delay with provider guidance taking precedence. */
        fun retryDelayMillis(
            retryNumber: Int,
            error: AgentError,
            jitterFraction: Double = Random.nextDouble(-RETRY_JITTER, RETRY_JITTER)
        ): Long {
            require(retryNumber > 0) { "retryNumber must be positive." }
            explicitRetryAfterMillis(error)?.let { return it }
            val delays = when {
                error.isTimeoutLike() -> FAST_RETRY_DELAYS_MILLIS
                error.code == AgentErrorCode.MODEL_RATE_LIMITED ->
                    RATE_LIMIT_RETRY_DELAYS_MILLIS
                error.code == AgentErrorCode.MODEL_UNAVAILABLE -> MODEL_RETRY_DELAYS_MILLIS
                else -> FAST_RETRY_DELAYS_MILLIS
            }
            val base = delays[(retryNumber - 1).coerceAtMost(delays.lastIndex)]
            val multiplier = 1.0 + jitterFraction.coerceIn(-RETRY_JITTER, RETRY_JITTER)
            return (base * multiplier).roundToLong().coerceAtLeast(0L)
        }

        private fun explicitRetryAfterMillis(error: AgentError): Long? {
            val millis = error.details["retryAfterMillis"].asLongOrNull()
            if (millis != null) return millis.coerceIn(0L, MAX_EXPLICIT_RETRY_DELAY_MILLIS)
            val seconds = error.details["retryAfterSeconds"].asLongOrNull() ?: return null
            return seconds.coerceIn(0L, MAX_EXPLICIT_RETRY_DELAY_MILLIS / 1_000L) * 1_000L
        }

        private fun AgentError.isTimeoutLike(): Boolean =
            listOf("reason", "remoteCode", "remoteType", "remoteMessage")
                .mapNotNull { details[it]?.toString() }
                .any { value ->
                    val normalized = value.lowercase()
                    "timeout" in normalized || "timed out" in normalized
                }

        private fun Any?.asLongOrNull(): Long? = when (this) {
            is Number -> toLong()
            is String -> trim().toLongOrNull()
            else -> null
        }

        private const val RETRY_JITTER = 0.2
        private const val MAX_EXPLICIT_RETRY_DELAY_MILLIS = 86_400_000L

        /** A model-requested count may only shrink the host limit. */
        fun clamp(requested: Int?, hostMaximum: Int): Int = when {
            requested == null -> hostMaximum
            requested < 1 -> 1
            else -> minOf(requested, hostMaximum)
        }

    }
}

/**
 * Decides whether a tool may run at all under the current privacy mode.
 *
 * The gate fails closed: an unknown sensitivity or an unknown privacy mode is
 * rejected instead of being treated as harmless aggregate data.
 */
object AgentSensitivityPolicy {
    fun isAllowed(
        sensitivity: AgentDataSensitivity,
        privacyMode: AgentPrivacyMode,
        policy: AgentPolicy
    ): Boolean = check(sensitivity, privacyMode, policy) == null

    fun check(
        sensitivity: AgentDataSensitivity,
        privacyMode: AgentPrivacyMode,
        policy: AgentPolicy
    ): AgentError? {
        if (privacyMode == AgentPrivacyMode.Unknown) {
            return blocked("unknown_privacy_mode", sensitivity)
        }
        return when (sensitivity) {
            AgentDataSensitivity.Aggregate,
            AgentDataSensitivity.Metadata -> null

            // Identifiers are allowed through this gate because they are not
            // sent as-is: AgentPrivacyPolicy replaces them with stable aliases
            // in AgentToolRunner.finish, before the result is serialized for a
            // model.  Local-only and explicit payload modes are unchanged.
            AgentDataSensitivity.Identifier -> null

            AgentDataSensitivity.Payload ->
                if (policy.allowPayload && privacyMode == AgentPrivacyMode.SelectedPayload) {
                    null
                } else {
                    blocked("payload_not_enabled", sensitivity)
                }

            // Credentials are never analysed by a model, in any mode.
            AgentDataSensitivity.Credential -> blocked("credential_never_shared", sensitivity)

            AgentDataSensitivity.Unknown -> blocked("unknown_sensitivity", sensitivity)
        }
    }

    private fun blocked(reason: String, sensitivity: AgentDataSensitivity) = AgentError(
        code = AgentErrorCode.PRIVACY_BLOCKED,
        userMessage = "This analysis step is not allowed by the current privacy mode.",
        retryable = false,
        details = mapOf(
            "reason" to reason,
            "sensitivity" to sensitivity.name
        )
    )
}
