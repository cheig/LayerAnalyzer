// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentBudgetTracker
import com.example.layanalyzer.ai.agent.AgentDetailRequest
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.data.AgentAnalysisRepository
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult

/**
 * A whitelisted, read-only local analysis capability.
 *
 * A tool never receives a file path, URL, class name or native handle from the
 * model.  It reads the capture only through [AgentToolContext.repository],
 * which is bound to the immutable session snapshot for this run.
 */
interface AgentTool {
    val definition: AgentToolDefinition

    /**
     * Whether this call consumes one evidence-analysis step.
     *
     * Orchestration tools still pass schema, privacy, timeout, result-byte and
     * audit checks, but do not reduce the budget available for capture reads.
     */
    val consumesEvidenceStep: Boolean
        get() = true

    suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult

    /**
     * Frames this call will dissect in full, so [AgentBudgetTracker] can charge
     * the per-call and per-session detail-frame budgets before any native work
     * starts.  Summary/statistics tools keep the default empty set.
     *
     * The arguments passed here have already been schema-validated.
     */
    fun detailFrames(arguments: Map<String, Any?>): Collection<Long> = emptyList()

    /**
     * Optional field/width hints used by the host before reserving detail
     * frames. Returning hints never widens the policy; it only selects one of
     * the host-owned grants.
     */
    fun detailRequest(arguments: Map<String, Any?>): AgentDetailRequest? = null

    /**
     * String arguments holding a display filter.  [AgentToolRunner] compiles
     * each of them before the tool runs, so a filter the engine would reject
     * never reaches native dissection and never costs budget — whether or not
     * the model thought to call validate_display_filter first.
     *
     * A tool whose whole purpose is to report on a filter's validity overrides
     * this with an empty set.
     */
    val filterArgumentNames: Set<String>
        get() = setOf("filter")
}

/**
 * Everything a tool is allowed to know about the run it executes in.
 *
 * The context carries no mutable repository, no ViewModel and no Android
 * Context, which keeps the whole tool layer runnable in plain JVM tests.
 */
class AgentToolContext(
    val toolCallId: String,
    val toolName: String,
    val snapshot: AgentCaptureSnapshot,
    val policy: AgentPolicy,
    val privacyMode: AgentPrivacyMode,
    val repository: AgentAnalysisRepository,
    /** Bytes this single result may occupy after encoding. */
    val resultByteAllowance: Int,
    val stepIndex: Int,
    /** Declared sensitivity of the executing tool, used as the result default. */
    val sensitivity: AgentDataSensitivity = AgentDataSensitivity.Aggregate,
    /**
     * Frames the budget granted to this call, when the tool declares detail
     * frames.  Null means "no detail frames were declared".  A non-null value
     * is the authoritative read list: the tool must dissect exactly these and
     * report the rest of its request as omitted.
     */
    val grantedDetailFrames: Set<Long>? = null,
    /** Requested frames the budget cut; the tool must list them as omitted. */
    val omittedDetailFrames: List<Long> = emptyList(),
    /** True when the per-session quota — not the per-call cap — cut frames. */
    val omittedBySessionQuota: Boolean = false,
    val omittedByPerCallLimit: Boolean = false,
    val omittedByResultByteQuota: Boolean = false,
    /** Distinct detail frames the run may still charge after this call. */
    val remainingDetailFrameQuota: Int = 0,
    val detailGrantLimit: Int = 0,
    val detailGrantReason: String = "default_projection",
    val remainingDetailResultBytes: Long = 0L,
    val argumentNormalizations: List<AgentArgumentNormalization> = emptyList(),
    val clock: () -> Long = { System.currentTimeMillis() },
    private val investigationDelegate: AgentInvestigationDelegate? = null
) {
    /** Host limit for a summary-style query; a model value may only shrink it. */
    fun summaryLimit(requested: Int? = null): Int =
        AgentPolicy.clamp(requested, policy.maxSummaryFramesPerCall)

    /** Host limit for a detail-style query; a model value may only shrink it. */
    fun detailLimit(requested: Int? = null): Int =
        AgentPolicy.clamp(requested, policy.maxDetailFramesPerCall)

    /** Host limit for a field projection; a model value may only shrink it. */
    fun fieldLimit(requested: Int? = null): Int =
        AgentPolicy.clamp(requested, policy.maxFieldsPerCall)

    /**
     * Budget fields every detail-reading tool should merge into its payload so
     * the model can see what was cut and plan its next call without guessing.
     *
     * [requestedFrames] is the tool's own declared request; the other three come
     * from the runner's reservation.
     */
    fun detailBudgetJson(requestedFrames: List<Long>): AgentJsonObject = mapOf(
        "requestedFrames" to requestedFrames,
        "requested" to requestedFrames.size,
        "granted" to (grantedDetailFrames?.size ?: requestedFrames.size),
        "omittedFrames" to omittedDetailFrames,
        "omittedByBudget" to (
            omittedBySessionQuota || omittedByPerCallLimit || omittedByResultByteQuota
        ),
        "omittedBySessionQuota" to omittedBySessionQuota,
        "omittedByPerCallLimit" to omittedByPerCallLimit,
        "omittedByResultByteQuota" to omittedByResultByteQuota,
        "remainingFrameQuota" to remainingDetailFrameQuota,
        "detailGrantLimit" to detailGrantLimit,
        "detailGrantReason" to detailGrantReason,
        "remainingDetailResultBytes" to remainingDetailResultBytes
    )

    /**
     * Build a successful result.  Provenance, truncation and final counts are
     * attached afterwards by [AgentToolRunner]; a tool must not fabricate them.
     */
    fun success(
        data: AgentJsonObject,
        returnedCount: Long = 0L,
        totalCount: Long = returnedCount,
        sensitivity: AgentDataSensitivity = this.sensitivity,
        truncated: Boolean = false,
        queryMode: String? = null
    ): AgentToolResult = AgentToolResult(
        toolCallId = toolCallId,
        toolName = toolName,
        success = true,
        error = null,
        truncated = truncated,
        sensitivity = sensitivity,
        returnedCount = returnedCount,
        totalCount = totalCount,
        queryMode = queryMode,
        data = data + argumentNormalizations.associate { normalization ->
            "${normalization.path.substringAfterLast('.') }Normalization" to mapOf(
                "truncated" to normalization.truncated,
                "originalLength" to normalization.originalLength,
                "normalizedLength" to normalization.normalizedLength,
                "ruleVersion" to normalization.ruleVersion
            )
        }
    )

    fun failure(error: AgentError): AgentToolResult = AgentToolResult(
        toolCallId = toolCallId,
        toolName = toolName,
        success = false,
        data = null,
        error = error,
        sensitivity = sensitivity
    )

    suspend fun delegateInvestigation(goal: String, maxTurns: Int): AgentJsonObject {
        val delegate = investigationDelegate ?: throw AgentToolException(
            code = AgentErrorCode.INTERNAL_ERROR,
            userMessage = "The delegated analysis service is unavailable.",
            details = mapOf("reason" to "delegate_unbound")
        )
        return delegate.investigate(goal, maxTurns)
    }
}

fun interface AgentInvestigationDelegate {
    suspend fun investigate(goal: String, maxTurns: Int): AgentJsonObject
}

/**
 * Structured failure a tool may raise instead of returning a result.
 *
 * [AgentToolRunner] converts this to the carried [AgentError] rather than to a
 * generic INTERNAL_ERROR, so a tool can report a precise, safe reason.
 */
class AgentToolException(
    val agentError: AgentError
) : Exception(agentError.userMessage) {
    constructor(
        code: AgentErrorCode,
        userMessage: String,
        retryable: Boolean = false,
        details: AgentJsonObject = emptyMap()
    ) : this(AgentError(code, userMessage, retryable, details))
}
