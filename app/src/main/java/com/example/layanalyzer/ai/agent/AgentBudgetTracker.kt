package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentTokenUsage

/** A granted reservation.  [grantedFrames] is the set the call may dissect. */
data class AgentBudgetReservation(
    val stepIndex: Int,
    val remainingSteps: Int = 0,
    val remainingResultBytes: Long = 0L,
    /**
     * Distinct frames this call may dissect: the per-call and per-session
     * caps applied to the request instead of rejecting it.
     */
    val grantedFrames: Set<Long> = emptySet(),
    /** Requested frames the caps cut; the tool must report them as omitted. */
    val omittedFrames: Set<Long> = emptySet(),
    /** True when the session quota — not the per-call cap — did the cutting. */
    val omittedBySessionQuota: Boolean = false,
    /** True when the per-call detail-frame grant did the cutting. */
    val omittedByPerCallLimit: Boolean = false,
    /** True when the running detail-result byte quota did the cutting. */
    val omittedByResultByteQuota: Boolean = false,
    /** Distinct detail frames this run may still charge after this call. */
    val remainingSessionDetailFrames: Int = 0,
    /** Effective frame limit selected for this request. */
    val detailGrantLimit: Int = 0,
    val detailGrantReason: String = "default_projection",
    val remainingDetailResultBytes: Long = 0L
)

/** Snapshot of consumed budget, safe to log and show in the UI. */
data class AgentBudgetUsage(
    val steps: Int = 0,
    val maxSteps: Int = 0,
    val detailFrames: Int = 0,
    val maxDetailFrames: Int = 0,
    val resultBytes: Long = 0L,
    val maxResultBytes: Long = 0L,
    val detailResultBytes: Long = 0L,
    val maxDetailResultBytes: Long = 0L,
    /** Normalized provider input, including cache reads and cache creation. */
    val cumulativeInputTokens: Long = 0L,
    /** Input that was neither read from nor written to the provider cache. */
    val uncachedInputTokens: Long = 0L,
    /** Input served from the provider cache. */
    val cachedInputTokens: Long = 0L,
    /** Input written into the provider cache. */
    val cacheCreationTokens: Long = 0L,
    /** Input budget units: uncached/creation tokens plus one tenth of cache reads. */
    val weightedInputTokens: Long = 0L,
    val maxCumulativeInputTokens: Long = 0L,
    val cumulativeOutputTokens: Long = 0L,
    val maxCumulativeOutputTokens: Long = 0L,
    /** Observational run time; it is not an exhaustion condition. */
    val elapsedMillis: Long = 0L
) {
    val stepsExhausted: Boolean
        get() = steps >= maxSteps

    val inputTokensExhausted: Boolean
        get() = maxCumulativeInputTokens > 0L &&
            weightedInputTokens >= maxCumulativeInputTokens

    val outputTokensExhausted: Boolean
        get() = maxCumulativeOutputTokens > 0L &&
            cumulativeOutputTokens >= maxCumulativeOutputTokens

    val totalInputTokens: Long
        get() = cumulativeInputTokens

    val outputTokens: Long
        get() = cumulativeOutputTokens
}

/**
 * Tracks what one Agent run has already spent.
 *
 * Reservation happens before the tool executes so a rejected call does not
 * consume a step, while byte accounting happens after truncation so the
 * recorded size matches what the model actually received. The tracker is
 * synchronized because different tool names may execute concurrently and UI
 * reads can arrive from other threads. Elapsed time is recorded for
 * observability; there is deliberately no run-wide wall-clock budget.
 */
class AgentBudgetTracker(
    val policy: AgentPolicy,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    private val guard = Any()
    private var startedAtMillis: Long = clock()
    private var steps: Int = 0
    private var resultBytes: Long = 0L
    private var detailResultBytes: Long = 0L
    private var totalInputTokens: Long = 0L
    private var uncachedInputTokens: Long = 0L
    private var cachedInputTokens: Long = 0L
    private var cacheCreationTokens: Long = 0L
    private var weightedInputTokens: Long = 0L
    private var outputTokens: Long = 0L
    private val detailFrames = LinkedHashSet<Long>()

    /** Reset for a new run; observational elapsed time restarts from now. */
    fun start(): Unit = synchronized(guard) {
        startedAtMillis = clock()
        steps = 0
        resultBytes = 0L
        detailResultBytes = 0L
        totalInputTokens = 0L
        uncachedInputTokens = 0L
        cachedInputTokens = 0L
        cacheCreationTokens = 0L
        weightedInputTokens = 0L
        outputTokens = 0L
        detailFrames.clear()
    }

    fun usage(): AgentBudgetUsage = synchronized(guard) {
        AgentBudgetUsage(
            steps = steps,
            maxSteps = policy.maxSteps,
            detailFrames = detailFrames.size,
            maxDetailFrames = policy.maxDetailFramesPerSession,
            resultBytes = resultBytes,
            maxResultBytes = policy.maxTotalResultBytes,
            detailResultBytes = detailResultBytes,
            maxDetailResultBytes = policy.maxDetailResultBytesPerSession,
            cumulativeInputTokens = totalInputTokens,
            uncachedInputTokens = uncachedInputTokens,
            cachedInputTokens = cachedInputTokens,
            cacheCreationTokens = cacheCreationTokens,
            weightedInputTokens = weightedInputTokens,
            maxCumulativeInputTokens = policy.maxCumulativeInputTokens,
            cumulativeOutputTokens = outputTokens,
            maxCumulativeOutputTokens = policy.maxCumulativeOutputTokens,
            elapsedMillis = (clock() - startedAtMillis).coerceAtLeast(0L)
        )
    }

    fun remainingSteps(): Int = synchronized(guard) { (policy.maxSteps - steps).coerceAtLeast(0) }

    /** True once no further tool call can be started. */
    fun isExhausted(): Boolean = synchronized(guard) {
        steps >= policy.maxSteps ||
            resultBytes >= policy.maxTotalResultBytes
    }

    /** True when another normal model request would exceed the run's cost policy. */
    fun isModelBudgetExhausted(): Boolean = synchronized(guard) {
        inputTokensExhausted() || outputTokensExhausted()
    }

    /** Charge provider-reported usage after every model attempt, including retries. */
    fun recordModelUsage(usage: AgentTokenUsage): Unit = synchronized(guard) {
        val input = usage.inputTokens.coerceAtLeast(0).toLong()
        val cached = usage.cachedInputTokens.coerceIn(0, usage.inputTokens.coerceAtLeast(0)).toLong()
        val creation = usage.cacheCreationTokens.coerceAtLeast(0).toLong()
            .coerceAtMost(input - cached)
        val uncached = input - cached - creation
        val discountedCached = (cached + CACHED_INPUT_WEIGHT_DENOMINATOR - 1L) /
            CACHED_INPUT_WEIGHT_DENOMINATOR
        totalInputTokens += input
        uncachedInputTokens += uncached
        cachedInputTokens += cached
        cacheCreationTokens += creation
        weightedInputTokens += uncached + creation + discountedCached
        outputTokens += usage.outputTokens.coerceAtLeast(0).toLong()
    }

    /**
     * Reserve one step and, for detail reads, grant the frames it may dissect.
     *
     * Frames already charged in this run are free, so a model re-reading frame
     * 120 does not pay twice, but it also cannot escape the session cap by
     * splitting one request into many.
     *
     * The frame caps grant rather than reject: a call asking for more than the
     * per-call or per-session limit gets the frames that fit and must report
     * the rest as omitted, so an oversized request degrades into a truncated
     * answer instead of a wasted step.  Only whole-run budgets (steps and
     * bytes) still fail the reservation; elapsed time never does.
     */
    fun reserve(
        requestedDetailFrames: Collection<Long> = emptyList(),
        detailRequest: AgentDetailRequest? = null
    ): Result<AgentBudgetReservation> =
        synchronized(guard) {
            if (steps >= policy.maxSteps) {
                return Result.failure(BudgetExceededException(stepsError()))
            }
            if (resultBytes >= policy.maxTotalResultBytes) {
                return Result.failure(BudgetExceededException(totalBytesError()))
            }

            val distinct = requestedDetailFrames.toSet()
            val detailGrant = policy.detailFrameGrant(detailRequest)
            val detailByteQuotaExhausted = distinct.isNotEmpty() &&
                detailResultBytes >= policy.maxDetailResultBytesPerSession

            // One pass in frame order, so the grant is always a *prefix* of the
            // sorted request: that is what makes "call again with omittedFrames"
            // terminate instead of handing back the same middle slice forever.
            //
            // A frame already charged this run costs no session quota but still
            // takes a per-call slot, because it is dissected again either way.
            // Charging happens only for frames that end up granted — deciding
            // the session debit before the per-call cap would bill frames this
            // call never reads and silently shrink the run's remaining quota.
            var sessionAllowance =
                (policy.maxDetailFramesPerSession - detailFrames.size).coerceAtLeast(0)
            val granted = LinkedHashSet<Long>()
            val newlyCharged = LinkedHashSet<Long>()
            val cutBySession = mutableListOf<Long>()
            if (!detailByteQuotaExhausted) for (frame in distinct.sorted()) {
                if (granted.size >= detailGrant.limit) break
                if (frame in detailFrames) {
                    granted += frame
                    continue
                }
                if (sessionAllowance <= 0) {
                    // Not a break: a later frame may already be charged and thus
                    // still free, and the model should get it rather than lose it
                    // to a neighbour it cannot afford.
                    cutBySession += frame
                    continue
                }
                sessionAllowance -= 1
                granted += frame
                newlyCharged += frame
            }
            val omitted = (distinct - granted).sorted().toSet()
            // True when the session quota did the cutting.  A frame cut after
            // the per-call break was never classified, so it counts as a session
            // cut when no session slot could have taken it anyway — otherwise
            // the model is told "call again later" for frames later calls can
            // never grant.
            val omittedBySessionQuota = !detailByteQuotaExhausted && omitted.isNotEmpty() && omitted.all { frame ->
                frame in cutBySession || (frame !in detailFrames && sessionAllowance <= 0)
            }
            val omittedByPerCallLimit = !detailByteQuotaExhausted && omitted.any { frame ->
                frame !in cutBySession && frame !in detailFrames
            }

            steps += 1
            detailFrames.addAll(newlyCharged)
            Result.success(
                AgentBudgetReservation(
                    stepIndex = steps,
                    remainingSteps = (policy.maxSteps - steps).coerceAtLeast(0),
                    remainingResultBytes = (policy.maxTotalResultBytes - resultBytes).coerceAtLeast(0L),
                    grantedFrames = granted,
                    omittedFrames = omitted,
                    omittedBySessionQuota = omittedBySessionQuota,
                    omittedByPerCallLimit = omittedByPerCallLimit,
                    omittedByResultByteQuota = detailByteQuotaExhausted,
                    remainingSessionDetailFrames =
                        (policy.maxDetailFramesPerSession - detailFrames.size).coerceAtLeast(0),
                    detailGrantLimit = detailGrant.limit,
                    detailGrantReason = when {
                        detailByteQuotaExhausted -> "detail_result_byte_quota"
                        omittedBySessionQuota -> "session_detail_frame_quota"
                        omittedByPerCallLimit -> detailGrant.reason
                        else -> detailGrant.reason
                    },
                    remainingDetailResultBytes =
                        (policy.maxDetailResultBytesPerSession - detailResultBytes)
                            .coerceAtLeast(0L)
                )
            )
        }

    /**
     * Admit an orchestration call without consuming an evidence step.
     *
     * Result bytes remain bounded because orchestration output still enters the
     * model transcript. The current evidence step is used only as an audit
     * position; it is not incremented.
     */
    fun reserveOrchestration(): Result<AgentBudgetReservation> = synchronized(guard) {
        if (resultBytes >= policy.maxTotalResultBytes) {
            return Result.failure(BudgetExceededException(totalBytesError()))
        }
        Result.success(
            AgentBudgetReservation(
                stepIndex = steps,
                remainingSteps = (policy.maxSteps - steps).coerceAtLeast(0),
                remainingResultBytes = (policy.maxTotalResultBytes - resultBytes).coerceAtLeast(0L),
                remainingSessionDetailFrames =
                    (policy.maxDetailFramesPerSession - detailFrames.size).coerceAtLeast(0),
                remainingDetailResultBytes =
                    (policy.maxDetailResultBytesPerSession - detailResultBytes).coerceAtLeast(0L)
            )
        )
    }

    /** Charge the encoded size of a result that was handed to the model. */
    fun recordResultBytes(bytes: Int, detailRead: Boolean = false): Unit = synchronized(guard) {
        if (bytes > 0) {
            resultBytes += bytes.toLong()
            if (detailRead) detailResultBytes += bytes.toLong()
        }
    }

    /** Bytes still available for the next single result. */
    fun resultByteAllowance(): Int = synchronized(guard) {
        val remaining = (policy.maxTotalResultBytes - resultBytes).coerceAtLeast(0L)
        minOf(policy.maxToolResultBytes.toLong(), remaining).toInt()
    }

    /** Bytes available to a detail result after both global and detail quotas. */
    fun detailResultByteAllowance(): Int = synchronized(guard) {
        val globalRemaining = (policy.maxTotalResultBytes - resultBytes).coerceAtLeast(0L)
        val detailRemaining =
            (policy.maxDetailResultBytesPerSession - detailResultBytes).coerceAtLeast(0L)
        minOf(
            policy.maxToolResultBytes.toLong(),
            policy.maxDetailResultBytesPerCall.toLong(),
            globalRemaining,
            detailRemaining
        ).toInt()
    }

    private fun stepsError() = AgentError(
        code = AgentErrorCode.MAX_STEPS_REACHED,
        userMessage = "The analysis reached its step limit.",
        retryable = false,
        details = mapOf("limit" to policy.maxSteps, "used" to steps)
    )

    private fun totalBytesError() = AgentError(
        code = AgentErrorCode.CONTEXT_LIMIT,
        userMessage = "The analysis reached its data limit.",
        retryable = false,
        details = mapOf("limit" to policy.maxTotalResultBytes, "used" to resultBytes)
    )

    /** Carries the structured reason a reservation failed. */
    class BudgetExceededException(val agentError: AgentError) :
        IllegalStateException(agentError.userMessage)

    private fun inputTokensExhausted(): Boolean =
        policy.maxCumulativeInputTokens > 0L &&
            weightedInputTokens >= policy.maxCumulativeInputTokens

    private fun outputTokensExhausted(): Boolean =
        policy.maxCumulativeOutputTokens > 0L &&
            outputTokens >= policy.maxCumulativeOutputTokens

    private companion object {
        const val CACHED_INPUT_WEIGHT_DENOMINATOR = 10L
    }
}
