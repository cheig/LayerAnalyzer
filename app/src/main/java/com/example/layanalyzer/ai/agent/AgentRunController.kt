package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.client.AiModelClient
import com.example.layanalyzer.data.AgentAnalysisRepository
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentRunPhase
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Owns the identity and the cancellation chain of one Agent run.
 *
 * The run's [AgentRunIdentity] comes from the caller, so it stays stable
 * across process restarts; only the per-turn request counter is derived
 * here, which keeps scripted-test request ids reproducible within a run
 * ("<runId>:model:<n>").
 *
 * The controller is the single place that knows a run has ended.  Phase
 * transitions are validated against AI-06's state machine and terminal states
 * latch, so a late model response or a native result that arrives after
 * cancellation cannot reopen a finished run.
 */
class AgentRunController(
    val identity: AgentRunIdentity,
    private val modelClient: AiModelClient,
    private val repository: AgentAnalysisRepository,
    /** Generation of the owning Agent run; bumped once on cancel. */
    initialGeneration: Long = 1L
) {
    private val generation = AtomicLong(initialGeneration)
    private val phaseRef = AtomicReference(AgentRunPhase.Idle)
    private val cancelled = AtomicBoolean(false)
    private val inFlightRequestId = AtomicReference<String?>(null)
    private val requestCounter = AtomicLong(0L)

    val agentGeneration: Long
        get() = generation.get()

    val phase: AgentRunPhase
        get() = phaseRef.get()

    val isCancelled: Boolean
        get() = cancelled.get()

    val isTerminal: Boolean
        get() = phaseRef.get().isTerminal

    /** Deterministic per-turn request id, globally unique via the run id. */
    fun nextRequestId(): String {
        val turn = requestCounter.incrementAndGet()
        val id = "${identity.runId}:model:$turn"
        inFlightRequestId.set(id)
        return id
    }

    /** Forget the in-flight request once its response has been consumed. */
    fun clearInFlightRequest(requestId: String) {
        inFlightRequestId.compareAndSet(requestId, null)
    }

    /**
     * Move to [next] if the transition is legal and the run has not finished.
     *
     * The result carries the phase observed by the successful CAS (or refusal),
     * avoiding a separate read that becomes stale when tool calls overlap.
     */
    fun transitionTo(next: AgentRunPhase): PhaseTransition {
        while (true) {
            val current = phaseRef.get()
            if (current == next) return PhaseTransition(!current.isTerminal, current)
            if (current.isTerminal) return PhaseTransition(false, current)
            if (!current.canTransitionTo(next)) return PhaseTransition(false, current)
            if (phaseRef.compareAndSet(current, next)) return PhaseTransition(true, current)
        }
    }

    /** Enter a terminal phase exactly once; later attempts are refused. */
    fun finish(terminal: AgentRunPhase): Boolean {
        require(terminal.isTerminal) { "$terminal is not a terminal phase." }
        while (true) {
            val current = phaseRef.get()
            if (current.isTerminal) return false
            if (phaseRef.compareAndSet(current, terminal)) return true
        }
    }

    /**
     * Cancel the run: bump the generation, stop the model request, stop native
     * work, and latch the Cancelled phase.
     *
     * The generation bump comes first so any result still in flight fails its
     * own snapshot check instead of committing.  Releasing the filter lease is
     * handled by CaptureSessionCoordinator, which restores the user's filter
     * from a NonCancellable block once the cancelled read unwinds — doing it
     * here would race with a read that has not yet returned.
     *
     * Idempotent: a second call does nothing, so a UI cancel followed by
     * onCleared cannot bump the generation twice and invalidate a *new* run.
     */
    fun cancel() {
        if (!cancelled.compareAndSet(false, true)) return
        generation.incrementAndGet()
        inFlightRequestId.getAndSet(null)?.let { requestId ->
            runCatching { modelClient.cancel(requestId) }
        }
        runCatching { repository.cancelLongRunningOperations() }
        finish(AgentRunPhase.Cancelled)
    }

    /** True when a result produced under [snapshotGeneration] may still commit. */
    fun isCurrent(snapshotGeneration: Long): Boolean =
        !cancelled.get() && snapshotGeneration == generation.get()

    fun cancelledError(): AgentError = AgentError(
        code = AgentErrorCode.CANCELLED,
        userMessage = "The analysis was cancelled.",
        retryable = true,
        details = mapOf(
            "conversationId" to identity.conversationId,
            "runId" to identity.runId
        )
    )
}

data class PhaseTransition(
    val moved: Boolean,
    val previous: AgentRunPhase
)

/** Terminal phases latch; nothing may follow them. */
internal val AgentRunPhase.isTerminal: Boolean
    get() = this == AgentRunPhase.Completed ||
        this == AgentRunPhase.Failed ||
        this == AgentRunPhase.FailedWithPartialReport ||
        this == AgentRunPhase.Cancelled

/**
 * The transitions AI-06 §4 permits.  Failed and Cancelled are reachable from
 * any running phase; everything else follows the documented path.
 */
internal fun AgentRunPhase.canTransitionTo(next: AgentRunPhase): Boolean {
    if (next == AgentRunPhase.Failed ||
        next == AgentRunPhase.FailedWithPartialReport ||
        next == AgentRunPhase.Cancelled
    ) {
        return !this.isTerminal
    }
    return when (this) {
        AgentRunPhase.Idle -> next == AgentRunPhase.Preparing
        AgentRunPhase.Preparing -> next == AgentRunPhase.Investigating ||
            next == AgentRunPhase.WaitingForModel
        AgentRunPhase.Investigating -> next == AgentRunPhase.WaitingForModel ||
            next == AgentRunPhase.Finalizing
        AgentRunPhase.WaitingForModel ->
            next == AgentRunPhase.RunningTool ||
                next == AgentRunPhase.ValidatingReport ||
                next == AgentRunPhase.Investigating ||
                next == AgentRunPhase.Finalizing ||
                next == AgentRunPhase.Revising
        // A tool turn may now end the run: submit_report delivers the final
        // report through the tool channel, so validation legitimately follows
        // RunningTool without passing back through the model.
        AgentRunPhase.RunningTool -> next == AgentRunPhase.WaitingForModel ||
            next == AgentRunPhase.Finalizing ||
            next == AgentRunPhase.ValidatingReport
        AgentRunPhase.Finalizing -> next == AgentRunPhase.ValidatingReport ||
            next == AgentRunPhase.Revising
        AgentRunPhase.Revising -> next == AgentRunPhase.ValidatingReport ||
            next == AgentRunPhase.Finalizing
        AgentRunPhase.ValidatingReport ->
            next == AgentRunPhase.WaitingForModel ||
                next == AgentRunPhase.Revising ||
                next == AgentRunPhase.Completed
        AgentRunPhase.Completed,
        AgentRunPhase.Failed,
        AgentRunPhase.FailedWithPartialReport,
        AgentRunPhase.Cancelled -> false
    }
}
