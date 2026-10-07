// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.background

import com.example.layanalyzer.ai.agent.AgentRunIdentity
import com.example.layanalyzer.ai.agent.AgentRunListener
import com.example.layanalyzer.ai.agent.AgentRunOutcome
import com.example.layanalyzer.ai.agent.AgentRunSnapshot
import com.example.layanalyzer.ai.agent.AgentStopReason
import com.example.layanalyzer.ai.agent.ProtocolAnalysisAgent
import com.example.layanalyzer.model.AgentAnalysisMode
import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentPriorContext
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AgentToolActivityStatus
import com.example.layanalyzer.model.AnalysisJobPhase
import com.example.layanalyzer.model.AnalysisJobState
import com.example.layanalyzer.model.AnalysisScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Everything needed to execute one analysis run. */
data class AgentRunRequest(
    val question: String,
    val scope: AnalysisScope,
    val privacyMode: AgentPrivacyMode,
    val appendQuestion: Boolean,
    val identity: AgentRunIdentity,
    val priorContext: AgentPriorContext? = null,
    /** Sanitised transcript of this conversation's prior rounds. */
    val history: List<AgentModelMessage> = emptyList(),
    /**
     * Visible conversation items the screen already shows and this run should
     * keep below its own output — a follow-up carries the prior round's items;
     * a retry (which deliberately blanks the failed trajectory) passes none.
     * Visibility only: the replayed model state is [history].
     */
    val visibleMessages: List<AgentConversationItem> = emptyList(),
    val visibleModelInteractions: List<AgentModelInteraction> = emptyList(),
    /**
     * Explicit playbook id from the suggestion-chip path, forwarded to
     * [ProtocolAnalysisAgent.run].  Null — every path that replays a prior
     * round — keeps the question-text matching.
     */
    val playbookId: String? = null,
    /**
     * EVL-CONTEXT-03: display filter this run's snapshot is framed with
     * instead of the session's applied one, forwarded to
     * [ProtocolAnalysisAgent.run].  Only the initial evidence-workflow
     * submission sets it; follow-ups, retries and resumes leave it null so
     * they stay framed against the session's applied filter.
     */
    val displayFilterOverride: String? = null,
    /**
     * EVL-CONTEXT-04: number of frames in the evidence set the override was
     * compiled from, forwarded to [ProtocolAnalysisAgent.run].  Null on
     * every path without an override.
     */
    val evidenceFrameCount: Int? = null
)

/**
 * Owns the one in-flight Agent run, on an Application-scoped coroutine.
 *
 * The ViewModel used to own this — the coroutine, the generation guard, the
 * terminal publication and the auto-save — which is precisely why pressing
 * Home or swiping the task away killed the analysis: `onCleared` cancelled the
 * ViewModel scope and everything in it.  Moving ownership here means the run
 * survives the Activity, and the thin foreground service is only there to
 * raise the *process* priority, never to hold run state.
 *
 * The coordinator exposes two replayable states — [jobState] for the coarse
 * phase and [snapshot] for the accumulated transcript — so a ViewModel created
 * after the run started (rotation, a second Activity, the restored process)
 * shows the same in-progress state instead of an empty screen.  [snapshot] is
 * also the source the Phase 4 checkpoint serialises at each atomic boundary.
 *
 * One run at a time: a second [start] is refused, matching the single native
 * session and the agent's own `activeController` guard.  The terminal state is
 * published from the caller of [cancel], not from the cancelled coroutine,
 * which may never resume — the same rule the ViewModel enforced.
 */
class AgentRunCoordinator(
    private val agent: ProtocolAnalysisAgent,
    private val scope: CoroutineScope,
    private val onRunActiveChanged: (Boolean) -> Unit = {},
    private val clock: () -> Long = { System.currentTimeMillis() },
    /**
     * Durable checkpoint sink for process-death recovery.  Null disables
     * persistence (unit tests); the run works identically either way.
     */
    private val jobStore: com.example.layanalyzer.data.AnalysisJobStore? = null,
    /** Capture the run is framed against, read at start for the checkpoint. */
    private val captureSourceProvider: (() -> CaptureSourceInfo?)? = null
) {
    private val guard = Any()
    private var activeJob: Job? = null
    private var runGeneration: Long = 0L
    private var currentIdentity: AgentRunIdentity? = null
    private var currentRequest: AgentRunRequest? = null

    // Checkpoint bookkeeping, owned by the guard.
    private var checkpointStage = com.example.layanalyzer.data.AnalysisCheckpoint.Queued
    private var inFlightRequestId: String? = null
    private var checkpointTurn: Int = 0
    private val completedToolCallIds = mutableListOf<String>()
    private var lastCheckpointAtMillis: Long = 0L
    private var runStartedAtMillis: Long = 0L

    private val _jobState = MutableStateFlow(AnalysisJobState(phase = AnalysisJobPhase.Completed))
    val jobState: StateFlow<AnalysisJobState> = _jobState.asStateFlow()

    private val _snapshot = MutableStateFlow(AgentRunSnapshot())
    val snapshot: StateFlow<AgentRunSnapshot> = _snapshot.asStateFlow()

    val isRunning: Boolean
        get() = synchronized(guard) { activeJob?.isActive == true }

    /** The identity of the in-flight run, for notification and checkpoint use. */
    val activeIdentity: AgentRunIdentity?
        get() = synchronized(guard) { if (isRunning) currentIdentity else null }

    /**
     * Begin [request] on the shared scope.  Returns false — without touching
     * the current run — when one is already in flight.
     */
    fun start(request: AgentRunRequest): Boolean {
        synchronized(guard) {
            if (activeJob?.isActive == true) return false
            runGeneration += 1
            currentIdentity = request.identity
            currentRequest = request
            checkpointStage = com.example.layanalyzer.data.AnalysisCheckpoint.Queued
            inFlightRequestId = null
            checkpointTurn = 0
            completedToolCallIds.clear()
            runStartedAtMillis = clock()
            lastCheckpointAtMillis = 0L
        }
        val generation = synchronized(guard) { runGeneration }

        // A follow-up keeps the on-screen conversation: its carried-over items
        // seed the fresh snapshot so the run appends below them instead of
        // replacing them.  A retry passes none and starts visually clean.
        _snapshot.value = AgentRunSnapshot(
            phase = AgentRunPhase.Preparing,
            messages = request.visibleMessages,
            modelInteractions = request.visibleModelInteractions
        )
        _jobState.value = AnalysisJobState(
            phase = AnalysisJobPhase.Queued,
            scope = request.scope,
            message = "Queued"
        )
        writeCheckpoint(force = true)
        onRunActiveChanged(true)

        val job = scope.launch {
            val result = try {
                agent.run(
                    question = request.question,
                    scope = request.scope,
                    privacyMode = request.privacyMode,
                    listener = CoordinatorListener(generation),
                    priorContext = request.priorContext,
                    identity = request.identity,
                    history = request.history,
                    playbookId = request.playbookId,
                    displayFilterOverride = request.displayFilterOverride,
                    evidenceFrameCount = request.evidenceFrameCount
                )
            } catch (cancelled: CancellationException) {
                // cancel() already published the terminal state.
                throw cancelled
            }

            if (generation != synchronized(guard) { runGeneration }) return@launch

            when (val outcome = result.outcome) {
                is AgentRunOutcome.Completed -> {
                    publishCompleted(outcome.report, result, outcome.stopReason)
                }
                is AgentRunOutcome.Failed -> {
                    publishFailed(outcome.error, outcome.report, result, partialFailure = false)
                }
                is AgentRunOutcome.FailedWithPartialReport -> {
                    publishFailed(outcome.error, outcome.report, result, partialFailure = true)
                }
                is AgentRunOutcome.Cancelled -> publishCancelled()
            }
            synchronized(guard) {
                activeJob = null
                currentIdentity = null
                currentRequest = null
            }
            onRunActiveChanged(false)
        }
        synchronized(guard) { activeJob = job }
        return true
    }

    /**
     * Cancel the active run.
     *
     * The agent is cancelled before the coroutine so the controller latches
     * Cancelled, the model request is dropped and native work is stopped; the
     * terminal state is written here rather than from the cancelled coroutine,
     * which may never resume.
     */
    fun cancel() {
        val job = synchronized(guard) {
            runGeneration += 1
            val job = activeJob
            activeJob = null
            currentIdentity = null
            currentRequest = null
            job
        } ?: return
        agent.cancel()
        job.cancel()
        publishCancelled()
        onRunActiveChanged(false)
    }

    /** The terminal state a cancelled run resolves to, for external callers. */
    fun publishExternalFailure(error: AgentError) {
        val current = _snapshot.value
        _snapshot.value = current.copy(
            phase = AgentRunPhase.Failed,
            activeTool = null,
            error = error,
            streamingText = ""
        )
        _jobState.value = AnalysisJobState(
            phase = AnalysisJobPhase.Failed,
            errorCode = error.code.name,
            message = "Analysis ended"
        )
    }

    // -------------------------------------------------------------- terminals

    private fun publishCompleted(
        report: AgentReport,
        result: com.example.layanalyzer.ai.agent.AgentRunResult,
        stopReason: AgentStopReason
    ) {
        val current = _snapshot.value
        _snapshot.value = current.copy(
            phase = AgentRunPhase.Completed,
            activeTool = null,
            report = report,
            error = null,
            analysisMode = result.analysisMode,
            tokenUsage = result.tokenUsage,
            streamingText = "",
            transcript = result.finalTranscript
        )
        _jobState.value = AnalysisJobState(
            phase = AnalysisJobPhase.Completed,
            processed = current.completedSteps.toLong(),
            total = current.completedSteps.toLong(),
            message = "Analysis complete"
        )
        clearCheckpoint()
    }

    private fun publishFailed(
        error: AgentError,
        partialReport: AgentReport?,
        result: com.example.layanalyzer.ai.agent.AgentRunResult,
        partialFailure: Boolean
    ) {
        val current = _snapshot.value
        _snapshot.value = current.copy(
            phase = if (partialFailure) {
                AgentRunPhase.FailedWithPartialReport
            } else {
                AgentRunPhase.Failed
            },
            activeTool = null,
            report = partialReport ?: current.report,
            error = error,
            analysisMode = result.analysisMode,
            tokenUsage = result.tokenUsage,
            streamingText = "",
            transcript = result.finalTranscript.takeIf { partialFailure } ?: emptyList()
        )
        _jobState.value = AnalysisJobState(
            phase = AnalysisJobPhase.Failed,
            processed = current.completedSteps.toLong(),
            errorCode = error.code.name,
            message = "Analysis failed"
        )
        clearCheckpoint()
    }

    private fun publishCancelled() {
        val current = _snapshot.value
        _snapshot.value = current.copy(
            phase = AgentRunPhase.Cancelled,
            activeTool = null,
            streamingText = ""
        )
        _jobState.value = AnalysisJobState(
            phase = AnalysisJobPhase.Cancelled,
            message = "Analysis cancelled"
        )
        clearCheckpoint()
    }

    // -------------------------------------------------------------- listener

    private inner class CoordinatorListener(
        private val generation: Long
    ) : AgentRunListener {
        private fun current(): Boolean =
            generation == synchronized(guard) { runGeneration }

        override fun onPhaseChanged(phase: AgentRunPhase) {
            if (!current()) return
            // Terminal phases are published from the run's result instead, so a
            // report and its phase always land together.
            if (phase == AgentRunPhase.Completed ||
                phase == AgentRunPhase.Failed ||
                phase == AgentRunPhase.Cancelled
            ) {
                return
            }
            val snap = _snapshot.value
            _snapshot.value = snap.copy(
                phase = phase,
                activeTool = if (phase == AgentRunPhase.RunningTool) snap.activeTool else null
            )
            _jobState.value = AnalysisJobState(
                phase = AnalysisJobPhase.Running,
                processed = snap.completedSteps.toLong(),
                message = phase.name
            )
        }

        override fun onToolActivity(activity: AgentToolActivity) {
            if (!current()) return
            val snap = _snapshot.value
            val running = activity.status == AgentToolActivityStatus.Running ||
                activity.status == AgentToolActivityStatus.Queued
            // The loop reports the same call twice (running, then finished), so
            // merge on id rather than appending a duplicate row.
            val merged = snap.toolActivities.toMutableList()
            val index = merged.indexOfFirst { it.toolCallId == activity.toolCallId }
            if (index >= 0) merged[index] = activity else merged += activity
            _snapshot.value = snap.copy(
                activeTool = if (running) activity else null,
                toolActivities = merged,
                completedSteps = merged.count {
                    it.status != AgentToolActivityStatus.Running &&
                        it.status != AgentToolActivityStatus.Queued
                }
            )
        }

        override fun onMessage(item: AgentConversationItem) {
            if (!current()) return
            val snap = _snapshot.value
            val merged = snap.messages.toMutableList()
            // Retry status updates reuse an id so only the current x/y attempt
            // stays visible. Id-less messages retain append-only behavior.
            val index = item.id.takeIf { it.isNotBlank() }
                ?.let { id -> merged.indexOfFirst { it.id == id } }
                ?: -1
            if (index >= 0) merged[index] = item else merged += item
            _snapshot.value = snap.copy(messages = merged)
        }

        override fun onModelInteraction(interaction: AgentModelInteraction) {
            if (!current()) return
            val snap = _snapshot.value
            _snapshot.value = snap.copy(
                modelInteractions = snap.modelInteractions + interaction
            )
        }

        override fun onStreamingUpdate(text: String) {
            if (!current()) return
            _snapshot.value = _snapshot.value.copy(streamingText = text)
        }

        override fun onAnalysisPlan(plan: AgentAnalysisPlan, completedSteps: Int) {
            if (!current()) return
            _snapshot.value = _snapshot.value.copy(
                analysisPlan = plan,
                completedPlanSteps = completedSteps.coerceIn(0, plan.steps.size)
            )
        }

        override fun onModelRequestStarted(requestId: String, turn: Int?) {
            if (!current()) return
            synchronized(guard) {
                checkpointStage = com.example.layanalyzer.data.AnalysisCheckpoint.ModelRequestStarted
                inFlightRequestId = requestId
                if (turn != null) checkpointTurn = turn
            }
            writeCheckpoint(force = true)   // must be immediate: billing ambiguity starts here
        }

        override fun onModelResponseCommitted(requestId: String, turn: Int?) {
            if (!current()) return
            synchronized(guard) {
                checkpointStage = com.example.layanalyzer.data.AnalysisCheckpoint.ModelResponseCommitted
                inFlightRequestId = null
                if (turn != null) checkpointTurn = turn
            }
            writeCheckpoint()
        }

        override fun onToolCallStarted(toolCallId: String) {
            if (!current()) return
            synchronized(guard) {
                checkpointStage = com.example.layanalyzer.data.AnalysisCheckpoint.ToolStarted
            }
            writeCheckpoint()
        }

        override fun onToolCallCommitted(toolCallId: String) {
            if (!current()) return
            synchronized(guard) {
                checkpointStage = com.example.layanalyzer.data.AnalysisCheckpoint.ToolResultCommitted
                if (toolCallId.isNotBlank()) completedToolCallIds += toolCallId
            }
            writeCheckpoint()
        }

        override fun onReportValidated() {
            if (!current()) return
            synchronized(guard) {
                checkpointStage = com.example.layanalyzer.data.AnalysisCheckpoint.ReportValidated
            }
            writeCheckpoint()
        }
    }

    // ---------------------------------------------------------- checkpoint I/O

    /**
     * Write the current checkpoint to [jobStore], best-effort.
     *
     * By default writes are debounced to one per 2 seconds; setting [force]
     * true bypasses the debounce — required for ModelRequestStarted (billing
     * ambiguity begins immediately) and terminal writes.
     */
    private fun writeCheckpoint(force: Boolean = false) {
        val store = jobStore ?: return
        val now = clock()
        val (shouldWrite, snap) = synchronized(guard) {
            val tooSoon = !force && (now - lastCheckpointAtMillis) < DEBOUNCE_MILLIS
            if (tooSoon) return
            lastCheckpointAtMillis = now
            true to _snapshot.value
        }
        if (!shouldWrite) return
        val req = currentRequest ?: return
        val identity = currentIdentity ?: return
        val captureSource = captureSourceProvider?.invoke()
        val stage = synchronized(guard) { checkpointStage }
        val requestId = synchronized(guard) { inFlightRequestId }
        val turn = synchronized(guard) { checkpointTurn }
        val toolIds = synchronized(guard) { completedToolCallIds.toList() }
        store.write(
            com.example.layanalyzer.data.AnalysisJobCheckpoint(
                conversationId = identity.conversationId,
                runId = identity.runId,
                requestId = requestId,
                captureFingerprint = captureSource?.fingerprint.orEmpty(),
                captureLocalPath = captureSource?.localPath.orEmpty(),
                captureDisplayName = captureSource?.displayName.orEmpty(),
                captureSizeBytes = captureSource?.sizeBytes ?: 0L,
                scope = req.scope,
                privacyMode = req.privacyMode,
                question = req.question,
                checkpoint = stage,
                turn = turn,
                completedSteps = snap.completedSteps,
                completedToolCallIds = toolIds,
                transcript = snap.messages,
                startedAtMillis = runStartedAtMillis
            )
        )
    }

    private fun clearCheckpoint() {
        val store = jobStore ?: return
        val runId = synchronized(guard) { currentIdentity?.runId }
        if (runId != null) store.delete(runId)
    }

    companion object {
        private const val DEBOUNCE_MILLIS = 2_000L
    }
}

/** Minimal capture identity needed for the Phase 4 checkpoint record. */
data class CaptureSourceInfo(
    val fingerprint: String,
    val localPath: String,
    val displayName: String = "",
    val sizeBytes: Long = 0L
)
