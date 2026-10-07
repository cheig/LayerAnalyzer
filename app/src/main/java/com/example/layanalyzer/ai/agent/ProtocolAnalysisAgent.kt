package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.client.AiModelClient
import com.example.layanalyzer.ai.audit.AgentDiagnosticsEventType
import com.example.layanalyzer.ai.audit.AgentDiagnosticsRecorder
import com.example.layanalyzer.ai.audit.AgentDiagnosticsSession
import com.example.layanalyzer.ai.audit.AgentRunAuditRecorder
import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.ai.audit.isAgentFatal
import com.example.layanalyzer.ai.cache.AgentToolCache
import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.AgentPlaybookStore
import com.example.layanalyzer.ai.tools.AgentToolAuditLog
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.ai.tools.AgentToolRunner
import com.example.layanalyzer.data.AgentAnalysisRepository
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentAnalysisMode
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentPriorContext
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentTokenUsage
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.resolveDisplayFilter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import java.util.concurrent.atomic.AtomicReference

/** Everything one analysis produced, including a partial report on failure. */
data class AgentRunResult(
    /**
     * Who this run belongs to: a cross-process conversation id plus the id of
     * this specific run.  Null only when the run was refused before it started.
     */
    val identity: AgentRunIdentity?,
    val outcome: AgentRunOutcome,
    val activities: List<AgentToolActivity> = emptyList(),
    val toolCallIds: List<String> = emptyList(),
    val analysisMode: AgentAnalysisMode = AgentAnalysisMode.FullAgent,
    val runRecord: AgentRunRecord? = null,
    /** Argument hashes of the steps the AI-24 cache answered. */
    val cacheHitArgumentHashes: Set<String> = emptySet(),
    /** Local diagnostics run identifier, safe to quote when reporting a failure. */
    val diagnosticId: String? = null,
    /** Provider-reported totals across every model attempt in this run. */
    val tokenUsage: AgentTokenUsage? = null,
    /**
     * This run's final model messages, sanitised for replay.  A conversation's
     * next run sends these as its history; empty unless the run reached a
     * terminal outcome through the loop.
     */
    val finalTranscript: List<AgentModelMessage> = emptyList()
) {
    /** The conversation this run belongs to; empty for a refused run. */
    val conversationId: String
        get() = identity?.conversationId.orEmpty()

    /** This run's unique id; also the diagnostics runId. Empty when refused. */
    val runId: String
        get() = identity?.runId.orEmpty()

    val report: AgentReport?
        get() = outcome.report

    val error: AgentError?
        get() = (outcome as? AgentRunOutcome.Failed)?.error

    val cancelled: Boolean
        get() = outcome is AgentRunOutcome.Cancelled
}

/**
 * The public entry point for one protocol analysis.
 *
 * A caller supplies a question and a scope; everything else — the snapshot, the
 * budget, the tool boundary, the evidence ledger and the final validation — is
 * assembled here, so no caller can start a run that skips one of them.
 *
 * One instance runs one analysis at a time, matching
 * [AgentPolicy.maxConcurrentSessions]: the shared native session has a single
 * global filter, so a second concurrent run would silently read through the
 * first one's filter.  A caller wanting a new analysis cancels the current one
 * first, which is what [ProtocolAgentViewModel] will do in AI-07.
 */
class ProtocolAnalysisAgent(
    private val repository: AgentAnalysisRepository,
    private val registry: AgentToolRegistry,
    private val modelClient: AiModelClient,
    private val policy: AgentPolicy = AgentPolicy(),
    /** Resolved once at run start so settings changes do not affect active work. */
    private val modelRetryCountProvider: (() -> Int)? = null,
    /** Resolved once at run start so settings changes do not affect active work. */
    private val modelRequestTimeoutMillisProvider: (() -> Long?)? = null,
    private val auditLog: AgentToolAuditLog? = null,
    private val clock: () -> Long = { System.currentTimeMillis() },
    /** Resolved once per run so configuration changes never alter an active run. */
    private val modelClientProvider: (() -> AiModelClient)? = null,
    private val playbookStore: AgentPlaybookStore? = null,
    /** AI-24 deterministic tool cache; null disables caching entirely. */
    private val toolCache: AgentToolCache? = null,
    /** AI-24 local diagnostics log; null disables recording entirely. */
    private val diagnostics: AgentDiagnosticsRecorder? = null,
    /** Native engine identity, part of the cache key. */
    private val nativeBuildMarker: () -> String = { "" }
) {
    private val activeController = AtomicReference<AgentRunController?>(null)

    /** The run currently in progress, if any.  Used by the UI to show state. */
    val currentPhase: AgentRunPhase
        get() = activeController.get()?.phase ?: AgentRunPhase.Idle

    val isRunning: Boolean
        get() = activeController.get()?.let { !it.isTerminal } ?: false

    /** Tool definitions used by the consent preview, without exposing the registry. */
    fun toolDefinitions(): List<AgentToolDefinition> = registry.definitions()

    /**
     * Analyse [question] against the currently open capture.
     *
     * The snapshot is created here rather than accepted from the caller, so the
     * fingerprint, generation and frame count are all read at the moment the run
     * starts and cannot be a stale set a caller held on to.
     *
     * [identity] is minted by the caller: a new conversation starts a fresh
     * [AgentRunIdentity.newConversation], a follow-up or retry reuses the
     * conversation id through [AgentRunIdentity.follow].  The agent never mints
     * ids itself — only the caller knows which of those this run is, and the id
     * must exist before the run starts so checkpoints and history can key on it.
     */
    suspend fun run(
        question: String,
        scope: AnalysisScope = AnalysisScope.CompleteFile,
        privacyMode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata,
        listener: AgentRunListener? = null,
        priorContext: AgentPriorContext? = null,
        identity: AgentRunIdentity = AgentRunIdentity.newConversation(),
        /** Sanitised transcript of this conversation's prior rounds. */
        history: List<AgentModelMessage> = emptyList(),
        /**
         * Explicit playbook id from the suggestion-chip path.  Null — every
         * existing call site — keeps the question-text matching, and a stale id
         * degrades to that same matching inside [AgentPlaybookStore.select].
         */
        playbookId: String? = null,
        /**
         * EVL-CONTEXT-03: display filter this run's snapshot is framed with
         * instead of the session's applied one (see [resolveDisplayFilter]).
         * Only the initial evidence-workflow submission passes it; follow-ups,
         * retries and resumes default to null and stay on the session filter.
         * The caller must already have validated the filter through the shared
         * capture-session coordinator — the agent runs no second validation.
         */
        displayFilterOverride: String? = null,
        /**
         * EVL-CONTEXT-04: number of frames in the evidence set the override
         * was compiled from, recorded at submission time and carried into
         * the snapshot so the report provenance can expose it.  Null on
         * every path without an override.
         */
        evidenceFrameCount: Int? = null
    ): AgentRunResult {
        if (isRunning) {
            return refused(
                AgentError(
                    code = AgentErrorCode.INTERNAL_ERROR,
                    userMessage = "Another analysis is already running.",
                    retryable = true,
                    details = mapOf("reason" to "concurrent_run")
                )
            )
        }

        val trimmedQuestion = question.trim()
        if (trimmedQuestion.isEmpty()) {
            return refused(
                AgentError(
                    code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                    userMessage = "Enter a question before starting the analysis.",
                    retryable = false,
                    details = mapOf("field" to "question")
                )
            )
        }

        val sessionId = identity.runId
        val diagnosticSession = try {
            diagnostics?.beginRun(
                sessionId = sessionId,
                runId = identity.runId,
                conversationId = identity.conversationId,
                startedAtMillis = clock()
            )
        } catch (failure: Throwable) {
            if (failure.isAgentFatal()) throw failure
            // Diagnostics are best effort. A read-only/full directory must not
            // prevent the actual analysis from running.
            null
        }
        var controller: AgentRunController? = null

        fun finish(result: AgentRunResult): AgentRunResult {
            val enriched = withDiagnosticId(result, diagnosticSession)
            finishDiagnostics(diagnosticSession, enriched.outcome)
            return enriched
        }

        return try {
            diagnosticSession?.configure(
                attributes = mapOf(
                    "scope" to scope.name,
                    "privacyMode" to privacyMode.name
                )
            )
            val selectedModelClient = try {
                modelClientProvider?.invoke() ?: modelClient
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                if (failure.isAgentFatal()) throw failure
                val error = unexpectedRunError("model_provider")
                diagnosticSession?.recordFailure(
                    type = AgentDiagnosticsEventType.Configuration,
                    boundary = "model.provider",
                    error = error,
                    throwable = failure,
                    phase = AgentRunPhase.Preparing.name,
                    status = "failed"
                )
                return finish(
                    AgentRunResult(
                        identity = identity,
                        outcome = AgentRunOutcome.Failed(error, report = null)
                    )
                )
            }
            val currentController = AgentRunController(
                identity = identity,
                modelClient = selectedModelClient,
                repository = repository
            )
            if (!activeController.compareAndSet(null, currentController)) {
                return finish(
                    AgentRunResult(
                        identity = identity,
                        outcome = AgentRunOutcome.Failed(
                            AgentError(
                                code = AgentErrorCode.INTERNAL_ERROR,
                                userMessage = "Another analysis is already running.",
                                retryable = true,
                                details = mapOf("reason" to "concurrent_run")
                            ),
                            report = null
                        )
                    )
                )
            }
            controller = currentController
            diagnosticSession?.configure(
                modelId = selectedModelClient.id,
                attributes = mapOf("modelResolved" to "true")
            )
            listener?.onPhaseChanged(AgentRunPhase.Preparing)

            val snapshot = try {
                when (val created = repository.createSnapshot(scope, displayFilterOverride, evidenceFrameCount)) {
                    is AgentAnalysisResult.Failure -> {
                        diagnosticSession?.recordFailure(
                            type = AgentDiagnosticsEventType.SnapshotFailed,
                            boundary = "snapshot",
                            error = created.error,
                            phase = AgentRunPhase.Preparing.name,
                            status = "failed",
                            attributes = mapOf("scope" to scope.name)
                        )
                        currentController.finish(AgentRunPhase.Failed)
                        listener?.onPhaseChanged(AgentRunPhase.Failed)
                        return finish(
                            AgentRunResult(
                                identity = identity,
                                outcome = AgentRunOutcome.Failed(created.error, report = null)
                            )
                        )
                    }
                    is AgentAnalysisResult.Success -> created.value.also { snapshot ->
                        diagnosticSession?.record(
                            type = AgentDiagnosticsEventType.SnapshotReady,
                            captureFingerprint = snapshot.captureFingerprint,
                            phase = AgentRunPhase.Preparing.name,
                            status = "succeeded",
                            attributes = mapOf(
                                "scope" to snapshot.scope.name,
                                "frameCount" to snapshot.frameCount.toString(),
                                "sessionGeneration" to snapshot.sessionGeneration.toString()
                            )
                        )
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                if (failure.isAgentFatal()) throw failure
                val error = unexpectedRunError("snapshot")
                diagnosticSession?.recordFailure(
                    type = AgentDiagnosticsEventType.SnapshotFailed,
                    boundary = "snapshot",
                    error = error,
                    throwable = failure,
                    phase = AgentRunPhase.Preparing.name,
                    status = "failed",
                    attributes = mapOf("scope" to scope.name)
                )
                currentController.finish(AgentRunPhase.Failed)
                listener?.onPhaseChanged(AgentRunPhase.Failed)
                return finish(
                    AgentRunResult(
                        identity = identity,
                        outcome = AgentRunOutcome.Failed(error, report = null)
                    )
                )
            }

            val runPolicy = policy.adaptiveForCapture(snapshot.frameCount).copy(
                maxModelRetries = (modelRetryCountProvider?.let { provider ->
                    runCatching { provider() }.getOrNull()
                } ?: policy.maxModelRetries).coerceIn(0, AgentPolicy.MAX_MODEL_RETRIES),
                maxModelRequestTimeoutMillis = (
                    modelRequestTimeoutMillisProvider?.let { provider ->
                        runCatching { provider() }.getOrNull()
                    } ?: policy.maxModelRequestTimeoutMillis
                    ).coerceIn(
                    1L,
                    AgentPolicy.MAX_MODEL_REQUEST_TIMEOUT_MILLIS
                )
            )

            finish(execute(
                identity = identity,
                controller = currentController,
                question = trimmedQuestion,
                snapshot = snapshot,
                privacyMode = privacyMode,
                listener = listener,
                modelClient = selectedModelClient,
                diagnostics = diagnosticSession,
                policy = runPolicy,
                priorContext = priorContext,
                history = history,
                playbookId = playbookId
            ))
        } catch (cancelled: CancellationException) {
            // Structured concurrency must keep working, but the run is still
            // marked terminal so nothing can commit against it afterwards.
            controller?.finish(AgentRunPhase.Cancelled)
            diagnosticSession?.finish(
                status = "cancelled",
                error = AgentError(
                    code = AgentErrorCode.CANCELLED,
                    userMessage = "The analysis was cancelled."
                ),
                attributes = mapOf(
                    "phase" to (controller?.phase?.name ?: AgentRunPhase.Preparing.name)
                )
            )
            throw cancelled
        } catch (failure: Throwable) {
            if (failure.isAgentFatal()) throw failure
            val phase = controller?.phase?.name ?: AgentRunPhase.Preparing.name
            val error = unexpectedRunError(phase)
            diagnosticSession?.recordFailure(
                type = AgentDiagnosticsEventType.Configuration,
                boundary = "run.${phase.lowercase()}",
                error = error,
                throwable = failure,
                phase = phase,
                status = "failed"
            )
            controller?.finish(AgentRunPhase.Failed)
            listener?.onPhaseChanged(AgentRunPhase.Failed)
            finish(
                AgentRunResult(
                    identity = identity,
                    outcome = AgentRunOutcome.Failed(error, report = null)
                )
            )
        } finally {
            // Only clear the slot if this run still owns it: a cancel followed
            // by a new run must not have its controller dropped by the old one.
            activeController.compareAndSet(controller, null)
        }
    }

    private suspend fun execute(
        identity: AgentRunIdentity,
        controller: AgentRunController,
        question: String,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode,
        listener: AgentRunListener?,
        modelClient: AiModelClient,
        diagnostics: AgentDiagnosticsSession?,
        policy: AgentPolicy,
        priorContext: AgentPriorContext?,
        history: List<AgentModelMessage>,
        playbookId: String?
    ): AgentRunResult {
        val sessionId = identity.runId
        val negotiator = modelClient as? com.example.layanalyzer.ai.client.AgentCapabilityNegotiator
        if (negotiator?.negotiateBeforeRun == true) {
            diagnostics?.record(
                type = AgentDiagnosticsEventType.Configuration,
                phase = AgentRunPhase.Preparing.name,
                status = "started",
                attributes = mapOf("capabilityNegotiation" to "true")
            )
            val negotiationError = negotiateCapabilitiesWithRetry(
                negotiator = negotiator,
                policy = policy,
                diagnostics = diagnostics
            )
            if (negotiationError != null) {
                controller.finish(AgentRunPhase.Failed)
                listener?.onPhaseChanged(AgentRunPhase.Failed)
                return AgentRunResult(
                    identity = identity,
                    outcome = AgentRunOutcome.Failed(negotiationError, report = null)
                )
            }
            diagnostics?.record(
                type = AgentDiagnosticsEventType.Configuration,
                phase = AgentRunPhase.Preparing.name,
                status = "succeeded",
                attributes = mapOf("capabilityNegotiation" to "true")
            )
        }
        val capabilities = modelClient.capabilities
        diagnostics?.record(
            type = AgentDiagnosticsEventType.Configuration,
            modelId = modelClient.id,
            phase = AgentRunPhase.Preparing.name,
            status = "ready",
            attributes = buildMap {
                put("toolCalling", capabilities.toolCalling.toString())
                put("structuredOutput", capabilities.structuredOutput.toString())
                put("maxContextTokens", capabilities.maxContextTokens.toString())
                put("maxOutputTokens", capabilities.maxOutputTokens.toString())
                put("tokenLimitSource", capabilities.tokenLimitSource.name)
                put(
                    "contextLimitSource",
                    if (capabilities.hasContextLimit) capabilities.tokenLimitSource.name else "fallback"
                )
                if (!capabilities.hasContextLimit) {
                    put("fallbackContextTokens", ContextPlanner.DEFAULT_CONTEXT_TOKENS.toString())
                }
            }
        )
        val playbook = try {
            playbookStore?.select(question, playbookId) ?: AgentPlaybook.generalCaptureHealth()
        } catch (_: IllegalArgumentException) {
            val error = AgentError(
                code = AgentErrorCode.INTERNAL_ERROR,
                userMessage = "The analysis playbook is unavailable.",
                retryable = false,
                details = mapOf("reason" to "playbook_validation")
            )
            diagnostics?.recordFailure(
                type = AgentDiagnosticsEventType.Configuration,
                boundary = "playbook.select",
                error = error,
                phase = AgentRunPhase.Preparing.name,
                status = "failed"
            )
            controller.finish(AgentRunPhase.Failed)
            listener?.onPhaseChanged(AgentRunPhase.Failed)
            return AgentRunResult(
                identity = identity,
                outcome = AgentRunOutcome.Failed(error, report = null)
            )
        }
        diagnostics?.configure(
            captureFingerprint = snapshot.captureFingerprint,
            playbookVersion = playbook.versionedId,
            attributes = mapOf(
                "playbookSelected" to "true",
                "initialToolCount" to playbook.initialTools.size.toString()
            )
        )
        val ledger = EvidenceLedger()
        val budget = AgentBudgetTracker(policy, clock)
        val runAudit = AgentRunAuditRecorder().apply {
            start(
                sessionId = sessionId,
                snapshot = snapshot,
                modelId = modelClient.id,
                promptVersion = AgentPrompt.VERSION,
                playbookVersion = playbook.versionedId,
                startedAtMillis = snapshot.startedAtMillis.takeIf { it > 0L } ?: clock()
            )
        }
        // Argument hashes of the steps the cache answered.  The hash is already
        // the audit boundary's own identifier, so recording which ones were
        // served from cache adds no new information about what was read.
        val cacheHitHashes = linkedSetOf<String>()
        val loop = AgentLoop(
            toolRunner = AgentToolRunner(
                registry = registry,
                repository = repository,
                policy = policy,
                budget = budget,
                auditLog = AgentToolAuditLog { entry ->
                    auditLog?.record(entry)
                    runAudit.record(entry)
                    if (entry.cacheHit) cacheHitHashes += entry.normalizedArgumentsHash
                },
                clock = clock,
                cache = toolCache,
                nativeBuildMarker = runCatching(nativeBuildMarker).getOrDefault("")
            ),
            modelClient = modelClient,
            controller = controller,
            policy = policy,
            ledger = ledger,
            validator = EvidenceValidator(clock = clock, policy = policy),
            listener = listener,
            playbook = playbook,
            clock = clock,
            diagnostics = diagnostics
        )

        val outcome = try {
            // One deferred-restore chain per run: tool calls keep their
            // temporary filter applied between reads and the coordinator
            // restores the user's filter once, when the loop ends.  The end
            // call is NonCancellable inside, so cancellation paths still
            // release the chain.
            repository.beginAgentFilterChain()
            try {
                loop.run(question, snapshot, privacyMode, priorContext, history)
            } finally {
                repository.endAgentFilterChain()
            }
        } catch (cancelled: CancellationException) {
            val runRecord = runAudit.finish(
                completedAtMillis = clock(),
                cancelReason = AgentStopReason.Cancelled.name
            )
            recordLegacyDiagnostics(runRecord, cacheHitHashes, report = null)
            throw cancelled
        } catch (failure: Throwable) {
            if (failure.isAgentFatal()) throw failure
            val error = unexpectedRunError("agent_loop")
            diagnostics?.recordFailure(
                type = AgentDiagnosticsEventType.Configuration,
                boundary = "agent.loop",
                error = error,
                throwable = failure,
                phase = controller.phase.name,
                status = "failed"
            )
            controller.finish(AgentRunPhase.Failed)
            listener?.onPhaseChanged(AgentRunPhase.Failed)
            val runRecord = runAudit.finish(
                completedAtMillis = clock(),
                cancelReason = error.code.name
            )
            recordLegacyDiagnostics(runRecord, cacheHitHashes, report = null)
            return AgentRunResult(
                identity = identity,
                outcome = AgentRunOutcome.Failed(error, report = null),
                activities = loop.activities(),
                toolCallIds = ledger.toolCallIds,
                analysisMode = loop.analysisMode,
                runRecord = runRecord,
                cacheHitArgumentHashes = cacheHitHashes,
                tokenUsage = loop.tokenUsage(),
                // The interrupted loop's partial trajectory is not committed:
                // a follow-up must not replay a half-finished round.
                finalTranscript = emptyList()
            )
        }
        // EVL-COVERAGE-03: the audit record carries the coverage receipt as
        // three counters, derived from the exact EvidenceCoverage object the
        // loop's trace holds (cited + uncited is the flagged set by
        // construction). Only counts cross the audit boundary; the
        // frame-number sets stay in the trace's in-memory object.
        val evidenceCoverage = loop.evidenceCoverage()
        val runRecord = runAudit.finish(
            completedAtMillis = clock(),
            report = outcome.report,
            cancelReason = when (outcome) {
                is AgentRunOutcome.Completed -> outcome.stopReason
                    .takeUnless { it == AgentStopReason.ModelFinal }
                    ?.name
                is AgentRunOutcome.Failed -> outcome.error.code.name
                is AgentRunOutcome.FailedWithPartialReport -> outcome.error.code.name
                is AgentRunOutcome.Cancelled -> AgentStopReason.Cancelled.name
            },
            evidenceFlaggedCount = evidenceCoverage
                ?.let { it.citedFrames.size + it.uncitedFrames.size } ?: 0,
            evidenceCitedCount = evidenceCoverage?.citedFrames?.size ?: 0,
            citationOutsideFlagged = evidenceCoverage?.citationOutsideFlagged?.size ?: 0
        )
        // Diagnostics are written for every terminal outcome, including a
        // cancellation: a run the user gave up on is often the one worth
        // looking at afterwards.
        runRecord?.let { record ->
            recordLegacyDiagnostics(record, cacheHitHashes, outcome.report)
        }
        return AgentRunResult(
            identity = identity,
            outcome = outcome,
            activities = loop.activities(),
            toolCallIds = ledger.toolCallIds,
            analysisMode = loop.analysisMode,
            runRecord = runRecord,
            cacheHitArgumentHashes = cacheHitHashes,
            tokenUsage = loop.tokenUsage(),
            finalTranscript = if (outcome is AgentRunOutcome.Cancelled) {
                emptyList()
            } else {
                loop.sanitizedTranscript()
            }
        )
    }

    private fun recordLegacyDiagnostics(
        record: AgentRunRecord?,
        cacheHitHashes: Set<String>,
        report: AgentReport?
    ) {
        record?.let {
            diagnostics?.record(
                record = it,
                cacheHitHashes = cacheHitHashes,
                removedEvidenceCount = removedEvidenceCount(report)
            )
        }
    }

    private suspend fun negotiateCapabilitiesWithRetry(
        negotiator: com.example.layanalyzer.ai.client.AgentCapabilityNegotiator,
        policy: AgentPolicy,
        diagnostics: AgentDiagnosticsSession?
    ): AgentError? {
        var retryCount = 0
        while (true) {
            currentCoroutineContext().ensureActive()
            val startedAt = clock()
            val attempt = retryCount + 1
            val attributes = mapOf(
                "capabilityNegotiation" to "true",
                "attempt" to attempt.toString(),
                "maxRetries" to policy.maxModelRetries.toString()
            )
            var thrown: Throwable? = null
            val error = try {
                negotiator.negotiateCapabilities()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                if (failure.isAgentFatal()) throw failure
                thrown = failure
                unexpectedRunError("capability_negotiation")
            }

            if (thrown != null) {
                diagnostics?.recordFailure(
                    type = AgentDiagnosticsEventType.Configuration,
                    boundary = "model.capability_negotiation",
                    error = error,
                    throwable = thrown,
                    phase = AgentRunPhase.Preparing.name,
                    status = "failed",
                    attributes = attributes + mapOf(
                        "durationMillis" to (clock() - startedAt).coerceAtLeast(0L).toString()
                    )
                )
            } else if (error != null) {
                diagnostics?.recordFailure(
                    type = AgentDiagnosticsEventType.Configuration,
                    boundary = "model.capability_negotiation",
                    error = error,
                    phase = AgentRunPhase.Preparing.name,
                    status = "failed",
                    attributes = attributes + mapOf(
                        "durationMillis" to (clock() - startedAt).coerceAtLeast(0L).toString()
                    )
                )
            } else {
                diagnostics?.record(
                    type = AgentDiagnosticsEventType.Configuration,
                    phase = AgentRunPhase.Preparing.name,
                    durationMillis = (clock() - startedAt).coerceAtLeast(0L),
                    status = "succeeded",
                    attributes = attributes
                )
                return null
            }

            // A thrown exception violates the model-client contract. Only a
            // normalized, explicitly retryable response should be retried.
            if (thrown != null) {
                return error ?: unexpectedRunError("capability_negotiation")
            }

            if (error == null ||
                !error.retryable ||
                retryCount >= policy.maxModelRetries
            ) {
                return error?.let { withRetryMetadata(it, retryCount) }
            }

            retryCount += 1
            delay(AgentPolicy.retryDelayMillis(retryCount, requireNotNull(error)))
        }
    }

    private fun withRetryMetadata(error: AgentError, retryCount: Int): AgentError =
        if (retryCount == 0) error else error.copy(
            details = error.details + mapOf("retryCount" to retryCount)
        )

    /**
     * How many citations the validator dropped, read from the limitations it
     * writes for exactly that reason.  Counting the rejections directly would
     * mean plumbing the validation result out of the loop; the limitation text
     * is the same information and is already part of the public report.
     */
    private fun removedEvidenceCount(report: AgentReport?): Int =
        report?.limitations?.count { it.startsWith(REMOVED_EVIDENCE_PREFIX) } ?: 0

    private fun withDiagnosticId(
        result: AgentRunResult,
        diagnostics: AgentDiagnosticsSession?
    ): AgentRunResult {
        val diagnosticId = diagnostics?.runId
        val outcome = when (val raw = result.outcome) {
            is AgentRunOutcome.Failed -> raw.copy(
                error = raw.error.copy(
                    details = raw.error.details + listOfNotNull(
                        diagnosticId?.let { "diagnosticId" to it }
                    ).toMap()
                )
            )
            is AgentRunOutcome.FailedWithPartialReport -> raw.copy(
                error = raw.error.copy(
                    details = raw.error.details + listOfNotNull(
                        diagnosticId?.let { "diagnosticId" to it }
                    ).toMap()
                )
            )
            else -> raw
        }
        return result.copy(
            outcome = outcome,
            diagnosticId = diagnosticId
        )
    }

    private fun finishDiagnostics(
        diagnostics: AgentDiagnosticsSession?,
        outcome: AgentRunOutcome
    ) {
        when (outcome) {
            is AgentRunOutcome.Completed -> diagnostics?.finish(
                status = "completed",
                attributes = mapOf("stopReason" to outcome.stopReason.name)
            )
            is AgentRunOutcome.Failed -> diagnostics?.finish(
                status = "failed",
                error = outcome.error,
                attributes = mapOf(
                    "reportPresent" to (outcome.report != null).toString()
                )
            )
            is AgentRunOutcome.FailedWithPartialReport -> diagnostics?.finish(
                status = "failed_partial_report",
                error = outcome.error,
                attributes = mapOf("reportPresent" to "true")
            )
            is AgentRunOutcome.Cancelled -> diagnostics?.finish(status = "cancelled")
        }
    }

    private fun unexpectedRunError(stage: String): AgentError = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The analysis stopped unexpectedly. Diagnostic information was saved locally.",
        retryable = true,
        details = mapOf("stage" to stage)
    )

    /**
     * Cancel the active run.  Safe to call when nothing is running, and safe to
     * call twice: [AgentRunController.cancel] is idempotent.
     */
    fun cancel() {
        activeController.get()?.cancel()
    }

    private fun refused(error: AgentError) = AgentRunResult(
        identity = null,
        outcome = AgentRunOutcome.Failed(error, report = null)
    )

    private companion object {
        /** Must match [EvidenceRejection.toLimitation]'s wording. */
        const val REMOVED_EVIDENCE_PREFIX = "Removed unverifiable evidence from"
    }
}
