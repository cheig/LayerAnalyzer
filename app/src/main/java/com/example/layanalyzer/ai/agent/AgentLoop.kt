package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.client.AiModelClient
import com.example.layanalyzer.ai.client.AiModelErrors
import com.example.layanalyzer.ai.client.OkHttpAgentHttpTransport
import com.example.layanalyzer.ai.client.StreamChunk
import com.example.layanalyzer.ai.client.AgentTruncationTarget
import com.example.layanalyzer.ai.audit.AgentDiagnosticsEventType
import com.example.layanalyzer.ai.audit.AgentDiagnosticsSession
import com.example.layanalyzer.ai.audit.isAgentFatal
import com.example.layanalyzer.ai.audit.toDiagnosticsFailure
import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.AgentPlaybookCheck
import com.example.layanalyzer.ai.privacy.AgentPrivacyPolicy
import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.ai.tools.AgentResultTruncator
import com.example.layanalyzer.ai.tools.AgentToolRunner
import com.example.layanalyzer.ai.tools.DeclareAnalysisPlanTool
import com.example.layanalyzer.ai.tools.DelegateInvestigationTool
import com.example.layanalyzer.ai.tools.SubmitReportTool
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentAnalysisPlanStep
import com.example.layanalyzer.model.AgentAnalysisMode
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.HOST_CONFIRMED_FINDING_PREFIX
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentPriorContext
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentReportProvenance
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AgentToolActivityStatus
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.AgentTokenUsage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.TimeoutCancellationException
import java.security.MessageDigest
import java.util.Locale

/** Observer for the UI layer; every value handed over is already redacted. */
interface AgentRunListener {
    fun onPhaseChanged(phase: AgentRunPhase) = Unit
    fun onToolActivity(activity: AgentToolActivity) = Unit
    fun onMessage(item: AgentConversationItem) = Unit
    fun onModelInteraction(interaction: AgentModelInteraction) = Unit
    fun onStreamingUpdate(text: String) = Unit
    fun onAnalysisPlan(plan: AgentAnalysisPlan, completedSteps: Int) = Unit

    /** A model request has been dispatched; [requestId] is now in flight. */
    fun onModelRequestStarted(requestId: String, turn: Int?) = Unit

    /**
     * A model request produced a terminal response (success or final failure);
     * the server-side state of [requestId] is now known locally.
     */
    fun onModelResponseCommitted(requestId: String, turn: Int?) = Unit

    /** A deterministic local tool call has begun executing. */
    fun onToolCallStarted(toolCallId: String) = Unit

    /** A deterministic local tool call produced its result. */
    fun onToolCallCommitted(toolCallId: String) = Unit

    /** A decoded report has passed host validation. */
    fun onReportValidated() = Unit
}

/** Terminal outcome of one loop execution. */
sealed class AgentRunOutcome {
    abstract val report: AgentReport?

    data class Completed(
        override val report: AgentReport,
        val stopReason: AgentStopReason
    ) : AgentRunOutcome()

    /** A run that could not finish; [report] carries whatever was confirmed. */
    data class Failed(
        val error: AgentError,
        override val report: AgentReport?
    ) : AgentRunOutcome()

    /** A terminal model failure where confirmed evidence was preserved. */
    data class FailedWithPartialReport(
        val error: AgentError,
        override val report: AgentReport
    ) : AgentRunOutcome()

    data class Cancelled(
        override val report: AgentReport? = null
    ) : AgentRunOutcome()
}

/**
 * The model/tool state machine for one analysis.
 *
 * The loop is the only component that talks to both a model and the tool
 * runner, and it keeps them strictly separated: a model may *ask* for a tool by
 * name, but every call still goes through [AgentToolRunner], which owns the
 * whitelist, the privacy gate and the budget.  Nothing the model returns can
 * widen what the host permits — the worst a hostile response can do is waste a
 * step and get a structured error back.
 *
 * Tool results enter the conversation marked `untrustedCaptureData = true`,
 * because their content comes from a capture file that an attacker may have
 * shaped.  A final report is never taken at face value either: it goes through
 * [EvidenceValidator] before it can reach the UI.
 */
class AgentLoop(
    private val toolRunner: AgentToolRunner,
    private val modelClient: AiModelClient,
    private val controller: AgentRunController,
    private val policy: AgentPolicy = AgentPolicy(),
    private val ledger: EvidenceLedger = EvidenceLedger(),
    private val validator: EvidenceValidator = EvidenceValidator(policy = policy),
    private val listener: AgentRunListener? = null,
    private val promptAssembler: PromptAssembler = PromptAssembler(),
    private val contextPlanner: ContextPlanner = ContextPlanner(),
    private val playbook: AgentPlaybook = AgentPlaybook.generalCaptureHealth(),
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val diagnostics: AgentDiagnosticsSession? = null,
    private val suspendDelay: suspend (Long) -> Unit = { millis -> delay(millis) },
    private val retryJitter: () -> Double = { kotlin.random.Random.nextDouble(-0.2, 0.2) }
) {
    private val budget: AgentBudgetTracker
        get() = toolRunner.budgetTracker

    private val executedToolCallIds = LinkedHashSet<String>()
    private val toolActivities = mutableListOf<AgentToolActivity>()
    private var enforceInitialTool: Boolean = false
    /**
     * Consecutive calls rejected on INVALID_TOOL_ARGUMENTS.  These are refused
     * before the budget reservation, so they spend neither a step nor bytes —
     * without this counter a wedged model could retry bad arguments until the
     * turn ceiling ends every run.
     */
    private var consecutiveInvalidArguments: Int = 0
    private var consecutiveInvalidFilters: Int = 0
    private var finalSummaryAttempted: Boolean = false
    private var revisionAttempted: Boolean = false
    /**
     * The validated report produced immediately before a revision turn.
     *
     * A revision is an *improvement* attempt, never a precondition for having an
     * answer: the report stored here already passed validation with its
     * unsupported citations removed.  Keeping it means a revision turn that dies
     * on a transport failure degrades to "the report we already had" instead of
     * throwing away a complete analysis and synthesizing a thinner one.
     */
    private var preRevisionReport: AgentReport? = null
    private var lastToolQueryKey: String? = null
    private var consecutiveIdenticalToolCalls: Int = 0
    private var messageCounter: Long = 0L
    private var modelInteractionCounter: Long = 0L
    private var accumulatedTokenUsage: AgentTokenUsage? = null
    private var declaredPlan: AgentAnalysisPlan? = null
    /**
     * Report envelope handed over by [SubmitReportTool], awaiting validation.
     *
     * The tool executes inside the tool-turn machinery, which reports back a
     * stop reason rather than a report, so the payload is parked here for the
     * turn loop to pick up once the turn unwinds.
     */
    private var submittedReport: AgentJsonObject? = null
    private val completedPlanStepIndices = LinkedHashSet<Int>()
    /**
     * Steps in [completedPlanStepIndices] whose matching tool call *succeeded*
     * (OPT-VAL-01-02).  [trackPlanExecution] runs for failures too — a failed
     * call was still executed, which is what rule 1 asks — so rule 2 cannot
     * read coverage off the completed set alone.
     */
    private val successfulPlanStepIndices = LinkedHashSet<Int>()
    private var completedPlanSteps: Int = 0
    private var planComplete: Boolean = false
    /**
     * OPT-VAL-01-02 / OPT-VAL-02-03 submit coverage-gate state.
     *
     * [submitCoverageRejected] makes the refusal strictly one-shot *per run
     * and across both coverage kinds*: the model gets exactly one chance to
     * close its playbook-check gaps and its signal gaps, and its next submit
     * is accepted whatever it says about coverage — the single flag keeps one
     * submit from eating two refusals (a check refusal here also spends the
     * run's one shot for the signal rule, by design).  [lastSubmitCoverage]
     * and [lastSubmitSignalCoverage] are the two rules' verdicts for the
     * submit currently being processed, and [playbookCheckGapLimitations]
     * the host-authored prose committed when a report is finally accepted
     * with check gaps — these flow into the report through
     * [commitSubmitCoverageAcceptance] and the validation trace; signal gaps
     * narrate themselves through the trace's rule-3 net instead, so a
     * finding counted as coverage at acceptance that validation later strips
     * still ends up in the limitations.
     */
    private var submitCoverageRejected: Boolean = false
    private var lastSubmitCoverage: PlaybookCheckCoverage? = null
    private var playbookCheckGapLimitations: List<String> = emptyList()
    /** Uncovered playbook checks at report acceptance; the RunMetrics count. */
    private var planCoverageGaps: Int = 0
    /**
     * OPT-VAL-02-03 signal-coverage verdicts for the submit being processed.
     * [lastSubmitSignalAttributable] is the gate's §3 attribution answer —
     * whether the submit can be refused over its signal gaps at all, as
     * opposed to merely recorded — and [signalCoverageGaps] is the RunMetrics
     * count of signals still unaddressed at acceptance, limitations-only
     * path included.
     */
    private var lastSubmitSignalCoverage: SignalCoverage? = null
    private var lastSubmitSignalAttributable: Boolean = false
    private var signalCoverageGaps: Int = 0
    /** Pure rules 2/3 evaluator; holds no state, so no constructor surface needed. */
    private val checkCoverageValidator = ReportCoverageValidator()
    /**
     * OPT-VAL-02-02 (design §5.2): the host-enumerated signal set of this
     * run's successful baseline calls.
     *
     * [runBaselineCalls] is the ordered ledger of every top-level (not
     * delegated) call of `get_capture_overview` / `get_expert_info` that
     * returned successfully — the `host-bootstrap-overview-1` /
     * `host-bootstrap-expert-2` calls, model re-runs of the same tools, and
     * the fallback single-summary `host-overview` call alike. [runSignals] is
     * re-extracted from the whole list on each addition; the extractor is
     * pure and the list is tiny, so this is bookkeeping, not work.
     *
     * Delegated child calls are deliberately excluded: the coverage gate of
     * OPT-VAL-02-03 will hold the *report author* — the top-level model — to
     * the signals it was shown, and an annotation is only honest when it is
     * the same set that was appended to that transcript's tool messages. A
     * child investigates in its own transcript; whatever it read surfaces in
     * the parent only through its delegated report.
     */
    private val signalExtractor = AgentSignalExtractor()
    private val runBaselineCalls = mutableListOf<HostCallPayload>()
    private var runSignals: AgentSignalSet = AgentSignalSet(emptyList())

    /**
     * The run's signal set as annotated into its tool messages so far;
     * OPT-VAL-02-03's coverage gate is the intended consumer. Read-only: the
     * annotation path is the only writer.
     */
    internal val currentRunSignals: AgentSignalSet get() = runSignals
    /**
     * Bounded grant of extra tool turns after the declared plan completes.
     *
     * A plan sized before any result was seen cannot anticipate truncation, so
     * a run that finished its steps holding cut evidence — with a continuation
     * the model could actually follow — gets a bounded chance to fill those
     * gaps instead of being forced into an Incomplete report while most of its
     * step budget is still unspent.
     *
     * The grant is renewable rather than one-shot: truncation discovered *during*
     * gap-fill is the same problem as truncation discovered before it, and a
     * one-shot grant would strand it. [planGapFillTurnsUsed] is what keeps the
     * total bounded by `maxPlanGapFillTurns` across all renewals.
     */
    private var planGapFillGranted: Boolean = false
    private var planGapFillTurnsRemaining: Int = 0
    private var planGapFillTurnsUsed: Int = 0
    private var planGapFillNudgePending: Boolean = false
    /** Consecutive granted turns that filled nothing; bounds a wedged grant. */
    private var consecutiveOffPurposeGapFillTurns: Int = 0
    /** Successful-but-truncated calls whose result carried a usable continuation. */
    private val evidenceGaps = AgentEvidenceGapTracker()
    private var delegatedDepth: Int = 0
    private var bootstrapToolCount: Int = 0
    private var bootstrapResultBytes: Long = 0L
    private var bootstrapDurationMillis: Long = 0L
    /** Whether the replayed history was compacted before the first model call. */
    private var historyCompactedAtEntry: Boolean = false
    /** Provider calls, including every retry attempt. */
    private var modelRequestCount: Int = 0
    /** Logical calls into [requestModelWithRetry]; retries do not consume this budget. */
    private var logicalModelRequestCount: Int = 0
    private var runStartedAtMillis: Long = 0L
    private var modelRequestsBeforeFirstEvidence: Int? = null
    private var runMetricsRecorded: Boolean = false
    /**
     * Evidence citations submitted to host validation across every validation
     * round of this run ([citationsRejected] being the ones removed); the
     * numbers behind `citationRejectionRate`.  Accumulated in
     * [validationResult] — see the comment there for the exact caliber.
     */
    private var citationsSubmitted: Int = 0
    private var citationsRejected: Int = 0
    /**
     * OPT-VAL-04-03 polarity double-track counters, accumulated in
     * [validationResult] on the same per-round caliber as the citation counters
     * above: [negativePolarityDeclared] is the number of findings that declared
     * `Negative` among the citations submitted each round, and
     * [negativePolarityConflict] is the number of `polarity_claim_conflict`
     * rejections the first validate() of each round produced (the positive/
     * neutral declarations contradicted by an absence-claiming observation).
     * Surfaced as `negativePolarityDeclared` / `negativePolarityConflict` on
     * the RunMetrics event; the summariser derives the conflict rate between
     * them.  Counts only, never finding text.
     */
    private var negativePolarityDeclared: Int = 0
    private var negativePolarityConflict: Int = 0
    /**
     * OPT-VAL-03-01 question-alignment rejections this run — entries the host
     * removed for a dangling finding reference or an `addressed` claim left
     * without surviving evidence — accumulated in [validationResult] on the
     * same first-validate() caliber as the polarity counters above: one
     * round through this funnel counts the rejections raised against the
     * report as submitted that round.  Double-validate dedupe: the reconcile
     * pass re-validates the FIRST pass's output, whose violating entries are
     * already removed, so it cannot re-raise them — and counting only the
     * first validate() additionally mirrors the citation numerator exactly.
     * Surfaced as `alignmentFailures` on the RunMetrics event; counts only,
     * never question prose or finding ids (those ride the report's
     * limitations).  0 on valve-off runs and on runs whose entries all held.
     */
    private var alignmentFailures: Int = 0
    /**
     * Confidence histogram of the most recently validated report, counted in
     * [validationResult] and surfaced as `confidenceDistribution` on the
     * RunMetrics event.
     */
    private var lastValidatedConfidenceCounts: Map<AgentConfidence, Int> = emptyMap()

    /**
     * EVL-COVERAGE-03: the evidence-coverage receipt of the last report this
     * loop validated — the exact [EvidenceCoverage] object the run trace
     * carries (set in [validationResult] alongside the trace, no copy). The
     * last validated submission of a run is its accepted report, so reading
     * this after a terminal outcome yields the run's coverage. Null when no
     * report was ever validated (cancelled or failed before a submission).
     */
    private var lastEvidenceCoverage: EvidenceCoverage? = null
    private val stickyOutputCeilingByStage = mutableMapOf<AgentModelRequestStage, Int>()

    var analysisMode: AgentAnalysisMode = AgentAnalysisMode.FullAgent
        private set

    /**
     * The model-message list this run is building, referenced from [run] so
     * [transcript] can hand out its live or final state.  The loop mutates the
     * list in place (the compactor rewrites it in place too), so one reference
     * stays valid for the whole run.
     */
    private var transcriptRef: List<AgentModelMessage> = emptyList()

    /**
     * The run's model messages, safe to read while running and authoritative
     * after a terminal outcome.  This is what a follow-up run replays as its
     * history; callers wanting the sendable form use [sanitizedTranscript].
     */
    fun transcript(): List<AgentModelMessage> = transcriptRef.toList()

    /** [transcript] with everything that must not cross a request boundary removed. */
    fun sanitizedTranscript(): List<AgentModelMessage> =
        ConversationHistorySanitizer.sanitize(transcript())

    /** Redacted activity list for the UI; safe to read after the run ends. */
    fun activities(): List<AgentToolActivity> = toolActivities.toList()

    /** Provider-reported totals across all model attempts in this run. */
    fun tokenUsage(): AgentTokenUsage? = accumulatedTokenUsage

    /**
     * EVL-COVERAGE-03: the coverage receipt of the last validated report —
     * the same object the run trace's [AgentRunTrace.evidenceCoverage]
     * carries. Audit counts are derived from it; the frame-number sets stay
     * in memory.
     */
    fun evidenceCoverage(): EvidenceCoverage? = lastEvidenceCoverage

    /** Redacted run metrics suitable for diagnostics attributes. */
    internal fun diagnosticAttributes(): Map<String, String> = mapOf(
        "bootstrapToolCount" to bootstrapToolCount.toString(),
        "bootstrapResultBytes" to bootstrapResultBytes.toString(),
        "modelRequestsBeforeFirstEvidence" to
            (modelRequestsBeforeFirstEvidence ?: modelRequestCount).toString(),
        "modelRequestCount" to modelRequestCount.toString(),
        "logicalModelRequestCount" to logicalModelRequestCount.toString(),
        "planStepsCompleted" to completedPlanSteps.toString(),
        "planStepsTotal" to (declaredPlan?.steps?.size ?: 0).toString(),
        "runElapsedMillis" to (clock() - runStartedAtMillis).coerceAtLeast(0L).toString(),
        "bootstrapDurationMillis" to bootstrapDurationMillis.toString(),
        "historyCompactedAtEntry" to historyCompactedAtEntry.toString()
    )

    suspend fun run(
        question: String,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode,
        priorContext: AgentPriorContext? = null,
        /** Sanitised transcript of the prior rounds; replayed before the question. */
        history: List<AgentModelMessage> = emptyList(),
        /**
         * Prebuilt evidence-set section (EVL-CONTEXT-02); `null` emits no
         * section and leaves the prompt bytes unchanged.  The workspace — and
         * therefore a real value — is only visible to the UI layer, which
         * feeds it in a later task (EVL-CONTEXT-03/04).
         */
        evidenceSetSection: String? = null
    ): AgentRunOutcome {
        moveTo(AgentRunPhase.Preparing)
        budget.start()
        runStartedAtMillis = clock()
        // OPT-VAL-02-02: signals are a per-run enumeration. A replayed
        // history's own `host-signals:` lines stay in the transcript as they
        // were written — ids are content hashes, so for an unchanged capture
        // they name the same facts this run would re-derive.
        runBaselineCalls.clear()
        runSignals = AgentSignalSet(emptyList())

        toolRunner.bindInvestigationDelegate { goal, maxTurns ->
            runDelegatedInvestigation(goal, maxTurns, snapshot, privacyMode)
        }

        val capabilities = modelClient.capabilities
        val toolDefinitions = toolRunner.toolDefinitions()
        val messages = promptAssembler.initialMessages(
            question = question,
            snapshot = snapshot,
            policy = policy,
            privacyMode = privacyMode,
            tools = toolDefinitions,
            playbook = playbook,
            priorContext = priorContext,
            history = history,
            evidenceSetSection = evidenceSetSection
        ).toMutableList()
        transcriptRef = messages
        enforceInitialTool = playbook.matchesIntent(question)

        // History rides into every request of this run, so an oversized one must
        // be bounded before the first model call — tighter than the in-run 0.75
        // trigger, which only fires after turns have been spent.
        historyCompactedAtEntry = false
        if (history.isNotEmpty()) {
            val entryTrigger = (contextPlanner.effectiveInputLimit(
                reportedContextLimit = capabilities.maxContextTokens,
                reportedOutputLimit = capabilities.maxOutputTokens
            ) * HISTORY_ENTRY_TRIGGER_RATIO).toInt().coerceAtLeast(1)
            if (contextPlanner.estimator.estimateMessages(messages) > entryTrigger) {
                if (AgentConversationCompactor.compact(messages, retainedTurns = HISTORY_RETAINED_TURNS)) {
                    historyCompactedAtEntry = true
                }
            }
        }

        diagnostics?.record(
            type = AgentDiagnosticsEventType.Configuration,
            phase = AgentRunPhase.Preparing.name,
            status = "history",
            attributes = mapOf(
                "historyMessageCount" to history.size.toString(),
                "initialMessageCount" to messages.size.toString(),
                "historyCompactedAtEntry" to historyCompactedAtEntry.toString()
            )
        )

        emitMessage(AgentConversationRole.User, question)

        val bootstrap = runAnalysisBootstrap(
            messages = messages,
            snapshot = snapshot,
            privacyMode = privacyMode,
            skipForPriorOverview = historyHasSuccessfulBootstrap(history)
        )
        bootstrap.stopReason?.let { stop ->
            return if (stop == AgentStopReason.Cancelled) {
                cancelledOutcome()
            } else {
                finishAfterStop(
                    question = question,
                    snapshot = snapshot,
                    privacyMode = privacyMode,
                    messages = messages,
                    stopReason = stop
                )
            }
        }

        if (!moveTo(AgentRunPhase.Investigating)) return cancelledOutcome()

        if (!capabilities.toolCalling) {
            return runSingleSummaryFallback(question, snapshot, privacyMode, messages)
        }

        // Invalid arguments, empty tool-call lists and initial-tool nudges all
        // consume a turn without consuming a step, so the ceiling lives above
        // the step budget: it guards a wedged loop, not work.  Kept in policy
        // because a narrowed run needs a narrower one.
        val maxTurns = if (capabilities.toolCalling) policy.maxTurns else 1
        var turn = 0

        while (true) {
            currentCoroutineContext().ensureActive()
            turn += 1

            budgetStop()?.let { stop ->
                return finishAfterStop(
                    question = question,
                    snapshot = snapshot,
                    privacyMode = privacyMode,
                    messages = messages,
                    stopReason = stop
                )
            }
            if (turn > maxTurns) {
                return finishAfterStop(
                    question = question,
                    snapshot = snapshot,
                    privacyMode = privacyMode,
                    messages = messages,
                    stopReason = AgentStopReason.MaxStepsReached
                )
            }

            if (planComplete) {
                return finishAfterStop(
                    question = question,
                    snapshot = snapshot,
                    privacyMode = privacyMode,
                    messages = messages,
                    stopReason = AgentStopReason.PlanComplete
                )
            }

            if (!moveTo(AgentRunPhase.WaitingForModel)) return cancelledOutcome()

            // Compaction rewrites the transcript prefix, which discards every
            // provider cache breakpoint after the newest discovery note. It is
            // therefore threshold-driven rather than per-turn: a run pays that
            // cost a couple of times instead of on every turn past the window.
            AgentConversationCompactor.compactIfNeeded(
                messages = messages,
                estimator = contextPlanner.estimator,
                contextLimitTokens = contextPlanner.effectiveInputLimit(
                    reportedContextLimit = capabilities.maxContextTokens,
                    reportedOutputLimit = capabilities.maxOutputTokens
                )
            )
            val context = contextPlanner.plan(
                source = messages,
                reportedContextLimit = capabilities.maxContextTokens,
                reportedOutputLimit = capabilities.maxOutputTokens
            )
            applyContextCompactions(messages, context)
            if (context.partial) {
                // finishAfterStop resolves a pending revision to the validated
                // pre-revision report before considering a forced summary.
                return finishAfterStop(
                    question = question,
                    snapshot = snapshot,
                    privacyMode = privacyMode,
                    messages = messages,
                    stopReason = AgentStopReason.ContextLimit
                )
            }

            val awaitingRevision = preRevisionReport != null
            val requestStage = if (awaitingRevision) {
                AgentModelRequestStage.Revision
            } else if (declaredPlan == null) {
                AgentModelRequestStage.PlanDeclaration
            } else {
                AgentModelRequestStage.ToolSelection
            }
            val maxOutputTokens = capabilities.clampOutputTokens(
                AgentOutputBudget.tokens(requestStage, capabilities.maxOutputTokens)
            )
            // A revision turn only returns the rejected findings, so it asks for
            // the narrow schema and gets a correspondingly smaller generation.
            // It also follows the Finalizing contract and ships no tools: the
            // run already has a validated report, and Revising permits no tool
            // turn, so offering tools would invite an unexecutable answer.
            if (awaitingRevision && !moveTo(AgentRunPhase.Revising)) return cancelledOutcome()
            val response = requestModelWithRetry(
                messages = context.messages,
                toolDefinitions = if (awaitingRevision) emptyList() else toolDefinitions,
                responseSchema = when {
                    !capabilities.structuredOutput -> null
                    awaitingRevision -> AgentPrompt.REVISED_FINDINGS_SCHEMA
                    else -> AgentPrompt.REPORT_SCHEMA
                },
                privacyMode = privacyMode,
                maxOutputTokens = maxOutputTokens,
                estimatedInputTokens = context.estimatedInputTokens,
                turn = turn,
                boundary = if (awaitingRevision) "model.respond.revision" else "model.respond",
                requestStage = requestStage
            )

            if (controller.isCancelled) return cancelledOutcome()

            when (response) {
                is AgentModelResponse.ToolCalls -> {
                    if (awaitingRevision) {
                        // The revision request ships no tools and Revising
                        // permits no tool turn, so this batch can never be
                        // executed. Resolve it inline instead of letting the
                        // refused RunningTool transition masquerade as a
                        // user cancellation.
                        return finalizeRevisionToolCalls(
                            response = response,
                            question = question,
                            snapshot = snapshot,
                            privacyMode = privacyMode,
                            messages = messages
                        )
                    }
                    val initialCalls = initialCallsFor(response.calls, messages) ?: continue
                    // Provider chat APIs require the assistant tool-call turn to
                    // precede Tool messages on the next request. Keeping it in
                    // the vendor-neutral transcript also lets every adapter
                    // reconstruct a valid multi-turn conversation.
                    messages += AgentModelMessage.assistant(
                        content = response.assistantContent,
                        toolCalls = initialCalls,
                        reasoningContent = response.reasoningContent
                    )
                    val execution = executeToolCalls(
                        initialCalls,
                        messages,
                        snapshot,
                        privacyMode,
                        turn
                    )
                    // A report that arrived over the tool channel is the run's
                    // answer.  It goes through the same validator and revision
                    // path as a free-text Final, so completeness and evidence
                    // rules do not depend on how the report was transported.
                    val submitted = consumeSubmittedReport()
                    if (submitted != null) {
                        val outcome = finalizeReport(
                            response = submitted,
                            question = question,
                            snapshot = snapshot,
                            messages = messages,
                            allowRevision = true
                        )
                        if (outcome != null) return outcome
                        continue
                    }
                    if (execution.stopReason != null) {
                        return if (execution.stopReason == AgentStopReason.Cancelled) {
                            cancelledOutcome()
                        } else {
                            finishAfterStop(
                                question = question,
                                snapshot = snapshot,
                                privacyMode = privacyMode,
                                messages = messages,
                                stopReason = execution.stopReason
                            )
                        }
                    }
                }

                is AgentModelResponse.Final -> {
                    // A free-text final answer is this run's conclusion and must
                    // be replayable by a follow-up, so it enters the transcript
                    // as the assistant turn that answers the current question.
                    // The revision path appends its own exchanges instead.
                    if (!awaitingRevision) {
                        messages += AgentModelMessage.assistant(
                            content = response.rawJson ?: response.report?.summary.orEmpty(),
                            reasoningContent = response.reasoningContent
                        )
                    }
                    finalizeReport(
                        response = response,
                        question = question,
                        snapshot = snapshot,
                        messages = messages,
                        allowRevision = true
                    )?.let { return it }
                }

                is AgentModelResponse.Refusal -> {
                    // A model that declines to revise has not invalidated the
                    // report it already produced.
                    completeWithUnrevisedReport()?.let { return it }
                    val error = response.error ?: AgentError(
                        code = AgentErrorCode.MODEL_UNAVAILABLE,
                        userMessage = "The analysis model declined to answer.",
                        retryable = false,
                        details = mapOf("reason" to "refusal")
                    )
                    return fail(error, snapshot, AgentStopReason.ModelFailure)
                }

                is AgentModelResponse.Failure -> {
                    // A structured CANCELLED response identifies the model
                    // request, not necessarily the root Agent run.  Gateways
                    // can return it when a request is abandoned while the run
                    // itself is still alive.  Only the controller's state is
                    // authoritative for a user/root cancellation; otherwise
                    // keep the evidence and enter the normal partial-report
                    // recovery path below.
                    if (controller.isCancelled) return cancelledOutcome()
                    // A failed revision turn must not cost the user the report
                    // that was already validated before it.
                    completeWithUnrevisedReport()?.let { return it }
                    if (budget.isModelBudgetExhausted()) {
                        return finishAfterStop(
                            question = question,
                            snapshot = snapshot,
                            privacyMode = privacyMode,
                            messages = messages,
                            stopReason = AgentStopReason.ContextLimit
                        )
                    }
                    return finishAfterStop(
                        question = question,
                        snapshot = snapshot,
                        privacyMode = privacyMode,
                        messages = messages,
                        stopReason = response.error.code.let { code ->
                            // CANCELLED is a model-request failure when the
                            // controller is not cancelled.  Mapping it to the
                            // run-level Cancelled reason here would make
                            // finishAfterStop discard the confirmed ledger.
                            if (code == AgentErrorCode.CANCELLED) {
                                AgentStopReason.ModelFailure
                            } else {
                                code.toStopReason()
                            }
                        },
                        terminalError = response.error.forPartialReport()
                    )
                }
            }
        }
    }

    /**
     * Call the model without changing the conversation or spending a tool step
     * between attempts.  A retryable response is transient by definition; all
     * other failures keep the existing fail-fast behavior.
     *
     * The user's retry setting applies in full to every logical request here,
     * and retries never consume the run's [AgentPolicy.maxModelRequests] budget.
     * What the error category decides is how each attempt *differs* from the
     * last: output truncation gets a larger allowance, response-size and
     * timeout failures get a smaller one, and an oversized input is compacted
     * once. A failure that can no longer adapt that way is deterministic, so
     * [ModelRetryPolicy] hands off to the summary path rather than replaying an
     * identical request for the remaining attempts.
     */
    private suspend fun requestModelWithRetry(
        messages: List<AgentModelMessage>,
        toolDefinitions: List<AgentToolDefinition>,
        responseSchema: AgentJsonObject?,
        privacyMode: AgentPrivacyMode,
        maxOutputTokens: Int,
        estimatedInputTokens: Int,
        turn: Int? = null,
        boundary: String,
        forcedSummary: Boolean = false,
        formatRepair: Boolean = false,
        stopReason: AgentStopReason? = null,
        requestStage: AgentModelRequestStage = when {
            forcedSummary -> AgentModelRequestStage.ForcedSummary
            boundary.contains("revision") -> AgentModelRequestStage.Revision
            boundary.contains("single_summary") -> AgentModelRequestStage.FinalReport
            else -> AgentModelRequestStage.ToolSelection
        }
    ): AgentModelResponse {
        logicalModelRequestCount += 1
        var retryCount = 0
        var plannedMessages = messages
        var plannedInputTokens = estimatedInputTokens
        var pendingStickyCeiling: Int? = null
        // Shrinks across response-size and gateway-timeout retries so a smaller
        // generation has a chance of succeeding, down to the floor in
        // [ModelRetryPolicy.MIN_RETRY_OUTPUT_TOKENS].
        var outputTokenCeiling = maxOf(maxOutputTokens, stickyOutputCeilingByStage[requestStage] ?: 0)
        while (true) {
            currentCoroutineContext().ensureActive()
            val cachePlannedMessages = CacheBreakpointPlanner.mark(
                messages = plannedMessages,
                additionalSystemBlocks = if (responseSchema == null) 0 else 1
            )

            val requestId = controller.nextRequestId()
            modelRequestCount += 1
            val requestStartedAt = clock()
            // Every remote model attempt gets its own host-owned timeout, and
            // the user's retry setting bounds how many attempts this loop makes.
            // Whole-run logical request budgets deliberately do not consume
            // retry attempts.
            val timeoutMillis = policy.maxModelRequestTimeoutMillis
            val requestPhase = when {
                forcedSummary -> AgentRunPhase.Finalizing
                boundary.contains("revision") -> AgentRunPhase.Revising
                else -> AgentRunPhase.Investigating
            }
            val attributes = buildMap {
                put("requestIdHash", requestHash(requestId))
                put("messageCount", cachePlannedMessages.size.toString())
                put("toolCount", toolDefinitions.size.toString())
                put("timeoutMillis", timeoutMillis.toString())
                put("maxOutputTokens", outputTokenCeiling.toString())
                put("estimatedInputTokens", plannedInputTokens.toString())
                put("attempt", (retryCount + 1).toString())
                put("maxRetries", policy.maxModelRetries.toString())
                put("modelRequestCount", modelRequestCount.toString())
                put("logicalModelRequestCount", logicalModelRequestCount.toString())
                put("phase", requestPhase.name)
                put("requestStage", requestStage.name)
                put(
                    "responseLimitBytes",
                    OkHttpAgentHttpTransport.DEFAULT_MAX_RESPONSE_BYTES.toString()
                )
                if (forcedSummary) put("forcedSummary", "true")
                if (formatRepair) put("formatRepair", "true")
                stopReason?.let { put("stopReason", it.name) }
            }
            diagnostics?.record(
                type = AgentDiagnosticsEventType.ModelRequestStarted,
                phase = requestPhase.name,
                turn = turn,
                status = "started",
                attributes = attributes
            )
            // The checkpoint boundary: from here until the response is consumed
            // the request's server-side state is unknown to a restarter.
            listener?.onModelRequestStarted(requestId, turn)

            val modelRequest = AgentModelRequest(
                requestId = requestId,
                messages = cachePlannedMessages,
                toolDefinitions = toolDefinitions,
                responseSchema = responseSchema,
                timeoutMillis = timeoutMillis,
                maxOutputTokens = outputTokenCeiling,
                privacyMode = privacyMode
            )

            var unexpectedFailure: Throwable? = null
            var firstTokenAtMillis: Long? = null
            val response = try {
                if (modelClient.capabilities.streaming) {
                    val streamingText = StringBuilder()
                    listener?.onStreamingUpdate("")
                    modelClient.respondStreaming(modelRequest) { chunk ->
                        if (firstTokenAtMillis == null && chunk.hasModelOutput()) {
                            firstTokenAtMillis = clock()
                        }
                        if (chunk is StreamChunk.TextDelta && chunk.text.isNotEmpty()) {
                            streamingText.append(chunk.text)
                            if (streamingText.length > MAX_STREAMING_PREVIEW_CHARS) {
                                streamingText.delete(
                                    0,
                                    streamingText.length - MAX_STREAMING_PREVIEW_CHARS
                                )
                            }
                            listener?.onStreamingUpdate(
                                AgentPrivacyPolicy.sanitizeReportText(streamingText.toString())
                            )
                        }
                    }
                } else {
                    modelClient.respond(modelRequest)
                }
            } catch (cancelled: CancellationException) {
                diagnostics?.record(
                    type = AgentDiagnosticsEventType.ModelResponse,
                    phase = requestPhase.name,
                    turn = turn,
                    durationMillis = (clock() - requestStartedAt).coerceAtLeast(0L),
                    status = "cancelled",
                    attributes = attributes
                )
                // A delegated request can be cancelled by its enclosing tool
                // timeout. Only an explicit root-run cancellation may latch
                // the shared controller into the terminal Cancelled phase.
                if (controller.isCancelled) {
                    controller.finish(AgentRunPhase.Cancelled)
                }
                throw cancelled
            } catch (failure: Throwable) {
                if (failure.isAgentFatal()) throw failure
                unexpectedFailure = failure
                AgentModelResponse.Failure(unexpectedModelError())
            } finally {
                controller.clearInFlightRequest(requestId)
                listener?.onStreamingUpdate("")
            }
            val requestCompletedAt = clock()

            response.usage?.let { usage ->
                accumulatedTokenUsage = (accumulatedTokenUsage ?: AgentTokenUsage()) + usage
                budget.recordModelUsage(usage)
            }
            val responseAttributes = attributes + response.usage.toDiagnosticAttributes(
                estimatedInputTokens = estimatedInputTokens
            )

            unexpectedFailure?.let { failure ->
                diagnostics?.recordFailure(
                    type = AgentDiagnosticsEventType.ModelResponse,
                    boundary = boundary,
                    error = (response as AgentModelResponse.Failure).error,
                    throwable = failure,
                    phase = requestPhase.name,
                    turn = turn,
                    status = "failed",
                    attributes = responseAttributes
                )
            }
            diagnostics?.record(
                type = AgentDiagnosticsEventType.ModelResponse,
                phase = requestPhase.name,
                turn = turn,
                durationMillis = (requestCompletedAt - requestStartedAt).coerceAtLeast(0L),
                status = modelResponseType(response),
                failure = (response as? AgentModelResponse.Failure)?.error
                    ?.toDiagnosticsFailure("$boundary.response"),
                attributes = responseAttributes
            )

            listener?.onModelInteraction(
                AgentModelInteraction(
                    id = "${controller.identity.runId}:interaction-${modelInteractionCounter++}",
                    turn = turn,
                    attempt = retryCount + 1,
                    request = modelRequest,
                    response = response,
                    startedAtMillis = requestStartedAt,
                    firstTokenAtMillis = firstTokenAtMillis,
                    completedAtMillis = requestCompletedAt
                )
            )
            // The request's outcome is now known locally and folded into the
            // trajectory, so a restarter may treat it as committed.
            listener?.onModelResponseCommitted(requestId, turn)

            // AiModelClient implementations are expected to map provider and
            // transport failures into AgentModelResponse.Failure. An exception
            // here is a host/adapter contract violation, so keep the old
            // fail-fast behavior instead of retrying a programming error.
            if (unexpectedFailure != null) return response

            if (controller.isCancelled) {
                return AgentModelResponse.Failure(AiModelErrors.cancelled(requestId))
            }

            val error = (response as? AgentModelResponse.Failure)?.error
            if (error == null) {
                pendingStickyCeiling?.let { stickyOutputCeilingByStage[requestStage] = it }
                return response.withRetryMetadata(retryCount)
            }
            if (error.code == AgentErrorCode.CANCELLED ||
                budget.isModelBudgetExhausted()
            ) {
                return response.withRetryMetadata(retryCount)
            }

            val truncationTarget = AgentTruncationTarget.from(error.details["truncationTarget"])
            val decision = ModelRetryPolicy.decide(
                error = error,
                phase = requestPhase,
                requestStage = requestStage,
                truncationTarget = truncationTarget,
                retriesUsed = retryCount,
                currentOutputTokens = outputTokenCeiling,
                maximumOutputTokens = modelClient.capabilities.clampOutputTokens(
                    if (requestStage == AgentModelRequestStage.PlanDeclaration ||
                        requestStage == AgentModelRequestStage.ToolSelection
                    ) {
                        maxOf(
                            AgentOutputBudget.tokens(requestStage, modelClient.capabilities.maxOutputTokens),
                            (outputTokenCeiling.toLong() * 2L)
                                .coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                        )
                    } else {
                        AgentOutputBudget.tokens(requestStage, modelClient.capabilities.maxOutputTokens)
                    }
                ),
                userMaxRetries = policy.maxModelRetries
            )
            if (decision.kind == ModelRetryDecisionKind.Stop ||
                decision.kind == ModelRetryDecisionKind.ForceSummary
            ) {
                return response.withRetryMetadata(retryCount)
            }
            val previousOutputTokens = outputTokenCeiling
            decision.outputTokens?.let { outputTokenCeiling = it }
            if (error.code == AgentErrorCode.MODEL_OUTPUT_TRUNCATED &&
                truncationTarget == AgentTruncationTarget.ToolCalls &&
                outputTokenCeiling > previousOutputTokens
            ) {
                pendingStickyCeiling = outputTokenCeiling
            }
            if (decision.requiresInputCompaction) {
                // Compaction is the only lever that can make an oversized input
                // fit. If it cannot shrink the payload, the next attempt would
                // resend what already overflowed, so stop rather than spend the
                // remaining retries on a certain failure.
                val compacted = plannedMessages.toMutableList()
                val beforeTokens = plannedInputTokens
                val changed = AgentConversationCompactor.compact(compacted, retainedTurns = 1)
                val replanned = contextPlanner.plan(
                    source = compacted,
                    reportedContextLimit = modelClient.capabilities.maxContextTokens,
                    reportedOutputLimit = outputTokenCeiling
                )
                applyContextCompactions(compacted, replanned)
                if (!changed || replanned.partial || replanned.estimatedInputTokens >= beforeTokens) {
                    diagnostics?.record(
                        type = AgentDiagnosticsEventType.ModelResponse,
                        phase = requestPhase.name,
                        turn = turn,
                        status = "input_compaction_failed",
                        attributes = mapOf(
                            "inputCompactionFailed" to "true",
                            "estimatedInputTokensBefore" to beforeTokens.toString(),
                            "estimatedInputTokensAfter" to replanned.estimatedInputTokens.toString()
                        )
                    )
                    return response.withRetryMetadata(retryCount)
                }
                plannedMessages = replanned.messages
                plannedInputTokens = replanned.estimatedInputTokens
            }
            retryCount += 1
            val delayMillis = AgentPolicy.retryDelayMillis(
                retryNumber = retryCount,
                error = error,
                jitterFraction = retryJitter()
            )
            // A retry the run goes on to recover from is a step-level event and
            // deliberately raises no conversation bubble. The failed attempt
            // stays auditable as a failed model interaction on the step list
            // (AgentModelInteractionRow), and a retry that is *not* recovered
            // raises the run's own terminal error bubble through fail(...).
            // Emitting one here put "analysis failed" on screen next to a
            // report the same run went on to produce.
            diagnostics?.record(
                type = AgentDiagnosticsEventType.ModelResponse,
                phase = requestPhase.name,
                turn = turn,
                status = "retry_${decision.kind.name.lowercase()}",
                attributes = mapOf(
                    "retryDecision" to decision.kind.name,
                    "requestStage" to requestStage.name,
                    "truncationTarget" to truncationTarget.wireName,
                    "truncatedRetryDirection" to if (outputTokenCeiling > previousOutputTokens) "up" else "none",
                    "outputTokensSticky" to (stickyOutputCeilingByStage[requestStage] ?: 0).toString(),
                    "outputTokensBefore" to previousOutputTokens.toString(),
                    "outputTokensAfter" to outputTokenCeiling.toString(),
                    "retryCount" to retryCount.toString()
                )
            )
            suspendDelay(delayMillis)
        }
    }

    private fun AgentModelResponse.withRetryMetadata(retryCount: Int): AgentModelResponse {
        if (retryCount == 0 || this !is AgentModelResponse.Failure) return this
        return copy(
            error = error.copy(
                details = error.details + mapOf("retryCount" to retryCount)
            )
        )
    }

    private fun AgentTokenUsage?.toDiagnosticAttributes(
        estimatedInputTokens: Int
    ): Map<String, String> {
        val usage = this ?: return emptyMap()
        return buildMap {
            put("actualInputTokens", usage.inputTokens.toString())
            put("cachedInputTokens", usage.cachedInputTokens.toString())
            put("cacheCreationTokens", usage.cacheCreationTokens.toString())
            put("outputTokens", usage.outputTokens.toString())
            if (usage.inputTokens > 0) {
                put(
                    "estimatorRatio",
                    (estimatedInputTokens.toDouble() / usage.inputTokens.toDouble()).toString()
                )
            }
        }
    }

    /** Produce bounded baseline evidence before the first remote model request. */
    private suspend fun runAnalysisBootstrap(
        messages: MutableList<AgentModelMessage>,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode,
        /** True when the replayed history already holds a successful overview. */
        skipForPriorOverview: Boolean = false
    ): ToolTurnExecution {
        val startedAt = clock()
        val availableTools = toolRunner.toolDefinitions().mapTo(LinkedHashSet()) { it.name }
        if (skipForPriorOverview) {
            diagnostics?.record(
                type = AgentDiagnosticsEventType.AnalysisBootstrap,
                phase = AgentRunPhase.Preparing.name,
                durationMillis = 0L,
                status = "skipped_prior_context",
                attributes = diagnosticAttributes()
            )
            bootstrapDurationMillis = 0L
            return ToolTurnExecution(results = emptyList(), stopReason = null)
        }
        val bootstrapTools = if (policy.analysisBootstrapEnabled) {
            playbook.bootstrapTools(availableTools)
        } else {
            emptyList()
        }
        var stopReason: AgentStopReason? = null
        val results = mutableListOf<AgentToolResult>()

        if (AgentPlaybook.CAPTURE_OVERVIEW_TOOL in bootstrapTools) {
            if (!moveTo(AgentRunPhase.WaitingForModel)) {
                bootstrapDurationMillis = (clock() - startedAt).coerceAtLeast(0L)
                return ToolTurnExecution(stopReason = AgentStopReason.Cancelled)
            }
            val overviewCall = AgentToolCall(
                toolCallId = "host-bootstrap-overview-1",
                toolName = AgentPlaybook.CAPTURE_OVERVIEW_TOOL,
                arguments = emptyMap()
            )
            messages += hostToolCallMessage(overviewCall)
            val overviewExecution = executeToolCalls(
                calls = listOf(overviewCall),
                messages = messages,
                snapshot = snapshot,
                privacyMode = privacyMode,
                turn = 0
            )
            results += overviewExecution.results
            stopReason = overviewExecution.stopReason

            val overview = overviewExecution.results.singleOrNull()
            if (stopReason == null &&
                overview?.success == true &&
                overview.hasExpertErrorsOrWarnings() &&
                BOOTSTRAP_EXPERT_TOOL in availableTools
            ) {
                val expertCall = AgentToolCall(
                    toolCallId = "host-bootstrap-expert-2",
                    toolName = BOOTSTRAP_EXPERT_TOOL,
                    arguments = mapOf(
                        "severities" to listOf("error", "warning"),
                        "offset" to 0,
                        "limit" to BOOTSTRAP_EXPERT_LIMIT
                    )
                )
                messages += hostToolCallMessage(expertCall)
                val expertExecution = executeToolCalls(
                    calls = listOf(expertCall),
                    messages = messages,
                    snapshot = snapshot,
                    privacyMode = privacyMode,
                    turn = 0
                )
                results += expertExecution.results
                stopReason = expertExecution.stopReason
            }
        }

        bootstrapToolCount = results.size
        bootstrapResultBytes = results.sumOf { it.resultBytes.toLong() }
        bootstrapDurationMillis = (clock() - startedAt).coerceAtLeast(0L)
        diagnostics?.record(
            type = AgentDiagnosticsEventType.AnalysisBootstrap,
            phase = if (results.isEmpty()) AgentRunPhase.Preparing.name else AgentRunPhase.RunningTool.name,
            durationMillis = bootstrapDurationMillis,
            status = when {
                !policy.analysisBootstrapEnabled -> "disabled"
                results.isEmpty() -> "skipped"
                stopReason != null -> "stopped"
                results.any { !it.success } -> "partial"
                else -> "succeeded"
            },
            attributes = diagnosticAttributes()
        )
        return ToolTurnExecution(results, stopReason)
    }

    /**
     * Thinking-mode Chat Completions providers require a reasoning marker on
     * every replayed assistant tool turn. Host calls have no model reasoning,
     * so an explicit empty marker distinguishes them from ordinary messages.
     */
    private fun hostToolCallMessage(call: AgentToolCall): AgentModelMessage =
        AgentModelMessage.assistant(
            toolCalls = listOf(call),
            reasoningContent = ""
        )

    private fun AgentToolResult.hasExpertErrorsOrWarnings(): Boolean {
        val values = data ?: return false
        val errors = (values["expertErrorCount"] as? Number)?.toLong() ?: 0L
        val warnings = (values["expertWarningCount"] as? Number)?.toLong() ?: 0L
        return errors > 0L || warnings > 0L
    }

    /**
     * Whether the replayed history already contains a successful capture
     * overview.  The bootstrap overview is deterministic for a capture, so a
     * prior round's result is this round's result; repeating the host call
     * would only re-inject bytes the history already carries.
     */
    private fun historyHasSuccessfulBootstrap(history: List<AgentModelMessage>): Boolean =
        history.any { message ->
            message.role == AgentModelMessageRole.Tool &&
                message.toolResult?.success == true &&
                message.toolName == AgentPlaybook.CAPTURE_OVERVIEW_TOOL
        }

    // --------------------------------------------------------------- tooling

    /** Run one model tool turn, preserving transcript order across parallel work. */
    private suspend fun executeToolCalls(
        calls: List<AgentToolCall>,
        messages: MutableList<AgentModelMessage>,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode,
        turn: Int,
        delegated: Boolean = false
    ): ToolTurnExecution {
        if (!delegated && planComplete) {
            // A provider may return a stale or amended tool call after the
            // declared plan ended.  Drop the whole batch before it reaches the
            // runner; a changed argument or tool id must not reopen discovery.
            return ToolTurnExecution(stopReason = AgentStopReason.PlanComplete)
        }
        if (calls.isEmpty()) {
            // Nothing to do, but the turn still counted; nudge the model rather
            // than ending a run that may still be recoverable.
            messages += AgentModelMessage.user(AgentPrompt.EMPTY_TOOL_CALL_NUDGE)
            return ToolTurnExecution()
        }

        if (!moveTo(AgentRunPhase.RunningTool)) {
            return ToolTurnExecution(stopReason = AgentStopReason.Cancelled)
        }

        // A gap-fill turn is granted for one purpose, so the batch is screened
        // against the pending gaps before anything executes. Screened up front so
        // the grant that happens *during* this batch (the batch that completed
        // the plan) does not charge itself.
        val gapFillTurn = !delegated && planGapFillGranted && planGapFillTurnsRemaining > 0
        val gapFillMatches = if (gapFillTurn) {
            calls.associate { call -> call.toolCallId to evidenceGaps.matching(call) }
        } else {
            emptyMap()
        }
        // Orchestration calls are excluded throughout: submitting the report is
        // always allowed, and a batch that only submits is not an off-purpose
        // attempt to spend the grant.
        val screenedCalls = calls.filter { it.toolName !in ORCHESTRATION_TOOLS }
        val gapFillOffPurpose = gapFillTurn &&
            screenedCalls.isNotEmpty() &&
            screenedCalls.all { gapFillMatches[it.toolCallId] == null }

        val prepared = calls.mapIndexed { index, call ->
            val rejected = when {
                delegated && call.toolName in ORCHESTRATION_TOOLS -> forbiddenDelegatedCallResult(call)
                call.toolCallId.isBlank() || !executedToolCallIds.add(call.toolCallId) ->
                    duplicateCallResult(call)
                gapFillTurn && call.toolName !in ORCHESTRATION_TOOLS &&
                    gapFillMatches[call.toolCallId] == null ->
                    offPurposeGapFillResult(call)
                else -> null
            }
            PreparedToolCall(index, call, rejected)
        }
        prepared.forEach { recordStartedActivity(it.call) }
        prepared.forEach { listener?.onToolCallStarted(it.call.toolCallId) }

        val mayParallelize = modelClient.capabilities.parallelToolCalls &&
            prepared.size > 1 &&
            declaredPlan == null &&
            prepared.none { it.call.toolName in ORCHESTRATION_TOOLS }
        val results = mutableListOf<AgentToolResult>()
        var stopReason: AgentStopReason? = null
        val requiresPlanAcceptance = !delegated &&
            declaredPlan == null &&
            prepared.firstOrNull()?.call?.toolName == DeclareAnalysisPlanTool.NAME

        if (mayParallelize) {
            val executions = coroutineScope {
                prepared.groupBy { it.call.toolName }.values.map { sameToolCalls ->
                    async {
                        sameToolCalls.map { item ->
                            executePreparedToolCall(item, snapshot, privacyMode, turn)
                        }
                    }
                }.awaitAll().flatten()
            }.sortedBy { it.index }
            for (execution in executions) {
                currentCoroutineContext().ensureActive()
                if (controller.isCancelled) {
                    return ToolTurnExecution(results, AgentStopReason.Cancelled)
                }
                results += execution.result
                val terminal = processToolExecution(execution, messages, turn, delegated)
                if (terminal != null) {
                    if (stopReason == null) stopReason = terminal
                    break
                }
            }
        } else {
            var blockRemainingForInvalidPlan = false
            for (item in prepared) {
                currentCoroutineContext().ensureActive()
                if (controller.isCancelled) {
                    return ToolTurnExecution(results, AgentStopReason.Cancelled)
                }
                val execution = if (blockRemainingForInvalidPlan) {
                    blockedByInvalidPlanExecution(item)
                } else {
                    executePreparedToolCall(item, snapshot, privacyMode, turn)
                }
                results += execution.result
                val terminal = processToolExecution(execution, messages, turn, delegated)
                if (terminal != null) {
                    if (stopReason == null) stopReason = terminal
                    break
                }
                if (requiresPlanAcceptance &&
                    item.call.toolName == DeclareAnalysisPlanTool.NAME &&
                    declaredPlan == null
                ) {
                    blockRemainingForInvalidPlan = true
                }
            }
            if (requiresPlanAcceptance && declaredPlan == null && stopReason == null) {
                messages += AgentModelMessage.user(AgentPrompt.INVALID_ANALYSIS_PLAN_NUDGE)
            }
        }

        if (planGapFillNudgePending) {
            planGapFillNudgePending = false
            // Appended after the whole batch so assistant tool-call and Tool
            // result messages stay contiguous for strict providers.
            if (stopReason == null) {
                messages += AgentModelMessage.user(
                    AgentPrompt.planGapFillNudge(
                        turns = planGapFillTurnsRemaining,
                        gaps = evidenceGaps.ordered().map { it.describe() }
                    )
                )
            }
        }
        if (gapFillTurn) {
            // Retire whatever this batch actually filled, then charge only if it
            // filled something. A turn spent on a rejected or off-purpose call
            // leaves the grant untouched: charging it would let a model burn the
            // whole grant without ever re-reading a single truncated result,
            // which is precisely the observed failure.
            val filled = prepared.count { item ->
                val gap = gapFillMatches[item.call.toolCallId]
                if (gap == null || item.rejectedResult != null) {
                    false
                } else {
                    evidenceGaps.retire(gap)
                    true
                }
            }
            if (filled > 0) {
                planGapFillTurnsRemaining -= 1
                planGapFillTurnsUsed += 1
                consecutiveOffPurposeGapFillTurns = 0
            } else if (screenedCalls.isNotEmpty()) {
                // Not charged — but still bounded. A rejected call costs no step
                // either, so without a ceiling here a model that never returns to
                // the truncated evidence could keep trading turns for rejections
                // until the whole turn budget was gone. A batch of nothing but
                // orchestration calls is not such an attempt and is not counted.
                consecutiveOffPurposeGapFillTurns += 1
            }
            diagnostics?.record(
                type = AgentDiagnosticsEventType.PlanDeviation,
                phase = AgentRunPhase.RunningTool.name,
                turn = turn,
                status = if (filled > 0) "gap_fill_used" else "gap_fill_off_purpose",
                attributes = mapOf(
                    "gapsFilled" to filled.toString(),
                    "gapsPending" to evidenceGaps.size.toString(),
                    "gapFillTurnsRemaining" to planGapFillTurnsRemaining.toString(),
                    "gapFillTurnsUsed" to planGapFillTurnsUsed.toString()
                )
            )
            if (gapFillOffPurpose && stopReason == null) {
                messages += AgentModelMessage.user(
                    AgentPrompt.offPurposeGapFillNudge(
                        turns = planGapFillTurnsRemaining,
                        gaps = evidenceGaps.ordered().map { it.describe() }
                    )
                )
            }
            val abandonedGrant =
                consecutiveOffPurposeGapFillTurns >= MAX_OFF_PURPOSE_GAP_FILL_TURNS
            when {
                // The model has stopped engaging with the grant: withdraw it
                // rather than keep offering turns it does not use.
                abandonedGrant -> planComplete = true
                // Still turns left and gaps to spend them on: carry on.
                planGapFillTurnsRemaining > 0 && !evidenceGaps.isEmpty -> Unit
                // A gap-fill read can itself return truncated. Renewing here —
                // bounded by the same total — keeps that newly-created gap from
                // being stranded with turns still on the clock.
                stopReason == null && tryEnterPlanGapFill() -> Unit
                else -> planComplete = true
            }
        }

        if (stopReason == null && !moveTo(AgentRunPhase.WaitingForModel)) {
            stopReason = AgentStopReason.Cancelled
        }
        return ToolTurnExecution(results, stopReason)
    }

    private suspend fun processToolExecution(
        execution: ToolExecution,
        messages: MutableList<AgentModelMessage>,
        turn: Int,
        delegated: Boolean
    ): AgentStopReason? {
        val call = execution.call
        val result = execution.result
        if (execution.recordInLedger && call.toolName !in ORCHESTRATION_TOOLS) {
            ledger.record(call, result, execution.stepIndex)
            if (modelRequestsBeforeFirstEvidence == null) {
                modelRequestsBeforeFirstEvidence = modelRequestCount
            }
            val continuation = result.truncation.continuation
            if (result.success && result.truncation.truncated &&
                continuation != null && continuation["available"] != false
            ) {
                evidenceGaps.record(call, result)
            }
        }
        // OPT-VAL-01-02 / OPT-VAL-02-03: the submit coverage gates refuse a
        // submit at the acceptance site, and the refusal must reach the model
        // (and the activity list) as this call's tool error — so it is
        // evaluated before anything downstream consumes the result, and a
        // refused call never parks a report.
        val coverageRejection =
            if (!delegated && call.toolName == SubmitReportTool.NAME && result.success) {
                evaluateSubmitCoverageGates(call, result)
            } else {
                null
            }
        recordActivity(call, coverageRejection ?: result, execution.startedAt)
        // The tool's result is now folded into the trajectory, so a restarter
        // may treat the call as committed.
        listener?.onToolCallCommitted(call.toolCallId)
        // The diagnostics keep the tool-execution truth here: whether the
        // registry call itself worked.  The gate's verdict gets its own
        // records inside [evaluateSubmitCoverageGates].
        recordToolDiagnostics(
            call = call,
            result = result,
            turn = turn,
            stepIndex = execution.stepIndex,
            startedAt = execution.startedAt,
            unexpectedFailure = execution.unexpectedFailure
        )

        val modelResult = withPlaybookRecommendation(coverageRejection ?: result)
        // OPT-VAL-02-02: fold this call into the run's signal set (raw
        // result, before host decorations) and append the `host-signals:`
        // line to the *rendered* content — after AgentToolRunner's redaction
        // (which produced result.data) and after the ledger recorded the
        // unannotated payload above, so the annotation reaches the model's
        // transcript only and never masquerades as tool payload data.
        val modelContent = toolContent(modelResult) + hostSignalsLine(result, delegated)
        messages += AgentModelMessage.fromToolResult(modelResult, modelContent)
        emitMessage(
            role = AgentConversationRole.Tool,
            content = modelResult.error?.userMessage ?: toolSummaryText(modelResult),
            toolCallId = call.toolCallId,
            toolName = modelResult.toolName.ifBlank { "(rejected)" },
            untrusted = true,
            error = modelResult.error
        )

        var planFinishedNow = false
        if (!delegated) {
            if (call.toolName == DeclareAnalysisPlanTool.NAME && result.success) {
                acceptDeclaredPlan(result)
            } else if (call.toolName == SubmitReportTool.NAME && result.success) {
                if (coverageRejection == null && acceptSubmittedReport(result)) {
                    commitSubmitCoverageAcceptance()
                }
            } else if (call.toolName !in ORCHESTRATION_TOOLS && execution.recordInLedger) {
                planFinishedNow = trackPlanExecution(call, result.success)
                if (planFinishedNow && tryEnterPlanGapFill()) {
                    planFinishedNow = false
                }
            }
        }

        var stopReason = when {
            // A submitted report ends the run on the model's own terms, so it
            // outranks a plan that happens to complete on the same turn.
            submittedReport != null -> AgentStopReason.ModelFinal
            planFinishedNow -> AgentStopReason.PlanComplete
            else -> terminalStopFor(result)
        }
        if (execution.recordInLedger &&
            call.toolName !in ORCHESTRATION_TOOLS &&
            isRepeatedToolQuery(result) &&
            stopReason == null
        ) {
            stopReason = AgentStopReason.RepeatedToolCall
        }

        if (execution.countsInvalidArgumentRetry) {
            if (result.error?.code == AgentErrorCode.INVALID_TOOL_ARGUMENTS) {
                consecutiveInvalidArguments += 1
                if (consecutiveInvalidArguments > policy.maxInvalidArgumentRetries && stopReason == null) {
                    stopReason = AgentStopReason.InvalidArguments
                }
            } else {
                consecutiveInvalidArguments = 0
            }
        }

        if (result.error?.code == AgentErrorCode.INVALID_DISPLAY_FILTER) {
            consecutiveInvalidFilters += 1
            if (consecutiveInvalidFilters >= MAX_INVALID_FILTER_FAILURES_BEFORE_VALIDATION &&
                call.toolName != "validate_display_filter"
            ) {
                messages += AgentModelMessage.user(AgentPrompt.INVALID_DISPLAY_FILTER_NUDGE)
                diagnostics?.record(
                    type = AgentDiagnosticsEventType.PlanDeviation,
                    phase = AgentRunPhase.Investigating.name,
                    turn = turn,
                    toolName = call.toolName,
                    status = "invalid_filter_nudge",
                    attributes = mapOf(
                        "validationRequired" to "true",
                        "invalidFilterCount" to consecutiveInvalidFilters.toString()
                    )
                )
            }
        } else if (result.success || call.toolName == "validate_display_filter") {
            consecutiveInvalidFilters = 0
        }
        return stopReason
    }

    private suspend fun executePreparedToolCall(
        prepared: PreparedToolCall,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode,
        turn: Int
    ): ToolExecution {
        val call = prepared.call
        val startedAt = clock()
        diagnostics?.record(
            type = AgentDiagnosticsEventType.ToolStarted,
            phase = AgentRunPhase.RunningTool.name,
            turn = turn,
            step = if (call.toolName in ORCHESTRATION_TOOLS) {
                budget.usage().steps
            } else {
                budget.usage().steps + 1
            },
            toolName = call.toolName,
            status = "started"
        )
        val result = prepared.rejectedResult ?: try {
            toolRunner.execute(call, snapshot, privacyMode)
        } catch (cancelled: CancellationException) {
            val stepIndex = toolRunner.takeStepIndex(call.toolCallId) ?: budget.usage().steps
            toolRunner.takeUnexpectedFailure(call.toolCallId)
            diagnostics?.record(
                type = AgentDiagnosticsEventType.ToolFinished,
                phase = AgentRunPhase.RunningTool.name,
                turn = turn,
                step = stepIndex,
                toolName = call.toolName,
                durationMillis = (clock() - startedAt).coerceAtLeast(0L),
                status = "cancelled"
            )
            controller.finish(AgentRunPhase.Cancelled)
            throw cancelled
        }
        return ToolExecution(
            index = prepared.index,
            call = call,
            result = result,
            startedAt = startedAt,
            stepIndex = toolRunner.takeStepIndex(call.toolCallId) ?: budget.usage().steps,
            unexpectedFailure = toolRunner.takeUnexpectedFailure(call.toolCallId)
        )
    }

    private fun blockedByInvalidPlanExecution(prepared: PreparedToolCall): ToolExecution {
        val startedAt = clock()
        return ToolExecution(
            index = prepared.index,
            call = prepared.call,
            result = blockedByInvalidPlanResult(prepared.call),
            startedAt = startedAt,
            stepIndex = budget.usage().steps,
            unexpectedFailure = null,
            recordInLedger = false,
            countsInvalidArgumentRetry = false
        )
    }

    private data class PreparedToolCall(
        val index: Int,
        val call: AgentToolCall,
        val rejectedResult: AgentToolResult?
    )

    private data class ToolExecution(
        val index: Int,
        val call: AgentToolCall,
        val result: AgentToolResult,
        val startedAt: Long,
        val stepIndex: Int,
        val unexpectedFailure: Throwable?,
        val recordInLedger: Boolean = true,
        val countsInvalidArgumentRetry: Boolean = true
    )

    private data class ToolTurnExecution(
        val results: List<AgentToolResult> = emptyList(),
        val stopReason: AgentStopReason? = null
    )

    /**
     * Stop a model that is re-asking the exact same validated query.  The hash
     * is produced by the runner after argument normalization, so key order and
     * harmless numeric spelling changes do not bypass this guard.
     */
    private fun isRepeatedToolQuery(result: AgentToolResult): Boolean {
        val hash = result.provenance.normalizedArgumentsHash.trim()
        val toolName = result.toolName.trim()
        if (hash.isEmpty() || toolName.isEmpty()) {
            lastToolQueryKey = null
            consecutiveIdenticalToolCalls = 0
            return false
        }

        val key = "$toolName|$hash"
        if (key == lastToolQueryKey) {
            consecutiveIdenticalToolCalls += 1
        } else {
            lastToolQueryKey = key
            consecutiveIdenticalToolCalls = 1
        }
        return consecutiveIdenticalToolCalls >= policy.maxConsecutiveIdenticalToolCalls
    }

    private fun recordToolDiagnostics(
        call: AgentToolCall,
        result: AgentToolResult,
        turn: Int,
        stepIndex: Int,
        startedAt: Long,
        unexpectedFailure: Throwable? = null
    ) {
        diagnostics?.record(
            type = AgentDiagnosticsEventType.ToolFinished,
            phase = AgentRunPhase.RunningTool.name,
            turn = turn,
            step = stepIndex,
            toolName = result.toolName.ifBlank { call.toolName },
            argumentsHash = result.provenance.normalizedArgumentsHash.takeIf { it.isNotBlank() },
            durationMillis = result.durationMillis.takeIf { it > 0L }
                ?: (clock() - startedAt).coerceAtLeast(0L),
            status = if (result.success) "succeeded" else "failed",
            failure = unexpectedFailure?.toDiagnosticsFailure(
                boundary = "tool.${result.toolName.ifBlank { call.toolName }}",
                errorCode = result.error?.code ?: AgentErrorCode.INTERNAL_ERROR,
                retryable = result.error?.retryable ?: false
            ) ?: result.error?.toDiagnosticsFailure(
                "tool.${result.toolName.ifBlank { call.toolName }}"
            ),
            attributes = diagnosticToolAttributes(call, result)
        )
    }

    /** Redacted dimensions for performance diagnostics; argument values never leave this boundary. */
    private fun diagnosticToolAttributes(
        call: AgentToolCall,
        result: AgentToolResult
    ): Map<String, String> = buildMap {
        put("returnedCount", result.returnedCount.toString())
        put("totalCount", result.totalCount.toString())
        put("truncated", result.truncated.toString())
        put("sensitivity", result.sensitivity.name)
        put("resultBytes", result.resultBytes.toString())
        put("scope", result.provenance.scope.name)
        put("sourceTruncated", result.truncation.sourceTruncated.toString())
        put("quotaTruncated", result.truncation.quotaTruncated.toString())
        put("payloadTruncated", result.truncation.payloadTruncated.toString())
        put("contextCompacted", result.truncation.contextCompacted.toString())
        put("omittedFrameCount", result.truncation.omittedFrames.size.toString())
        put("omittedPathCount", result.truncation.omittedPaths.size.toString())
        put("hasContinuation", (result.truncation.continuation != null).toString())
        result.queryMode?.let { put("queryMode", it) }
        result.provenance.queryMode?.let { put("provenanceQueryMode", it) }

        val data = result.data.orEmpty()
        (data["matchedPackets"] as? Number)?.let { put("matchedPackets", it.toLong().toString()) }
        (data["scannedPackets"] as? Number)?.let { put("scannedPackets", it.toLong().toString()) }
        (data["sampled"] as? Boolean)?.let { put("sampled", it.toString()) }
        (data["coverageComplete"] as? Boolean)?.let { put("coverageComplete", it.toString()) }
        (data["delegateIncomplete"] as? Boolean)?.let { put("delegateIncomplete", it.toString()) }
        (data["incompleteReason"] as? String)?.let { put("delegateIncompleteReason", it) }
        val normalizations = data.filterKeys { it.endsWith("Normalization") }
        put("normalizationCount", normalizations.size.toString())
        normalizations.values
            .mapNotNull { it as? Map<*, *> }
            .firstOrNull()
            ?.let { normalization ->
                (normalization["originalLength"] as? Number)?.let {
                    put("normalizationOriginalLength", it.toLong().toString())
                }
                (normalization["normalizedLength"] as? Number)?.let {
                    put("normalizationEffectiveLength", it.toLong().toString())
                }
                (normalization["ruleVersion"] as? String)?.let {
                    put("normalizationRuleVersion", it)
                }
            }
        listOf("requestedFrames", "omittedFrames", "sampleFrames", "anomalyFrames")
            .forEach { key ->
                collectionSize(data[key])?.let { put("${key}Count", it.toString()) }
            }
        listOf("requested", "granted", "returned", "total")
            .forEach { key ->
                (data[key] as? Number)?.let { put("data$key", it.toLong().toString()) }
            }
        (call.arguments["filter"] as? String)?.trim()?.takeIf { it.isNotEmpty() }?.let { filter ->
            put("filterHash", shortDiagnosticHash(filter))
        }
    }

    private fun collectionSize(value: Any?): Int? = when (value) {
        is Collection<*> -> value.size
        is Iterable<*> -> value.count()
        is Array<*> -> value.size
        else -> null
    }

    private fun shortDiagnosticHash(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { byte -> "%02x".format(byte) }.take(16)
    }

    /**
     * Whether this tool failure must end the run.
     *
     * Budget exhaustion and session loss are host-level: no later call can
     * succeed, so continuing would only burn model turns.  An invalid filter or
     * a timeout is a per-call answer the model can legitimately work around.
     */
    private fun terminalStopFor(result: AgentToolResult): AgentStopReason? {
        val code = result.error?.code ?: return null
        return when (code) {
            AgentErrorCode.MAX_STEPS_REACHED,
            AgentErrorCode.CONTEXT_LIMIT,
            AgentErrorCode.SESSION_CHANGED,
            AgentErrorCode.NO_CAPTURE -> code.toStopReason()
            AgentErrorCode.CANCELLED -> AgentStopReason.Cancelled
            else -> null
        }
    }

    private fun duplicateCallResult(call: AgentToolCall): AgentToolResult = AgentToolResult(
        toolCallId = call.toolCallId,
        // Left blank rather than echoing the model's requested name: this call
        // never reached the registry, so the string is unvalidated input.
        toolName = "",
        success = false,
        error = AgentError(
            code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
            userMessage = "That analysis step was already performed.",
            retryable = false,
            details = mapOf("reason" to "duplicate_tool_call_id")
        )
    )

    private fun forbiddenDelegatedCallResult(call: AgentToolCall): AgentToolResult = AgentToolResult(
        toolCallId = call.toolCallId,
        toolName = call.toolName.takeIf { it in ORCHESTRATION_TOOLS }.orEmpty(),
        success = false,
        error = AgentError(
            code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
            userMessage = "That orchestration step is not available inside a delegated investigation.",
            retryable = false,
            details = mapOf("reason" to "delegation_recursion_blocked")
        )
    )

    /**
     * A call made during a gap-fill turn that fills no pending gap.
     *
     * Structured rather than silent so the model can correct course: the error
     * names the permitted purpose and the turn is not charged, which together
     * make the grant recoverable instead of merely spent.
     */
    private fun offPurposeGapFillResult(call: AgentToolCall): AgentToolResult = AgentToolResult(
        toolCallId = call.toolCallId,
        toolName = call.toolName.takeIf { requested ->
            toolRunner.toolDefinitions().any { it.name == requested }
        }.orEmpty(),
        success = false,
        error = AgentError(
            code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
            userMessage = "The declared plan is complete. These extra turns may only continue " +
                "truncated reads, so this call was not run.",
            retryable = true,
            details = mapOf(
                "reason" to "gap_fill_off_purpose",
                "pendingGaps" to evidenceGaps.ordered().map { it.describe() }
            )
        )
    )

    private fun blockedByInvalidPlanResult(call: AgentToolCall): AgentToolResult = AgentToolResult(
        toolCallId = call.toolCallId,
        toolName = call.toolName.takeIf { requested ->
            toolRunner.toolDefinitions().any { it.name == requested }
        }.orEmpty(),
        success = false,
        error = AgentError(
            code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
            userMessage = "The analysis step was not run because the accompanying plan was invalid.",
            retryable = true,
            details = mapOf("reason" to "invalid_analysis_plan")
        )
    )

    /**
     * Take the parked report envelope, if a `submit_report` call produced one.
     *
     * The envelope is re-encoded rather than decoded here so the existing
     * [finalizeReport] path stays the single place that knows how to turn a
     * report payload into a validated [AgentReport].
     */
    private fun consumeSubmittedReport(): AgentModelResponse.Final? {
        val envelope = submittedReport ?: return null
        submittedReport = null
        return AgentModelResponse.Final(reportJson = AgentResultTruncator.encode(envelope))
    }

    /**
     * Park a schema-validated report envelope for the turn loop to finalize.
     *
     * The arguments already passed the provider's schema check and the host's
     * argument validator, so nothing here re-parses free text — the payload is
     * a map, and the only work left is to strip the tool's own bookkeeping key
     * before the codec sees it.
     */
    private fun acceptSubmittedReport(result: AgentToolResult): Boolean {
        val data = result.data ?: return false
        val envelope = data.filterKeys { it != "submitted" }
        if (envelope["summary"] == null && envelope["findings"] == null) return false
        submittedReport = envelope
        diagnostics?.record(
            type = AgentDiagnosticsEventType.ModelResponse,
            phase = AgentRunPhase.RunningTool.name,
            status = "report_submitted",
            attributes = mapOf(
                "transport" to "tool_call",
                "findingCount" to ((envelope["findings"] as? List<*>)?.size ?: 0).toString()
            ) + checkCoverageAcceptanceAttributes() + signalCoverageAcceptanceAttributes()
        )
        return true
    }

    /**
     * OPT-VAL-01-02 rule 2 and OPT-VAL-02-03 rule 3 at the submit acceptance
     * site, sharing one refusal: both coverage kinds are evaluated for this
     * `submit_report` call, and a submit that leaves any gap in either kind —
     * and can be refused for at least one of them — is refused exactly once
     * per run.  The single shot is deliberately joint rather than per rule:
     * two one-shot flags would let one submit eat two refusals and would
     * force the model into two revision rounds for gaps the host could have
     * named together.  Whatever the model does next — run the missing
     * checks, attach the missing signals, or re-submit unchanged — the second
     * submit is accepted, with check gaps committed as host-authored
     * limitations here and signal gaps narrated by the rule-3 net at
     * validation time (which also sees the final surviving findings).
     *
     * Degradation per the task doc's optional-with-default contract, per
     * kind.  Rule 2: when check coverage cannot be attributed — no plan was
     * declared, or no plan step names a check — the host records limitations
     * instead of refusing, because the model was never asked to bind its
     * steps to checks.  Rule 3 (§3's attribution contract, design §5.2's
     * 降级兼容 bullet): signal gaps refuse only when the submit is *readable*
     * (the envelope safe-decodes; an undecodable one contributes no
     * attribution — the host cannot honestly refuse what it cannot count)
     * and its author could have carried `relatedSignals` at all: the model
     * client declares structured output (the §8.1 capability flag, read
     * where [run] reads it), or the submitted report proves the channel by
     * using one of the agent-report-2 structured fields (≥1 finding carries
     * a non-empty `relatedSignals`).  Free-text finals and legacy reports
     * that use none of the structured fields on a backend that negotiated
     * structured output off are never refused — they get limitations, so the
     * pure-text path cannot deadlock a revision on a field it may not have.
     *
     * Rule 2 is skipped entirely — no verdict, no extra attributes,
     * byte-for-byte the pre-gate behavior — when its policy escape valve is
     * off, or when the question never matched a playbook intent
     * ([enforceInitialTool], the run's established playbook-hit predicate).
     * Rule 3 is not playbook-scoped: a baseline signal enumerated by the
     * host is a fact of the capture, not of the playbook, so it gates every
     * non-delegated submit while signals were enumerated — including free
     * questions — and is skipped entirely, same pre-gate shape, when its
     * valve is off or the run enumerated nothing.
     */
    private fun evaluateSubmitCoverageGates(
        call: AgentToolCall,
        result: AgentToolResult
    ): AgentToolResult? {
        lastSubmitCoverage = if (policy.enforcePlaybookCheckCoverage && enforceInitialTool) {
            checkCoverageValidator.checkCoverageGaps(
                playbook = playbook,
                plan = declaredPlan,
                completedStepIndices = completedPlanStepIndices.toSet(),
                successfulStepIndices = successfulPlanStepIndices.toSet(),
                enforcementEnabled = true
            )
        } else {
            null
        }
        lastSubmitSignalCoverage = if (policy.enforceSignalCoverage && !runSignals.isEmpty) {
            val submitted = decodeSubmittedEnvelope(result)
            lastSubmitSignalAttributable = submitted != null && (
                modelClient.capabilities.structuredOutput ||
                    submitted.findings.any { it.relatedSignals.isNotEmpty() }
                )
            checkCoverageValidator.signalCoverageGaps(
                signals = runSignals.signals,
                findings = submitted?.findings.orEmpty(),
                limitations = submitted?.limitations.orEmpty(),
                enforcementEnabled = true
            )
        } else {
            lastSubmitSignalAttributable = false
            null
        }
        val checkGaps = lastSubmitCoverage?.uncoveredChecks.orEmpty()
        val signalGaps = lastSubmitSignalCoverage?.unaddressedSignals.orEmpty()
        if (checkGaps.isEmpty() && signalGaps.isEmpty()) return null
        val attributable = (lastSubmitCoverage?.attributable == true) || lastSubmitSignalAttributable
        if (attributable && !submitCoverageRejected) {
            submitCoverageRejected = true
            if (checkGaps.isNotEmpty()) {
                diagnostics?.record(
                    type = AgentDiagnosticsEventType.PlanDeviation,
                    phase = AgentRunPhase.RunningTool.name,
                    status = "playbook_check_coverage_rejected",
                    attributes = mapOf(
                        "reason" to "playbook_check_coverage_gap",
                        "playbookCheckGaps" to checkGaps.size.toString(),
                        "uncoveredCheckIds" to checkGaps.joinToString(",") { it.id }
                    )
                )
            }
            if (signalGaps.isNotEmpty()) {
                diagnostics?.record(
                    type = AgentDiagnosticsEventType.PlanDeviation,
                    phase = AgentRunPhase.RunningTool.name,
                    status = "signal_coverage_rejected",
                    attributes = mapOf(
                        "reason" to "signal_coverage_gap",
                        "signalCoverageGaps" to signalGaps.size.toString(),
                        "unaddressedSignalIds" to signalGaps.joinToString(",") { it.signalId }
                    )
                )
            }
            return submitCoverageRejection(call, checkGaps, signalGaps)
        }
        return null
    }

    /**
     * The offered report, decoded through the codec's safe decode (the same
     * one [finalizeReport] will use on the parked envelope), or null when the
     * envelope cannot be read at all.  Only [SubmitReportTool]'s bookkeeping
     * key is stripped, mirroring [acceptSubmittedReport].
     */
    private fun decodeSubmittedEnvelope(result: AgentToolResult): AgentReport? {
        val data = result.data ?: return null
        val envelope = data.filterKeys { it != "submitted" }
        return AgentJsonCodec.decodeReport(AgentResultTruncator.encode(envelope)).getOrNull()
    }

    /** Fold the accepted gate verdicts into the report/RunMetrics channels. */
    private fun commitSubmitCoverageAcceptance() {
        lastSubmitCoverage?.let { coverage ->
            playbookCheckGapLimitations = coverage.gapLimitations()
            planCoverageGaps = coverage.uncoveredChecks.size
        }
        // The signal count lands at acceptance (limitations-only path
        // included, like rule 2's count); the gap prose itself rides the
        // trace's rule-3 net so it is computed against the final findings.
        lastSubmitSignalCoverage?.let { coverage ->
            signalCoverageGaps = coverage.unaddressedSignals.size
        }
    }

    /**
     * Gap diagnostics for the `report_submitted` record (§2.3 rule 5 of the
     * task doc): a stable disposition code plus the uncovered checks' ids —
     * never descriptions or model prose.  Empty when the gate did not run at
     * all, which keeps the record in its exact pre-gate shape.
     */
    private fun checkCoverageAcceptanceAttributes(): Map<String, String> {
        val coverage = lastSubmitCoverage ?: return emptyMap()
        if (coverage.clean) return mapOf("checkCoverage" to "covered")
        return mapOf(
            // Disposition per kind: the one-shot flag is joint across both
            // rules now, so check gaps narrate the outcome their own
            // attribution explains — refused-and-accepted-as-such when they
            // were refusals, limitations-only when they never could be.
            "checkCoverage" to if (coverage.attributable && submitCoverageRejected) {
                "finalized_with_gaps"
            } else {
                "unattributable_gaps"
            },
            "playbookCheckGaps" to coverage.uncoveredChecks.size.toString(),
            "uncoveredCheckIds" to coverage.uncoveredChecks.joinToString(",") { it.id }
        )
    }

    /**
     * OPT-VAL-02-03 signal counterpart of [checkCoverageAcceptanceAttributes]
     * on the same `report_submitted` record: a stable disposition code, the
     * unaddressed count and the signal ids — ids, kinds and counts only, the
     * extractor guarantees none of those carries capture text.  Empty when
     * the rule did not run at all (valve off) or had nothing to gate (the
     * run enumerated no signals), which keeps the record in its exact
     * pre-gate shape either way.
     */
    private fun signalCoverageAcceptanceAttributes(): Map<String, String> {
        val coverage = lastSubmitSignalCoverage ?: return emptyMap()
        if (coverage.clean) return mapOf("signalCoverage" to "covered")
        return mapOf(
            "signalCoverage" to if (lastSubmitSignalAttributable) {
                "finalized_with_gaps"
            } else {
                "unattributable_gaps"
            },
            "signalCoverageGaps" to coverage.unaddressedSignals.size.toString(),
            "unaddressedSignalIds" to coverage.unaddressedSignals
                .joinToString(",") { it.signalId }
        )
    }

    /**
     * The refusal the model sees for a gated submit — from either or both
     * coverage rules, since the run's one shot is shared.  Phrased like the
     * loop's other structured rejections: the message names each gap list
     * and the two exits (close the gaps then re-submit, or re-submit as-is
     * and have the gaps recorded), and the details carry the checks with
     * their recommended tools and the signals with their id/kind/value short
     * forms so a client can render the lists without parsing prose.
     */
    private fun submitCoverageRejection(
        call: AgentToolCall,
        checkGaps: List<AgentPlaybookCheck>,
        signalGaps: List<AgentSignal>
    ): AgentToolResult {
        val reasonCodes = buildList {
            if (checkGaps.isNotEmpty()) add("playbook_check_coverage_gap")
            if (signalGaps.isNotEmpty()) add("signal_coverage_gap")
        }.joinToString(",")
        val userMessage = buildString {
            append("The report was not accepted: ")
            if (checkGaps.isNotEmpty()) {
                append("these playbook checks were not covered by a " +
                    "successfully executed plan step: ")
                append(checkGaps.joinToString { check -> "\"${check.id}\" (${check.description})" })
                append(". ")
            }
            if (signalGaps.isNotEmpty()) {
                append("these host-enumerated baseline signals were addressed by no " +
                    "finding's relatedSignals and by no limitation naming the signal id: ")
                append(signalGaps.joinToString { signal ->
                    "${signal.signalId} (${signal.kind} ${signal.value} ${signal.unit})"
                })
                append(". ")
            }
            when {
                checkGaps.isNotEmpty() && signalGaps.isNotEmpty() -> append(
                    "Run the missing checks and attach the missing signals — to a relevant " +
                        "finding's relatedSignals or to a limitation that names their ids — " +
                        "and submit the report again, or submit again unchanged to finalize " +
                        "the report with these gaps recorded as limitations."
                )
                checkGaps.isNotEmpty() -> append(
                    "Run the missing checks and submit the report again, or submit again " +
                        "unchanged to finalize the report with these gaps recorded as limitations."
                )
                else -> append(
                    "Attach each missing signal to a relevant finding via relatedSignals, or " +
                        "address it in a limitation that names its signal id, or submit again " +
                        "unchanged to finalize the report with these gaps recorded as limitations."
                )
            }
        }
        val details = mutableMapOf<String, Any?>("reason" to reasonCodes)
        if (checkGaps.isNotEmpty()) {
            details["uncoveredChecks"] = checkGaps.map { check ->
                mapOf(
                    "id" to check.id,
                    "description" to check.description,
                    "recommendedTools" to check.recommendedTools
                )
            }
        }
        if (signalGaps.isNotEmpty()) {
            details["unaddressedSignals"] = signalGaps.map { signal ->
                mapOf(
                    "id" to signal.signalId,
                    "kind" to signal.kind,
                    "value" to signal.value
                )
            }
        }
        return AgentToolResult(
            toolCallId = call.toolCallId,
            toolName = SubmitReportTool.NAME,
            success = false,
            error = AgentError(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = userMessage,
                retryable = true,
                details = details
            )
        )
    }

    private fun acceptDeclaredPlan(result: AgentToolResult): Boolean {
        val plan = parseDeclaredPlan(result) ?: return false
        declaredPlan = plan
        completedPlanStepIndices.clear()
        successfulPlanStepIndices.clear()
        completedPlanSteps = 0
        planComplete = false
        listener?.onAnalysisPlan(plan, completedPlanSteps)
        diagnostics?.record(
            type = AgentDiagnosticsEventType.PlanDeclared,
            phase = AgentRunPhase.RunningTool.name,
            status = "declared",
            attributes = mapOf("stepCount" to plan.steps.size.toString())
        )
        return true
    }

    /** One semantic parser shared by plan acceptance and same-turn gating. */
    private fun parseDeclaredPlan(result: AgentToolResult): AgentAnalysisPlan? {
        val data = result.data ?: return null
        val goal = AgentPrivacyPolicy.sanitizeReportText(
            data["goal"]?.toString()?.trim().orEmpty()
        )
        val availableTools = toolRunner.toolDefinitions().mapTo(LinkedHashSet()) { it.name }
        val steps = ((data["steps"] as? Iterable<*>) ?: emptyList<Any?>()).mapNotNull { raw ->
            val step = raw as? Map<*, *> ?: return@mapNotNull null
            val tool = step["tool"]?.toString()?.trim().orEmpty()
            val purpose = AgentPrivacyPolicy.sanitizeReportText(
                step["purpose"]?.toString()?.trim().orEmpty()
            )
            // Optional (OPT-VAL-01-02): a plan from before the field exists —
            // or one that simply does not bind steps to checks — parses and
            // behaves exactly as it did, with the empty default making the
            // run unattributable for the coverage gate.
            val checkId = AgentPrivacyPolicy.sanitizeReportText(
                step["checkId"]?.toString()?.trim().orEmpty()
            )
            if (tool !in availableTools || tool in ORCHESTRATION_TOOLS || purpose.isBlank()) {
                null
            } else {
                AgentAnalysisPlanStep(tool, purpose, checkId)
            }
        }.take(DeclareAnalysisPlanTool.MAX_PLAN_STEPS)
        if (goal.isBlank() || steps.isEmpty()) return null
        return AgentAnalysisPlan(goal, steps)
    }

    /**
     * Match a data-tool call to the first still-unmatched plan step of the
     * same name.
     *
     * A failed call still completes its step — the work was executed and
     * rule 1 must not report it as skipped — but only a success enters
     * [successfulPlanStepIndices], which is what makes a step count as
     * coverage for a playbook check (OPT-VAL-01-02 rule 2: 同名工具成功调用匹配).
     */
    private fun trackPlanExecution(call: AgentToolCall, succeeded: Boolean): Boolean {
        val plan = declaredPlan ?: return false
        if (planGapFillGranted && completedPlanStepIndices.size >= plan.steps.size) {
            // Gap-fill turns are host-granted continuation reads, not plan
            // deviations; the turn ceiling in executeToolCalls bounds them.
            return false
        }
        val matchedStepIndex = plan.steps.indices.firstOrNull { index ->
            index !in completedPlanStepIndices && plan.steps[index].tool == call.toolName
        }
        if (matchedStepIndex != null) {
            completedPlanStepIndices += matchedStepIndex
            if (succeeded) {
                successfulPlanStepIndices += matchedStepIndex
            }
            completedPlanSteps = completedPlanStepIndices.size
            listener?.onAnalysisPlan(plan, completedPlanSteps)
            if (completedPlanSteps >= plan.steps.size) {
                planComplete = true
                return true
            }
            return false
        }
        val unfinishedTools = plan.steps.indices
            .filterNot { it in completedPlanStepIndices }
            .map { plan.steps[it].tool }
            .distinct()
        diagnostics?.record(
            type = AgentDiagnosticsEventType.PlanDeviation,
            phase = AgentRunPhase.RunningTool.name,
            toolName = call.toolName,
            status = "unplanned",
            attributes = mapOf(
                "expectedTool" to unfinishedTools.joinToString(",").ifEmpty { "plan_complete" },
                "completedPlanSteps" to completedPlanSteps.toString(),
                "declaredPlanSteps" to plan.steps.size.toString()
            )
        )
        return false
    }

    /**
     * Decide whether the just-completed plan earns bounded gap-fill turns.
     *
     * Granted when (a) the policy allows it, (b) at least one successful result
     * was truncated with a continuation the model can actually follow, and (c)
     * the step budget still has room.  On a grant [planComplete] (set by
     * [trackPlanExecution]) is rolled back and the nudge is queued so it lands
     * *after* the current tool batch — a user message between an assistant
     * tool-call and its Tool results would break message grouping on strict
     * providers.
     *
     * Renewable, not one-shot: a gap-fill read can itself come back truncated,
     * and a run that has just been handed a fresh continuation is in exactly the
     * situation the grant was designed for. [planGapFillTurnsUsed] carries across
     * renewals so the total never exceeds the policy ceiling.
     */
    private fun tryEnterPlanGapFill(): Boolean {
        if (policy.maxPlanGapFillTurns <= 0) return false
        if (evidenceGaps.isEmpty) return false
        if (budget.remainingSteps() <= 0) return false
        val remainingGrant = policy.maxPlanGapFillTurns - planGapFillTurnsUsed
        if (remainingGrant <= 0) return false
        val renewal = planGapFillGranted
        planGapFillGranted = true
        planGapFillTurnsRemaining = remainingGrant
        planGapFillNudgePending = true
        planComplete = false
        diagnostics?.record(
            type = AgentDiagnosticsEventType.PlanDeviation,
            phase = AgentRunPhase.RunningTool.name,
            status = if (renewal) "gap_fill_renewed" else "gap_fill_granted",
            attributes = mapOf(
                "gapFillTurns" to planGapFillTurnsRemaining.toString(),
                "gapFillTurnsUsed" to planGapFillTurnsUsed.toString(),
                "recoverableTruncations" to evidenceGaps.size.toString(),
                "remainingSteps" to budget.remainingSteps().toString()
            )
        )
        return true
    }

    /**
     * A general-health run must orient itself before it can spend a packet-detail
     * budget. The model may still decide what to inspect after the overview; the
     * host merely prevents a first turn from skipping the trusted playbook's
     * bounded aggregate step.
     */
    private fun initialCallsFor(
        calls: List<AgentToolCall>,
        messages: MutableList<AgentModelMessage>
    ): List<AgentToolCall>? {
        val available = toolRunner.toolDefinitions().mapTo(LinkedHashSet()) { it.name }
        if (DeclareAnalysisPlanTool.NAME in available && declaredPlan == null) {
            val declaration = calls.firstOrNull { it.toolName == DeclareAnalysisPlanTool.NAME }
            if (declaration != null) {
                return buildList {
                    add(declaration)
                    calls.forEach { call -> if (call !== declaration) add(call) }
                }
            }
            messages += AgentModelMessage.user(
                "After reviewing the host-provided baseline evidence, call " +
                    "${DeclareAnalysisPlanTool.NAME} with the goal and ordered targeted-analysis steps."
            )
            return null
        }

        val requiredInitialTools = playbook.initialTools
            .filter { it != DeclareAnalysisPlanTool.NAME && it in available }
        val captureToolRan = ledger.all().any { it.toolName !in ORCHESTRATION_TOOLS }
        if (!enforceInitialTool || captureToolRan || requiredInitialTools.isEmpty()) return calls
        val initial = calls.firstOrNull { it.toolName in requiredInitialTools }
        if (initial != null) return listOf(initial)

        messages += AgentModelMessage.user(
            "Before targeted analysis, call one required initial tool: ${requiredInitialTools.joinToString()}."
        )
        return null
    }

    /**
     * Give the model one no-tools turn to turn the evidence ledger into a report
     * before the host falls back to its deterministic report.
     */
    private suspend fun finishAfterStop(
        question: String,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode,
        messages: MutableList<AgentModelMessage>,
        stopReason: AgentStopReason,
        terminalError: AgentError? = null
    ): AgentRunOutcome {
        if (stopReason == AgentStopReason.Cancelled) return cancelledOutcome()

        // A validated report parked for revision outranks a forced summary or
        // a synthesized fallback: the improvement turn ended, not the analysis.
        completeWithUnrevisedReport()?.let { return it }

        requestForcedFinalSummary(
            question = question,
            snapshot = snapshot,
            privacyMode = privacyMode,
            messages = messages,
            stopReason = stopReason,
            terminalError = terminalError
        )?.let { return it }

        val report = synthesizedReport(question, stopReason, snapshot)
        return if (terminalError != null) {
            failWithPartial(terminalError, report, snapshot, stopReason)
        } else {
            complete(report, snapshot, stopReason)
        }
    }

    private fun shouldAttemptForcedSummary(stopReason: AgentStopReason): Boolean = when (stopReason) {
        AgentStopReason.MaxStepsReached,
        AgentStopReason.MaxDurationReached,
        AgentStopReason.ContextLimit,
        AgentStopReason.RepeatedToolCall,
        AgentStopReason.PlanComplete,
        AgentStopReason.ModelFailure,
        AgentStopReason.InvalidArguments -> true
        else -> false
    }

    /** Return null only when no forced-summary request could be attempted. */
    private suspend fun requestForcedFinalSummary(
        question: String,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode,
        messages: MutableList<AgentModelMessage>,
        stopReason: AgentStopReason,
        terminalError: AgentError?
    ): AgentRunOutcome? {
        if (terminalError?.code == AgentErrorCode.CANCELLED) {
            return failWithPartial(
                error = terminalError,
                report = synthesizedReport(question, stopReason, snapshot),
                snapshot = snapshot,
                stopReason = stopReason
            )
        }
        if (!shouldAttemptForcedSummary(stopReason) || finalSummaryAttempted) return null
        finalSummaryAttempted = true
        if (!moveTo(AgentRunPhase.Finalizing)) return cancelledOutcome()

        // The forced-summary question goes into the run's real transcript first:
        // the summary the model produces from it is this run's conclusion and must
        // be replayable by a follow-up.  [ContextPlanner.planForFinalSummary]
        // returns its own bounded view, so planning never mutates this list.
        messages += AgentModelMessage.user(AgentPrompt.forcedFinalSummary(stopReason))
        val capabilities = modelClient.capabilities
        val context = contextPlanner.planForFinalSummary(
            source = messages,
            reportedContextLimit = capabilities.maxContextTokens,
            reportedOutputLimit = capabilities.maxOutputTokens
        )
        if (context.partial) return null

        val maxOutputTokens = capabilities.clampOutputTokens(
            AgentOutputBudget.tokens(
                AgentModelRequestStage.ForcedSummary,
                capabilities.maxOutputTokens
            )
        )
        val response = requestModelWithRetry(
            messages = context.messages,
            toolDefinitions = emptyList(),
            responseSchema = if (capabilities.structuredOutput) AgentPrompt.REPORT_SCHEMA else null,
            privacyMode = privacyMode,
            maxOutputTokens = maxOutputTokens,
            estimatedInputTokens = context.estimatedInputTokens,
            boundary = "model.respond.forced_summary",
            forcedSummary = true,
            stopReason = stopReason,
            requestStage = AgentModelRequestStage.ForcedSummary
        )
        val effectiveTerminalError = terminalError
        val finalResponse = if (
            response is AgentModelResponse.Failure &&
            response.error.isRepairableMalformedFinal()
        ) {
            requestForcedSummaryFormatRepair(
                context = context,
                privacyMode = privacyMode,
                maxOutputTokens = maxOutputTokens,
                stopReason = stopReason,
                error = response.error
            ) ?: response
        } else {
            response
        }

        return when (finalResponse) {
            is AgentModelResponse.Final -> {
                // The forced summary is the run's conclusion; record it as the
                // assistant turn answering the forced-summary question so a
                // follow-up run can replay it.
                messages += AgentModelMessage.assistant(
                    content = finalResponse.rawJson ?: finalResponse.report?.summary.orEmpty()
                )
                finalizeReport(
                    response = finalResponse,
                    question = question,
                    snapshot = snapshot,
                    stopReason = stopReason,
                    allowRevision = false,
                    // A report can recover the presentation, but an investigation
                    // error remains a real run failure and must not be hidden by
                    // the forced-summary request.
                    terminalError = effectiveTerminalError
                )
            }
            is AgentModelResponse.Failure -> {
                if (controller.isCancelled) {
                    cancelledOutcome()
                } else if (effectiveTerminalError == null &&
                    finalResponse.error.isDegradableFinalizingFailure()
                ) {
                    complete(
                        report = synthesizedReport(question, stopReason, snapshot)
                            .withForcedSummaryLimitation(finalResponse.error),
                        snapshot = snapshot,
                        stopReason = stopReason
                    )
                } else {
                    // The forced-summary request is best effort.  If the
                    // provider cancels only that request, never turn it into
                    // root-run cancellation: the ledger already contains
                    // confirmed evidence and synthesizedReport() is the
                    // guaranteed last-resort conclusion.
                    failWithPartial(
                        error = (effectiveTerminalError ?: finalResponse.error).forPartialReport(),
                        report = synthesizedReport(question, stopReason, snapshot),
                        snapshot = snapshot,
                        stopReason = stopReason
                    )
                }
            }
            is AgentModelResponse.Refusal -> {
                if (controller.isCancelled) {
                    cancelledOutcome()
                } else {
                    failWithPartial(
                         error = effectiveTerminalError ?: finalResponse.error ?: AiModelErrors.unavailable(
                            reason = "forced_summary_refusal"
                        ),
                        report = synthesizedReport(question, stopReason, snapshot),
                        snapshot = snapshot,
                        stopReason = stopReason
                    )
                }
            }
            is AgentModelResponse.ToolCalls -> {
                // The forced-summary request carries no tools, but a model that
                // has learned to report through submit_report may still answer
                // with it. That call *is* the report, so honour it rather than
                // discarding a complete answer as a contract violation.
                val reportCall = finalResponse.calls.firstOrNull {
                    it.toolName == SubmitReportTool.NAME && it.arguments.isNotEmpty()
                }
                val submitted = reportCall?.let { call ->
                    AgentJsonCodec.decodeReport(AgentResultTruncator.encode(call.arguments))
                        .getOrNull()
                }
                if (submitted != null) {
                    finalizeReport(
                        response = AgentModelResponse.Final(report = submitted),
                        question = question,
                        snapshot = snapshot,
                        stopReason = stopReason,
                        terminalError = effectiveTerminalError
                    ) ?: cancelledOutcome()
                } else {
                    failWithPartial(
                        error = effectiveTerminalError ?: AiModelErrors.contract(
                            reason = "forced_summary_returned_tool_calls"
                        ),
                        report = synthesizedReport(question, stopReason, snapshot),
                        snapshot = snapshot,
                        stopReason = stopReason
                    )
                }
            }
        }
    }

    /**
     * A malformed final is not a transient provider retry. Regenerate only the
     * compact, no-tools report once with an explicit format-repair instruction.
     */
    private suspend fun requestForcedSummaryFormatRepair(
        context: ContextPlan,
        privacyMode: AgentPrivacyMode,
        maxOutputTokens: Int,
        stopReason: AgentStopReason,
        error: AgentError
    ): AgentModelResponse? {
        val reason = error.details["reason"]?.toString().orEmpty()
        val repairSource = context.messages + AgentModelMessage.user(
            AgentPrompt.finalReportFormatRepair(reason)
        )
        val capabilities = modelClient.capabilities
        val repairContext = contextPlanner.planForFinalSummary(
            source = repairSource,
            reportedContextLimit = capabilities.maxContextTokens,
            reportedOutputLimit = capabilities.maxOutputTokens
        )
        if (repairContext.partial) return null
        return requestModelWithRetry(
            messages = repairContext.messages,
            toolDefinitions = emptyList(),
            responseSchema = if (capabilities.structuredOutput) AgentPrompt.REPORT_SCHEMA else null,
            privacyMode = privacyMode,
            maxOutputTokens = maxOutputTokens,
            estimatedInputTokens = repairContext.estimatedInputTokens,
            boundary = "model.respond.forced_summary_format_repair",
            forcedSummary = true,
            formatRepair = true,
            stopReason = stopReason,
            requestStage = AgentModelRequestStage.ForcedSummary
        )
    }

    private fun AgentError.isRepairableMalformedFinal(): Boolean =
        code == AgentErrorCode.MODEL_RESPONSE_MALFORMED &&
            details["reason"]?.toString() in REPAIRABLE_FINAL_FORMAT_REASONS

    private fun AgentError.isDegradableFinalizingFailure(): Boolean = when (code) {
        AgentErrorCode.CANCELLED,
        AgentErrorCode.MODEL_TIMEOUT,
        AgentErrorCode.MODEL_OUTPUT_TRUNCATED,
        AgentErrorCode.MODEL_RESPONSE_TOO_LARGE,
        AgentErrorCode.MODEL_RESPONSE_MALFORMED,
        AgentErrorCode.MODEL_RATE_LIMITED -> true
        AgentErrorCode.MODEL_UNAVAILABLE -> retryable
        else -> false
    }

    private fun AgentReport.withForcedSummaryLimitation(error: AgentError): AgentReport = copy(
        completeness = AgentReportCompleteness.Partial,
        limitations = limitations + listOf(
            "forced_summary_unavailable",
            "forced_summary_error=${error.code.name}",
            "confirmed_evidence=${ledger.successful().size}"
        )
    )

    /** One bounded no-tools request for models that cannot request later evidence. */
    private suspend fun runSingleSummaryFallback(
        question: String,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode,
        messages: MutableList<AgentModelMessage>
    ): AgentRunOutcome {
        analysisMode = AgentAnalysisMode.SingleSummary
        if (!policy.analysisBootstrapEnabled) {
            if (!moveTo(AgentRunPhase.WaitingForModel)) return cancelledOutcome()
            val overviewCall = AgentToolCall(
                toolCallId = "host-overview",
                toolName = AgentPlaybook.CAPTURE_OVERVIEW_TOOL,
                arguments = emptyMap()
            )
            messages += hostToolCallMessage(overviewCall)
            val legacyOverview = executeToolCalls(
                calls = listOf(overviewCall),
                messages = messages,
                snapshot = snapshot,
                privacyMode = privacyMode,
                turn = 1
            )
            legacyOverview.stopReason?.let { stop ->
                return if (stop == AgentStopReason.Cancelled) cancelledOutcome()
                else finishAfterStop(
                    question = question,
                    snapshot = snapshot,
                    privacyMode = privacyMode,
                    messages = messages,
                    stopReason = stop
                )
            }
        }
        if (!moveTo(AgentRunPhase.WaitingForModel)) return cancelledOutcome()
        val capabilities = modelClient.capabilities
        val context = contextPlanner.plan(
            source = messages,
            reportedContextLimit = capabilities.maxContextTokens,
            reportedOutputLimit = capabilities.maxOutputTokens
        )
        applyContextCompactions(messages, context)
        if (context.partial) {
            return finishAfterStop(
                question = question,
                snapshot = snapshot,
                privacyMode = privacyMode,
                messages = messages,
                stopReason = AgentStopReason.ContextLimit
            )
        }

        val maxOutputTokens = capabilities.clampOutputTokens(context.reservedOutputTokens)
        val response = requestModelWithRetry(
            messages = context.messages,
            toolDefinitions = emptyList(),
            responseSchema = if (capabilities.structuredOutput) AgentPrompt.REPORT_SCHEMA else null,
            privacyMode = privacyMode,
            maxOutputTokens = maxOutputTokens,
            estimatedInputTokens = context.estimatedInputTokens,
            turn = 1,
            boundary = "model.respond.single_summary",
            requestStage = AgentModelRequestStage.FinalReport
        )

        return when (response) {
            is AgentModelResponse.Final -> {
                // The single-summary answer is this run's conclusion; record it
                // so the transcript stays replayable for a follow-up.
                messages += AgentModelMessage.assistant(
                    content = response.rawJson ?: response.report?.summary.orEmpty()
                )
                finalizeReport(
                    response,
                    question,
                    snapshot,
                    allowRevision = false
                ) ?: complete(
                    synthesizedReport(question, AgentStopReason.ModelFailure, snapshot),
                    snapshot,
                    AgentStopReason.ModelFailure
                )
            }
            is AgentModelResponse.Failure -> fail(response.error, snapshot, response.error.code.toStopReason())
            is AgentModelResponse.Refusal -> fail(
                response.error ?: AiModelErrors.unavailable("single_summary_refusal"),
                snapshot,
                AgentStopReason.ModelFailure
            )
            is AgentModelResponse.ToolCalls -> complete(
                synthesizedReport(question, AgentStopReason.ModelFailure, snapshot),
                snapshot,
                AgentStopReason.ModelFailure
            )
        }
    }

    /** Keep deterministic planning data in an untrusted Tool message. */
    private fun withPlaybookRecommendation(result: AgentToolResult): AgentToolResult {
        if (!result.success || result.toolName != "get_capture_overview" || result.data == null) return result
        val recommendations = playbook.recommendedToolsForOverview(result.data)
        if (recommendations.isEmpty()) return result
        return result.copy(
            data = result.data + mapOf(
                "playbookRecommendation" to mapOf(
                    "playbook" to playbook.versionedId,
                    "recommendedNextTools" to recommendations
                )
            )
        )
    }

    /**
     * OPT-VAL-02-02 (design §5.2): record one successful baseline call in the
     * run's signal ledger and return the line the host appends to that call's
     * tool message content — the run's current signal ids in extractor
     * priority order, capped set included:
     *
     * `host-signals: [sig-…] (host-generated bookkeeping, not capture text)`
     *
     * Everything about the line is host-generated: the ids are content hashes
     * the [signalExtractor] minted from already-redacted payload data, so it
     * carries no capture text (nothing for the privacy gate to have missed).
     * The message itself keeps `untrustedCaptureData = true` — the structural
     * flag is per message and the rest of that message *is* capture-derived
     * JSON, so the design's "host bookkeeping, not capture text" marking is
     * carried in the wording, mirroring [AgentConversationCompactor]'s
     * self-labelled discovery notes: the flag tells the model the message is
     * data, and the parenthetical tells it whose data.
     *
     * Annotated: every successful top-level `get_capture_overview` /
     * `get_expert_info` message, bootstrap and model re-runs alike. Design
     * pins the line on the bootstrap overview message; the synchronous rule —
     * each such message ends with the full set visible *at that point in the
     * run* — is what makes "信号清单同步注入" true for the later expert
     * bootstrap call (whose `expert_group` signals could not appear on the
     * overview message already appended above it) and for every re-run,
     * because OPT-VAL-02-03 will hold the model to the full cumulative set
     * and every new signal must therefore become visible somewhere. Failed,
     * rejected, delegated-child and non-baseline calls get no line and
     * contribute nothing.
     *
     * The line is emitted even for an empty set (`host-signals: []`): the
     * model then knows the host enumerated and found nothing to address,
     * which a missing line cannot say, and the rule stays unconditional —
     * roughly 15 tokens on a message the transcript holds anyway.
     */
    private fun hostSignalsLine(result: AgentToolResult, delegated: Boolean): String {
        val baselineTool = result.toolName == AgentSignalExtractor.TOOL_CAPTURE_OVERVIEW ||
            result.toolName == AgentSignalExtractor.TOOL_EXPERT_INFO
        if (delegated || !result.success || !baselineTool || result.data == null) return ""
        runBaselineCalls += HostCallPayload(
            toolCallId = result.toolCallId,
            toolName = result.toolName,
            success = true,
            data = result.data
        )
        runSignals = signalExtractor.extract(runBaselineCalls)
        val ids = runSignals.signalIds.joinToString(
            separator = ", ",
            prefix = "[",
            postfix = "]"
        )
        return "\n$HOST_SIGNALS_PREFIX$ids$HOST_SIGNALS_PROVENANCE"
    }

    /** Run a serial sub-agent with an isolated transcript and shared host state. */
    private suspend fun runDelegatedInvestigation(
        goal: String,
        maxTurns: Int,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode
    ): AgentJsonObject {
        check(delegatedDepth == 0) { "Delegated investigations cannot recurse." }
        delegatedDepth += 1
        val startingIds = ledger.toolCallIds.toSet()
        val deadline = clock() + minOf(
            policy.maxDelegatedInvestigationTimeoutMillis,
            estimateDelegatedDeadlineMillis(maxTurns)
        )
        val childSnapshot = DelegatedSnapshot()
        val startingLogicalModelRequestCount = logicalModelRequestCount
        var childSteps = 0
        var incompleteReason: String? = null
        val parentRequestLimit = (policy.maxModelRequests - policy.reservedParentModelRequests)
            .coerceAtLeast(0)
        val delegatedRequestAllowance = minOf(
            policy.maxDelegatedModelRequests,
            (parentRequestLimit - startingLogicalModelRequestCount).coerceAtLeast(0)
        )
        val delegateRequestLimit = startingLogicalModelRequestCount + delegatedRequestAllowance
        val childTools = toolRunner.toolDefinitions().filterNot { it.name in ORCHESTRATION_TOOLS }
        val childMessages = promptAssembler.initialMessages(
            question = AgentPrompt.delegatedInvestigation(goal),
            snapshot = snapshot,
            policy = policy,
            privacyMode = privacyMode,
            tools = childTools,
            playbook = playbook.copy(
                initialTools = playbook.initialTools.filterNot { it in ORCHESTRATION_TOOLS }
            )
        ).toMutableList()
        var childReport: AgentReport? = null
        var childStopReason = AgentStopReason.ModelFailure
        try {
            withTimeout((deadline - clock()).coerceAtLeast(1L)) {
              for (turn in 1..maxTurns.coerceIn(1, DelegateInvestigationTool.MAX_TURNS)) {
                currentCoroutineContext().ensureActive()
                if (controller.isCancelled || budget.isExhausted() ||
                    clock() >= deadline ||
                    logicalModelRequestCount >= delegateRequestLimit ||
                    childSteps >= policy.maxDelegatedSteps
                ) {
                    incompleteReason = when {
                        clock() >= deadline -> "timeout"
                        controller.isCancelled -> "cancelled"
                        else -> "budget"
                    }
                    break
                }
                if (!moveTo(AgentRunPhase.WaitingForModel)) break
                val capabilities = modelClient.capabilities
                val context = contextPlanner.plan(
                    source = childMessages,
                    reportedContextLimit = capabilities.maxContextTokens,
                    reportedOutputLimit = capabilities.maxOutputTokens
                )
                applyContextCompactions(childMessages, context)
                if (context.partial) {
                    childStopReason = AgentStopReason.ContextLimit
                    break
                }
                val response = requestModelWithRetry(
                    messages = context.messages,
                    toolDefinitions = childTools,
                    responseSchema = if (capabilities.structuredOutput) AgentPrompt.REPORT_SCHEMA else null,
                    privacyMode = privacyMode,
                    maxOutputTokens = capabilities.clampOutputTokens(context.reservedOutputTokens),
                    estimatedInputTokens = context.estimatedInputTokens,
                    boundary = "model.respond.delegated",
                    requestStage = AgentModelRequestStage.ToolSelection
                )
                when (response) {
                    is AgentModelResponse.ToolCalls -> {
                        childMessages += AgentModelMessage.assistant(
                            content = response.assistantContent,
                            toolCalls = response.calls,
                            reasoningContent = response.reasoningContent
                        )
                        val remainingChildSteps = (policy.maxDelegatedSteps - childSteps)
                            .coerceAtLeast(0)
                        val executableCalls = response.calls.take(remainingChildSteps)
                        if (executableCalls.isEmpty()) {
                            incompleteReason = "budget"
                            break
                        }
                        val execution = executeToolCalls(
                            calls = executableCalls,
                            messages = childMessages,
                            snapshot = snapshot,
                            privacyMode = privacyMode,
                            turn = turn,
                            delegated = true
                        )
                        childSteps += executableCalls.size
                        childSnapshot.record(ledger, startingIds)
                        if (execution.stopReason != null) {
                            childStopReason = execution.stopReason
                            break
                        }
                        if (executableCalls.size < response.calls.size) {
                            incompleteReason = "budget"
                            break
                        }
                    }
                    is AgentModelResponse.Final -> {
                        val decoded = response.report ?: response.rawJson?.let { raw ->
                            AgentJsonCodec.decodeReport(raw).getOrNull()
                        }
                        if (decoded != null) {
                            childStopReason = AgentStopReason.ModelFinal
                            // OPT-VAL-02-03: the child's transcript carries no
                            // host-signals line, so the parent's signal set is
                            // not this report's contract (see validationResult).
                            childReport = validationResult(
                                decoded,
                                snapshot,
                                childStopReason,
                                signals = emptyList()
                            ).report
                            childSnapshot.report = childReport
                        }
                        break
                    }
                    is AgentModelResponse.Failure -> {
                        childStopReason = response.error.code.toStopReason()
                        break
                    }
                    is AgentModelResponse.Refusal -> break
                }
              }
            }
        } catch (timeout: TimeoutCancellationException) {
            childStopReason = AgentStopReason.ModelFailure
            incompleteReason = "timeout"
        } catch (cancelled: CancellationException) {
            if (controller.isCancelled) throw cancelled
            childStopReason = AgentStopReason.ModelFailure
            incompleteReason = "cancelled"
        } finally {
            delegatedDepth -= 1
            if (!controller.isTerminal && !controller.isCancelled) {
                moveTo(AgentRunPhase.RunningTool)
            }
        }

        val childCallIds = ledger.toolCallIds.filterNot(startingIds::contains)
        val report = childReport
        val incomplete = childStopReason != AgentStopReason.ModelFinal
        return mapOf(
            "summary" to (report?.summary
                ?: "The delegated investigation ended after ${childCallIds.size} tool step(s)."),
            "findings" to (report?.findings ?: childSnapshot.findings).take(MAX_DELEGATED_FINDINGS).map { finding ->
                mapOf(
                    "title" to finding.title,
                    "conclusion" to finding.conclusion,
                    "confidence" to finding.confidence.name,
                    "sourceToolCallIds" to finding.evidence
                        .map { it.sourceToolCallId }
                        .filter { it in childCallIds }
                        .distinct(),
                    "frameNumbers" to finding.evidence.mapNotNull { it.frameNumber }.distinct()
                )
            },
            "toolCallIds" to childCallIds,
            "stopReason" to childStopReason.name,
            "success" to true,
            "truncated" to incomplete,
            "delegateIncomplete" to incomplete,
            "incompleteReason" to (incompleteReason ?: when {
                controller.isCancelled -> "cancelled"
                clock() >= deadline -> "timeout"
                logicalModelRequestCount >= delegateRequestLimit ||
                    childSteps >= policy.maxDelegatedSteps -> "budget"
                else -> null
            }),
            "limitations" to (report?.limitations.orEmpty() +
                if (incomplete) listOf("delegate_incomplete") else emptyList())
                .take(MAX_DELEGATED_LIMITATIONS)
        )
    }

    private fun estimateDelegatedDeadlineMillis(maxTurns: Int): Long =
        (maxTurns.coerceIn(1, DelegateInvestigationTool.MAX_TURNS) * policy.maxModelRequestTimeoutMillis)
            .coerceAtMost(policy.maxDelegatedInvestigationTimeoutMillis)

    private class DelegatedSnapshot {
        var findings: List<AgentFinding> = emptyList()
        var report: AgentReport? = null

        fun record(ledger: EvidenceLedger, startingIds: Set<String>) {
            val ids = ledger.toolCallIds.filterNot(startingIds::contains)
            findings = ledger.successful()
                .filter { it.toolCallId in ids }
                .takeLast(MAX_DELEGATED_FINDINGS)
                .map { entry ->
                    AgentFinding(
                        id = "delegate-${entry.toolCallId}",
                        title = entry.toolName,
                        conclusion = entry.describe(),
                        severity = AgentFindingSeverity.Info,
                        confidence = AgentConfidence.Medium,
                        evidence = emptyList()
                    )
                }
        }
    }

    // -------------------------------------------------------------- reporting

    private suspend fun finalizeReport(
        response: AgentModelResponse.Final,
        question: String,
        snapshot: AgentCaptureSnapshot,
        stopReason: AgentStopReason = AgentStopReason.ModelFinal,
        messages: MutableList<AgentModelMessage>? = null,
        allowRevision: Boolean = false,
        terminalError: AgentError? = null
    ): AgentRunOutcome? {
        if (!moveTo(AgentRunPhase.ValidatingReport)) return cancelledOutcome()

        // A revision answers with corrected findings only. Merge them into the
        // report that was already validated rather than expecting a whole one.
        mergedRevision(response)?.let { merged ->
            preRevisionReport = null
            return finishValidatedReport(
                report = validationResult(merged, snapshot, stopReason).report,
                stopReason = stopReason,
                terminalError = terminalError
            )
        }
        // A revision answer that carried no usable findings must not fall
        // through to the full-report decode below: an undecodable answer would
        // replace the already-validated report with a synthesized fallback.
        completeWithUnrevisedReport()?.let { return it }

        val decoded = response.report ?: response.rawJson?.let { json ->
            AgentJsonCodec.decodeReport(json).getOrNull()
        }

        if (decoded == null) {
            // An unreadable final answer is not a report.  Rather than showing
            // the model's raw text, fall back to what the tools confirmed.
            val fallbackStop = stopReason.takeUnless { it == AgentStopReason.ModelFinal }
                ?: AgentStopReason.ModelFailure
            val fallback = synthesizedReport(question, fallbackStop, snapshot)
            return if (terminalError != null) {
                failWithPartial(terminalError, fallback, snapshot, fallbackStop)
            } else {
                complete(fallback, snapshot, fallbackStop)
            }
        }

        if (decoded.findings.isEmpty() && decoded.summary.isBlank() && ledger.successful().isNotEmpty()) {
            // A valid JSON envelope with no usable text or findings is still
            // an absent conclusion. Preserve the confirmed host evidence.
            val fallbackStop = stopReason.takeUnless { it == AgentStopReason.ModelFinal }
                ?: AgentStopReason.ModelFailure
            val fallback = synthesizedReport(question, fallbackStop, snapshot)
            return if (terminalError != null) {
                failWithPartial(terminalError, fallback, snapshot, fallbackStop)
            } else {
                complete(fallback, snapshot, fallbackStop)
            }
        }

        val modeLimited = if (analysisMode == AgentAnalysisMode.SingleSummary) {
            decoded.copy(
                completeness = AgentReportCompleteness.Partial,
                limitations = decoded.limitations + "This report was generated in single summary mode from one overview snapshot."
            )
        } else {
            decoded
        }
        val validation = validationResult(modeLimited, snapshot, stopReason)
        // The decoded report survived validation; a restarter may treat the
        // analysis outcome as committed rather than re-running the model.
        listener?.onReportValidated()
        val shouldRevise = allowRevision &&
            messages != null &&
            !revisionAttempted &&
            validation.rejections.size >= policy.minRejectionsForRevision &&
            budget.remainingSteps() > 0 &&
            !controller.isCancelled
        if (shouldRevise) {
            revisionAttempted = true
            preRevisionReport = validation.report
            val transcript = requireNotNull(messages)
            transcript += AgentModelMessage.assistant(
                content = AgentJsonCodec.encodeReport(modeLimited),
                reasoningContent = response.reasoningContent
            )
            transcript += AgentModelMessage.user(
                AgentPrompt.revisionRequest(
                    rejectionReasons = validation.rejections.map { it.reason },
                    rejectedFindingIds = validation.rejections.map { it.findingId }
                )
            )
            diagnostics?.record(
                type = AgentDiagnosticsEventType.Validation,
                phase = AgentRunPhase.ValidatingReport.name,
                status = "revision_requested",
                attributes = mapOf(
                    "rejectionCount" to validation.rejections.size.toString(),
                    "revisionAttempt" to "1"
                )
            )
            if (!moveTo(AgentRunPhase.WaitingForModel)) return cancelledOutcome()
            return null
        }
        return finishValidatedReport(validation.report, stopReason, terminalError)
    }

    /**
     * A report the host writes when the model never produced one.  It states
     * only what the ledger confirmed plus why the run stopped, so an interrupted
     * analysis still yields something the user can act on.
     */
    private fun synthesizedReport(
        question: String,
        stopReason: AgentStopReason,
        snapshot: AgentCaptureSnapshot
    ): AgentReport {
        val successfulEntries = ledger.successful()
        val failedEntries = ledger.failed()
        val confirmedEntries = successfulEntries.take(SYNTHESIZED_FINDING_LIMIT)
        val facts = confirmedEntries.map { it.describe() }
        val summary = if (successfulEntries.isEmpty() && failedEntries.isEmpty()) {
            "The analysis stopped before it could confirm anything about this capture."
        } else {
            buildString {
                append("The analysis stopped before a protocol-level conclusion was generated. ")
                append("It completed ${successfulEntries.size} data-tool call(s), with ")
                append("${failedEntries.size} failed call(s).")
                if (successfulEntries.size > confirmedEntries.size) {
                    append(" Showing the first ${confirmedEntries.size} confirmed result(s).")
                }
            }
        }
        return AgentReport(
            summary = summary,
            findings = confirmedEntries.mapIndexed { index, entry ->
                val observation = entry.describe()
                AgentFinding(
                    id = "confirmed-step-${index + 1}",
                    title = "Confirmed ${entry.toolName} result",
                    severity = AgentFindingSeverity.Info,
                    confidence = AgentConfidence.Low,
                    conclusion = observation,
                    evidence = listOf(
                        AgentEvidence(
                            type = AgentEvidenceType.Observation,
                            observation = observation,
                            sourceToolCallId = entry.toolCallId
                        )
                    )
                )
            },
            limitations = facts.map { "Confirmed: $it" },
            recommendedNextSteps = nextStepsFor(stopReason, question),
            provenance = AgentReportProvenance(
                captureFingerprint = snapshot.captureFingerprint,
                scope = snapshot.scope,
                displayFilter = snapshot.displayFilter,
                evidenceFrameCount = snapshot.evidenceFrameCount,
                modelId = modelClient.id,
                promptVersion = AgentPrompt.VERSION,
                playbookVersion = playbook.versionedId,
                generatedAtMillis = clock(),
                toolCallIds = ledger.toolCallIds,
                agentVersion = AgentPrompt.AGENT_VERSION,
                startedAtMillis = snapshot.startedAtMillis.takeIf { it > 0L },
                completedAtMillis = clock()
            ),
            completeness = AgentReportCompleteness.Incomplete
        )
    }

    private fun nextStepsFor(stopReason: AgentStopReason, question: String): List<String> =
        when (stopReason) {
            AgentStopReason.MaxStepsReached,
            AgentStopReason.MaxDurationReached,
            AgentStopReason.ContextLimit,
            AgentStopReason.RepeatedToolCall -> listOf(
                "Narrow the question or apply a display filter, then run the analysis again."
            )
            AgentStopReason.SessionChanged -> listOf(
                "Reopen the capture and run the analysis again."
            )
            AgentStopReason.ModelFailure,
            AgentStopReason.InvalidArguments -> listOf(
                "Retry the analysis: \"$question\"."
            )
            else -> emptyList()
        }

    /** Attach run provenance, then let the validator have the final say. */
    private fun validationResult(
        report: AgentReport,
        snapshot: AgentCaptureSnapshot,
        stopReason: AgentStopReason,
        /**
         * OPT-VAL-02-03: the signals the rule-3 net checks this report
         * against — by default the run's enumerated set, since the report's
         * author was the one shown them.  A delegated child's report opts
         * out at the call site: its author investigated in an isolated
         * transcript that carries no `host-signals:` line (see the [runSignals]
         * note), and the parent's own report still faces the full net.
         */
        signals: List<AgentSignal> = runSignals.signals
    ): EvidenceValidationResult {
        // Strip anything actionable from the model's prose before the report
        // reaches a renderer.  This is done here because every report — model
        // final, host-synthesized, or the partial one attached to a failure —
        // passes through this function, so no path can skip it.
        val sanitized = sanitizedProse(report)
        val withProvenance = sanitized.copy(
            provenance = sanitized.provenance.copy(
                modelId = modelClient.id,
                promptVersion = AgentPrompt.VERSION,
                playbookVersion = playbook.versionedId,
                agentVersion = AgentPrompt.AGENT_VERSION,
                startedAtMillis = sanitized.provenance.startedAtMillis
                    ?: snapshot.startedAtMillis.takeIf { it > 0L },
                completedAtMillis = clock()
            )
        )
        // EVL-COVERAGE-02: the run's evidence-coverage receipt. The flagged
        // set is this run's evidence set as the validator defines it — the
        // frame numbers the successful tool results of this run actually
        // returned (the same frames a citation is checked against) — because
        // the user's workspace evidence set lives in the UI layer and is not
        // reachable from the loop without a cross-layer change. The receipt
        // rides the trace for audit; the uncited-frame limitation is appended
        // below, after validation, at finalization.
        val evidenceCoverage = EvidenceCoverageEvaluator.evaluate(
            flagged = ledger.successful().flatMapTo(LinkedHashSet()) { it.frameNumbers },
            report = withProvenance
        )
        // EVL-COVERAGE-03: keep the exact receipt object the trace below
        // carries, so the audit record's counters are derived from the same
        // coverage the loop computed — no snapshot/copy in between.
        lastEvidenceCoverage = evidenceCoverage
        val trace = AgentRunTrace(
            snapshot = snapshot,
            ledger = ledger,
            stopReason = stopReason,
            budgetUsage = budget.usage(),
            // OPT-VAL-01-01: hand the validator the run's plan state so it can
            // turn any unexecuted declared step into a limitation. Both the
            // first and the reconcile validate() below read this same trace.
            declaredPlan = declaredPlan,
            completedPlanStepIndices = completedPlanStepIndices.toSet(),
            // OPT-VAL-01-02: the check-coverage gate already decided at
            // submit acceptance; this carries its final verdict into the
            // shared limitations channel.
            playbookCheckGapLimitations = playbookCheckGapLimitations,
            // OPT-VAL-02-03: rule 3's post-validation net — the signals this
            // report's author was shown, checked against the final surviving
            // findings.  `criticAddressedSignalIds` stays at its empty
            // default until OPT-COG-03-03 lands the Critic disposition
            // channel it is reserved for.
            signals = signals,
            // OPT-VAL-03-01: the capability signal gating the one host
            // limitation for a missing `questionAlignment` field — narrated
            // only on runs whose client was offered the (now required)
            // schema, never enforced on plain-text paths (the same
            // `capabilities.structuredOutput` that drives every
            // responseSchema decision and OPT-VAL-02-03's attribution gate).
            structuredOutputAvailable = modelClient.capabilities.structuredOutput,
            // EVL-COVERAGE-02: the coverage receipt computed above, so the
            // trace carries the accepted submission's evidence accounting.
            evidenceCoverage = evidenceCoverage
        )
        val firstValidation = validator.validate(
            report = withProvenance,
            trace = trace
        )
        // The model may omit a successful tool result or even deny that it
        // obtained one. Preserve host-confirmed observations as low-confidence
        // facts; never infer a protocol conclusion from them here.
        val reconciled = reconcileWithLedger(firstValidation.report)
        val validated = run {
            val result = if (reconciled == firstValidation.report) {
                firstValidation
            } else {
                validator.validate(report = reconciled, trace = trace)
            }
            // EVL-COVERAGE-02: the uncited-frame receipt is host-authored
            // prose appended AFTER validation, at loop finalization — the
            // same host-bookkeeping channel as the ledger reconciliation
            // note above. It never rides a model-writable field and never
            // enters a revision request, so the model cannot delete or
            // rewrite it. A clean accounting (every flagged frame cited, or
            // no evidence gathered at all) contributes no line and keeps the
            // report bytes unchanged.
            evidenceCoverage.uncitedFramesLimitation()?.let { limitation ->
                result.copy(
                    report = result.report.copy(
                        limitations = (result.report.limitations + limitation).distinct()
                    )
                )
            } ?: result
        }
        // OPT-EVAL-04-01 citation-quality counters.  Caliber: one submission is
        // one round through this funnel (every report handed to the validator:
        // model finals, merged revisions, delegated child reports, host-
        // synthesized fallbacks).  The denominator counts the citations as
        // submitted; the numerator counts the citation-level rejections the
        // first validate() of the round produced against exactly those
        // citations — the reconcile pass only re-checks survivors plus host-
        // added facts, so counting it would double-submit every survivor.
        citationsSubmitted += withProvenance.findings.sumOf { it.evidence.size }
        citationsRejected += firstValidation.rejections.size
        // OPT-VAL-04-03 polarity double-track counters, same first-validate()
        // caliber as the citation numerator above: declared negatives come from
        // the report as submitted this round, conflicts from the rejections the
        // first validate() raised against exactly those citations (the reconcile
        // pass only re-checks survivors, so counting it would double the round).
        negativePolarityDeclared += withProvenance.findings.count {
            it.polarity == AgentFindingPolarity.Negative
        }
        negativePolarityConflict += firstValidation.rejections.count {
            it.reason == "polarity_claim_conflict"
        }
        // OPT-VAL-03-01 question-alignment rejections, same first-validate()
        // caliber as the two counters above (caliber and double-validate
        // dedupe documented at the [alignmentFailures] declaration).
        alignmentFailures += firstValidation.rejections.count {
            it.reason == ReportCoverageValidator.ALIGNMENT_DANGLING_REFERENCE_REASON
        }
        // Every report the run finishes with has passed through here, so the
        // last update is the final (or most recent) validated report's
        // confidence distribution.
        lastValidatedConfidenceCounts = validated.report.findings
            .groupingBy { it.confidence }
            .eachCount()
        diagnostics?.record(
            type = AgentDiagnosticsEventType.Validation,
            phase = AgentRunPhase.ValidatingReport.name,
            status = "completed",
            attributes = mapOf(
                "findingCount" to validated.report.findings.size.toString(),
                "evidenceCount" to validated.report.findings.sumOf { it.evidence.size }.toString(),
                "completeness" to validated.report.completeness.name
            )
        )
        return validated
    }

    /** Add bounded, host-authored observations for successful but uncited calls. */
    private fun reconcileWithLedger(report: AgentReport): AgentReport {
        if (!containsEvidenceDenial(report)) return report

        val citedToolCallIds = report.findings
            .flatMap { it.evidence }
            .map { it.sourceToolCallId }
            .filter { it.isNotBlank() }
            .toSet()
        val successful = ledger.successful()
        if (successful.isEmpty()) return report
        val uncited = successful.filter { it.toolCallId !in citedToolCallIds }

        val availableSlots = (MAX_REPORT_FINDINGS - report.findings.size).coerceAtLeast(0)
        val hostFindings = uncited
            .take(minOf(MAX_HOST_RECONCILIATION_FINDINGS, availableSlots))
            .mapIndexed { index, entry ->
                val observation = entry.describe()
                AgentFinding(
                    id = "$HOST_CONFIRMED_FINDING_PREFIX${index + 1}",
                    title = "Host-confirmed ${entry.toolName} result",
                    severity = AgentFindingSeverity.Info,
                    confidence = AgentConfidence.Low,
                    conclusion = observation,
                    evidence = listOf(
                        AgentEvidence(
                            type = AgentEvidenceType.Observation,
                            observation = observation,
                            sourceToolCallId = entry.toolCallId
                        )
                    )
                )
            }
        val countText = if (uncited.isEmpty()) {
            "The model's text indicated that evidence was unavailable, but " +
                "the host recorded ${successful.size} successful tool result(s); " +
                "the host-confirmed result(s) remain authoritative for what was returned."
        } else {
            "The model's text indicated that evidence was unavailable, but Host " +
                "verification retained ${uncited.size} successful tool result(s) " +
                "that the model did not cite."
        }
        // The reconciliation note is host bookkeeping, not analysis: it belongs
        // in limitations (and the host-confirmed findings), never spliced into
        // the model-authored, user-facing summary.
        return report.copy(
            findings = report.findings + hostFindings,
            limitations = (report.limitations + countText).distinct()
        )
    }

    /** Detect an explicit claim that the successful tool evidence was absent. */
    private fun containsEvidenceDenial(report: AgentReport): Boolean {
        val text = buildString {
            append(report.summary)
            report.findings.forEach { finding ->
                append(' ')
                append(finding.title)
                append(' ')
                append(finding.conclusion)
            }
            report.limitations.forEach {
                append(' ')
                append(it)
            }
        }.lowercase(Locale.ROOT)
        val markers = listOf(
            "no evidence",
            "no relevant field",
            "no fields",
            "no matching field",
            "no matching data",
            "no data",
            "nothing was obtained",
            "nothing obtained",
            "could not obtain",
            "couldn't obtain",
            "unable to obtain",
            "unable to retrieve",
            "did not obtain",
            "didn't obtain",
            "not obtained",
            "not found",
            "none found",
            "not available",
            "did not return",
            "could not retrieve",
            "未获取",
            "未取得",
            "未获得",
            "没有获取",
            "没有取得",
            "没有获得",
            "未找到",
            "未发现",
            "未返回",
            "无法获取",
            "无法取得",
            "无法读取",
            "没有字段",
            "无相关字段"
        )
        return markers.any(text::contains)
    }

    private fun validated(
        report: AgentReport,
        snapshot: AgentCaptureSnapshot,
        stopReason: AgentStopReason
    ): AgentReport = validationResult(report, snapshot, stopReason).report

    /**
     * Sanitize every model-authored string in a report.
     *
     * Only free prose is touched.  `AgentEvidence.displayFilter` and
     * `frameNumber` are left exactly as they are: they are separately validated
     * against the engine and the ledger, and they are the only two things the UI
     * is allowed to turn into an action, so rewriting them here would break the
     * one navigation path the report is supposed to offer.
     */
    private fun sanitizedProse(report: AgentReport): AgentReport = report.copy(
        summary = AgentPrivacyPolicy.sanitizeReportText(report.summary),
        limitations = report.limitations.map(AgentPrivacyPolicy::sanitizeReportText),
        recommendedNextSteps = report.recommendedNextSteps.map(AgentPrivacyPolicy::sanitizeReportText),
        // OPT-VAL-03-01: the alignment entries' questionPart is model prose
        // too, and rule 4 may quote it back in a rejection limitation, so it
        // passes through the same sanitizer as every other report field.
        questionAlignment = report.questionAlignment.map { entry ->
            entry.copy(questionPart = AgentPrivacyPolicy.sanitizeReportText(entry.questionPart))
        },
        findings = report.findings.map { finding ->
            finding.copy(
                title = AgentPrivacyPolicy.sanitizeReportText(finding.title),
                conclusion = AgentPrivacyPolicy.sanitizeReportText(finding.conclusion),
                alternatives = finding.alternatives.map(AgentPrivacyPolicy::sanitizeReportText),
                recommendations = finding.recommendations.map(AgentPrivacyPolicy::sanitizeReportText),
                evidence = finding.evidence.map { evidence ->
                    evidence.copy(
                        observation = AgentPrivacyPolicy.sanitizeReportText(evidence.observation),
                        observedValue = AgentPrivacyPolicy.sanitizeReportValue(evidence.observedValue)
                    )
                }
            )
        }
    )

    private fun AgentError.forPartialReport(): AgentError =
        if (code == AgentErrorCode.CANCELLED) copy(retryable = true) else this

    // ------------------------------------------------------------- terminals

    private fun complete(
        report: AgentReport,
        snapshot: AgentCaptureSnapshot,
        stopReason: AgentStopReason
    ): AgentRunOutcome {
        val finalReport = validated(report, snapshot, stopReason)
        return completeValidated(finalReport, stopReason)
    }

    private fun completeValidated(
        finalReport: AgentReport,
        stopReason: AgentStopReason
    ): AgentRunOutcome {
        recordRunMetrics()
        if (!controller.finish(AgentRunPhase.Completed)) return cancelledOutcome()
        listener?.onPhaseChanged(AgentRunPhase.Completed)
        emitMessage(AgentConversationRole.Assistant, finalReport.summary, report = finalReport)
        return AgentRunOutcome.Completed(finalReport, stopReason)
    }

    private fun finishValidatedReport(
        report: AgentReport,
        stopReason: AgentStopReason,
        terminalError: AgentError?
    ): AgentRunOutcome = if (terminalError != null) {
        failWithValidatedPartial(terminalError, report)
    } else {
        completeValidated(report, stopReason)
    }

    /**
     * Fold a targeted revision into the report captured before the revision turn.
     *
     * Returns null when no revision is outstanding, or when the model answered
     * with something that carries no usable findings — in that case the caller
     * falls through to the normal report path, and the pre-revision report is
     * still available as a fallback.
     *
     * A revised finding may only *replace* one the host already had: an id the
     * host never issued is dropped, so a revision cannot smuggle in a new
     * finding, and the merged report is re-validated regardless.
     */
    private fun mergedRevision(response: AgentModelResponse.Final): AgentReport? {
        val base = preRevisionReport ?: return null
        val revisedFindings = response.rawJson
            ?.let { AgentJsonCodec.decodeRevisedFindings(it).getOrNull() }
            ?: response.report?.findings
            ?: return null
        val replacements = revisedFindings.associateBy { it.id }
        if (replacements.isEmpty()) return null
        return base.copy(
            findings = base.findings.map { finding ->
                replacements[finding.id] ?: finding
            }
        )
    }

    /**
     * Complete with the pre-revision report when a requested revision could not
     * finish.
     *
     * Returns null when there is nothing to fall back to, so callers keep their
     * existing failure path.  The report is already validated and stamped, so it
     * goes straight to [completeValidated] rather than through validation again.
     */
    private fun completeWithUnrevisedReport(): AgentRunOutcome? {
        val report = preRevisionReport ?: return null
        preRevisionReport = null
        return completeValidated(
            report.copy(limitations = report.limitations + UNREVISED_REPORT_LIMITATION),
            AgentStopReason.ModelFinal
        )
    }

    /**
     * Resolve a revision turn the model answered with tool calls instead of
     * corrected findings.
     *
     * The revision request carries no tool definitions, but a model that has
     * learned to report through submit_report may still answer with it — that
     * call *is* the corrected report, so it is decoded inline (never executed:
     * Revising permits no tool turn) and merged through the normal finalize
     * path.  Any other batch cannot be honoured; the validated pre-revision
     * report is kept rather than ending an improvement attempt as a failure.
     */
    private suspend fun finalizeRevisionToolCalls(
        response: AgentModelResponse.ToolCalls,
        question: String,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode,
        messages: MutableList<AgentModelMessage>
    ): AgentRunOutcome {
        val reportCall = response.calls.firstOrNull {
            it.toolName == SubmitReportTool.NAME && it.arguments.isNotEmpty()
        }
        val submitted = reportCall?.let { call ->
            AgentJsonCodec.decodeReport(AgentResultTruncator.encode(call.arguments))
                .getOrNull()
        }
        if (submitted != null) {
            return finalizeReport(
                response = AgentModelResponse.Final(report = submitted),
                question = question,
                snapshot = snapshot
            ) ?: cancelledOutcome()
        }
        diagnostics?.record(
            type = AgentDiagnosticsEventType.Validation,
            phase = AgentRunPhase.Revising.name,
            status = "revision_tool_calls",
            attributes = mapOf("toolCallCount" to response.calls.size.toString())
        )
        completeWithUnrevisedReport()?.let { return it }
        // Unreachable while a revision is pending; kept as an explicit stop so
        // a future refactor cannot fall through into tool execution.
        return finishAfterStop(
            question = question,
            snapshot = snapshot,
            privacyMode = privacyMode,
            messages = messages,
            stopReason = AgentStopReason.ModelFailure
        )
    }

    private fun fail(
        error: AgentError,
        snapshot: AgentCaptureSnapshot,
        stopReason: AgentStopReason
    ): AgentRunOutcome {
        val partial = validated(
            synthesizedReport("", stopReason, snapshot),
            snapshot,
            stopReason
        )
        recordRunMetrics()
        if (!controller.finish(AgentRunPhase.Failed)) return cancelledOutcome()
        listener?.onPhaseChanged(AgentRunPhase.Failed)
        emitMessage(AgentConversationRole.Error, error.userMessage, error = error)
        return AgentRunOutcome.Failed(error, partial)
    }

    /**
     * End with evidence that was preserved after the terminal model error.
     * This is intentionally distinct from [fail]: the report is still shown,
     * and the UI makes clear that the requested model conclusion was not
     * produced through the report's own partial-result warning and the error
     * card rather than through a conversation bubble.
     */
    private fun failWithPartial(
        error: AgentError,
        report: AgentReport,
        snapshot: AgentCaptureSnapshot,
        stopReason: AgentStopReason
    ): AgentRunOutcome {
        val partial = validated(report, snapshot, stopReason)
        return failWithValidatedPartial(error, partial)
    }

    /** Finish a report that already passed the evidence validator. */
    private fun failWithValidatedPartial(
        error: AgentError,
        partial: AgentReport
    ): AgentRunOutcome {
        recordRunMetrics()
        if (!controller.finish(AgentRunPhase.FailedWithPartialReport)) return cancelledOutcome()
        listener?.onPhaseChanged(AgentRunPhase.FailedWithPartialReport)
        // The run has a report to show, so its failure is a result-level fact
        // the report states for itself — the partial-result warning inside the
        // report card plus the error card beneath it — not a "分析失败" bubble
        // beside the conclusion it did produce.  A run that ends with nothing
        // to show still raises the bubble through [fail].
        return AgentRunOutcome.FailedWithPartialReport(error, partial)
    }

    private fun cancelledOutcome(): AgentRunOutcome {
        recordRunMetrics()
        controller.finish(AgentRunPhase.Cancelled)
        listener?.onPhaseChanged(AgentRunPhase.Cancelled)
        return AgentRunOutcome.Cancelled()
    }

    private fun recordRunMetrics() {
        if (runMetricsRecorded) return
        runMetricsRecorded = true
        diagnostics?.record(
            type = AgentDiagnosticsEventType.RunMetrics,
            phase = controller.phase.name,
            status = "recorded",
            attributes = diagnosticAttributes() + runQualityAttributes()
        )
    }

    /**
     * OPT-EVAL-04-01 run-quality metrics, merged into the RunMetrics event only
     * (an AnalysisBootstrap record happens before any validation, so its
     * values there would be trivially zero).  Rates, counts and a fixed-order
     * histogram — never finding titles, conclusions or capture data.
     */
    private fun runQualityAttributes(): Map<String, String> = mapOf(
        // Rejected citations / submitted citations over every validation round
        // of this run (caliber documented at the counters in
        // [validationResult]); 0 when nothing was ever submitted.
        "citationRejectionRate" to String.format(
            Locale.US,
            "%.4f",
            if (citationsSubmitted == 0) {
                0.0
            } else {
                citationsRejected.toDouble() / citationsSubmitted
            }
        ),
        // Whether the validator's rejections ever bought a revision turn.
        "revisionTriggered" to (if (revisionAttempted) 1 else 0).toString(),
        // Findings per confidence level in the final (or most recent) validated
        // report.  Fixed segment order so a summariser can parse it
        // positionally or by label without guessing.
        "confidenceDistribution" to CONFIDENCE_HISTOGRAM_ORDER.joinToString(separator = ",") { level ->
            "${level.name}:${lastValidatedConfidenceCounts[level] ?: 0}"
        },
        // Findings that declared `Negative` this run and the
        // `polarity_claim_conflict` rejections the OPT-VAL-04-03 cross-check
        // raised, both summed across validation rounds (caliber documented at
        // the counters in [validationResult]).  A rate between them is derived
        // by the summariser so it stays a count here, never a text field.
        "negativePolarityDeclared" to negativePolarityDeclared.toString(),
        "negativePolarityConflict" to negativePolarityConflict.toString(),
        // OPT-VAL-01-02: playbook checks still uncovered when the run's
        // report was accepted, including the unattributable (no plan / no
        // checkId) degradation path.  A count only; the ids live on the
        // `report_submitted` diagnostic.  0 whenever no report was ever
        // accepted on a gated submit, including valve-off runs.
        "planCoverageGaps" to planCoverageGaps.toString(),
        // OPT-VAL-02-03: host-enumerated baseline signals still unaddressed
        // when the run's report was accepted, the limitations-only
        // (undecodable / structured-output-unavailable / heuristic-absent)
        // degradation path included.  A count only; the ids live on the
        // `report_submitted` diagnostic.  0 whenever the rule did not run:
        // valve off, no signals enumerated, or no submit accepted.
        "signalCoverageGaps" to signalCoverageGaps.toString(),
        // OPT-VAL-03-01: question-alignment entries the host removed for a
        // dangling finding reference or an unsupported `addressed` claim,
        // summed across validation rounds (caliber documented at the
        // counters in [validationResult]).  A count only; the entry prose
        // rides the report's limitations, never this event.  0 on valve-off
        // runs, on runs that declared no entries at all (a missing field is
        // a limitation, never a rejection), and on runs whose entries held.
        "alignmentFailures" to alignmentFailures.toString()
    )

    /** Budget check run before each model turn, mirroring the tracker's own. */
    private fun budgetStop(): AgentStopReason? {
        val usage = budget.usage()
        return when {
            usage.steps >= usage.maxSteps -> AgentStopReason.MaxStepsReached
            usage.resultBytes >= usage.maxResultBytes -> AgentStopReason.ContextLimit
            usage.inputTokensExhausted -> AgentStopReason.ContextLimit
            usage.outputTokensExhausted -> AgentStopReason.ContextLimit
            logicalModelRequestCount >= policy.maxModelRequests -> AgentStopReason.MaxDurationReached
            else -> null
        }
    }

    /** Make context compression a one-way ratchet for the remainder of the run. */
    private fun applyContextCompactions(
        messages: MutableList<AgentModelMessage>,
        context: ContextPlan
    ) {
        if (context.compactedByToolCallId.isEmpty()) return
        messages.indices.forEach { index ->
            val message = messages[index]
            if (message.role != AgentModelMessageRole.Tool) return@forEach
            val replacement = message.toolCallId?.let(context.compactedByToolCallId::get) ?: return@forEach
            messages[index] = replacement
        }
    }

    // ---------------------------------------------------------------- events

    private fun moveTo(phase: AgentRunPhase): Boolean {
        val transition = controller.transitionTo(phase)
        // Re-entering the same phase is legal (tool, model, tool, ...) but is
        // not an event: the UI should not see WaitingForModel twice in a row.
        if (transition.moved && transition.previous != phase) listener?.onPhaseChanged(phase)
        if (!transition.moved && !controller.isTerminal) {
            // A refusal from a live phase is an illegal edge — a host bug, not
            // a cancellation.  Callers still stop the run, but the diagnostics
            // log must say why instead of presenting a silent fake cancel.
            diagnostics?.record(
                type = AgentDiagnosticsEventType.PhaseTransition,
                phase = transition.previous.name,
                status = "refused",
                attributes = mapOf(
                    "from" to transition.previous.name,
                    "to" to phase.name
                )
            )
        }
        return transition.moved
    }

    private fun recordStartedActivity(call: AgentToolCall) {
        val activity = AgentToolActivity(
            toolCallId = call.toolCallId,
            toolName = call.toolName.takeIf { it in toolRunner.toolDefinitions().map { definition -> definition.name } }
                ?: "(rejected)",
            status = AgentToolActivityStatus.Running,
            argumentsSummary = argumentsSummary(call.arguments),
            startedAtMillis = clock()
        )
        upsertActivity(activity)
    }

    private fun recordActivity(
        call: AgentToolCall,
        result: AgentToolResult,
        startedAt: Long
    ) {
        val activity = AgentToolActivity(
            toolCallId = call.toolCallId,
            // Never the model's own string: see the note in emitMessage below.
            toolName = result.toolName.ifBlank { "(rejected)" },
            status = if (result.success) {
                AgentToolActivityStatus.Succeeded
            } else {
                AgentToolActivityStatus.Failed
            },
            argumentsSummary = argumentsSummary(call.arguments),
            startedAtMillis = startedAt,
            completedAtMillis = clock(),
            returnedCount = result.returnedCount,
            totalCount = result.totalCount,
            truncated = result.truncated,
            resultBytes = result.resultBytes,
            scope = result.provenance.scope,
            queryMode = result.queryMode ?: result.provenance.queryMode,
            sampled = result.data?.get("sampled") as? Boolean ?: false,
            error = result.error
        )
        upsertActivity(activity)
    }

    private fun upsertActivity(activity: AgentToolActivity) {
        val index = toolActivities.indexOfFirst { it.toolCallId == activity.toolCallId }
        if (index >= 0) toolActivities[index] = activity else toolActivities += activity
        listener?.onToolActivity(activity)
    }

    /**
     * Argument *names* only.  A value can hold a Call-ID, a host name or any
     * other capture-derived identifier, and this string is rendered in the UI
     * and written to logs.
     */
    private fun argumentsSummary(arguments: AgentJsonObject): String =
        arguments.keys.sorted().joinToString()

    private fun emitMessage(
        role: AgentConversationRole,
        content: String,
        toolCallId: String? = null,
        toolName: String? = null,
        untrusted: Boolean = false,
        error: AgentError? = null,
        report: AgentReport? = null
    ) {
        val listener = listener ?: return
        listener.onMessage(
            AgentConversationItem(
                id = "${controller.identity.runId}:message-${messageCounter++}",
                role = role,
                content = content,
                createdAtMillis = clock(),
                toolCallId = toolCallId,
                toolName = toolName,
                untrustedCaptureData = untrusted,
                error = error,
                report = report
            )
        )
    }

    private fun toolContent(result: AgentToolResult): String {
        if (!result.success) return errorContent(result)
        val data = result.data ?: return "{}"
        return AgentResultTruncator.encode(data)
    }

    private fun errorContent(result: AgentToolResult): String {
        val error = result.error ?: return "{\"error\":\"unknown\"}"
        return "{\"error\":\"${error.code.name}\",\"retryable\":${error.retryable}}"
    }

    private fun modelResponseType(response: AgentModelResponse): String = when (response) {
        is AgentModelResponse.ToolCalls -> "tool_calls"
        is AgentModelResponse.Final -> "final"
        is AgentModelResponse.Refusal -> "refusal"
        is AgentModelResponse.Failure -> "failure"
    }

    /** Done is bookkeeping; every other non-empty chunk is generated output. */
    private fun StreamChunk.hasModelOutput(): Boolean = when (this) {
        is StreamChunk.TextDelta -> text.isNotEmpty()
        is StreamChunk.ToolCallStart -> true
        is StreamChunk.ToolCallArgumentDelta -> delta.isNotEmpty()
        is StreamChunk.Done -> false
    }

    private fun requestHash(requestId: String): String =
        Integer.toHexString(requestId.hashCode())

    private fun unexpectedModelError(): AgentError = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The analysis model failed unexpectedly. Diagnostic information was saved locally.",
        retryable = true,
        details = mapOf("boundary" to "model.respond")
    )

    private fun toolSummaryText(result: AgentToolResult): String = buildString {
        append(result.toolName)
        append(": returned ")
        append(result.returnedCount)
        if (result.totalCount > result.returnedCount) {
            append(" of ")
            append(result.totalCount)
        }
        if (result.truncated) append(" (truncated)")
    }

    private companion object {
        const val SYNTHESIZED_FINDING_LIMIT = 8
        const val MAX_HOST_RECONCILIATION_FINDINGS = 8
        const val MAX_REPORT_FINDINGS = 20
        const val MAX_STREAMING_PREVIEW_CHARS = 16_000

        /**
         * Replayed history may occupy at most this fraction of the effective
         * input limit, tighter than the in-run 0.75 compaction trigger, so the
         * first model call of a continuation still has room for new turns.
         */
        const val HISTORY_ENTRY_TRIGGER_RATIO = 0.5

        /** Turns kept verbatim when the entry compaction fires. */
        const val HISTORY_RETAINED_TURNS = AgentConversationCompactor.MAX_RETAINED_TURNS

        const val MAX_INVALID_FILTER_FAILURES_BEFORE_VALIDATION = 2
        /**
         * Granted turns that may fill nothing before the grant is withdrawn.
         *
         * Off-purpose turns cost no quota and no step, so this is what stops a
         * model that has decided to ignore the grant from trading the remaining
         * turn budget for rejections.
         */
        const val MAX_OFF_PURPOSE_GAP_FILL_TURNS = 2
        const val UNREVISED_REPORT_LIMITATION =
            "A follow-up pass to strengthen the evidence for some findings could not " +
                "be completed, so citations that the host could not verify were " +
                "removed rather than corrected."
        const val MAX_DELEGATED_FINDINGS = 8
        const val MAX_DELEGATED_LIMITATIONS = 8
        val REPAIRABLE_FINAL_FORMAT_REASONS = setOf(
            "malformed_final",
            "empty_content",
            "no_json_object",
            "invalid_json",
            "invalid_report_envelope"
        )
        const val BOOTSTRAP_EXPERT_TOOL = "get_expert_info"
        const val BOOTSTRAP_EXPERT_LIMIT = 20
        /**
         * Pinned prefix of the OPT-VAL-02-02 host annotation (design §5.2);
         * the provenance note is the line's trust marking (see
         * [hostSignalsLine]).
         */
        const val HOST_SIGNALS_PREFIX = "host-signals: "
        const val HOST_SIGNALS_PROVENANCE =
            " (host-generated bookkeeping, not capture text)"
        /** Fixed segment order of the RunMetrics `confidenceDistribution`. */
        val CONFIDENCE_HISTOGRAM_ORDER = listOf(
            AgentConfidence.High,
            AgentConfidence.Medium,
            AgentConfidence.Low,
            AgentConfidence.Unknown
        )
        val ORCHESTRATION_TOOLS = setOf(
            DeclareAnalysisPlanTool.NAME,
            DelegateInvestigationTool.NAME,
            SubmitReportTool.NAME
        )
    }
}
