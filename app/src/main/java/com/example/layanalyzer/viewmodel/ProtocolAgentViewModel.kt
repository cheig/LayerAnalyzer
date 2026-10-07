// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.layanalyzer.ai.agent.AgentConsent
import com.example.layanalyzer.ai.agent.AgentRunIdentity
import com.example.layanalyzer.ai.agent.AgentRunListener
import com.example.layanalyzer.ai.agent.AgentRunSnapshot
import com.example.layanalyzer.ai.background.AgentRunCoordinator
import com.example.layanalyzer.ai.background.AgentRunRequest
import com.example.layanalyzer.ai.agent.AgentRunOutcome
import com.example.layanalyzer.ai.agent.AgentStopReason
import com.example.layanalyzer.ai.agent.AgentProviderConfig
import com.example.layanalyzer.ai.agent.AgentSettings
import com.example.layanalyzer.ai.agent.AgentSettingsStore
import com.example.layanalyzer.ai.agent.DefaultAgentSettingsStore
import com.example.layanalyzer.ai.agent.MutableAgentSettingsStore
import com.example.layanalyzer.ai.agent.ProtocolAnalysisAgent
import com.example.layanalyzer.ai.agent.SecretStore
import com.example.layanalyzer.ai.agent.AgentPrompt
import com.example.layanalyzer.ai.agent.selectableMetadataMode
import com.example.layanalyzer.ai.audit.AgentDiagnosticsRecorder
import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.ai.cache.AgentToolCache
import com.example.layanalyzer.ai.client.GatewayAccountRepository
import com.example.layanalyzer.ai.client.GatewayAccountUiState
import com.example.layanalyzer.ai.client.ProviderModelFetcher
import com.example.layanalyzer.ai.client.ProviderModelFetchResult
import com.example.layanalyzer.ai.client.ProviderModelFetchFailure
import com.example.layanalyzer.ai.privacy.AgentRequestPreviewBuilder
import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.AgentPlaybookStore
import com.example.layanalyzer.ai.playbook.PlaybookUsageStore
import com.example.layanalyzer.ai.playbook.sortedByUsage
import com.example.layanalyzer.ai.playbook.ScenarioPackageDescription
import com.example.layanalyzer.ai.playbook.ScenarioOrigin
import com.example.layanalyzer.ai.playbook.ScenarioQuarantineEvent
import com.example.layanalyzer.ai.playbook.ScenarioQuarantineEventChannel
import com.example.layanalyzer.ai.playbook.ScenarioValidationError
import com.example.layanalyzer.ai.playbook.nextQuarantineCodes
import com.example.layanalyzer.ai.playbook.UserScenarioStore
import com.example.layanalyzer.ai.playbook.VersionedScenarioPackageStore
import com.example.layanalyzer.data.AgentSessionStore
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.CaptureSessionState
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRound
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentAnalysisMode
import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentConsentPrompt
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentLocalDataCategory
import com.example.layanalyzer.model.AgentLocalDataUsage
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentPriorContext
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentRequestPreview
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentSavedSession
import com.example.layanalyzer.model.AgentSavedSessionSummary
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AgentToolActivityStatus
import com.example.layanalyzer.model.AnalysisJobPhase
import com.example.layanalyzer.model.AnalysisJobState
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.ProtocolAgentUiState
import com.example.layanalyzer.model.resolveDisplayFilter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield

/**
 * The in-memory draft behind the scenario editor.
 *
 * Purely transient state: nothing persists until
 * [ProtocolAgentViewModel.saveScenario] hands the draft to the user scenario
 * layer, and dismissing the editor discards it.  The draft is also the *only*
 * home of the editing input (OPT-DRAFT-01): the editor is a controlled
 * component that renders [playbook] and routes every field change back
 * through [ProtocolAgentViewModel.updateDraft], so an activity recreation —
 * rotation included — recollects the flow and finds the typed content still
 * there instead of reseeding a stale snapshot.
 *
 * [validationErrors] maps a field path (for example `title` or
 * `checks[2].description`) to the machine-readable reason that field was
 * rejected, exactly as [UserScenarioStore.save] reported it (stable code +
 * args, no prose), so the editor can localize the reasons and highlight the
 * offending fields inline.  Because [playbook] now moves with every
 * keystroke, the inline errors cannot compare against it to decide whether
 * a field still holds the rejected value; [validatedPlaybook] is the frozen
 * snapshot of exactly what the store saw at the last rejection, which is
 * what the editor compares against instead.
 */
data class AgentScenarioDraft(
    /** The editable scenario content; its id is store-owned once saved. */
    val playbook: AgentPlaybook,
    /** True while authoring a brand-new scenario, false while editing one. */
    val isNew: Boolean,
    /** Field path → rejection reason code from the last save attempt. */
    val validationErrors: Map<String, ScenarioValidationError> = emptyMap(),
    /**
     * True when the editor must render the playbook read-only ("View
     * details").  Only [ProtocolAgentViewModel.startViewScenario] sets it;
     * the authoring events always produce an editable draft, so the editor
     * keys its save affordances off this flag alone.
     */
    val readOnly: Boolean = false,
    /**
     * The generation this ViewModel assigned when the draft was opened
     * (OPT-DRAFT-01).  Every open event mints a strictly newer epoch and
     * [ProtocolAgentViewModel.updateDraft] pins the epoch through edits, so
     * an in-flight save compares epochs — not object identity — to decide
     * whether the editor it saved from is still the one on screen: with a
     * controlled draft every keystroke copies the draft, making the old
     * `=== draft` reference guard meaningless.
     */
    val epoch: Long = 0L,
    /**
     * The exact playbook [UserScenarioStore.save] rejected alongside the
     * current [validationErrors], or null before a rejection has ever been
     * written back.  The editor shows a store error on a field only while
     * the live value still equals the value in this snapshot.
     */
    val validatedPlaybook: AgentPlaybook? = null
)

/**
 * Owns one protocol-analysis Agent session for the UI.
 *
 * This deliberately lives beside [PacketListViewModel] rather than inside it:
 * the Agent has its own generation, its own cancellation chain and its own
 * lifetime, and folding it into the list ViewModel would let a paging
 * invalidation and an Agent run cancel each other by accident.
 *
 * The UI never touches [ProtocolAnalysisAgent], a snapshot or a model client;
 * it reads [uiState] and calls the event functions here.  Everything published
 * has already been redacted by AI-06 — no hidden model reasoning and no raw
 * request bodies reach this class, so nothing here has to strip them.
 */
class ProtocolAgentViewModel(
    private val agent: ProtocolAnalysisAgent,
    private val coordinator: CaptureSessionCoordinator,
    private val settings: AgentSettingsStore = DefaultAgentSettingsStore(),
    private val secretStore: SecretStore? = null,
    private val gatewayAccountRepository: GatewayAccountRepository? = null,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val runCoordinator: AgentRunCoordinator? = null,
    externalScope: CoroutineScope? = null,
    /** AI-24 stores.  All three are optional so JVM tests stay filesystem-free. */
    private val sessionStore: AgentSessionStore? = null,
    private val toolCache: AgentToolCache? = null,
    private val diagnostics: AgentDiagnosticsRecorder? = null,
    /** Phase 4: durable run checkpoint store. */
    private val jobStore: com.example.layanalyzer.data.AnalysisJobStore? = null,
    /** AI-26 scenario rule package; null in JVM tests that do not touch assets. */
    private val scenarioPackageStore: VersionedScenarioPackageStore? = null,
    /** The same selector instance used by ProtocolAnalysisAgent. */
    private val playbookStore: AgentPlaybookStore? = null,
    /** Scenario pick counts that order the chips; null keeps package order. */
    private val playbookUsageStore: PlaybookUsageStore? = null,
    /** Fetches the model catalog a BYOK provider advertises via `/models`. */
    private val providerModelFetcher: ProviderModelFetcher? = null,
    /**
     * The user scenario layer backing the management events below
     * ([startNewScenario], [startEditScenario], [saveScenario],
     * [copyScenario], [deleteScenario]).  Null means the layer is not wired
     * yet (the factory passes nothing), and every management event is then a
     * no-op: the editor never opens and nothing deletes or copies.  Must be
     * the *same instance* the [playbookStore] was built with —
     * [AgentPlaybookStore.reload] only folds the user layer back into the
     * merged chip list when the store itself holds it.
     */
    private val userScenarios: UserScenarioStore? = null,
    /**
     * OPT-QNT-01: the Application-scoped quarantine notice channel wired to
     * the user scenario layer's `onQuarantine` sink.  Collected as soon as
     * this ViewModel exists, which is what makes the notice survive the
     * assembly-time `load()` that can quarantine a corrupt file before any
     * ViewModel was ever constructed (the channel buffers until consumed).
     * Null in JVM tests that do not wire the channel.
     */
    private val quarantineEvents: ScenarioQuarantineEventChannel? = null
) : ViewModel() {

    private val runScope: CoroutineScope = externalScope ?: viewModelScope

    /** In-flight saved-list rebuild; a newer refresh supersedes an older one. */
    private var savedSessionsRefreshJob: Job? = null

    /** In-flight local-data usage rebuild; a newer refresh supersedes an older one. */
    private var localDataUsageRefreshJob: Job? = null

    /** In-flight interrupted-banner rebuild; a newer refresh supersedes an older one. */
    private var interruptedJobRefreshJob: Job? = null

    private val _uiState = MutableStateFlow(
        ProtocolAgentUiState(privacyMode = settings.settings.privacyMode)
    )
    val uiState: StateFlow<ProtocolAgentUiState> = _uiState.asStateFlow()

    private val _configuration = MutableStateFlow(settings.settings)
    val configuration: StateFlow<com.example.layanalyzer.ai.agent.AgentSettings> =
        _configuration.asStateFlow()

    private val _gatewayAccount = MutableStateFlow(
        gatewayAccountRepository?.state?.value ?: GatewayAccountUiState()
    )
    val gatewayAccount: StateFlow<GatewayAccountUiState> = _gatewayAccount.asStateFlow()

    private val _consentPrompt = MutableStateFlow<AgentConsentPrompt?>(null)
    val consentPrompt: StateFlow<AgentConsentPrompt?> = _consentPrompt.asStateFlow()

    private val _analysisJob = MutableStateFlow(AnalysisJobState(phase = AnalysisJobPhase.Completed))
    val analysisJob: StateFlow<AnalysisJobState> = _analysisJob.asStateFlow()

    /** The current run's hash-only audit record. It is not persisted locally. */
    private val _lastRunRecord = MutableStateFlow<AgentRunRecord?>(null)
    val lastRunRecord: StateFlow<AgentRunRecord?> = _lastRunRecord.asStateFlow()

    /** Automatically saved analyses on disk, newest first. */
    private val _savedSessions = MutableStateFlow<List<AgentSavedSessionSummary>>(emptyList())
    val savedSessions: StateFlow<List<AgentSavedSessionSummary>> = _savedSessions.asStateFlow()

    /**
     * Conversations whose saved file is currently being deleted.
     *
     * Exposed so the UI can disable the row's delete button: the optimistic
     * removal below normally hides the row instantly, but a concurrent history
     * refresh can bring it back on screen for the few hundred milliseconds the
     * file IO still needs, and a second tap then must be refused.
     */
    private val _deletingSavedSessionIds = MutableStateFlow<Set<String>>(emptySet())
    val deletingSavedSessionIds: StateFlow<Set<String>> =
        _deletingSavedSessionIds.asStateFlow()

    /**
     * A saved report opened for viewing.
     *
     * Held apart from [uiState] so restoring one never looks like a finished
     * run: the transcript, the tool activity and the retry affordance all
     * belong to a live run, and a report read back from disk has none of them.
     */
    private val _restoredSession = MutableStateFlow<AgentSavedSession?>(null)
    val restoredSession: StateFlow<AgentSavedSession?> = _restoredSession.asStateFlow()

    /**
     * An interrupted run from a previous process that matches the capture
     * currently open, visible above the composer.
     *
     * Null when there is no interrupted job, when the job's capture no longer
     * matches, or when the user dismissed it.
     */
    private val _interruptedJob =
        MutableStateFlow<com.example.layanalyzer.data.AnalysisJobCheckpoint?>(null)
    val interruptedJob: StateFlow<com.example.layanalyzer.data.AnalysisJobCheckpoint?> =
        _interruptedJob.asStateFlow()

    /** Disk usage and last-cleanup time shown by the settings screen. */
    private val _localDataUsage = MutableStateFlow(AgentLocalDataUsage())
    val localDataUsage: StateFlow<AgentLocalDataUsage> = _localDataUsage.asStateFlow()

    /** AI-26: the active scenario rule package, for the user-visible provenance card. */
    private val _scenarioPackage = MutableStateFlow(
        scenarioPackageStore?.let { runCatching { it.describe() }.getOrNull() }
    )
    val scenarioPackage: StateFlow<ScenarioPackageDescription?> = _scenarioPackage.asStateFlow()

    /**
     * The package order for the trusted scenario choices.
     *
     * Kept apart from [playbooks] so re-sorting always starts from the original
     * sequence; sorting an already-sorted list would erode the curated order the
     * package declared for scenarios the user has never picked.
     */
    private var basePlaybooks: List<AgentPlaybook> = loadActivePlaybooks()

    /**
     * The same choices, ordered so the ones this user reaches for come first.
     *
     * Only the *order* depends on usage. The list itself still comes from the
     * verified package, and which playbook a question runs under is decided by
     * intent matching, not by this count.
     */
    private val _playbooks = MutableStateFlow(orderedPlaybooks(basePlaybooks))
    val playbooks: StateFlow<List<AgentPlaybook>> = _playbooks.asStateFlow()

    /**
     * The scenario editor's draft, or null while no editor is open.
     *
     * Kept apart from [uiState] because it is a pure editing session: nothing
     * here affects a run, and cancelling the editor ([dismissEditingScenario])
     * must leave no trace — a draft is memory-only until a successful save.
     *
     * The draft is also the single source of the editor's *input*
     * (OPT-DRAFT-01): the editor renders [AgentScenarioDraft.playbook] and
     * sends every field change back through [updateDraft], so an activity
     * recreation restores the half-typed scenario by recollecting this flow
     * rather than reseeding a composable-local copy.
     */
    private val _editingScenario = MutableStateFlow<AgentScenarioDraft?>(null)
    val editingScenario: StateFlow<AgentScenarioDraft?> = _editingScenario.asStateFlow()

    /**
     * The epoch most recently handed out to a draft (OPT-DRAFT-01).
     *
     * Only the `start*Scenario` open events advance it, and those are UI
     * entry points running on the main thread — the same thread the save
     * callback writes back on — so a plain counter is enough; no atomics.
     */
    private var lastScenarioDraftEpoch = 0L

    /**
     * Scenarios whose delete is currently in flight.
     *
     * Exposed so the UI can disable the row's delete button, mirroring
     * [deletingSavedSessionIds]: the optimistic removal below normally hides
     * the chip instantly, but the reload at the end of the delete can bring
     * the entry back on screen for the instant the IO still needs, and a
     * second tap then must be refused.
     */
    private val _deletingScenarioIds = MutableStateFlow<Set<String>>(emptySet())
    val deletingScenarioIds: StateFlow<Set<String>> =
        _deletingScenarioIds.asStateFlow()

    /**
     * Bumped by exactly one per *successful* scenario save (SRE-EDITOR-06).
     *
     * A monotonic counter rather than a one-shot flow or a SharedFlow: the
     * UI reads it as plain state in `collectAsState`, a recomposition can
     * never lose an event it has not observed yet, and a JVM test awaits a
     * concrete count.  Field rejections and failed writes leave it alone —
     * those keep the editor open and report through the draft's errors or a
     * transient error instead.
     */
    private val _scenarioSaveCompleted = MutableStateFlow(0)
    val scenarioSaveCompleted: StateFlow<Int> = _scenarioSaveCompleted.asStateFlow()

    /**
     * True while a scenario save is in flight (OPT-SAVE-01).
     *
     * The guard [saveScenario] refuses repeat taps with: without it, a Save
     * clicked several times before the first IO window closes runs several
     * complete saves — the store version jumps once per tap and
     * [scenarioSaveCompleted] bumps several times, so the user gets several
     * "Scenario saved" notices for one edit.  The flag is set synchronously
     * on the calling (main) thread before the coroutine is launched, so a
     * second tap cannot slip through while the first is still only queued,
     * and it is cleared in a `finally`, so a failed write releases it exactly
     * like a successful one.  Exposed so the editor can disable its Save
     * button for the duration; the refusal in the ViewModel stays the
     * authority, the disabled button is only the visible affordance.
     */
    private val _savingScenario = MutableStateFlow(false)
    val savingScenario: StateFlow<Boolean> = _savingScenario.asStateFlow()

    /**
     * OPT-QNT-01: the quarantine notices to surface, as the stable reason
     * codes collected from [quarantineEvents] — reason codes only, never a
     * file name or playbook content.
     *
     * The list only ever grows with *distinct* codes
     * ([nextQuarantineCodes]): the store already reports one quarantine once
     * per unreadable file, and this consumer-side dedupe is what pins "one
     * quarantine, one notice" even if the same code is published again.  The
     * host page raises one snackbar per newly appended code and remembers how
     * many it has announced, so a rotation never replays the notice.
     */
    private val _scenarioQuarantineCodes = MutableStateFlow<List<String>>(emptyList())
    val scenarioQuarantineCodes: StateFlow<List<String>> = _scenarioQuarantineCodes.asStateFlow()

    /**
     * The host tool whitelist the scenario editor's Initial tools chips offer.
     *
     * Sourced from the same store the save boundary validates against
     * ([AgentPlaybookStore.availableToolNames]), so every chip the editor shows
     * is exactly a tool [UserScenarioStore.save] accepts.  Empty when there is
     * no store (JVM tests without assets), which the editor renders as an empty
     * chip row rather than a fake whitelist.
     */
    val scenarioToolWhitelist: Set<String>
        get() = playbookStore?.availableToolNames.orEmpty()

    /** Argument hashes the cache answered during the last run. */
    private var lastRunCacheHits: Set<String> = emptySet()

    private var lastClearedAtMillis: Long? = null

    /** The one in-flight run; a second submit is refused rather than queued. */
    private var activeJob: Job? = null

    /** Bumped per run so a late listener callback cannot write stale state. */
    private var runGeneration: Long = 0L

    /** Retained so [retry] can resend the same question under a new run. */
    private var lastQuestion: String? = null
    private var lastScope: AnalysisScope = AnalysisScope.CompleteFile
    /** The question that produced the report currently on screen. */
    private var reportQuestion: String? = null

    /**
     * The committed model transcript of this conversation's finished rounds,
     * sanitised for replay.  A follow-up sends it as the new run's history so
     * the model sees what earlier rounds established, and it is what a saved
     * session stores for restoration.  Only a run that reached a terminal
     * outcome with a report updates this; failed or cancelled attempts are not
     * committed, mirroring how their messages leave the visible transcript.
     */
    private var committedTranscript: List<AgentModelMessage> = emptyList()

    /** The capture this conversation belongs to; follow-ups may not cross it. */
    private var conversationFingerprint: String? = null
    private var conversationSessionGeneration: Long = 0L
    private var conversationFilter: String = ""
    private var conversationPrivacyMode: AgentPrivacyMode? = null
    private var pendingConsentRun: PendingConsentRun? = null

    /**
     * The identity of the conversation currently on screen.  A new question
     * mints a fresh [AgentRunIdentity]; a follow-up or retry keeps
     * [conversationId] and only advances [latestRunId], so one conversation
     * always maps to exactly one saved-history file.
     */
    private var conversationId: String? = null
    private var latestRunId: String? = null
    private val conversationRunIds = mutableListOf<String>()
    private var conversationCreatedAtMillis: Long = 0L

    init {
        observeSession()
        observeSettings()
        observeGatewayAccount()
        observeRunCoordinator()
        // OPT-QNT-01: subscribe before anything else can delay it, because the
        // quarantine that fired while the Application object graph was built is
        // already buffered on the channel and this is what drains it.
        observeScenarioQuarantine()
        // Startup refreshes are asynchronous: with a large saved history the
        // first screen must not wait on a directory-wide decode.
        refreshSavedSessions()
        refreshLocalDataUsage()
        refreshInterruptedJob()
    }

    // ------------------------------------------------------------- user events

    /**
     * Start a new analysis.
     *
     * A run already in progress is *not* silently replaced: the user is told to
     * cancel first, because cancelling for them would throw away a partially
     * gathered trajectory they may still want.
     */
    fun submitQuestion(
        question: String,
        scope: AnalysisScope = AnalysisScope.CompleteFile,
        /**
         * Explicit playbook id from the suggestion-chip path.  Null — every
         * free-text entry point — keeps the question-text matching.
         */
        playbookId: String? = null,
        /**
         * EVL-CONTEXT-03: display filter this run is framed with instead of
         * the session's applied one (see [resolveDisplayFilter]).  Passed by
         * the evidence workflow's "analyze with this evidence" entry, which
         * compiles the filter via EvidenceFrameFilter and must already have
         * validated it through the shared capture-session coordinator — the
         * agent runs no second validation.  The override applies to *this*
         * submission only: follow-ups, retries and resumes deliberately do
         * not carry it and stay framed against the session's applied filter.
         */
        displayFilterOverride: String? = null,
        /**
         * EVL-CONTEXT-04: number of frames in the evidence set the override
         * was compiled from, recorded at submission time so the report
         * provenance can expose it ("Analysis scope: evidence set (N
         * frames)").  Null on every path without an override — no count is
         * ever invented.
         */
        evidenceFrameCount: Int? = null
    ) {
        val trimmed = question.trim()
        if (trimmed.isEmpty()) {
            publishTransient(blankQuestionError())
            return
        }
        if (isRunning()) {
            publishTransient(concurrentRunError())
            return
        }
        val session = coordinator.state.value
        if (!session.hasSession) {
            publishTransient(noCaptureError())
            return
        }
        if (session.fileFingerprint.isBlank()) {
            publishTransient(fingerprintPendingError())
            return
        }

        // A question about a different capture starts a fresh conversation: the
        // earlier transcript describes packets that are no longer open.
        if (conversationFingerprint != null && conversationFingerprint != session.fileFingerprint) {
            resetConversation()
        }

        val privacyMode = settings.settings.privacyMode.selectableMetadataMode()
        if (requestConsentIfNeeded(
                trimmed, scope, session, false, privacyMode, playbookId,
                displayFilterOverride, evidenceFrameCount
            )
        ) {
            return
        }
        startRun(
            trimmed, scope, session,
            appendQuestion = false,
            privacyMode = privacyMode,
            identity = AgentRunIdentity.newConversation(),
            playbookId = playbookId,
            displayFilterOverride = displayFilterOverride,
            evidenceFrameCount = evidenceFrameCount
        )
    }

    /**
     * Ask a follow-up against the same capture, keeping the visible transcript.
     *
     * The Agent still creates a *new* snapshot for the follow-up, so a filter the
     * user changed in between is picked up rather than silently reused; when that
     * changes the scope the run was framed against, the UI is told via
     * [ProtocolAgentUiState.scopeChanged].
     */
    fun continueConversation(question: String) {
        val trimmed = question.trim()
        if (trimmed.isEmpty()) {
            publishTransient(blankQuestionError())
            return
        }
        if (isRunning()) {
            publishTransient(concurrentRunError())
            return
        }
        val session = coordinator.state.value
        if (!session.hasSession) {
            publishTransient(noCaptureError())
            return
        }
        // Follow-up is only meaningful while the same capture is open; anything
        // else would attach new answers to a transcript about another file.
        val fingerprint = conversationFingerprint
        if (fingerprint != null && fingerprint != session.fileFingerprint) {
            publishTransient(sessionChangedError())
            return
        }

        val privacyMode = conversationPrivacyMode
            ?: settings.settings.privacyMode.selectableMetadataMode()
        if (requestConsentIfNeeded(trimmed, lastScope, session, true, privacyMode)) return
        startRun(
            trimmed, lastScope, session,
            appendQuestion = true,
            privacyMode = privacyMode,
            identity = followUpIdentity(),
            history = committedTranscript
        )
    }

    /** Abandon the transcript and report; the next question starts clean. */
    fun startNewConversation() {
        cancel()
        resetConversation()
    }

    /**
     * Re-run the previous question.
     *
     * A retry is another attempt at the *same* conversation: it keeps the
     * conversationId and mints only a new runId, so history keeps one record
     * instead of forking a second file for the same question.  It deliberately
     * does not route through [submitQuestion], which would mint a fresh
     * conversation and, when the capture changed, reset the very conversation
     * being retried.
     */
    fun retry() {
        val question = lastQuestion
        if (question == null) {
            publishTransient(nothingToRetryError())
            return
        }
        if (isRunning()) {
            publishTransient(concurrentRunError())
            return
        }
        val session = coordinator.state.value
        if (!session.hasSession) {
            publishTransient(noCaptureError())
            return
        }
        if (session.fileFingerprint.isBlank()) {
            publishTransient(fingerprintPendingError())
            return
        }
        // A retry of a question about a capture that is no longer open would
        // attach a new run to a transcript about another file.
        val fingerprint = conversationFingerprint
        if (fingerprint != null && fingerprint != session.fileFingerprint) {
            publishTransient(sessionChangedError())
            return
        }
        // A retry answers the same question again, so the failed attempt's
        // messages are dropped rather than shown above a second answer.  The
        // report it produced still moves to the archive first: an earlier
        // round's conclusion survives the retry even though its transcript is
        // rebuilt.
        val stateBeforeReset = _uiState.value
        val carriedPastReports = archivePriorRound(stateBeforeReset, appendQuestion = true)
        resetTranscriptForRetry()
        if (carriedPastReports.isNotEmpty()) {
            _uiState.value = _uiState.value.copy(pastReports = carriedPastReports)
        }
        val privacyMode = conversationPrivacyMode
            ?: settings.settings.privacyMode.selectableMetadataMode()
        if (requestConsentIfNeeded(question, lastScope, session, true, privacyMode)) return
        startRun(
            question, lastScope, session,
            appendQuestion = true,
            privacyMode = privacyMode,
            identity = followUpIdentity(),
            history = committedTranscript
        )
    }

    /**
     * Cancel the active run.
     *
     * With a [runCoordinator] the run is Application-owned, so this forwards to
     * it; the coordinator cancels the agent before the coroutine so the
     * controller latches Cancelled and the terminal state is published from the
     * cancelling thread, not from a coroutine that may never resume.
     */
    fun cancel() {
        val coordinator = runCoordinator
        if (coordinator != null) {
            if (!coordinator.isRunning) return
            coordinator.cancel()
            return
        }
        if (!isRunning()) return
        runGeneration += 1
        agent.cancel()
        activeJob?.cancel()
        activeJob = null
        publishCancelled()
    }

    fun clearTransientError() {
        _uiState.value = _uiState.value.copy(transientError = null, scopeChanged = false)
    }

    /** Accept the exact versioned policy shown in [consentPrompt]. */
    fun acceptConsent() {
        val pending = pendingConsentRun ?: return
        (settings as? MutableAgentSettingsStore)?.acceptCurrentConsent()
        _consentPrompt.value = null
        pendingConsentRun = null
        val session = coordinator.state.value
        if (!session.hasSession || session.fileFingerprint.isBlank()) {
            publishTransient(noCaptureError())
            return
        }
        startRun(
            pending.question,
            pending.scope,
            session,
            pending.appendQuestion,
            pending.privacyMode,
            pending.identity,
            history = committedTranscript,
            playbookId = pending.playbookId,
            displayFilterOverride = pending.displayFilterOverride
        )
    }

    fun declineConsent() {
        pendingConsentRun = null
        _consentPrompt.value = null
    }

    /** Update idle-session configuration; an active run keeps its model snapshot. */
    fun updateSettings(next: AgentSettings) {
        val previous = _configuration.value
        val requested = next.normalized()
        val normalized = conversationPrivacyMode?.let { lockedMode ->
            requested.copy(privacyMode = lockedMode)
        } ?: requested.copy(privacyMode = requested.privacyMode.selectableMetadataMode())
        val changedModelOrPolicy = previous.providerId != normalized.providerId ||
            previous.modelId != normalized.modelId ||
            previous.gatewayBaseUrl != normalized.gatewayBaseUrl ||
            previous.activeProvider?.apiType != normalized.activeProvider?.apiType ||
            previous.privacyMode != normalized.privacyMode
        val persisted = if (changedModelOrPolicy) {
            normalized.copy(firstUseConsentVersion = null)
        } else {
            normalized
        }
        val persistedNormalized = persisted.normalized()
        (settings as? MutableAgentSettingsStore)?.update(persistedNormalized)
            ?: publishTransient(settingsReadOnlyError())
        if (settings.settingsFlow == null) _configuration.value = persistedNormalized
        if (changedModelOrPolicy) {
            pendingConsentRun = null
            _consentPrompt.value = null
        }
        _uiState.value = _uiState.value.copy(privacyMode = persistedNormalized.privacyMode)
    }

    /** Update only the per-conversation data mode without overwriting newer model settings. */
    fun updatePrivacyMode(mode: AgentPrivacyMode) {
        if (conversationPrivacyMode != null) return
        updateSettings(
            settings.settings.copy(
                privacyMode = mode.selectableMetadataMode()
            )
        )
    }

    /** Select a configured provider/model without opening a configuration form. */
    fun selectModel(providerId: String, modelId: String) {
        val current = settings.settings.normalized()
        val provider = current.providers.firstOrNull { it.id == providerId }
        val model = provider?.models?.firstOrNull { it.id == modelId }
        if (provider == null || model == null) {
            publishTransient(
                AgentError(
                    code = AgentErrorCode.MODEL_UNAVAILABLE,
                    userMessage = "The selected model is not configured.",
                    retryable = false,
                    details = mapOf("reason" to "unknown_configured_model")
                )
            )
            return
        }
        updateSettings(
            current.copy(
                providerId = provider.id,
                modelId = model.id,
                gatewayBaseUrl = provider.baseUrl,
                byokConfigured = provider.apiKeyConfigured
            )
        )
    }

    fun saveByokSecret(secret: String) {
        saveByokSecret(settings.settings.normalized().providerId, secret)
    }

    fun saveByokSecret(providerId: String, secret: String) {
        val current = settings.settings.normalized()
        val provider = current.providers.firstOrNull { it.id == providerId }
        if (provider == null) {
            publishTransient(settingsReadOnlyError())
            return
        }
        saveByokSecret(provider, secret)
    }

    /** Saves a key for an existing or newly drafted provider. */
    fun saveByokSecret(provider: AgentProviderConfig, secret: String) {
        val store = secretStore
        if (store == null) {
            publishTransient(settingsReadOnlyError())
            return
        }
        val current = settings.settings.normalized()
        val normalizedProvider = provider.normalized()
        val updatedProviders = if (current.providers.any { it.id == normalizedProvider.id }) {
            current.providers.map {
                if (it.id == normalizedProvider.id) normalizedProvider else it
            }
        } else {
            current.providers + normalizedProvider
        }
        if (store.forAlias(normalizedProvider.secretKeyAlias).save(secret).isSuccess) {
            updateSettings(
                current.copy(
                    providers = updatedProviders.map {
                        if (it.id == normalizedProvider.id) {
                            it.copy(apiKeyConfigured = true)
                        } else {
                            it
                        }
                    },
                    byokConfigured = if (current.providerId == normalizedProvider.id) {
                        true
                    } else {
                        current.byokConfigured
                    }
                )
            )
        } else {
            publishTransient(secretSaveError())
        }
    }

    fun clearByokSecret() {
        clearByokSecret(settings.settings.normalized().providerId)
    }

    fun clearByokSecret(providerId: String) {
        val current = settings.settings.normalized()
        val provider = current.providers.firstOrNull { it.id == providerId } ?: return
        secretStore?.forAlias(provider.secretKeyAlias)?.clear()
        val updatedProviders = current.providers.map {
            if (it.id == providerId) it.copy(apiKeyConfigured = false) else it
        }
        updateSettings(
            current.copy(
                providers = updatedProviders,
                byokConfigured = if (current.providerId == providerId) false else current.byokConfigured
            )
        )
    }

    /**
     * List the models a BYOK provider advertises via its `/models` endpoint.
     *
     * [provider] is the editor draft: its baseUrl and apiType decide the URL and
     * auth scheme. [typedApiKey] is the key the user just entered; when blank,
     * the stored key for this provider is used instead.
     */
    suspend fun fetchProviderModels(
        provider: AgentProviderConfig,
        typedApiKey: String
    ): ProviderModelFetchResult {
        val fetcher = providerModelFetcher ?: return ProviderModelFetchResult.Failure(
            ProviderModelFetchFailure.Network
        )
        val normalized = provider.normalized()
        val key = typedApiKey.trim().ifBlank {
            secretStore?.forAlias(normalized.secretKeyAlias)?.read().orEmpty()
        }
        return fetcher.fetchModels(normalized.baseUrl, normalized.apiType, key)
    }

    /** Refresh the account-safe model and quota view shown by the Agent page. */
    fun refreshGatewayAccount() {
        val repository = gatewayAccountRepository ?: return
        val current = settings.settings
        if (!current.isCloudConfigured ||
            current.privacyMode == AgentPrivacyMode.LocalOnly ||
            current.byokConfigured
        ) {
            repository.clear()
            return
        }
        runScope.launch { repository.refresh() }
    }

    fun previewFor(question: String, scope: AnalysisScope = AnalysisScope.CompleteFile): AgentRequestPreview? {
        val session = coordinator.state.value
        if (!session.hasSession || session.fileFingerprint.isBlank() || question.isBlank()) return null
        return buildPreview(question.trim(), scope, session, settings.settings.privacyMode)
    }

    // ------------------------------------------------------------ persistence

    /** Reload the saved list, filtered to the capture that is open. */
    fun refreshSavedSessions() {
        val store = sessionStore ?: return
        val fingerprint = coordinator.state.value.fileFingerprint
        // The store decodes every saved file to summarise it; with a large
        // history that is multi-hundred-millisecond disk+JSON work, which
        // belongs on IO — not on the main thread the caller came from.
        savedSessionsRefreshJob?.cancel()
        savedSessionsRefreshJob = runScope.launch { refreshSavedSessionsNow(fingerprint) }
    }

    /**
     * Refresh the saved list inside the caller's coroutine.
     *
     * [refreshSavedSessions] fires this on [runScope]; callers that need the
     * list published before they proceed (the automatic save, the delete path)
     * call this directly so the ordering stays deterministic.  The result for
     * a capture that changed mid-refresh is dropped: a capture switch must not
     * publish a list for the previous capture.
     */
    private suspend fun refreshSavedSessionsNow(fingerprint: String) {
        val store = sessionStore ?: return
        val sessions = withContext(Dispatchers.IO) {
            runCatching { store.listForCapture(fingerprint) }.getOrDefault(emptyList())
        }
        if (coordinator.state.value.fileFingerprint == fingerprint) {
            _savedSessions.value = sessions
        }
    }

    /**
     * Open a saved analysis.
     *
     * A session saved with its transcript is put back on screen as a live
     * conversation, so the user returns to where they left off and can ask a
     * follow-up.  Anything older — a pre-schema-3 file that holds only a report
     * — falls back to the read-only dialog, since there is no conversation to
     * resume.  Either way a report whose fingerprint differs from the open
     * capture may not drive navigation: its frame numbers describe another file.
     */
    fun restoreSavedSession(conversationId: String) {
        val store = sessionStore ?: return
        val saved = runCatching { store.load(conversationId) }.getOrNull()
        if (saved == null) {
            publishTransient(savedSessionUnavailableError())
            refreshSavedSessions()
            return
        }
        // Second fingerprint gate: the list is already filtered by
        // listForCapture, but a caller that holds a bare id must never get a
        // conversation from another capture restored onto this one.
        if (!saved.matchesCapture(coordinator.state.value.fileFingerprint)) {
            publishTransient(sessionChangedError())
            refreshSavedSessions()
            return
        }
        if (saved.isResumable) {
            resumeSavedSession(saved)
        } else {
            _restoredSession.value = saved
        }
    }

    /**
     * Put a saved conversation back on screen as the current session.
     *
     * Restoring the private conversation fields matters as much as the UI
     * state: [conversationFingerprint] and friends are what a follow-up checks
     * before it runs, and [reportQuestion] is what [AgentPriorContext] needs to
     * tell the model what was already concluded.  Without them a resumed
     * conversation would look continuable but would start from nothing.
     *
     * A run in progress is left alone; replacing it would discard a trajectory
     * the user has not finished with.
     */
    fun resumeSavedSession(saved: AgentSavedSession) {
        if (isRunning()) {
            publishTransient(concurrentRunError())
            return
        }

        activeJob = null
        runGeneration += 1

        val session = coordinator.state.value
        val matchesCapture = saved.matchesCapture(session.fileFingerprint)

        lastQuestion = saved.userQuestion
        lastScope = saved.analysisScope
        reportQuestion = saved.userQuestion.takeIf { it.isNotBlank() }
        // Only adopt the saved conversation's capture identity when that capture
        // is the one open.  Otherwise leave the live session's identity in place
        // so the next question is correctly treated as a new conversation
        // instead of a follow-up about a file that is no longer loaded.
        conversationFingerprint = if (matchesCapture) saved.captureFingerprint else null
        conversationSessionGeneration =
            if (matchesCapture) saved.sessionGeneration else session.sessionGeneration
        conversationFilter = saved.displayFilter
        conversationPrivacyMode = saved.privacyMode
        // The conversation id and run history travel with the transcript, so a
        // follow-up on the resumed conversation appends a run to the same file
        // rather than forking a new one.
        if (matchesCapture) {
            conversationId = saved.conversationId
            latestRunId = saved.latestRunId.takeIf { it.isNotBlank() }
            conversationRunIds.clear()
            conversationRunIds += saved.runIds
            conversationCreatedAtMillis = saved.createdAtMillis
        }
        // The saved transcript is the sanitized prior-rounds history a v5
        // session persisted; a v4 file decodes to an empty list, whose
        // follow-ups fall back to the summary path.
        committedTranscript = saved.conversationTranscript
        lastRunCacheHits = emptySet()
        _lastRunRecord.value = null
        _restoredSession.value = null

        _uiState.value = _uiState.value.copy(
            phase = AgentRunPhase.Completed,
            conversationId = if (matchesCapture) saved.conversationId else null,
            runId = saved.latestRunId.takeIf { matchesCapture && it.isNotBlank() },
            messages = saved.messages.map { item ->
                // Message ids are "<runId>:message-<n>"; the runId is a
                // cross-process UUID so a follow-up after a relaunch can no
                // longer collide with a restored id, but the restored-prefix
                // is kept as defence in depth and so repeated save/resume
                // cycles keep the id stable instead of re-prefixing.
                if (item.id.isBlank() || item.id.startsWith(RESTORED_ID_PREFIX)) {
                    item
                } else {
                    item.copy(id = "$RESTORED_ID_PREFIX${item.id}")
                }
            },
            modelInteractions = saved.modelInteractions,
            activeTool = null,
            completedSteps = saved.completedSteps,
            report = saved.report,
            privacyMode = saved.privacyMode,
            error = null,
            completionWarning = null,
            transientError = null,
            toolActivities = saved.toolActivities,
            analysisMode = AgentAnalysisMode.FullAgent,
            tokenUsage = saved.tokenUsage,
            streamingText = "",
            analysisPlan = saved.analysisPlan,
            completedPlanSteps = saved.completedPlanSteps,
            pastReports = saved.rounds,
            scopeChanged = false
        )
        publishJob(AgentRunPhase.Completed)
    }

    fun dismissRestoredSession() {
        _restoredSession.value = null
    }

    /**
     * Reload the interrupted-job banner.
     *
     * Shows the banner only when: a job exists, it is marked interrupted, and
     * its capture fingerprint matches the one currently open.  The scan reads
     * every checkpoint rather than the active one — a record flipped to
     * interrupted at process start is by definition no longer "active", so the
     * active-only query could never surface the banner it exists to show.
     */
    fun refreshInterruptedJob() {
        val store = jobStore ?: return
        val fingerprint = coordinator.state.value.fileFingerprint
        // The scan reads every checkpoint file and decodes its JSON; this runs
        // during ViewModel creation on the main thread when the engine state
        // flips to Ready, so a long job history must not decode inline here.
        interruptedJobRefreshJob?.cancel()
        interruptedJobRefreshJob = runScope.launch { refreshInterruptedJobNow(fingerprint) }
    }

    /** [refreshInterruptedJob] for callers already inside a coroutine. */
    private suspend fun refreshInterruptedJobNow(fingerprint: String) {
        val store = jobStore ?: return
        val job = withContext(Dispatchers.IO) {
            runCatching { store.list().firstOrNull { it.interrupted } }.getOrNull()
        }
        _interruptedJob.value = when {
            job == null -> null
            fingerprint.isBlank() -> null
            job.captureFingerprint != fingerprint -> null
            else -> job
        }
    }

    /**
     * Dismiss the interrupted-job banner without resuming.
     *
     * The checkpoint is also deleted so it does not reappear after the next
     * cold start.
     */
    fun dismissInterruptedJob() {
        val job = _interruptedJob.value ?: return
        _interruptedJob.value = null
        val store = jobStore ?: return
        // A single-file delete is still disk IO; keep it off the main thread
        // for the slow-storage devices that motivated the delete-path fix.
        runScope.launch {
            withContext(Dispatchers.IO + NonCancellable) {
                runCatching { store.delete(job.runId) }
            }
        }
    }

    /**
     * Resume an interrupted run as a new run under the same conversation.
     *
     * The previous run's checkpoint is cleared first so the Interrupted banner
     * never shows for the resumed run.  If the checkpoint's last boundary was
     * [AnalysisCheckpoint.ModelRequestStarted], this requires explicit user
     * confirmation before calling here (the UI enforces this).
     */
    fun resumeInterruptedJob() {
        val job = _interruptedJob.value ?: return
        val session = coordinator.state.value
        if (!session.hasSession || session.fileFingerprint.isBlank()) {
            publishTransient(noCaptureError())
            return
        }
        if (job.captureFingerprint != session.fileFingerprint) {
            _interruptedJob.value = null
            publishTransient(sessionChangedError())
            return
        }
        if (isRunning()) {
            publishTransient(concurrentRunError())
            return
        }
        runCatching { jobStore?.delete(job.runId) }
        _interruptedJob.value = null

        // The terminal state before the process died was auto-saved with its
        // sanitized transcript; borrowing it from there lets the resumed run
        // replay the full history.  Empty keeps the prior-context seed below.
        // The saved conversation's archived rounds come back with it, as do the
        // visible messages: the round accordion derives its rounds from them,
        // so a resumed job without them would show only the new round and drop
        // the earlier conversation the user thought they were returning to.
        val priorSaved = if (job.conversationId.isNotBlank()) {
            runCatching { sessionStore?.load(job.conversationId) }.getOrNull()
        } else {
            null
        }
        committedTranscript = priorSaved?.conversationTranscript.orEmpty()
        val restoredMessages = priorSaved?.messages.orEmpty().map { item ->
            // Same mapping as resumeSavedSession: message ids embed the
            // cross-process run id, so collisions cannot happen, but the
            // prefix keeps repeated save/resume cycles idempotent.
            if (item.id.isBlank() || item.id.startsWith(RESTORED_ID_PREFIX)) {
                item
            } else {
                item.copy(id = "$RESTORED_ID_PREFIX${item.id}")
            }
        }
        _uiState.value = _uiState.value.copy(
            pastReports = priorSaved?.rounds.orEmpty(),
            messages = restoredMessages
        )

        val identity = AgentRunIdentity.follow(job.conversationId)
        conversationId = job.conversationId
        conversationRunIds += identity.runId
        latestRunId = identity.runId
        conversationFingerprint = session.fileFingerprint
        conversationSessionGeneration = session.sessionGeneration
        conversationCreatedAtMillis = job.startedAtMillis.takeIf { it > 0L } ?: clock()

        val privacyMode = job.privacyMode.let {
            if (it == AgentPrivacyMode.LocalOnly) it else it
        }
        conversationPrivacyMode = privacyMode

        val priorContext = if (job.transcript.isNotEmpty()) {
            // Seed the resumed run with the last assistant message as prior
            // context so the model knows what was already concluded.
            val lastAssistantContent = job.transcript.lastOrNull {
                it.role == AgentConversationRole.Assistant && it.content.isNotBlank()
            }?.content
            val lastReport = job.transcript.lastOrNull {
                it.role == AgentConversationRole.Assistant && it.report != null
            }?.report
            if (lastReport != null && lastAssistantContent != null) {
                AgentPriorContext.from(job.question, lastReport)
            } else null
        } else null

        startRun(
            question = job.question,
            scope = job.scope,
            session = session,
            // A resumed conversation is by definition a continuation: whatever
            // the checkpoint's boundary, the restored rounds stay on screen
            // above the new round instead of being blanked as a first question
            // would do.
            appendQuestion = priorContext != null || restoredMessages.isNotEmpty(),
            privacyMode = privacyMode,
            identity = identity,
            // The resumed run is a new round of this conversation, so it
            // replays whatever earlier rounds committed.
            history = committedTranscript
        )
    }

    fun deleteSavedSession(conversationId: String) {
        val store = sessionStore ?: return
        // One tap starts exactly one delete: a second tap on a row that is
        // already being deleted is dropped instead of queueing a duplicate
        // that would race the first delete's history rebuild.
        while (true) {
            val current = _deletingSavedSessionIds.value
            if (conversationId in current) return
            if (_deletingSavedSessionIds.compareAndSet(current, current + conversationId)) break
        }
        // The row leaves the list the moment the tap registers. The actual
        // delete is file IO plus a decode scan for legacy-id fallback — tens
        // to hundreds of milliseconds with a large history, previously enough
        // for the user to think the tap had missed and to tap again.
        _savedSessions.value = _savedSessions.value.filterNot {
            it.conversationId == conversationId
        }
        runScope.launch {
            val removed = withContext(Dispatchers.IO + NonCancellable) {
                runCatching { store.delete(conversationId) }.getOrDefault(false)
            }
            // Only the deleted conversation's restored dialog closes; a
            // different open dialog is untouched by this deletion.
            if (_restoredSession.value?.conversationId == conversationId) {
                _restoredSession.value = null
            }
            _deletingSavedSessionIds.value = _deletingSavedSessionIds.value - conversationId
            refreshSavedSessionsNow(coordinator.state.value.fileFingerprint)
            refreshLocalDataUsageNow()
            if (!removed) {
                // The optimistic removal was a promise; a failed delete must
                // not strand it. The refresh above re-lists the row when the
                // file survived, and the error bar explains what happened.
                publishTransient(savedSessionDeleteError())
            }
        }
    }

    /** Whether a restored report's evidence may drive navigation right now. */
    fun canOpenRestoredEvidence(): Boolean {
        val saved = _restoredSession.value ?: return false
        return saved.matchesCapture(coordinator.state.value.fileFingerprint)
    }

    /**
     * Delete the selected local Agent data.
     *
     * Each category maps to exactly one directory this app owns; nothing else
     * under filesDir is touched, so clearing Agent data can never take a
     * capture, a workspace or a preference with it.
     */
    fun clearLocalData(categories: Set<AgentLocalDataCategory>) {
        if (categories.isEmpty()) return
        if (AgentLocalDataCategory.SavedSessions in categories) {
            sessionStore?.clear()
            _restoredSession.value = null
            refreshSavedSessions()
        }
        if (AgentLocalDataCategory.Cache in categories) toolCache?.clear()
        if (AgentLocalDataCategory.Diagnostics in categories) diagnostics?.clear()
        lastClearedAtMillis = clock()
        refreshLocalDataUsage()
    }

    fun clearAllLocalData() {
        clearLocalData(AgentLocalDataCategory.entries.toSet())
    }

    /**
     * Remove the downloaded rule package and return to the built-in rules.
     *
     * Rule packages are not user data the app can edit, but they are app-owned
     * state the user must be able to inspect and reset; the built-in package is
     * unaffected because it lives in the APK, not under filesDir.
     */
    fun clearDownloadedScenarioPackage() {
        val store = scenarioPackageStore ?: return
        runCatching { store.clearDownloadedPackage() }
        _scenarioPackage.value = runCatching { store.describe() }.getOrNull()
        basePlaybooks = loadActivePlaybooks(reload = true)
        _playbooks.value = orderedPlaybooks(basePlaybooks)
    }

    /**
     * Remember that the user picked a scenario chip, so it rises in the list.
     *
     * Called from the chip itself rather than from [submitQuestion], because a
     * typed question is not a scenario choice even when its text happens to
     * match one.
     */
    fun recordPlaybookUsage(playbookId: String) {
        val store = playbookUsageStore ?: return
        store.record(playbookId)
        _playbooks.value = orderedPlaybooks(basePlaybooks)
    }

    private fun orderedPlaybooks(playbooks: List<AgentPlaybook>): List<AgentPlaybook> {
        val usage = playbookUsageStore?.usage?.value ?: return playbooks
        return playbooks.sortedByUsage(usage)
    }

    private fun loadActivePlaybooks(reload: Boolean = false): List<AgentPlaybook> = runCatching {
        when {
            playbookStore != null && reload -> playbookStore.reload()
            playbookStore != null -> playbookStore.load()
            else -> scenarioPackageStore?.active()?.content?.playbooks.orEmpty()
        }
    }.getOrDefault(emptyList())

    // ---------------------------------------------------- scenario management

    /**
     * Open the editor on a blank user scenario.
     *
     * The draft carries no identity at all: the id is minted by the user
     * scenario layer at save time and the version is store-owned, so an
     * unsaved scenario has neither.  Opening always mints a fresh draft
     * epoch (OPT-DRAFT-01), which is what ties an in-flight save to the
     * editor it was started from.
     */
    fun startNewScenario() {
        if (userScenarios == null) return
        _editingScenario.value = AgentScenarioDraft(
            playbook = blankUserScenario(),
            isNew = true,
            epoch = nextScenarioDraftEpoch()
        )
    }

    /**
     * Open the editor on an existing scenario.
     *
     * The preset lock is structural: only [ScenarioOrigin.User] playbooks are
     * editable, and a built-in one is silently ignored rather than refused —
     * the UI never offers the affordance, so a call reaching here with one is
     * out of contract, not a user error to report.
     */
    fun startEditScenario(playbook: AgentPlaybook) {
        if (userScenarios == null) return
        if (playbook.origin != ScenarioOrigin.User) return
        _editingScenario.value = AgentScenarioDraft(
            playbook = playbook,
            isNew = false,
            epoch = nextScenarioDraftEpoch()
        )
    }

    /**
     * Open the scenario read-only ("View details").
     *
     * Unlike the authoring events this is origin-blind and needs no user
     * layer: viewing only renders playbook content and never persists
     * anything, so a built-in preset can be inspected too — exactly where the
     * long-press menu offers details because editing is locked.  A second
     * call simply replaces the open draft, matching the editor's single-draft
     * slot — with a fresh epoch, so a save still in flight for the replaced
     * draft cannot write back into the details view.
     */
    fun startViewScenario(playbook: AgentPlaybook) {
        _editingScenario.value = AgentScenarioDraft(
            playbook = playbook,
            isNew = false,
            readOnly = true,
            epoch = nextScenarioDraftEpoch()
        )
    }

    /** Close the editor, discarding the draft; nothing was ever persisted. */
    fun dismissEditingScenario() {
        _editingScenario.value = null
    }

    /**
     * Apply an editing change to the open draft (OPT-DRAFT-01).
     *
     * The scenario editor is a controlled component: it renders
     * [AgentScenarioDraft.playbook] and reports every field change here, so
     * the ViewModel — not a composable-local copy — is the single source of
     * the editing input, and an activity recreation that discards every
     * `remember` still finds the half-typed scenario in
     * [editingScenario].  A no-op while no editor is open (a late callback
     * after dismissal, say).
     *
     * The epoch is pinned through the transform: editing a draft is the same
     * editor session, never a new one, so an in-flight save's write-back
     * still lands.  [AgentScenarioDraft.validatedPlaybook] and
     * [AgentScenarioDraft.validationErrors] ride along on the copy — the
     * per-field error display compares the live value against the snapshot,
     * so an error disappears the moment its field is edited; the whole map
     * is replaced by the next save attempt's outcome.
     */
    fun updateDraft(transform: (AgentScenarioDraft) -> AgentScenarioDraft) {
        _editingScenario.update { current ->
            current?.let { transform(it).copy(epoch = it.epoch) }
        }
    }

    /**
     * Mint the next draft epoch; only the open events call this, all on the
     * main thread, so a plain increment is enough (see
     * [lastScenarioDraftEpoch]).
     */
    private fun nextScenarioDraftEpoch(): Long {
        lastScenarioDraftEpoch += 1
        return lastScenarioDraftEpoch
    }

    /**
     * Persist the open draft.
     *
     * The submitted content is the draft's own [AgentScenarioDraft.playbook]
     * (OPT-DRAFT-01): the editor is a controlled component with no copy of
     * its own, so there is nothing to hand in and no stale local state to
     * trust.  The store owns identity: a brand-new scenario with a blank id
     * gets one minted ([UserScenarioStore.generateScenarioId]) for the save
     * attempt, and an edited one keeps the id it was saved under — only the
     * store-assigned version moves.  A field rejection comes back as the
     * draft's [AgentScenarioDraft.validationErrors], with the rejected
     * content frozen into [AgentScenarioDraft.validatedPlaybook] for the
     * per-field "still holds the rejected value" comparison, and the editor
     * stays open; a failed write surfaces a transient error and also keeps
     * the editor open, so the user's text is never lost to a disk failure.
     * A successful save closes the editor, bumps [scenarioSaveCompleted] so
     * the host page can raise its "Scenario saved" notice, and reloads the
     * merged playbook list so the new scenario joins the chips.
     *
     * The rejection write-back is guarded by the draft [AgentScenarioDraft.epoch],
     * not by reference equality: with a controlled draft every keystroke
     * copies the draft, so the open editor is regularly *not* the same object
     * the save started from — but it is still the same editor session until
     * the draft is dismissed or replaced by an open event, which is exactly
     * what a matching epoch means.  An in-flight edit typed while the IO ran
     * is therefore preserved rather than clobbered by the write-back.
     *
     * OPT-SAVE-01: one save runs at a time.  A tap arriving while the IO
     * window is still open is dropped rather than queued — the draft it
     * would have saved is the same draft already on its way to the store,
     * so a second complete save would only jump the store version again and
     * bump [scenarioSaveCompleted] with a duplicate "saved" notice.  The
     * [savingScenario] flag is what the editor disables its Save button off.
     */
    fun saveScenario() {
        val store = userScenarios ?: return
        val draft = _editingScenario.value ?: return
        // Claim the in-flight slot before launching: the check has to be
        // synchronous with the tap, or two fast clicks could both pass it
        // while the first save is still only a queued coroutine.
        if (!_savingScenario.compareAndSet(expect = false, update = true)) return
        val epoch = draft.epoch
        val submitted = draft.playbook
        runScope.launch {
            try {
                val candidate = withContext(Dispatchers.IO) {
                    submitted.copy(
                        id = if (draft.isNew && submitted.id.isBlank()) {
                            store.generateScenarioId(submitted.title)
                        } else {
                            submitted.id
                        }
                    )
                }
                val outcome = withContext(Dispatchers.IO) {
                    runCatching { store.save(candidate) }
                }
                outcome.fold(
                    onSuccess = { errors ->
                        if (errors.isNotEmpty()) {
                            // The editor may have been dismissed (or replaced
                            // with another draft) while the IO ran; never
                            // resurrect it.  Epoch, not identity: edits since
                            // the save started legitimately replace the draft
                            // object.
                            val current = _editingScenario.value
                            if (current != null && current.epoch == epoch) {
                                _editingScenario.value = current.copy(
                                    validationErrors = errors,
                                    validatedPlaybook = candidate
                                )
                            }
                        } else {
                            _editingScenario.value = null
                            // The success signal fires before the chip reload
                            // so the notice never depends on the reload
                            // completing.
                            _scenarioSaveCompleted.update { it + 1 }
                            refreshPlaybooksFromStore()
                        }
                    },
                    onFailure = {
                        publishTransient(scenarioSaveFailedError())
                    }
                )
            } finally {
                // OPT-SAVE-01: release the in-flight slot however the save
                // ended — accepted, rejected, or failed write — so the next
                // tap is never locked out by an attempt that already returned.
                _savingScenario.value = false
            }
        }
    }

    /**
     * Save a copy of the scenario under a freshly minted id.
     *
     * The copy strips the overlay extras (they attach to the source's identity
     * in the operator layer and never persist on the user layer) and starts a
     * new version lineage: version and origin are store-assigned on save.  The
     * source is looked up in the merged list, so built-in scenarios can be
     * copied as starting points while staying unmodifiable themselves.  This
     * deliberately never touches the editor or an open draft.
     */
    fun copyScenario(playbookId: String) {
        val store = userScenarios ?: return
        val playbookStore = playbookStore ?: return
        runScope.launch {
            val source = withContext(Dispatchers.IO) {
                runCatching { playbookStore.load() }.getOrNull()
                    ?.firstOrNull { it.id == playbookId }
            } ?: return@launch
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    store.save(
                        source.copy(
                            id = store.generateCopyId(source.id),
                            thresholds = emptyList(),
                            recommendedFilters = emptyList()
                        )
                    )
                }
            }
            outcome.fold(
                onSuccess = { errors ->
                    if (errors.isEmpty()) {
                        refreshPlaybooksFromStore()
                    } else {
                        // A copy is fully store-derived content, so a field
                        // rejection has no editor to go back to and stays a
                        // reason-code-only transient error.
                        publishTransient(scenarioCopyFailedError())
                    }
                },
                onFailure = {
                    publishTransient(scenarioCopyFailedError())
                }
            )
        }
    }

    /**
     * Delete a user scenario.
     *
     * The preset lock is the id namespace itself: only [UserScenarioStore.USER_ID_PREFIX]
     * ids are deletable, so a built-in id is a silent no-op.  The chip leaves
     * the list the moment the tap registers, and the trailing reload restores
     * consistency even when the delete turned out to be a no-op — whatever the
     * layer really holds is what the chips show again.  The usage count is
     * cleared with the scenario so a deleted id stops ordering chips.
     */
    fun deleteScenario(playbookId: String) {
        val store = userScenarios ?: return
        if (!playbookId.startsWith(UserScenarioStore.USER_ID_PREFIX)) return
        // One tap starts exactly one delete; a second tap on a chip that is
        // already being deleted is dropped instead of racing the first.
        while (true) {
            val current = _deletingScenarioIds.value
            if (playbookId in current) return
            if (_deletingScenarioIds.compareAndSet(current, current + playbookId)) break
        }
        _playbooks.value = _playbooks.value.filterNot { it.id == playbookId }
        runScope.launch {
            withContext(Dispatchers.IO + NonCancellable) {
                runCatching { store.delete(playbookId) }
                playbookUsageStore?.clear(playbookId)
                refreshPlaybooksFromStore()
            }
            _deletingScenarioIds.value = _deletingScenarioIds.value - playbookId
        }
    }

    /**
     * The reload-and-reorder shared by every event that changes the user
     * layer: [reload] folds the layer back into the merged list and the
     * ordering restarts from the package sequence so a changed usage map
     * cannot erode the curated order further.
     */
    private suspend fun refreshPlaybooksFromStore() {
        withContext(Dispatchers.IO) {
            basePlaybooks = loadActivePlaybooks(reload = true)
            _playbooks.value = orderedPlaybooks(basePlaybooks)
        }
    }

    /** An unsaved scenario: no id, no version, and no content yet. */
    private fun blankUserScenario(): AgentPlaybook = AgentPlaybook(
        id = "",
        version = 0,
        title = "",
        intentHints = emptyList(),
        protocols = emptyList(),
        initialTools = emptyList(),
        requiredFields = emptyList(),
        checks = emptyList(),
        successPath = emptyList(),
        failureBranches = emptyList(),
        requiredLimitations = emptyList(),
        outputSections = emptyList(),
        origin = ScenarioOrigin.User
    )

    fun refreshLocalDataUsage() {
        // Same disk-first work as the saved list: byte counts, entry counts and
        // diagnostics sizes all stat/read the filesystem and run on IO.
        localDataUsageRefreshJob?.cancel()
        localDataUsageRefreshJob = runScope.launch { refreshLocalDataUsageNow() }
    }

    /** [refreshLocalDataUsage] for callers already inside a coroutine. */
    private suspend fun refreshLocalDataUsageNow() {
        val sessionStore = sessionStore
        val toolCache = toolCache
        val diagnostics = diagnostics
        val usage = withContext(Dispatchers.IO) {
            AgentLocalDataUsage(
                savedSessionCount = sessionStore?.count() ?: 0,
                savedSessionBytes = sessionStore?.totalBytes() ?: 0L,
                cacheEntryCount = toolCache?.diskEntryCount() ?: 0,
                cacheBytes = toolCache?.diskBytes() ?: 0L,
                diagnosticsBytes = diagnostics?.totalBytes() ?: 0L,
                lastClearedAtMillis = lastClearedAtMillis
            )
        }
        _localDataUsage.value = usage
    }

    /** Redacted diagnostics text for an explicit user-initiated export. */
    fun exportDiagnostics(): String? = diagnostics?.exportRedacted()

    // ------------------------------------------------------------------ run

    /**
     * The identity for a follow-up or retry run: the on-screen conversation is
     * kept (minted lazily so a follow-up on a very old conversation still has a
     * stable key), and only the run id advances.
     */
    private fun followUpIdentity(): AgentRunIdentity {
        val existing = conversationId
        return if (existing.isNullOrBlank()) {
            AgentRunIdentity.newConversation()
        } else {
            AgentRunIdentity.follow(existing)
        }
    }

    private fun startRun(
        question: String,
        scope: AnalysisScope,
        session: CaptureSessionState,
        appendQuestion: Boolean,
        privacyMode: AgentPrivacyMode,
        identity: AgentRunIdentity,
        /** Replayed prior rounds; a follow-up passes [committedTranscript]. */
        history: List<AgentModelMessage> = emptyList(),
        /**
         * Explicit playbook id for this run.  Only the chip submission — and
         * the consent acceptance replaying it — set it; follow-ups, retries
         * and resumes pass null so selection stays question-text matching.
         */
        playbookId: String? = null,
        /**
         * EVL-CONTEXT-03: display filter this run's snapshot is framed with
         * instead of the session's applied one (see [resolveDisplayFilter]).
         * Only the initial evidence-workflow submission — and the consent
         * acceptance replaying it — passes it; follow-ups, retries and resumes
         * pass null.  When set, the scope-notice bookkeeping below records the
         * *effective* filter, so a later follow-up that finds the session on a
         * different filter correctly reports the scope change.
         */
        displayFilterOverride: String? = null,
        evidenceFrameCount: Int? = null
    ) {
        runGeneration += 1
        val generation = runGeneration

        val base = _uiState.value
        // A follow-up replaces the report on screen with this run's outcome, so
        // the finished round is archived first; a first question starts a new
        // conversation and carries nothing over.
        val pastReportsForRun = archivePriorRound(base, appendQuestion)
        val priorContext = if (appendQuestion) {
            reportQuestion?.let { priorQuestion ->
                base.report?.let { priorReport ->
                    AgentPriorContext.from(priorQuestion, priorReport)
                }
            }
        } else {
            null
        }
        if (!appendQuestion) reportQuestion = null

        lastQuestion = question
        lastScope = scope
        conversationFingerprint = session.fileFingerprint
        conversationSessionGeneration = session.sessionGeneration

        // The identity for this run was minted by the caller.  A new
        // conversation starts its bookkeeping here; a follow-up or retry only
        // appends the new run id, so the saved file is updated, never forked.
        if (conversationId != identity.conversationId) {
            conversationId = identity.conversationId
            conversationRunIds.clear()
            conversationCreatedAtMillis = clock()
        }
        conversationRunIds += identity.runId
        latestRunId = identity.runId

        // The scope notice compares against the filter this conversation was
        // framed with, so only a follow-up can raise it.  A run framed by a
        // displayFilterOverride is framed with that override, not with the
        // session's applied filter — record the effective one.
        val effectiveFilter = resolveDisplayFilter(
            session.appliedDisplayFilter,
            displayFilterOverride
        )
        val scopeChanged = appendQuestion &&
            scope == AnalysisScope.CurrentFilter &&
            conversationFilter != effectiveFilter
        conversationFilter = effectiveFilter

        val runPrivacyMode = if (appendQuestion) {
            conversationPrivacyMode ?: privacyMode
        } else {
            privacyMode
        }
        conversationPrivacyMode = runPrivacyMode
        _uiState.value = base.copy(
            phase = AgentRunPhase.Preparing,
            conversationId = identity.conversationId,
            runId = identity.runId,
            messages = if (appendQuestion) base.messages else emptyList(),
            modelInteractions = if (appendQuestion) base.modelInteractions else emptyList(),
            activeTool = null,
            completedSteps = if (appendQuestion) base.completedSteps else 0,
            report = if (appendQuestion) base.report else null,
            pastReports = pastReportsForRun,
            privacyMode = runPrivacyMode,
            error = null,
            completionWarning = null,
            transientError = null,
            scopeChanged = scopeChanged,
            toolActivities = if (appendQuestion) base.toolActivities else emptyList(),
            analysisMode = AgentAnalysisMode.FullAgent,
            tokenUsage = null,
            streamingText = "",
            analysisPlan = null,
            completedPlanSteps = 0
        )

        val coordinator = runCoordinator
        if (coordinator != null) {
            // The coordinator owns the run on an Application scope.  The
            // snapshot observer updates the UI state and auto-saves on a
            // terminal outcome, so a ViewModel that dies here loses nothing.
            // A follow-up carries the visible transcript forward; a retry has
            // already blanked it and starts the screen clean.
            val started = coordinator.start(
                AgentRunRequest(
                    question = question,
                    scope = scope,
                    privacyMode = runPrivacyMode,
                    appendQuestion = appendQuestion,
                    identity = identity,
                    priorContext = priorContext,
                    history = history,
                    visibleMessages = base.messages,
                    visibleModelInteractions = base.modelInteractions,
                    playbookId = playbookId,
                    displayFilterOverride = displayFilterOverride,
                    evidenceFrameCount = evidenceFrameCount
                )
            )
            if (!started) publishTransient(concurrentRunError())
            return
        }

        publishJob(AgentRunPhase.Preparing)
        activeJob = runScope.launch {
            val result = try {
                agent.run(
                    question = question,
                    scope = scope,
                    privacyMode = runPrivacyMode,
                    listener = RunListener(generation),
                    priorContext = priorContext,
                    identity = identity,
                    history = history,
                    playbookId = playbookId,
                    displayFilterOverride = displayFilterOverride,
                    evidenceFrameCount = evidenceFrameCount
                )
            } catch (cancelled: CancellationException) {
                // cancel() already published the terminal state.
                throw cancelled
            }

            if (generation != runGeneration) return@launch

            // A refusal from the Agent carries no identity; keep the previous
            // one rather than blanking it.
            result.identity?.let { resultIdentity ->
                _uiState.value = _uiState.value.copy(
                    conversationId = resultIdentity.conversationId,
                    runId = resultIdentity.runId
                )
            }
            _uiState.value = _uiState.value.copy(tokenUsage = result.tokenUsage)
            _lastRunRecord.value = result.runRecord
            lastRunCacheHits = result.cacheHitArgumentHashes

            when (val outcome = result.outcome) {
                is AgentRunOutcome.Completed -> {
                    reportQuestion = question
                    committedTranscript = result.finalTranscript
                    saveAnalysisAutomatically(
                        outcome.report, question, session, runPrivacyMode,
                        pastReports = _uiState.value.pastReports
                    )
                    publishCompleted(
                        report = outcome.report,
                        activities = result.activities,
                        analysisMode = result.analysisMode,
                        stopReason = outcome.stopReason
                    )
                }
                is AgentRunOutcome.Failed -> {
                    if (outcome.report != null) reportQuestion = question
                    // A failed run without a partial report commits nothing: the
                    // next follow-up replays what earlier rounds established.
                    if (outcome.report != null) committedTranscript = result.finalTranscript
                    outcome.report?.let {
                        saveAnalysisAutomatically(
                            it, question, session, runPrivacyMode,
                            pastReports = _uiState.value.pastReports
                        )
                    }
                    publishFailed(outcome.error, outcome.report, result.analysisMode)
                }
                is AgentRunOutcome.FailedWithPartialReport -> {
                    reportQuestion = question
                    committedTranscript = result.finalTranscript
                    saveAnalysisAutomatically(
                        outcome.report, question, session, runPrivacyMode,
                        pastReports = _uiState.value.pastReports
                    )
                    publishFailed(
                        outcome.error,
                        outcome.report,
                        result.analysisMode,
                        partialFailure = true
                    )
                }
                is AgentRunOutcome.Cancelled -> publishCancelled()
            }
            activeJob = null
        }
    }

    /**
     * Persist the conversation automatically after every terminal run that
     * produced a report. The saved file is the regular history entry for the
     * conversation; there is no separate "recovery copy" that needs promotion.
     *
     * Unredacted runs are included because saved sessions retain the complete
     * transcript regardless of privacy mode. Credentials are never part of the
     * persisted conversation.
     */
    private suspend fun saveAnalysisAutomatically(
        report: AgentReport,
        question: String,
        session: CaptureSessionState,
        privacyMode: AgentPrivacyMode,
        pastReports: List<AgentConversationRound> = emptyList()
    ) {
        val store = sessionStore ?: return
        val state = _uiState.value
        val saved = withContext(Dispatchers.IO) {
            store.save(
                report = report,
                userQuestion = question,
                runRecord = _lastRunRecord.value,
                captureFingerprint = session.fileFingerprint,
                conversationId = conversationId ?: state.conversationId.orEmpty(),
                captureDisplayName = session.localPathIdentity,
                analysisConfigVersion = session.analysisConfigVersion,
                cacheHits = lastRunCacheHits,
                messages = state.messages,
                modelInteractions = state.modelInteractions,
                toolActivities = state.toolActivities,
                analysisPlan = state.analysisPlan,
                completedPlanSteps = state.completedPlanSteps,
                completedSteps = state.completedSteps,
                privacyMode = privacyMode,
                tokenUsage = state.tokenUsage,
                sessionGeneration = session.sessionGeneration,
                latestRunId = latestRunId.orEmpty(),
                runIds = conversationRunIds.toList(),
                createdAtMillis = conversationCreatedAtMillis,
                conversationTranscript = committedTranscript,
                rounds = pastReports
            )
        }
        if (saved.isFailure) {
            publishTransient(saveFailedError())
            yield()
            return
        }
        // Serialise the post-save refreshes into this coroutine so the saved
        // list and the usage card are consistent the moment the terminal state
        // is visible, without doing their disk work on the main thread.
        refreshSavedSessionsNow(coordinator.state.value.fileFingerprint)
        refreshLocalDataUsageNow()
    }

    /**
     * Bridges AI-06 events onto the UI state, dropping anything from a run the
     * user has already cancelled or replaced.
     */
    private inner class RunListener(private val generation: Long) : AgentRunListener {
        override fun onPhaseChanged(phase: AgentRunPhase) {
            if (generation != runGeneration) return
            // Terminal phases are published from the run's result instead, so a
            // report and its phase always land together.
            if (phase == AgentRunPhase.Completed ||
                phase == AgentRunPhase.Failed ||
                phase == AgentRunPhase.Cancelled
            ) {
                return
            }
            _uiState.value = _uiState.value.copy(
                phase = phase,
                activeTool = if (phase == AgentRunPhase.RunningTool) {
                    _uiState.value.activeTool
                } else {
                    null
                }
            )
            publishJob(phase)
        }

        override fun onToolActivity(activity: AgentToolActivity) {
            if (generation != runGeneration) return
            val current = _uiState.value
            val running = activity.status == AgentToolActivityStatus.Running ||
                activity.status == AgentToolActivityStatus.Queued
            // The loop reports the same call twice (running, then finished), so
            // merge on id rather than appending a duplicate row.
            val merged = current.toolActivities.toMutableList()
            val index = merged.indexOfFirst { it.toolCallId == activity.toolCallId }
            if (index >= 0) merged[index] = activity else merged += activity

            _uiState.value = current.copy(
                activeTool = if (running) activity else null,
                toolActivities = merged,
                completedSteps = merged.count { it.status != AgentToolActivityStatus.Running &&
                    it.status != AgentToolActivityStatus.Queued }
            )
            publishJob(_uiState.value.phase)
        }

        override fun onMessage(item: AgentConversationItem) {
            if (generation != runGeneration) return
            val current = _uiState.value
            val merged = current.messages.toMutableList()
            // A re-emitted id replaces what is already on screen instead of
            // appearing twice. The loop mints a fresh id per message, so this
            // is a guard against a replayed item rather than the normal path.
            val index = item.id.takeIf { it.isNotBlank() }
                ?.let { id -> merged.indexOfFirst { it.id == id } }
                ?: -1
            if (index >= 0) merged[index] = item else merged += item
            _uiState.value = current.copy(messages = merged)
        }

        override fun onModelInteraction(interaction: AgentModelInteraction) {
            if (generation != runGeneration) return
            val current = _uiState.value
            _uiState.value = current.copy(
                modelInteractions = current.modelInteractions + interaction
            )
        }

        override fun onStreamingUpdate(text: String) {
            if (generation != runGeneration) return
            _uiState.value = _uiState.value.copy(streamingText = text)
        }

        override fun onAnalysisPlan(plan: AgentAnalysisPlan, completedSteps: Int) {
            if (generation != runGeneration) return
            _uiState.value = _uiState.value.copy(
                analysisPlan = plan,
                completedPlanSteps = completedSteps.coerceIn(0, plan.steps.size)
            )
        }
    }

    // -------------------------------------------------------------- terminals

    private fun publishCompleted(
        report: AgentReport,
        activities: List<AgentToolActivity>,
        analysisMode: AgentAnalysisMode,
        stopReason: AgentStopReason
    ) {
        val warning = completionWarning(stopReason)
        val current = _uiState.value
        _uiState.value = current.copy(
            phase = AgentRunPhase.Completed,
            activeTool = null,
            report = report,
            error = null,
            completionWarning = warning,
            toolActivities = if (activities.isEmpty()) current.toolActivities else activities,
            analysisMode = analysisMode,
            streamingText = ""
        )
        publishJob(AgentRunPhase.Completed, warning?.code)
    }

    private fun publishFailed(
        error: AgentError,
        partialReport: AgentReport?,
        analysisMode: AgentAnalysisMode,
        partialFailure: Boolean = false
    ) {
        val current = _uiState.value
        _uiState.value = current.copy(
            phase = if (partialFailure) {
                AgentRunPhase.FailedWithPartialReport
            } else {
                AgentRunPhase.Failed
            },
            activeTool = null,
            // Keep whatever the run confirmed before it failed.
            report = partialReport ?: current.report,
            error = error,
            completionWarning = null,
            analysisMode = analysisMode,
            streamingText = "",
            // A run that ended with a report in hand states its failure where
            // the report is — the partial-result warning inside the report card
            // and the error card under it — so it raises no "分析失败" bubble
            // next to the conclusion it did produce.  Only a run that ends with
            // nothing to show adds the bubble.
            messages = if (partialFailure || current.messages.any { it.error == error }) {
                current.messages
            } else {
                current.messages + errorMessage(error)
            }
        )
        publishJob(
            if (partialFailure) AgentRunPhase.FailedWithPartialReport else AgentRunPhase.Failed,
            error.code
        )
    }

    private fun publishCancelled() {
        _uiState.value = _uiState.value.copy(
            phase = AgentRunPhase.Cancelled,
            activeTool = null,
            streamingText = ""
        )
        publishJob(AgentRunPhase.Cancelled)
    }

    // ---------------------------------------------------------------- session

    /**
     * Watch the shared capture session.
     *
     * Only a real capture change ends a run.  Navigating between the packet list
     * and the Agent screen does not touch this state, which is why page changes
     * cannot cancel an analysis.
     */
    private fun observeSession() {
        runScope.launch {
            var lastFingerprint = coordinator.state.value.fileFingerprint
            coordinator.state.collect { session ->
                // The saved list carries a per-entry "belongs to the open
                // capture" flag, so opening a different file has to re-evaluate
                // it even when no conversation is in progress.
                if (session.fileFingerprint != lastFingerprint) {
                    lastFingerprint = session.fileFingerprint
                    refreshSavedSessions()
                }

                val fingerprint = conversationFingerprint ?: return@collect

                if (!session.hasSession) {
                    endForSessionChange(clearConversation = true)
                    return@collect
                }
                val changed = session.fileFingerprint != fingerprint ||
                    (conversationSessionGeneration != 0L &&
                        session.sessionGeneration != conversationSessionGeneration)
                if (changed) {
                    endForSessionChange(clearConversation = true)
                }
            }
        }
    }

    private fun observeSettings() {
        val flow = settings.settingsFlow ?: return
        runScope.launch {
            flow.collect { next ->
                _configuration.value = next
                if (!isRunning() && conversationPrivacyMode == null) {
                    _uiState.value = _uiState.value.copy(privacyMode = next.privacyMode)
                }
                if (next.isCloudConfigured &&
                    next.privacyMode != AgentPrivacyMode.LocalOnly &&
                    !next.byokConfigured
                ) {
                    refreshGatewayAccount()
                } else {
                    gatewayAccountRepository?.clear()
                }
            }
        }
    }

    private fun observeGatewayAccount() {
        val repository = gatewayAccountRepository ?: return
        runScope.launch {
            repository.state.collect { _gatewayAccount.value = it }
        }
        refreshGatewayAccount()
    }

    /**
     * Drain the quarantine notice channel (OPT-QNT-01).
     *
     * The user scenario layer quarantines a corrupt / hand-edited / newer-
     * schema file by renaming it aside and degrading to an empty layer, and
     * its `onQuarantine` sink publishes the stable reason code onto
     * [quarantineEvents].  Collecting the buffered channel here — rather than
     * a replay-less hot flow — is what keeps the *first* notice alive when the
     * quarantine fired during app assembly, before this ViewModel existed.
     * Each event only carries the reason code ([ScenarioQuarantineEvent]), so
     * nothing user-authored can reach the UI through this path, and the
     * consumer-side dedupe in [nextQuarantineCodes] is what guarantees one
     * quarantine surfaces exactly one notice.
     */
    private fun observeScenarioQuarantine() {
        val events = quarantineEvents ?: return
        runScope.launch {
            events.events.collect { event ->
                _scenarioQuarantineCodes.update { nextQuarantineCodes(it, event) }
            }
        }
    }

    /**
     * Mirror the Application-owned run into the UI state.
     *
     * When a [runCoordinator] is present the run outlives this ViewModel, so
     * the UI state is a *projection* of the coordinator's replayable snapshot:
     * a ViewModel created after the run started (rotation, process restore)
     * immediately sees the in-progress transcript instead of an empty screen.
     * The coordinator also drives the coarse job banner and the auto-save.
     */
    private fun observeRunCoordinator() {
        val coordinator = runCoordinator ?: return
        runScope.launch {
            coordinator.snapshot.collect { snap ->
                applyCoordinatorSnapshot(snap)
            }
        }
        runScope.launch {
            coordinator.jobState.collect { job ->
                _analysisJob.value = job
            }
        }
    }

    private var lastPersistedRunId: String? = null

    private fun applyCoordinatorSnapshot(snap: AgentRunSnapshot) {
        val base = _uiState.value
        _uiState.value = base.copy(
            phase = snap.phase,
            conversationId = conversationId ?: snap.report?.let { base.conversationId },
            runId = latestRunId,
            messages = snap.messages,
            modelInteractions = snap.modelInteractions,
            activeTool = snap.activeTool,
            completedSteps = snap.completedSteps,
            report = snap.report ?: base.report,
            error = snap.error,
            completionWarning = snap.completionWarning,
            toolActivities = snap.toolActivities,
            analysisMode = snap.analysisMode,
            tokenUsage = snap.tokenUsage,
            streamingText = snap.streamingText,
            analysisPlan = snap.analysisPlan,
            completedPlanSteps = snap.completedPlanSteps
        )

        // Save exactly once per run, on a terminal outcome that produced a
        // report, keyed by the run id so a follow-up updates the conversation.
        val terminalWithReport = when (snap.phase) {
            AgentRunPhase.Completed,
            AgentRunPhase.FailedWithPartialReport -> snap.report != null
            AgentRunPhase.Failed -> snap.report != null
            else -> false
        }
        val runId = latestRunId
        if (terminalWithReport && runId != null && runId != lastPersistedRunId) {
            lastPersistedRunId = runId
            // The run committed its trajectory; the next follow-up replays it.
            if (snap.transcript.isNotEmpty()) committedTranscript = snap.transcript
            snap.report?.let { report ->
                runScope.launch {
                    saveAnalysisAutomatically(
                        report,
                        lastQuestion.orEmpty(),
                        coordinator.state.value,
                        _uiState.value.privacyMode,
                        pastReports = _uiState.value.pastReports
                    )
                }
            }
        }
    }

    private fun requestConsentIfNeeded(
        question: String,
        scope: AnalysisScope,
        session: CaptureSessionState,
        appendQuestion: Boolean,
        privacyMode: AgentPrivacyMode,
        /** Chip override kept alive across the prompt into [acceptConsent]. */
        playbookId: String? = null,
        /** Display-filter override kept alive across the prompt, as above. */
        displayFilterOverride: String? = null,
        /** Evidence frame count kept alive across the prompt, as above. */
        evidenceFrameCount: Int? = null
    ): Boolean {
        val current = settings.settings.copy(privacyMode = privacyMode)
        if (!AgentConsent.requiresConsent(current)) return false
        // The identity is minted now, before consent, so accepting the prompt
        // runs under the same ids the question was framed with instead of
        // silently starting a different conversation or run.
        val identity = if (appendQuestion) followUpIdentity() else AgentRunIdentity.newConversation()
        pendingConsentRun = PendingConsentRun(
            question, scope, appendQuestion, privacyMode, identity,
            playbookId, displayFilterOverride, evidenceFrameCount
        )
        _consentPrompt.value = AgentConsentPrompt(
            providerId = current.providerId,
            modelId = current.modelId,
            providerName = current.activeProvider?.name.orEmpty(),
            modelName = current.activeModel?.name.orEmpty(),
            privacyMode = current.privacyMode,
            scope = scope,
            frameCount = session.frameCount,
            appliedDisplayFilter = session.appliedDisplayFilter,
            preview = buildPreview(question, scope, session, current.privacyMode)
        )
        return true
    }

    private fun buildPreview(
        question: String,
        scope: AnalysisScope,
        session: CaptureSessionState,
        privacyMode: AgentPrivacyMode
    ): AgentRequestPreview {
        val snapshot = AgentCaptureSnapshot(
            sessionHandle = session.sessionHandle,
            fileFingerprint = session.fileFingerprint,
            frameCount = session.frameCount,
            displayFilter = session.appliedDisplayFilter,
            scope = scope,
            startedAtMillis = clock(),
            analysisGeneration = 0L,
            sessionGeneration = session.sessionGeneration,
            agentGeneration = 0L
        )
        val request = AgentModelRequest(
            requestId = "preview",
            messages = listOf(
                AgentModelMessage.system(
                    AgentPrompt.systemPrompt(
                        snapshot,
                        com.example.layanalyzer.ai.agent.AgentPolicy(),
                        privacyMode
                    )
                ),
                AgentModelMessage.user(question)
            ),
            toolDefinitions = agent.toolDefinitions(),
            responseSchema = AgentPrompt.REPORT_SCHEMA,
            privacyMode = privacyMode
        )
        return AgentRequestPreviewBuilder.build(request, scope)
    }

    private fun endForSessionChange(clearConversation: Boolean) {
        val wasRunning = isRunning()
        if (wasRunning) {
            runGeneration += 1
            if (runCoordinator != null) {
                runCoordinator.cancel()
            } else {
                agent.cancel()
                activeJob?.cancel()
                activeJob = null
            }
        }

        if (clearConversation) {
            // A report about a capture that is no longer open must not stay on
            // screen as if it described the new one.  AI-14 is what lets a user
            // keep one deliberately, by saving it to the workspace first.
            resetConversation()
        }
        if (wasRunning) {
            val error = sessionChangedError()
            _uiState.value = _uiState.value.copy(
                phase = AgentRunPhase.Failed,
                activeTool = null,
                error = error
            )
            publishJob(AgentRunPhase.Failed, error.code)
        }
    }

    private fun resetConversation() {
        conversationFingerprint = null
        conversationSessionGeneration = 0L
        conversationFilter = ""
        conversationPrivacyMode = null
        conversationId = null
        latestRunId = null
        conversationRunIds.clear()
        conversationCreatedAtMillis = 0L
        lastQuestion = null
        lastScope = AnalysisScope.CompleteFile
        reportQuestion = null
        committedTranscript = emptyList()
        pendingConsentRun = null
        _consentPrompt.value = null
        _lastRunRecord.value = null
        lastRunCacheHits = emptySet()
        _uiState.value = ProtocolAgentUiState(privacyMode = settings.settings.privacyMode)
        _analysisJob.value = AnalysisJobState(phase = AnalysisJobPhase.Completed)
    }

    private fun resetTranscriptForRetry() {
        _uiState.value = _uiState.value.copy(
            messages = emptyList(),
            modelInteractions = emptyList(),
            toolActivities = emptyList(),
            activeTool = null,
            completedSteps = 0,
            report = null,
            error = null,
            completionWarning = null,
            transientError = null,
            streamingText = "",
            analysisPlan = null,
            completedPlanSteps = 0
        )
        reportQuestion = null
    }

    // ------------------------------------------------------------- lifecycle

    /**
     * With an Application-owned run the ViewModel's destruction must not stop
     * the analysis — that is the entire point of the coordinator.  Only a
     * legacy in-ViewModel run (no coordinator) still needs its agent cancelled.
     */
    override fun onCleared() {
        if (runCoordinator == null && isRunning()) {
            runGeneration += 1
            agent.cancel()
            activeJob?.cancel()
            activeJob = null
        }
        super.onCleared()
    }

    // ---------------------------------------------------------------- helpers

    private fun isRunning(): Boolean =
        runCoordinator?.isRunning ?: (activeJob?.isActive == true)

    /**
     * AI-07 §4.5 mapping.  This is the Agent's own job state; it never writes to
     * PacketListViewModel's, so the two banners cannot overwrite each other.
     */
    private fun publishJob(phase: AgentRunPhase, errorCode: AgentErrorCode? = null) {
        val state = _uiState.value
        val jobPhase = when (phase) {
            AgentRunPhase.Preparing,
            AgentRunPhase.Investigating,
            AgentRunPhase.WaitingForModel,
            AgentRunPhase.RunningTool,
            AgentRunPhase.Finalizing,
            AgentRunPhase.Revising,
            AgentRunPhase.ValidatingReport -> AnalysisJobPhase.Running
            AgentRunPhase.Completed -> AnalysisJobPhase.Completed
            AgentRunPhase.Failed -> AnalysisJobPhase.Failed
            AgentRunPhase.FailedWithPartialReport -> AnalysisJobPhase.Failed
            AgentRunPhase.Cancelled -> AnalysisJobPhase.Cancelled
            AgentRunPhase.Idle -> AnalysisJobPhase.Completed
        }
        _analysisJob.value = AnalysisJobState(
            phase = jobPhase,
            processed = state.completedSteps.toLong(),
            total = state.maxSteps.toLong(),
            scope = lastScope,
            errorCode = (errorCode ?: state.error?.code)?.name,
            message = phaseMessage(phase, state)
        )
    }

    /** Short, already-public status text; never a model's own words. */
    private fun phaseMessage(phase: AgentRunPhase, state: ProtocolAgentUiState): String? =
        when (phase) {
            AgentRunPhase.Preparing -> "Preparing the capture for analysis"
            AgentRunPhase.Investigating -> "Investigating the capture"
            AgentRunPhase.WaitingForModel -> "Waiting for the analysis model"
            AgentRunPhase.RunningTool -> state.activeTool?.toolName
                ?.takeIf { it.isNotBlank() }
                ?.let { "Running $it" }
                ?: "Running an analysis step"
            AgentRunPhase.ValidatingReport -> "Checking the evidence"
            AgentRunPhase.Finalizing -> "Preparing the final report"
            AgentRunPhase.Revising -> "Correcting report citations"
            AgentRunPhase.Completed -> state.completionWarning?.userMessage ?: "Analysis complete"
            AgentRunPhase.Failed -> state.error?.userMessage
            AgentRunPhase.FailedWithPartialReport ->
                state.error?.userMessage ?: "Analysis stopped with a partial report"
            AgentRunPhase.Cancelled -> "Analysis cancelled"
            AgentRunPhase.Idle -> null
        }

    private fun publishTransient(error: AgentError) {
        _uiState.value = _uiState.value.copy(transientError = error)
    }

    private fun completionWarning(stopReason: AgentStopReason): AgentError? = when (stopReason) {
        AgentStopReason.ModelFinal -> null
        AgentStopReason.PlanComplete -> null
        AgentStopReason.MaxStepsReached -> AgentError(
            code = AgentErrorCode.MAX_STEPS_REACHED,
            userMessage = "The analysis stopped after reaching its step limit. The report is incomplete.",
            details = mapOf("stopReason" to stopReason.name)
        )
        AgentStopReason.MaxDurationReached -> AgentError(
            code = AgentErrorCode.MAX_STEPS_REACHED,
            userMessage = "The analysis stopped after reaching its time limit. The report is incomplete.",
            details = mapOf("stopReason" to stopReason.name)
        )
        AgentStopReason.ContextLimit -> AgentError(
            code = AgentErrorCode.CONTEXT_LIMIT,
            userMessage = "The analysis stopped after reaching its context or data limit. The report is incomplete.",
            details = mapOf("stopReason" to stopReason.name)
        )
        AgentStopReason.RepeatedToolCall -> AgentError(
            code = AgentErrorCode.MAX_STEPS_REACHED,
            userMessage = "The analysis stopped because the model repeated a tool query. The report is incomplete.",
            details = mapOf("stopReason" to stopReason.name)
        )
        AgentStopReason.ToolFailure -> AgentError(
            code = AgentErrorCode.INTERNAL_ERROR,
            userMessage = "The analysis stopped because an analysis step failed. The report is incomplete.",
            details = mapOf("stopReason" to stopReason.name)
        )
        AgentStopReason.SessionChanged -> AgentError(
            code = AgentErrorCode.SESSION_CHANGED,
            userMessage = "The capture changed while the analysis was running. The report is incomplete.",
            details = mapOf("stopReason" to stopReason.name)
        )
        AgentStopReason.ModelFailure -> AgentError(
            code = AgentErrorCode.MODEL_UNAVAILABLE,
            userMessage = "The analysis model stopped responding before the report was finished.",
            details = mapOf("stopReason" to stopReason.name)
        )
        AgentStopReason.InvalidArguments -> AgentError(
            code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
            userMessage = "The model kept sending invalid tool arguments. The report is incomplete.",
            details = mapOf("stopReason" to stopReason.name)
        )
        AgentStopReason.Cancelled -> AgentError(
            code = AgentErrorCode.CANCELLED,
            userMessage = "The analysis was cancelled before the report was finished.",
            details = mapOf("stopReason" to stopReason.name)
        )
    }

    private fun errorMessage(error: AgentError) = AgentConversationItem(
        id = "error-$runGeneration-${_uiState.value.messages.size}",
        role = AgentConversationRole.Error,
        content = error.userMessage,
        createdAtMillis = clock(),
        error = error
    )

    /**
     * Move the report still on screen into the conversation's archive when the
     * incoming follow-up is about to replace it.  The stable round id makes
     * this idempotent across resumed sessions whose rounds were read back from
     * disk, so one round can never appear twice in the list.
     */
    private fun archivePriorRound(
        state: ProtocolAgentUiState,
        appendQuestion: Boolean
    ): List<AgentConversationRound> {
        if (!appendQuestion) return emptyList()
        val report = state.report ?: return state.pastReports
        val question = reportQuestion
            ?: state.messages.lastOrNull { it.role == AgentConversationRole.User }?.content.orEmpty()
        val round = AgentConversationRound(
            question = question,
            report = report,
            completedAtMillis = clock()
        )
        return if (state.pastReports.any { it.stableId == round.stableId }) {
            state.pastReports
        } else {
            state.pastReports + round
        }
    }

    private fun concurrentRunError() = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "Cancel the running analysis before starting another one.",
        retryable = true,
        details = mapOf("reason" to "concurrent_run")
    )

    private fun blankQuestionError() = AgentError(
        code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
        userMessage = "Enter a question before starting the analysis.",
        retryable = false,
        details = mapOf("field" to "question")
    )

    private fun noCaptureError() = AgentError(
        code = AgentErrorCode.NO_CAPTURE,
        userMessage = "Open a capture before starting an analysis.",
        retryable = false
    )

    private fun sessionChangedError() = AgentError(
        code = AgentErrorCode.SESSION_CHANGED,
        userMessage = "The capture changed, so the analysis was stopped.",
        retryable = true
    )

    private fun fingerprintPendingError() = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The capture is still being prepared. Try again in a moment.",
        retryable = true,
        details = mapOf("stage" to "fingerprint")
    )

    private fun nothingToRetryError() = AgentError(
        code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
        userMessage = "There is no previous question to retry.",
        retryable = false,
        details = mapOf("reason" to "no_previous_question")
    )

    private fun settingsReadOnlyError() = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "Model settings cannot be changed in this build.",
        retryable = false,
        details = mapOf("reason" to "settings_read_only")
    )

    private fun saveFailedError() = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The analysis could not be saved to this device.",
        retryable = true,
        details = mapOf("reason" to "session_store_write_failed")
    )

    private fun savedSessionUnavailableError() = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "That saved analysis could not be read.",
        retryable = false,
        details = mapOf("reason" to "saved_session_unreadable")
    )

    private fun savedSessionDeleteError() = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The saved analysis could not be deleted from this device.",
        retryable = true,
        details = mapOf("reason" to "saved_session_delete_failed")
    )

    private fun scenarioSaveFailedError() = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The scenario could not be saved to this device.",
        retryable = true,
        details = mapOf("reason" to "scenario_save_failed")
    )

    private fun scenarioCopyFailedError() = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The scenario could not be copied.",
        retryable = true,
        details = mapOf("reason" to "scenario_copy_failed")
    )

    private fun secretSaveError() = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The API key could not be stored securely.",
        retryable = false,
        details = mapOf("reason" to "secret_store_failed")
    )

    private data class PendingConsentRun(
        val question: String,
        val scope: AnalysisScope,
        val appendQuestion: Boolean,
        val privacyMode: AgentPrivacyMode,
        val identity: AgentRunIdentity,
        /** Explicit playbook id the blocked submission carried, if any. */
        val playbookId: String? = null,
        /** Display-filter override the blocked submission carried, if any. */
        val displayFilterOverride: String? = null,
        /** Evidence frame count the blocked submission carried, if any. */
        val evidenceFrameCount: Int? = null
    )

    private companion object {
        /**
         * Namespace for message ids read back from disk.
         *
         * A live run mints ids from a counter that restarts with the process, so
         * without this a follow-up on a resumed conversation would collide with
         * the ids it just restored.  The colon matches the separator the loop
         * already uses, and no session id starts with this word.
         */
        const val RESTORED_ID_PREFIX = "restored:"
    }
}
