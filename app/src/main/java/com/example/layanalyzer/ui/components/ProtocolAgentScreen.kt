package com.example.layanalyzer.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.FactCheck
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.HelpOutline
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import com.example.layanalyzer.R
import com.example.layanalyzer.ai.agent.AgentSettings
import com.example.layanalyzer.ai.agent.selectableMetadataMode
import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.ai.client.GatewayAccountUiState
import com.example.layanalyzer.ai.export.AgentReportExporter
import com.example.layanalyzer.ai.markdown.ReportMarkdown
import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.ScenarioPackageDescription
import com.example.layanalyzer.ai.playbook.ScenarioPackageSource
import com.example.layanalyzer.model.AgentConsentPrompt
import com.example.layanalyzer.model.AgentConversationRound
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentRequestPreview
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentAnalysisMode
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentFilterPreviewState
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.isHostConfirmedToolResult
import com.example.layanalyzer.model.AgentLocalDataCategory
import com.example.layanalyzer.model.AgentLocalDataUsage
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentEvidenceScope
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentSavedSession
import com.example.layanalyzer.model.AgentSavedSessionSummary
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.DisplayFilterUiState
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.ProtocolAgentUiState
import com.example.layanalyzer.viewmodel.formatFileSize
import com.example.layanalyzer.viewmodel.AgentScenarioDraft

/** Stable handles for the controls the UI tests drive. */
object AgentTestTags {
    const val QUESTION_INPUT = "agent_question_input"
    const val PRIVACY_REDACTED = "agent_privacy_redacted"
    const val PRIVACY_UNREDACTED = "agent_privacy_unredacted"
    const val REPORT_LIST = "agent_report_list"

    /** The folded run-setup row (scope / model / scenario rules). */
    const val RUN_CONFIG_TOGGLE = "agent_run_config_toggle"
}

/**
 * The Agent workspace page.
 *
 * The whole page is one [LazyColumn] with the composer pinned underneath, so a
 * report with many findings scrolls without the input drifting off screen and
 * without composing cards the user never reaches.
 *
 * Everything shown here comes from [ProtocolAgentUiState] and its explicit
 * in-memory interaction trace. The trace is normalized at the model boundary;
 * this screen never reaches for a snapshot or a model client.
 */
@Composable
fun ProtocolAgentScreen(
    uiState: ProtocolAgentUiState,
    currentFile: FileSessionInfo?,
    displayFilter: DisplayFilterUiState,
    onSubmitQuestion: (String, AnalysisScope, String?, Int?) -> Unit,
    onContinueConversation: (String) -> Unit,
    onCancel: () -> Unit,
    onRetry: () -> Unit,
    onNewConversation: () -> Unit,
    onClearTransientError: () -> Unit,
    onFrameClick: (Long) -> Unit,
    onEvidenceClick: (AgentEvidence, AgentReport) -> Unit = { evidence, _ ->
        evidence.frameNumber?.let(onFrameClick)
    },
    onSaveFinding: (AgentFinding, AgentReport) -> Unit = { _, _ -> },
    onExportReport: (AgentReport) -> Unit = {},
    agentFilterPreview: AgentFilterPreviewState? = null,
    onConfirmAgentFilterPreview: () -> Unit = {},
    onDismissAgentFilterPreview: () -> Unit = {},
    modifier: Modifier = Modifier,
    settings: AgentSettings = AgentSettings(),
    onPrivacyModeChange: (AgentPrivacyMode) -> Unit = {},
    consentPrompt: AgentConsentPrompt? = null,
    onModelSelectionChange: (String, String) -> Unit = { _, _ -> },
    onAcceptConsent: () -> Unit = {},
    onDeclineConsent: () -> Unit = {},
    gatewayAccount: GatewayAccountUiState = GatewayAccountUiState(),
    onRefreshGatewayAccount: () -> Unit = {},
    /** AI-24 saved analyses and local-data controls. */
    savedSessions: List<AgentSavedSessionSummary> = emptyList(),
    /** Conversation ids whose delete is in flight; their rows refuse re-taps. */
    deletingSavedSessions: Set<String> = emptySet(),
    restoredSession: AgentSavedSession? = null,
    /** Whether the restored report describes the capture that is open. */
    restoredSessionMatchesCapture: Boolean = false,
    /** Phase 4: an interrupted run waiting for user action. */
    interruptedJob: com.example.layanalyzer.data.AnalysisJobCheckpoint? = null,
    onResumeInterruptedJob: () -> Unit = {},
    onDismissInterruptedJob: () -> Unit = {},
    localDataUsage: AgentLocalDataUsage = AgentLocalDataUsage(),
    onOpenSavedSession: (String) -> Unit = {},
    onDeleteSavedSession: (String) -> Unit = {},
    onDismissRestoredSession: () -> Unit = {},
    onClearLocalData: (Set<AgentLocalDataCategory>) -> Unit = {},
    onExportDiagnostics: () -> Unit = {},
    /** AI-26: the active scenario rule package shown for provenance. */
    scenarioPackage: ScenarioPackageDescription? = null,
    playbooks: List<AgentPlaybook> = emptyList(),
    /** Records that a scenario chip was picked, so it rises in the list. */
    onPlaybookUsed: (String) -> Unit = {},
    /** Long-press menu: edit a user scenario in the scenario editor. */
    onEditScenario: (AgentPlaybook) -> Unit = {},
    /** Long-press menu: save a duplicate of the scenario under a fresh id. */
    onCopyScenario: (String) -> Unit = {},
    /** Long-press menu: delete a user scenario. */
    onDeleteScenario: (String) -> Unit = {},
    /**
     * Long-press menu: open the scenario read-only. Mounted as the read-only
     * mode of the full-screen scenario editor (SRE-EDITOR-01).
     */
    onViewScenarioDetails: (AgentPlaybook) -> Unit = {},
    /**
     * The "New scenario" chip on the expanded scenario list. Opens the
     * scenario editor on a blank draft (SRE-EDITOR-01).
     */
    onNewScenario: () -> Unit = {},
    /** The open scenario editor draft (edit or read-only details); null closes the editor. */
    editingScenario: AgentScenarioDraft? = null,
    /** Closes the scenario editor without persisting anything. */
    onDismissScenarioEditor: () -> Unit = {},
    /**
     * Persists the scenario draft; wired to the editor's bottom action bar
     * (SRE-EDITOR-06).  Carries no playbook (OPT-DRAFT-01): the draft in the
     * ViewModel is the single source of the editing input, and the editor's
     * field changes already went through [onScenarioPlaybookChange].
     */
    onSaveScenario: () -> Unit = {},
    /**
     * OPT-SAVE-01: true while the ViewModel has a scenario save in flight.
     * Threaded to the editor so its Save button disables for that window,
     * matching the ViewModel's refusal of repeat taps.
     */
    scenarioSaving: Boolean = false,
    /**
     * Routes an edited playbook from the scenario editor back into the
     * ViewModel draft (OPT-DRAFT-01, controlled editor): the screen renders
     * the draft and never holds a copy, so a rotation re-reads the flow with
     * the typed content intact.
     */
    onScenarioPlaybookChange: (AgentPlaybook) -> Unit = {},
    /**
     * Monotonic count of successful scenario saves published by the ViewModel
     * (SRE-EDITOR-06).  An increase over the announced count raises the
     * "Scenario saved" snackbar.
     */
    scenarioSaveCompleted: Int = 0,
    /**
     * OPT-QNT-01: the distinct quarantine reason codes the ViewModel collected
     * from the user scenario layer.  One notice per newly appended code; the
     * codes themselves stay out of the UI — the snackbar text is fixed, so no
     * file name or scenario content can leak through this surface.
     */
    scenarioQuarantineCodes: List<String> = emptyList(),
    /** Tools the scenario editor's Initial tools chips offer; empty renders no chips. */
    scenarioToolWhitelist: Set<String> = emptySet(),
    onClearScenarioPackage: () -> Unit = {},
    /**
     * EVL-UI-07: the current run's audit record, the badge's only trustworthy
     * source for the cited/flagged counts. Null (no run record) suppresses the
     * coverage section entirely rather than printing invented numbers.
     */
    evidenceCoverageRun: AgentRunRecord? = null
) {
    if (currentFile == null) {
        AgentNoCaptureState(modifier)
        return
    }

    // Saved rather than remembered: a rotation must not discard a half-typed
    // question or silently move the analysis back to the whole file.  Neither is
    // ever auto-submitted — only the send button and the chips call the
    // ViewModel, which is what keeps a rebuild from re-asking a question.
    var question by rememberSaveable(currentFile.localPath) { mutableStateOf("") }
    var composerPrivacyMode by remember(settings.privacyMode) {
        mutableStateOf(settings.privacyMode.selectableMetadataMode())
    }
    // A display filter is usually the user's intent for an on-device Agent
    // run.  Starting there avoids an accidental full-file dissection on a
    // packet-dense capture; Complete file remains an explicit choice.
    var selectedScope by rememberSaveable(currentFile.localPath) {
        mutableStateOf(
            if (displayFilter.appliedExpression.isNotBlank()) {
                AnalysisScope.CurrentFilter
            } else {
                AnalysisScope.CompleteFile
            }
        )
    }
    // Keep an explicit choice across rotation, while allowing a restored
    // pre-default state to follow the current filter. The second state key is
    // intentionally separate so older saved UI state is treated as implicit.
    var scopeWasExplicitlySelected by rememberSaveable(
        currentFile.localPath,
        "scope-explicit-v1"
    ) { mutableStateOf(false) }
    val hasDisplayFilter = displayFilter.appliedExpression.isNotBlank()
    val scope = when {
        !scopeWasExplicitlySelected && hasDisplayFilter -> AnalysisScope.CurrentFilter
        !hasDisplayFilter && selectedScope == AnalysisScope.CurrentFilter -> AnalysisScope.CompleteFile
        else -> selectedScope
    }
    var showClearLocalData by rememberSaveable { mutableStateOf(false) }
    var historyAndDataExpanded by rememberSaveable(currentFile.localPath, "history-and-data-v1") {
        mutableStateOf(false)
    }
    var selectedModelInteractionId by rememberSaveable { mutableStateOf<String?>(null) }
    val listState = rememberLazyListState()
    val selectedModelInteraction = uiState.modelInteractions.firstOrNull {
        it.id == selectedModelInteractionId
    }
    var pastReportsExpanded by rememberSaveable(currentFile.localPath, "past-reports-v1") {
        mutableStateOf(false)
    }
    var selectedPastReportId by rememberSaveable { mutableStateOf<String?>(null) }
    // The run setup (scope / model / scenario rules) starts folded: it is
    // chosen once per capture and is dead weight while a report is being read.
    // Saveable, so a rotation keeps a deliberately closed panel closed.
    var runConfigExpanded by rememberSaveable(currentFile.localPath, "run-config-v1") {
        mutableStateOf(false)
    }

    val isRunning = uiState.isRunning
    val canSend = question.isNotBlank() && !isRunning
    // Tool results remain in the ViewModel for the model/context contract, but
    // the public step trace already presents the same result in a more useful
    // form. Rendering both creates a duplicate tool entry for every call.
    val visibleMessages = uiState.messages.filterNot {
        it.role == AgentConversationRole.Tool
    }
    val submit: () -> Unit = {
        val trimmed = question.trim()
        if (trimmed.isNotEmpty() && !isRunning) {
            // A follow-up keeps the transcript; a first question starts one.
            // The evidence-workflow entry (EVL-UI-05) is what passes a
            // displayFilterOverride and its evidenceFrameCount; the free-text
            // and playbook paths here deliberately pass none.
            if (uiState.canContinue) onContinueConversation(trimmed)
            else onSubmitQuestion(trimmed, scope, null, null)
            question = ""
        }
    }

    // The conversation renders as a round accordion: one collapsible unit per
    // asked question, at most one of them expanded. null = all collapsed, a
    // legal resting state (and the state a stale key degrades to — a retry or
    // session switch can leave a key that no longer names any round, which
    // firstOrNull simply fails to match).
    var expandedRoundKey by rememberSaveable(currentFile.localPath, "round-accordion-v1") {
        mutableStateOf<String?>(null)
    }
    val rounds = buildTranscriptRounds(visibleMessages, uiState.report)
    val lastRoundKey = rounds.lastOrNull()?.key
    val archivedReports = orphanArchivedRounds(rounds, uiState.report, uiState.pastReports)
    val selectedPastReport = archivedReports.firstOrNull {
        it.stableId == selectedPastReportId
    }
    // v1–v2 archives hold a report but no messages at all; the main-area
    // fallback keeps their report reachable in the pre-accordion layout.
    val fallbackReport = uiState.report.takeIf { rounds.isEmpty() }

    // R3: when a new round appears during a run, it becomes the only expanded
    // round. A sentinel guards the one-frame window where isRunning is already
    // true but the coordinator snapshot has not yet appended the new User
    // bubble — acting on the transition alone would expand the old round and
    // immediately collapse it, a visible flicker.
    var lastSeenRoundKey by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(lastRoundKey, isRunning) {
        if (isRunning && lastRoundKey != null && lastRoundKey != lastSeenRoundKey) {
            expandedRoundKey = lastRoundKey
        }
        lastSeenRoundKey = lastRoundKey
    }

    // R6: the report reveal. On the running→finished transition with a report,
    // hand focus to the last round (whose embedded report is what just landed).
    // This is edge-triggered rather than a standing condition so a user who
    // expands a historical round afterwards is not yanked back on recombination.
    var lastSeenRunning by remember { mutableStateOf(false) }
    LaunchedEffect(isRunning, uiState.report) {
        val finished = lastSeenRunning && !isRunning
        lastSeenRunning = isRunning
        if (finished && uiState.report != null && lastRoundKey != null) {
            expandedRoundKey = lastRoundKey
        }
    }

    // The rendered list is a pure plan; scroll positioning reads the same plan,
    // so an index can never drift from what is on screen (the old hand-mirrored
    // counter skipped two conditional item types and pointed at the wrong row).
    val plan = agentListItemPlan(
        rounds = rounds,
        expandedRoundKey = expandedRoundKey,
        fallbackReport = fallbackReport,
        showScenarioPackage = scenarioPackage != null,
        // The local provider is deletable; an empty provider list or a
        // selection that no longer resolves to a configured provider must not
        // advertise a gateway account for a provider that does not exist.
        showGatewayAccount = settings.activeProvider != null &&
            settings.providerId != AgentSettings.LOCAL_PROVIDER_ID &&
            !settings.byokConfigured,
        interruptedJobRunId = interruptedJob?.takeIf { !isRunning }?.runId,
        showSuggestions = visibleMessages.isEmpty() && !isRunning,
        hasToolActivity = uiState.toolActivities.isNotEmpty() || uiState.modelInteractions.isNotEmpty(),
        isRunning = isRunning,
        error = uiState.error,
        showPartialReportWarning = uiState.phase == AgentRunPhase.FailedWithPartialReport,
        completionWarningMessage = uiState.completionWarning?.userMessage,
        tokenUsage = uiState.tokenUsage,
        isCancelled = uiState.phase == AgentRunPhase.Cancelled,
        singleSummaryMode = uiState.analysisMode == AgentAnalysisMode.SingleSummary
    )

    // The plan still describes the run-setup entries — it is the contract the
    // JVM tests pin — but the screen renders them inside one folded
    // [AgentRunConfigBar] instead of three full cards. Dropping their
    // placeholders here is what keeps the list and the scroll math in step:
    // every index below is looked up in this same filtered list.
    val renderedPlan = plan.filterNot {
        it.key == AgentScopeSpec.key ||
            it.key == AgentModelSpec.key ||
            it.key == AgentScenarioPackageSpec.key
    }

    // Follow the trace while a run is producing steps, but only while the user
    // is already near the tail: a list that jumps on every finished tool
    // cannot be scrolled backwards to read earlier output.  A run start (no
    // items yet) still snaps down so progress begins in view.
    LaunchedEffect(uiState.toolActivities.size, visibleMessages.size, isRunning) {
        if (!isRunning) return@LaunchedEffect
        val info = listState.layoutInfo
        if (info.totalItemsCount == 0) return@LaunchedEffect
        val lastItemInfo = info.visibleItemsInfo.lastOrNull() ?: return@LaunchedEffect
        val nearTail = lastItemInfo.index >= info.totalItemsCount - TAIL_FOLLOW_SLACK_ITEMS &&
            lastItemInfo.offset + lastItemInfo.size <= info.viewportEndOffset +
            TAIL_FOLLOW_VIEWPORT_SLACK_PX
        if (nearTail || info.visibleItemsInfo.size >= info.totalItemsCount) {
            listState.animateScrollToItem(info.totalItemsCount - 1)
        }
    }

    // The report reveal: scroll once per finished run, after the focus handoff
    // above has grown the expanded round's report sections. Keyed on the
    // anchor itself — not plan.size, which also moves on tool-trace updates
    // and would yank the user back while reading a historical round.
    var lastScrolledAnchor by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(renderedPlan.reportAnchorKey) {
        val anchor = renderedPlan.reportAnchorKey ?: return@LaunchedEffect
        if (anchor == lastScrolledAnchor) return@LaunchedEffect
        lastScrolledAnchor = anchor
        // Index into the rendered list, not the plan: the run-setup placeholders
        // are filtered out and the folded config row adds one item of its own.
        val anchorIndex = renderedPlan.indexOfFirst { it.key == anchor } +
            RunConfigListItemCount
        val target = snapshotFlow {
            anchorIndex to listState.layoutInfo.totalItemsCount
        }.first { (index, count) -> count > index }.second
        listState.animateScrollToItem(anchorIndex.coerceAtMost(target - 1))
    }

    // Scenario-copy feedback: the ViewModel copy is async fire-and-forget, so
    // the success notice is raised immediately on tap; a failed copy reports
    // through the ViewModel's transient error bar, not this snackbar.
    val snackbarHostState = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()
    val copyCreatedMessage = stringResource(R.string.agent_scenario_copy_created)
    // OPT-QUESTION-01: the question a scenario chip submits.  Chip clicks land
    // in a plain click handler, not the composition, so the localized `%1$s`
    // prefix is read here and passed down to [suggestedQuestion].
    val scenarioQuestionPrefix = stringResource(R.string.agent_scenario_question_prefix)

    // OPT-SHOW-01: the scenario chip row is collapsed by default and user
    // scenarios merge to the tail (SRE-MERGE-01), so a just-saved or
    // just-copied chip would sit hidden behind "More (N)" right under the
    // success snackbar it contradicts.  The collapse state therefore lives
    // here, at the host of both success signals, and [onScenarioListGrew] is
    // the single funnel every "the list gained a chip" event raises it
    // through — the same host channel OPT-COPY-01 extends, not a new signal
    // beside it.  Saveable so the user's own toggle survives a rebuild; the
    // re-expand itself is edge-triggered by the events below (the save path
    // is gated on [announcedSaveCount]), so rotation never replays it.
    var scenariosExpanded by rememberSaveable { mutableStateOf(false) }
    val onScenarioListGrew: () -> Unit = { scenariosExpanded = true }

    val onScenarioCopied: () -> Unit = {
        // The copy dispatch has just appended its chip to the tail; lift the
        // fold before the notice goes up so the new chip is on screen with it.
        onScenarioListGrew()
        coroutineScope.launch {
            snackbarHostState.showSnackbar(
                message = copyCreatedMessage,
                duration = SnackbarDuration.Short
            )
        }
    }

    // SRE-EDITOR-06: the save-completed notice.  The ViewModel bumps a counter
    // per successful save, and the announced count is saved state so a
    // rotation does not replay it.  A stored count above the live counter
    // (a recreated ViewModel after process death) self-heals on the next
    // difference instead of silencing the notice forever.
    val scenarioSavedMessage = stringResource(R.string.agent_scenario_editor_saved)
    var announcedSaveCount by rememberSaveable { mutableStateOf(0) }
    LaunchedEffect(scenarioSaveCompleted) {
        if (scenarioSaveCompleted != announcedSaveCount) {
            announcedSaveCount = scenarioSaveCompleted
            // OPT-SHOW-01: the same edge trigger as the notice — a save added
            // a chip at the tail, so show the list before saying it is saved.
            // On rotation the announced count restores equal, this branch
            // does not run, and the (saveable) expansion state is simply kept.
            onScenarioListGrew()
            snackbarHostState.showSnackbar(
                message = scenarioSavedMessage,
                duration = SnackbarDuration.Short
            )
        }
    }

    // OPT-QNT-01: the quarantine notice.  The user scenario layer used to
    // degrade a corrupt file to an empty layer with only a Log.w, so custom
    // scenarios vanished silently after a restart; now every distinct
    // quarantine reason code the ViewModel drained from the app-scoped
    // channel grows this list once (deduplicated already, one code one
    // notice) and each growth raises one snackbar.  Like the save notice, the
    // announced count is saved state so a rotation does not replay it.
    val scenarioQuarantineMessage = stringResource(R.string.agent_scenario_quarantine_notice)
    var announcedQuarantineCount by rememberSaveable { mutableStateOf(0) }
    LaunchedEffect(scenarioQuarantineCodes) {
        if (scenarioQuarantineCodes.size > announcedQuarantineCount) {
            announcedQuarantineCount = scenarioQuarantineCodes.size
            snackbarHostState.showSnackbar(
                message = scenarioQuarantineMessage,
                duration = SnackbarDuration.Long
            )
        } else if (scenarioQuarantineCodes.size < announcedQuarantineCount) {
            // A recreated ViewModel with a fresh channel cannot re-report the
            // old quarantines; resync so the notice stays reachable later
            // instead of being silenced forever.
            announcedQuarantineCount = scenarioQuarantineCodes.size
        }
    }

    Box(modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .testTag(AgentTestTags.REPORT_LIST),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // One folded row replaces the scope, model and scenario-rule
                // cards: static choices the user made once, which used to hold
                // the top of the page — and the transcript below it — hostage.
                item(key = "run-config") {
                    AgentRunConfigBar(
                        currentFile = currentFile,
                        displayFilter = displayFilter,
                        scope = scope,
                        scopeLocked = uiState.canContinue || isRunning,
                        scopeChanged = uiState.scopeChanged,
                        onScopeChange = {
                            selectedScope = it
                            scopeWasExplicitlySelected = true
                        },
                        settings = settings,
                        privacyMode = uiState.privacyMode,
                        onModelSelected = onModelSelectionChange,
                        scenarioPackage = scenarioPackage,
                        onClearScenarioPackage = onClearScenarioPackage,
                        expanded = runConfigExpanded,
                        onExpandedChange = { runConfigExpanded = it }
                    )
                }

                // From here down to the report, the list renders the plan: one
                // dispatcher keeps the LazyColumn and the scroll math honest.
                items(
                    renderedPlan,
                    key = { it.key },
                    contentType = { it.kind }
                ) { spec ->
                    when (spec) {
                        AgentScopeSpec,
                        AgentModelSpec,
                        AgentScenarioPackageSpec -> Unit // folded into "run-config"

                        AgentGatewayAccountSpec -> if (
                            settings.activeProvider != null &&
                            settings.providerId != AgentSettings.LOCAL_PROVIDER_ID &&
                            !settings.byokConfigured
                        ) {
                            AgentGatewayAccountCard(
                                state = gatewayAccount,
                                onRefresh = onRefreshGatewayAccount
                            )
                        }

                        is AgentInterruptedJobSpec -> interruptedJob?.let { job ->
                            AgentInterruptedJobRow(
                                job = job,
                                onResume = onResumeInterruptedJob,
                                onDismiss = onDismissInterruptedJob
                            )
                        }

                        AgentSuggestionsSpec ->
                            // Suggestions are only useful before there is a
                            // transcript to read; afterwards the composer is
                            // the place to continue.
                            AgentSuggestedQuestions(
                                playbooks = playbooks,
                                enabled = true,
                                expanded = scenariosExpanded,
                                onExpandedChange = { scenariosExpanded = it },
                                onEditScenario = onEditScenario,
                                onCopyScenario = onCopyScenario,
                                onDeleteScenario = onDeleteScenario,
                                onViewScenarioDetails = onViewScenarioDetails,
                                onNewScenario = onNewScenario,
                                onScenarioCopied = onScenarioCopied
                            ) { playbook ->
                                onPlaybookUsed(playbook.id)
                                onSubmitQuestion(playbook.suggestedQuestion(scenarioQuestionPrefix), scope, null, null)
                            }

                        is AgentRoundHeaderSpec -> AgentRoundHeader(
                            spec = spec,
                            onToggle = {
                                expandedRoundKey =
                                    if (spec.expanded) null else spec.round.key
                            }
                        )

                        is AgentRoundMessageSpec -> AgentMessageBubble(spec.message)

                        is AgentReportHeaderSpec -> AgentReportHeader(
                            report = spec.report,
                            playbooks = playbooks,
                            onExport = { onExportReport(spec.report) }
                        )

                        is AgentReportPartialNoticeSpec -> AgentNoticeRow(
                            icon = Icons.Default.Warning,
                            text = stringResource(R.string.agent_report_partial_explanation)
                        )

                        is AgentReportNoFindingsSpec -> Text(
                            text = stringResource(R.string.agent_report_no_findings),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        is AgentReportFindingsTitleSpec ->
                            AgentSectionLabel(stringResource(R.string.agent_report_findings))

                        is AgentReportFindingSpec -> AgentFindingCard(
                            finding = spec.finding,
                            onFrameClick = onFrameClick.takeIf { !spec.readOnly } ?: {},
                            onEvidenceClick = if (spec.readOnly) {
                                null
                            } else {
                                { evidence -> onEvidenceClick(evidence, spec.report) }
                            },
                            onSaveToWorkspace = if (spec.readOnly) {
                                null
                            } else {
                                { onSaveFinding(spec.finding, spec.report) }
                            }
                        )

                        is AgentReportLimitationsSpec -> AgentLimitationCard(spec.limitations)

                        is AgentReportNextStepsSpec -> Column {
                            AgentSectionLabel(stringResource(R.string.agent_report_next_steps))
                            spec.steps.forEach { step ->
                                Spacer(Modifier.height(3.dp))
                                AgentMarkdownText(step, style = MaterialTheme.typography.bodySmall, listItem = true)
                            }
                        }

                        is AgentReportCoverageSpec -> ReportCoverageBadgeSection(
                            model = ReportCoverageBadge.from(evidenceCoverageRun, spec.report),
                            canOpenFrames = !spec.readOnly,
                            onFrameClick = onFrameClick
                        )

                        AgentToolActivitySpec -> AgentToolActivityList(
                            activities = uiState.toolActivities,
                            modelInteractions = uiState.modelInteractions,
                            onOpenModelInteraction = { selectedModelInteractionId = it.id }
                        )

                        AgentPhaseSpec -> AgentPhaseIndicator(uiState)

                        is AgentErrorSpec -> AgentErrorCard(spec.error, onRetry)

                        AgentPartialReportWarningSpec -> AgentNoticeRow(
                            icon = Icons.Default.Warning,
                            text = "The model failed before the final conclusion. The report below contains only confirmed partial evidence."
                        )

                        is AgentCompletionWarningSpec -> AgentNoticeRow(
                            icon = Icons.Default.Warning,
                            text = spec.message
                        )

                        is AgentTokenUsageSpec -> {
                            val usage = spec.usage
                            Text(
                                text = if (usage.cachedInputTokens > 0) {
                                    stringResource(
                                        R.string.agent_token_usage_cached,
                                        formatAgentTokenCount(usage.inputTokens),
                                        formatAgentTokenCount(usage.cachedInputTokens),
                                        formatAgentTokenCount(usage.outputTokens)
                                    )
                                } else {
                                    stringResource(
                                        R.string.agent_token_usage,
                                        formatAgentTokenCount(usage.inputTokens),
                                        formatAgentTokenCount(usage.outputTokens)
                                    )
                                },
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                            )
                        }

                        AgentCancelledSpec -> AgentCancelledCard(onRetry)

                        AgentSingleSummaryModeSpec -> AgentNoticeRow(
                            icon = Icons.Default.Warning,
                            text = stringResource(R.string.agent_single_summary_mode)
                        )
                    }
                }

                // Earlier rounds' reports sit below the current one: the top
                // report is always the newest round, and the archive is an
                // on-demand view rather than a competing result.
                if (archivedReports.isNotEmpty()) {
                    item(key = "past-reports-header") {
                        AgentExpandableSectionHeader(
                            title = stringResource(R.string.agent_past_reports_title, archivedReports.size),
                            summary = archivedReports.lastOrNull()?.question,
                            expanded = pastReportsExpanded,
                            onToggle = { pastReportsExpanded = !pastReportsExpanded },
                            expandDescription = stringResource(R.string.agent_past_reports_expand),
                            collapseDescription = stringResource(R.string.agent_past_reports_collapse)
                        )
                    }
                    if (pastReportsExpanded) {
                        items(
                            archivedReports.asReversed(),
                            key = { "past-${it.stableId}" }
                        ) { round ->
                            AgentPastReportRow(
                                round = round,
                                onOpen = { selectedPastReportId = round.stableId }
                            )
                        }
                    }
                }

                // Saved analyses sit below the live report: they are a history,
                // not a result, and a user reading this run's findings should
                // not have to scroll past the archive to reach them.
                if (savedSessions.isNotEmpty() || !localDataUsage.isEmpty) {
                    item(key = "saved-analyses-title") {
                        AgentExpandableSectionHeader(
                            title = stringResource(R.string.agent_history_and_data_title),
                            summary = stringResource(
                                R.string.agent_history_and_data_summary,
                                savedSessions.size,
                                localDataUsage.totalBytes.formatFileSize()
                            ),
                            expanded = historyAndDataExpanded,
                            onToggle = { historyAndDataExpanded = !historyAndDataExpanded },
                            expandDescription = stringResource(R.string.agent_history_and_data_expand),
                            collapseDescription = stringResource(R.string.agent_history_and_data_collapse)
                        )
                    }
                    if (historyAndDataExpanded) {
                        items(savedSessions, key = { "saved-${it.conversationId}" }) { saved ->
                            AgentSavedSessionRow(
                                saved = saved,
                                deleting = saved.conversationId in deletingSavedSessions,
                                onOpen = { onOpenSavedSession(saved.conversationId) },
                                onDelete = { onDeleteSavedSession(saved.conversationId) }
                            )
                        }
                        if (savedSessions.isEmpty()) {
                            item(key = "saved-analyses-empty") {
                                Text(
                                    text = stringResource(R.string.agent_saved_analyses_empty),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                        item(key = "local-data") {
                            AgentLocalDataCard(
                                usage = localDataUsage,
                                onClear = { showClearLocalData = true },
                                onExportDiagnostics = onExportDiagnostics
                            )
                        }
                    }
                }
            }

            AgentComposer(
                question = question,
                onQuestionChange = { question = it },
                privacyMode = composerPrivacyMode,
                onPrivacyModeChange = { mode ->
                    composerPrivacyMode = mode
                    onPrivacyModeChange(mode)
                },
                privacyModeEnabled = !isRunning && visibleMessages.isEmpty(),
                isRunning = isRunning,
                canSend = canSend,
                isFollowUp = uiState.canContinue,
                canStartNew = visibleMessages.isNotEmpty() && !isRunning,
                onSend = submit,
                onCancel = onCancel,
                onNewConversation = onNewConversation
            )
        }

        // Overlaid rather than stacked: a refused action is transient and must
        // not push the composer around while the user is still typing.
        uiState.transientError?.let { transient ->
            AgentTransientErrorBar(
                error = transient,
                onDismiss = onClearTransientError,
                modifier = Modifier.align(Alignment.BottomCenter)
            )
        }

        // The copy-created notice floats above the pinned composer so it never
        // blocks the question input while it is visible.
        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = ScenarioCopySnackbarBottomPadding)
        )
    }

    selectedModelInteraction?.let { interaction ->
        AgentModelInteractionDialog(
            interaction = interaction,
            onDismiss = { selectedModelInteractionId = null }
        )
    }

    consentPrompt?.let { prompt ->
        AgentConsentDialog(
            prompt = prompt,
            previewEnabled = settings.requestPreviewEnabled,
            onAccept = onAcceptConsent,
            onDecline = onDeclineConsent
        )
    }

    agentFilterPreview?.let { preview ->
        AgentFilterPreviewDialog(
            preview = preview,
            onConfirm = onConfirmAgentFilterPreview,
            onDismiss = onDismissAgentFilterPreview
        )
    }

    selectedPastReport?.let { round ->
        AgentPastReportDialog(
            round = round,
            onFrameClick = onFrameClick,
            onDismiss = { selectedPastReportId = null }
        )
    }

    restoredSession?.let { saved ->
        AgentSavedSessionDialog(
            saved = saved,
            // A saved report may only navigate when it describes the capture
            // that is open; otherwise its frame numbers point at packets in a
            // different file, so the dialog stays read-only.  The check belongs
            // to the ViewModel, which is what holds the live fingerprint.
            canOpenFrames = restoredSessionMatchesCapture,
            onFrameClick = onFrameClick,
            onDismiss = onDismissRestoredSession
        )
    }

    if (showClearLocalData) {
        AgentClearLocalDataDialog(
            usage = localDataUsage,
            onConfirm = { categories ->
                onClearLocalData(categories)
                showClearLocalData = false
            },
            onDismiss = { showClearLocalData = false }
        )
    }

    // Mounted last so it draws above the other dialogs: it is the one
    // full-screen surface here and nothing else should stack over it.  The
    // bottom action bar saves through onSaveScenario (SRE-EDITOR-06); a
    // rejection keeps the editor open with the errors written back, and a
    // success closes it and announces itself via scenarioSaveCompleted.
    editingScenario?.let { draft ->
        AgentScenarioEditorScreen(
            draft = draft,
            toolWhitelist = scenarioToolWhitelist,
            // OPT-COPY-01: the merged list lets the editor label a copied
            // scenario with its source's title instead of the raw id.
            playbooks = playbooks,
            onDismiss = onDismissScenarioEditor,
            onSave = onSaveScenario,
            // OPT-SAVE-01: the Save button greys out while a save is in
            // flight; the ViewModel's refusal of repeat taps still applies.
            savingScenario = scenarioSaving,
            onPlaybookChange = onScenarioPlaybookChange
        )
    }
}

internal fun formatAgentTokenCount(tokens: Int): String {
    val value = tokens.coerceAtLeast(0).toLong()
    val (divisor, suffix) = when {
        value >= 1_000_000L -> 1_000_000L to "m"
        value >= 1_000L -> 1_000L to "k"
        else -> return value.toString()
    }
    val roundedTenths = (value * 10L + divisor / 2L) / divisor
    return if (roundedTenths % 10L == 0L) {
        "${roundedTenths / 10L}$suffix"
    } else {
        "${roundedTenths / 10L}.${roundedTenths % 10L}$suffix"
    }
}

/**
 * One round's collapsible header: "Round N · question", with the round's
 * conclusion (or an interrupted marker) as the always-visible summary line.
 */
@Composable
private fun AgentRoundHeader(
    spec: AgentRoundHeaderSpec,
    onToggle: () -> Unit
) {
    val title = stringResource(R.string.agent_round_title, spec.ordinal, spec.round.question)
    val summary = when {
        spec.round.report != null -> remember(spec.round.report.summary) {
            ReportMarkdown.preview(spec.round.report.summary)
        }
        spec.running -> null
        else -> stringResource(R.string.agent_round_interrupted_summary)
    }
    AgentExpandableSectionHeader(
        title = title,
        summary = summary,
        expanded = spec.expanded,
        onToggle = onToggle,
        expandDescription = stringResource(R.string.agent_round_expand),
        collapseDescription = stringResource(R.string.agent_round_collapse)
    )
}

/**
 * A report's header row: title, completeness badge, copy/export, the summary
 * paragraph and the scenario provenance. The findings and trailing sections are
 * separate plan entries rendered around this one.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AgentReportHeader(
    report: AgentReport,
    playbooks: List<AgentPlaybook>,
    onExport: () -> Unit
) {
    val clipboard = LocalClipboardManager.current
    Column {
        HorizontalDivider()
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = stringResource(R.string.agent_report_title),
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(Modifier.width(8.dp))
            AgentCompletenessBadge(report.completeness)
        }
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
            verticalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            TextButton(
                onClick = {
                    clipboard.setText(AnnotatedString(AgentReportExporter().markdown(report)))
                }
            ) {
                Icon(Icons.Default.ContentCopy, contentDescription = null, Modifier.size(16.dp))
                Spacer(Modifier.width(5.dp))
                Text(stringResource(R.string.agent_copy_markdown))
            }
            TextButton(onClick = onExport) {
                Text(stringResource(R.string.agent_export_report))
            }
        }
        if (report.summary.isNotBlank()) {
            Spacer(Modifier.height(6.dp))
            AgentMarkdownText(report.summary)
        }
        // EVL-CONTEXT-04: when the run was framed by an evidence override,
        // say so on the report itself with the recorded evidence frame count.
        val evidenceScopeCount = AgentEvidenceScope.reportFrameCount(
            displayFilterOverride = report.provenance.displayFilter,
            evidenceFrameCount = report.provenance.evidenceFrameCount
        )
        if (evidenceScopeCount != null ||
            report.provenance.playbookVersion?.isNotBlank() == true
        ) {
            Spacer(Modifier.height(8.dp))
            AgentSectionLabel(stringResource(R.string.agent_report_provenance))
        }
        evidenceScopeCount?.let { frameCount ->
            Text(
                text = stringResource(R.string.agent_report_evidence_scope, frameCount),
                style = MaterialTheme.typography.bodySmall
            )
        }
        report.provenance.playbookVersion?.takeIf { it.isNotBlank() }?.let { versionedId ->
            val playbookName = playbooks.firstOrNull { it.versionedId == versionedId }?.title
                ?: versionedId.substringBeforeLast('@').replace('-', ' ')
                    .replaceFirstChar { it.uppercase() }
            Text(
                text = stringResource(R.string.agent_report_scenario, playbookName),
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                text = versionedId,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun AgentExpandableSectionHeader(
    title: String,
    summary: String?,
    expanded: Boolean,
    onToggle: () -> Unit,
    expandDescription: String,
    collapseDescription: String,
    modifier: Modifier = Modifier
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
        shape = RoundedCornerShape(8.dp),
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle)
    ) {
        Row(
            modifier = Modifier.padding(start = 12.dp, end = 8.dp, top = 9.dp, bottom = 9.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Medium
                )
                summary?.takeIf { it.isNotBlank() }?.let { text ->
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = text,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            Spacer(Modifier.width(8.dp))
            Icon(
                imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                contentDescription = if (expanded) collapseDescription else expandDescription,
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * EVL-UI-07: the report's evidence-coverage badge.
 *
 * [model] is null whenever the run record and the host limitation cannot be
 * reconciled, and then nothing at all is rendered — the badge is a receipt, and
 * a receipt that might contradict the limitation below it is worse than none.
 * The uncited frames open their packets only when [canOpenFrames]; a historical
 * round's frames belong to a capture that is not loaded, so there they stay
 * plain text.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ReportCoverageBadgeSection(
    model: ReportCoverageBadgeModel?,
    canOpenFrames: Boolean,
    onFrameClick: (Long) -> Unit
) {
    if (model == null) return
    var expanded by rememberSaveable { mutableStateOf(false) }
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.FactCheck,
                contentDescription = null,
                modifier = Modifier.size(16.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.width(6.dp))
            AgentSectionLabel(
                stringResource(
                    R.string.agent_report_coverage_badge,
                    model.citedCount,
                    model.flaggedCount
                )
            )
        }
        if (model.totalUncited > 0) {
            Spacer(Modifier.height(4.dp))
            AgentExpandableSectionHeader(
                title = stringResource(R.string.agent_report_coverage_uncited_title),
                summary = null,
                expanded = expanded,
                onToggle = { expanded = !expanded },
                expandDescription = stringResource(R.string.expand),
                collapseDescription = stringResource(R.string.collapse)
            )
            if (expanded) {
                Spacer(Modifier.height(4.dp))
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    model.uncitedFrames.forEach { frame ->
                        val label = stringResource(R.string.agent_evidence_frame, frame)
                        if (canOpenFrames) {
                            AssistChip(onClick = { onFrameClick(frame) }, label = { Text(label) })
                        } else {
                            Text(
                                text = label,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                if (model.uncitedOverflow > 0) {
                    Spacer(Modifier.height(3.dp))
                    Text(
                        text = stringResource(
                            R.string.agent_report_coverage_uncited_overflow,
                            model.uncitedOverflow
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

// ------------------------------------------------------- run configuration

/**
 * Scope, model and scenario rules, folded into one summary row.
 *
 * All three are decisions the user makes once, then never touches again while
 * reading — yet each used to own a full card at the top of the list, pushing
 * the transcript (and the report the user came back for) below the fold on a
 * phone. They now share a single tappable line that reads as a status strip —
 * "完整文件 · 本地模型 · 内置规则" — and expand into the real controls only on
 * demand. The row scrolls with the list rather than sitting above it: a folded
 * strip that cannot be scrolled away is still a strip taking up room.
 *
 * The fold is never silent about state that needs the user: [agent_run_config_attention]
 * raises an error-tinted marker on the collapsed row whenever the scope moved
 * underneath an open conversation or the rules fell back to the built-in
 * package, so nothing important is only discoverable by expanding.
 */
@Composable
private fun AgentRunConfigBar(
    currentFile: FileSessionInfo,
    displayFilter: DisplayFilterUiState,
    scope: AnalysisScope,
    scopeLocked: Boolean,
    scopeChanged: Boolean,
    onScopeChange: (AnalysisScope) -> Unit,
    settings: AgentSettings,
    privacyMode: AgentPrivacyMode,
    onModelSelected: (String, String) -> Unit,
    scenarioPackage: ScenarioPackageDescription?,
    onClearScenarioPackage: () -> Unit,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit
) {
    val normalizedSettings = settings.normalized()
    val activeProvider = normalizedSettings.providers
        .firstOrNull { it.id == normalizedSettings.providerId }
    val activeModel = activeProvider?.models?.firstOrNull { it.id == normalizedSettings.modelId }
    // The header only has one line to work with, so the model reads as a name:
    // the provider, the endpoint and the key source are all one tap away below.
    val modelSummary = if (
        normalizedSettings.activeProvider == null ||
        normalizedSettings.providerId == AgentSettings.LOCAL_PROVIDER_ID
    ) {
        stringResource(R.string.agent_run_config_model_local)
    } else {
        activeModel?.name?.takeIf { it.isNotBlank() }
            ?: activeModel?.id
            ?: normalizedSettings.modelId
    }
    val summary = listOfNotNull(
        stringResource(
            if (scope == AnalysisScope.CurrentFilter) {
                R.string.agent_scope_current_filter
            } else {
                R.string.agent_scope_complete_file
            }
        ),
        modelSummary,
        scenarioPackage?.let { packageDescription ->
            stringResource(
                when (packageDescription.source) {
                    ScenarioPackageSource.BuiltIn -> R.string.agent_run_config_package_builtin
                    ScenarioPackageSource.Downloaded -> R.string.agent_run_config_package_downloaded
                }
            )
        }
    ).joinToString(" · ")
    val needsAttention = scopeChanged || scenarioPackage?.fallbackApplied == true
    val toggleDescription = stringResource(
        if (expanded) R.string.agent_run_config_collapse else R.string.agent_run_config_expand
    )

    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 40.dp)
                    .clickable(role = Role.Button) { onExpandedChange(!expanded) }
                    .testTag(AgentTestTags.RUN_CONFIG_TOGGLE)
                    .semantics { contentDescription = toggleDescription }
                    .padding(horizontal = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.Tune,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = summary,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                if (needsAttention) {
                    Spacer(Modifier.width(6.dp))
                    Icon(
                        Icons.Default.Warning,
                        contentDescription = stringResource(R.string.agent_run_config_attention),
                        modifier = Modifier.size(15.dp),
                        tint = MaterialTheme.colorScheme.error
                    )
                }
                Spacer(Modifier.width(4.dp))
                Icon(
                    if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (expanded) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Column(Modifier.padding(horizontal = 12.dp)) {
                    AgentScopeControls(
                        currentFile = currentFile,
                        displayFilter = displayFilter,
                        scope = scope,
                        scopeLocked = scopeLocked,
                        scopeChanged = scopeChanged,
                        onScopeChange = onScopeChange
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    AgentModelControls(
                        settings = settings,
                        privacyMode = privacyMode,
                        onModelSelected = onModelSelected
                    )
                    scenarioPackage?.let { packageDescription ->
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        AgentScenarioPackageControls(
                            description = packageDescription,
                            onClearDownloaded = onClearScenarioPackage
                        )
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ scope

@Composable
private fun AgentScopeControls(
    currentFile: FileSessionInfo,
    displayFilter: DisplayFilterUiState,
    scope: AnalysisScope,
    scopeLocked: Boolean,
    scopeChanged: Boolean,
    onScopeChange: (AnalysisScope) -> Unit
) {
    val hasFilter = displayFilter.appliedExpression.isNotBlank()
    Column(Modifier.padding(vertical = 10.dp)) {
        AgentSectionLabel(stringResource(R.string.agent_scope_title))
        Spacer(Modifier.height(6.dp))
        Text(
            text = currentFile.displayName,
            style = MaterialTheme.typography.titleSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = stringResource(
                R.string.agent_scope_file_summary,
                currentFile.sizeBytes.formatFileSize(),
                currentFile.frameCount
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = scope == AnalysisScope.CompleteFile,
                onClick = { onScopeChange(AnalysisScope.CompleteFile) },
                enabled = !scopeLocked,
                label = { Text(stringResource(R.string.agent_scope_complete_file)) }
            )
            FilterChip(
                selected = scope == AnalysisScope.CurrentFilter,
                onClick = { onScopeChange(AnalysisScope.CurrentFilter) },
                // Offering "current filter" with no filter applied would
                // promise a narrower scope than the run would actually use.
                enabled = !scopeLocked && hasFilter,
                label = { Text(stringResource(R.string.agent_scope_current_filter)) }
            )
        }

        Spacer(Modifier.height(6.dp))
        Text(
            text = if (hasFilter) {
                stringResource(
                    R.string.agent_scope_filter_summary,
                    displayFilter.visibleCount,
                    displayFilter.totalCount,
                    displayFilter.appliedExpression
                )
            } else {
                stringResource(R.string.agent_scope_no_filter)
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )

        if (scopeChanged) {
            Spacer(Modifier.height(8.dp))
            AgentNoticeRow(
                icon = Icons.Default.Warning,
                text = stringResource(R.string.agent_scope_changed)
            )
        }
    }
}

@Composable
private fun AgentModelControls(
    settings: AgentSettings,
    privacyMode: AgentPrivacyMode,
    onModelSelected: (String, String) -> Unit
) {
    val normalizedSettings = settings.normalized()
    val providers = normalizedSettings.providers
    val activeProvider = providers.firstOrNull { it.id == normalizedSettings.providerId }
    val activeModel = activeProvider?.models?.firstOrNull { it.id == normalizedSettings.modelId }
    var providerMenuExpanded by remember { mutableStateOf(false) }
    var modelMenuExpanded by remember { mutableStateOf(false) }
    Column(Modifier.padding(vertical = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Lock, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.width(7.dp))
            AgentSectionLabel(stringResource(R.string.agent_model_status_title))
        }
        Spacer(Modifier.height(5.dp))
        Text(
            text = when {
                // The local provider is deletable, so the mock status line
                // also has to hold when a local provider does not exist at
                // all (all providers removed): a selection that cannot be
                // resolved to a configured provider is the offline demo.
                normalizedSettings.activeProvider == null ||
                    normalizedSettings.providerId == AgentSettings.LOCAL_PROVIDER_ID ->
                    stringResource(R.string.agent_model_mock)
                normalizedSettings.byokConfigured &&
                    normalizedSettings.providerId != AgentSettings.GATEWAY_PROVIDER_ID ->
                    stringResource(
                        R.string.agent_model_direct,
                        activeProvider?.name ?: normalizedSettings.providerId,
                        activeModel?.displayName ?: normalizedSettings.modelId
                    )
                else ->
                    stringResource(
                        R.string.agent_model_gateway,
                        activeProvider?.name ?: normalizedSettings.providerId,
                        activeModel?.displayName ?: normalizedSettings.modelId
                    )
            },
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box {
                TextButton(onClick = { providerMenuExpanded = true }) {
                    Text(
                        text = activeProvider?.name
                            ?: stringResource(R.string.agent_local_provider),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                DropdownMenu(
                    expanded = providerMenuExpanded,
                    onDismissRequest = { providerMenuExpanded = false }
                ) {
                    providers.forEach { provider ->
                        DropdownMenuItem(
                            text = { Text(provider.name) },
                            onClick = {
                                providerMenuExpanded = false
                                provider.models.firstOrNull()?.let { model ->
                                    onModelSelected(provider.id, model.id)
                                }
                            }
                        )
                    }
                }
            }
            Box {
                TextButton(
                    onClick = { modelMenuExpanded = true },
                    enabled = activeProvider?.models?.isNotEmpty() == true
                ) {
                    Text(
                        text = activeModel?.displayName
                            ?: normalizedSettings.modelId,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                DropdownMenu(
                    expanded = modelMenuExpanded,
                    onDismissRequest = { modelMenuExpanded = false }
                ) {
                    activeProvider?.models?.forEach { model ->
                        DropdownMenuItem(
                            text = { Text(model.displayName) },
                            onClick = {
                                modelMenuExpanded = false
                                onModelSelected(activeProvider.id, model.id)
                            }
                        )
                    }
                }
            }
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text = "${stringResource(R.string.agent_privacy_label)}: ${agentPrivacyLabel(privacyMode)}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun AgentScenarioPackageControls(
    description: ScenarioPackageDescription,
    onClearDownloaded: () -> Unit
) {
    Column(Modifier.padding(vertical = 10.dp)) {
        AgentSectionLabel(stringResource(R.string.agent_scenario_package_title))
        Spacer(Modifier.height(5.dp))
        Text(
            text = stringResource(
                R.string.agent_scenario_package_version,
                description.packageId,
                description.version,
                stringResource(
                    when (description.source) {
                        ScenarioPackageSource.BuiltIn -> R.string.agent_scenario_package_source_builtin
                        ScenarioPackageSource.Downloaded -> R.string.agent_scenario_package_source_downloaded
                    }
                )
            ),
            style = MaterialTheme.typography.bodySmall
        )
        if (description.changeSummary.isNotBlank()) {
            Spacer(Modifier.height(4.dp))
            Text(
                text = description.changeSummary,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (description.fallbackApplied) {
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.agent_scenario_package_fallback),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.error
            )
        }
        if (description.downloadedAvailable) {
            Spacer(Modifier.height(4.dp))
            TextButton(onClick = onClearDownloaded) {
                Text(stringResource(R.string.agent_scenario_package_clear))
            }
        }
    }
}

@Composable
private fun AgentGatewayAccountCard(
    state: GatewayAccountUiState,
    onRefresh: () -> Unit
) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                AgentSectionLabel(stringResource(R.string.agent_gateway_account_title))
                Spacer(Modifier.weight(1f))
                IconButton(onClick = onRefresh, enabled = !state.isLoading) {
                    Icon(
                        Icons.Default.Refresh,
                        contentDescription = stringResource(R.string.agent_gateway_refresh)
                    )
                }
            }
            when {
                state.isLoading -> {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.agent_gateway_loading))
                    }
                }
                state.error != null -> {
                    Text(
                        text = state.error.userMessage,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                !state.isAvailable -> {
                    Text(
                        stringResource(R.string.agent_gateway_not_authenticated),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                else -> {
                    state.account?.let { account ->
                        Text(
                            stringResource(
                                R.string.agent_gateway_account_identity,
                                account.userId,
                                account.organizationId ?: "-"
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    if (state.models.isNotEmpty()) {
                        Text(
                            stringResource(
                                R.string.agent_gateway_models,
                                state.models.filter { it.allowed }
                                    .joinToString { it.displayName }
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    state.usage?.let { usage ->
                        Spacer(Modifier.height(4.dp))
                        GatewayUsageLines(usage)
                    }
                }
            }
        }
    }
}

@Composable
private fun GatewayUsageLines(
    usage: com.example.layanalyzer.ai.client.GatewayUsage
) {
    val quota = usage.quota
    val lines = mutableListOf<String>()
    if (quota.requestsPerMinute != null) {
        lines += stringResource(
            R.string.agent_gateway_requests,
            usage.requestsThisMinute,
            quota.requestsPerMinute
        )
    }
    if (quota.concurrentSessions != null) {
        lines += stringResource(
            R.string.agent_gateway_concurrency,
            usage.activeSessions,
            quota.concurrentSessions
        )
    }
    if (quota.tokensPerMonth != null) {
        lines += stringResource(
            R.string.agent_gateway_tokens,
            usage.tokensThisMonth,
            quota.tokensPerMonth
        )
    }
    if (quota.costMicrosPerMonth != null) {
        lines += stringResource(
            R.string.agent_gateway_cost,
            usage.costMicrosThisMonth,
            quota.costMicrosPerMonth
        )
    }
    if (lines.isEmpty()) {
        Text(stringResource(R.string.agent_gateway_usage_unavailable), style = MaterialTheme.typography.bodySmall)
    } else {
        lines.forEach { line ->
            Text(line, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun AgentConsentDialog(
    prompt: AgentConsentPrompt,
    previewEnabled: Boolean,
    onAccept: () -> Unit,
    onDecline: () -> Unit
) {
    var showPreview by rememberSaveable(prompt.modelId, prompt.preview.totalCharacters) {
        mutableStateOf(false)
    }
    AlertDialog(
        onDismissRequest = onDecline,
        title = { Text(stringResource(R.string.agent_consent_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
                Text(
                    stringResource(
                        R.string.agent_consent_provider,
                        prompt.providerName.ifBlank { prompt.providerId },
                        prompt.modelName.ifBlank { prompt.modelId }
                    )
                )
                Text(stringResource(R.string.agent_consent_scope, prompt.frameCount, prompt.scope.name))
                if (prompt.appliedDisplayFilter.isNotBlank()) {
                    Text(
                        stringResource(
                            R.string.agent_consent_filter,
                            prompt.appliedDisplayFilter
                        ),
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                prompt.preview.categories.forEach { category ->
                    Text(
                        stringResource(
                            R.string.agent_consent_category,
                            categoryLabel(category.category),
                            category.itemCount
                        ),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                Text(
                    stringResource(R.string.agent_consent_raw_capture_guarantee),
                    style = MaterialTheme.typography.bodySmall
                )
                if (prompt.privacyMode == AgentPrivacyMode.UnredactedMetadata) {
                    Text(
                        stringResource(R.string.agent_consent_unredacted_notice),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                Text(
                    stringResource(R.string.agent_consent_cost_notice),
                    style = MaterialTheme.typography.bodySmall
                )
                Text(
                    stringResource(R.string.agent_consent_truncation),
                    style = MaterialTheme.typography.bodySmall
                )
                if (previewEnabled) {
                    TextButton(onClick = { showPreview = true }) {
                        Text(stringResource(R.string.agent_view_request_preview))
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onAccept) { Text(stringResource(R.string.agent_consent_accept)) }
        },
        dismissButton = {
            TextButton(onClick = onDecline) { Text(stringResource(R.string.agent_consent_decline)) }
        }
    )

    if (showPreview) {
        AgentRequestPreviewDialog(prompt.preview) { showPreview = false }
    }
}

@Composable
private fun AgentRequestPreviewDialog(
    preview: AgentRequestPreview,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.agent_request_preview_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    stringResource(
                        R.string.agent_preview_totals,
                        preview.totalCharacters,
                        preview.estimatedTokens
                    )
                )
                preview.messages.forEach { message ->
                    Text(
                        stringResource(
                            R.string.agent_preview_message,
                            message.role.name,
                            message.characterCount,
                            message.estimatedTokens
                        ),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                if (preview.toolNames.isNotEmpty()) {
                    Text(
                        stringResource(R.string.agent_preview_tools, preview.toolNames.joinToString()),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                preview.categories.forEach { category ->
                    Text(
                        stringResource(
                            R.string.agent_preview_category,
                            categoryLabel(category.category),
                            category.itemCount
                        ),
                        style = MaterialTheme.typography.bodySmall
                    )
                    category.examples.forEach { example ->
                        Text(
                            stringResource(R.string.agent_preview_example, example),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                if (preview.truncated) {
                    Text(stringResource(R.string.agent_preview_truncated))
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) } }
    )
}

@Composable
private fun categoryLabel(category: AgentDataSensitivity): String = stringResource(
    when (category) {
        AgentDataSensitivity.Aggregate -> R.string.agent_data_category_aggregate
        AgentDataSensitivity.Metadata -> R.string.agent_data_category_metadata
        AgentDataSensitivity.Identifier -> R.string.agent_data_category_identifier
        AgentDataSensitivity.Payload -> R.string.agent_data_category_payload
        AgentDataSensitivity.Credential -> R.string.agent_data_category_credential
        AgentDataSensitivity.Unknown -> R.string.agent_data_category_unknown
    }
)

/** How many scenarios stay visible before the user asks for the rest. */
private const val COLLAPSED_SCENARIO_COUNT = 4

/** How many scenarios the collapsed chip row hides behind "More (N)". */
internal fun hiddenScenarioCount(totalScenarios: Int): Int =
    (totalScenarios - COLLAPSED_SCENARIO_COUNT).coerceAtLeast(0)

/**
 * The scenarios the chip row renders: the collapsed head while folded (and a
 * list that never overflows), or everything once expanded.  Kept generic and
 * side-effect-free so the fold rule the OPT-SHOW-01 auto-expand serves — a
 * tail-appended chip is invisible until expanded — is JVM-testable.
 */
internal fun <T> visibleScenarios(playbooks: List<T>, expanded: Boolean): List<T> =
    if (expanded || hiddenScenarioCount(playbooks.size) == 0) {
        playbooks
    } else {
        playbooks.take(COLLAPSED_SCENARIO_COUNT)
    }

/**
 * Bottom clearance for the scenario-copy snackbar: it must float above the
 * pinned composer (one compact row — see [AgentComposer]) instead of covering
 * the input field for the whole snackbar duration.
 */
private val ScenarioCopySnackbarBottomPadding = 72.dp

/**
 * How many list slots the folded run-setup row occupies. Kept as a named
 * constant because the report-anchor scroll offset is derived from it: the
 * rendered list is [agentListItemPlan] minus the setup placeholders plus this
 * one item, so any index into it shifts by exactly this much.
 */
private const val RunConfigListItemCount = 1

/**
 * Tail-follow tolerance for auto-scroll: the viewport must already show one of
 * this many last items for a new step to pull it down, and any overscroll past
 * the content edge still counts as "at the tail".
 */
private const val TAIL_FOLLOW_SLACK_ITEMS = 2
private const val TAIL_FOLLOW_VIEWPORT_SLACK_PX = 120f

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AgentSuggestedQuestions(
    playbooks: List<AgentPlaybook>,
    enabled: Boolean,
    /**
     * OPT-SHOW-01: whether the fold is open.  Host-owned rather than a local
     * `rememberSaveable` so the save/copy success events can lift it — the
     * new chip sits at the tail (SRE-MERGE-01) and would otherwise hide
     * behind "More (N)" under the notice that says it was saved.
     */
    expanded: Boolean,
    /** Routes the user's own More/Less toggle back into the host state. */
    onExpandedChange: (Boolean) -> Unit,
    onEditScenario: (AgentPlaybook) -> Unit = {},
    onCopyScenario: (String) -> Unit = {},
    onDeleteScenario: (String) -> Unit = {},
    onViewScenarioDetails: (AgentPlaybook) -> Unit = {},
    /** Taps the "New scenario" chip; the editor mounts in SRE-EDITOR-01. */
    onNewScenario: () -> Unit = {},
    /** Fires right after a copy dispatch, to raise the success snackbar. */
    onScenarioCopied: () -> Unit = {},
    onPick: (AgentPlaybook) -> Unit
) {
    // A verified package ships a dozen scenarios; showing them all buries the
    // rest of the page on first open. The list arrives most-used first, so the
    // collapsed head is the useful part rather than an arbitrary prefix.
    // (OPT-SHOW-01: the fold itself lives in the host now — see the
    // `expanded` parameter — so success events can open it.)
    val hiddenCount = hiddenScenarioCount(playbooks.size)
    val visible = visibleScenarios(playbooks, expanded)
    // Success feedback is immediate on tap: the ViewModel copy runs async and
    // the refreshed chip list arrives on its own; a failure surfaces through
    // the transient error bar instead of the snackbar.
    val copyScenarioWithFeedback: (String) -> Unit = { playbookId ->
        onCopyScenario(playbookId)
        onScenarioCopied()
    }
    // Deletion is irreversible and this confirm dialog is the only safety net,
    // so the menu entry only stages the target here; the ViewModel call happens
    // after an explicit confirm. The chip then disappears through the
    // ViewModel's optimistic removal — no local list edit, and the in-flight
    // delete guard lives there too.
    var pendingDelete by remember { mutableStateOf<AgentPlaybook?>(null) }
    val deleteScenarioWithConfirm: (String) -> Unit = { playbookId ->
        pendingDelete = playbooks.firstOrNull { it.id == playbookId }
    }
    var showHelp by rememberSaveable { mutableStateOf(false) }

    Column {
        Text(
            text = stringResource(R.string.agent_idle_intro),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            AgentSectionLabel(stringResource(R.string.agent_suggested_questions))
            Spacer(Modifier.width(4.dp))
            // OPT-CHIP-01: no explicit size so the IconButton keeps its
            // Material default 48.dp touch target; the 16.dp Icon below
            // controls the visual size.
            IconButton(onClick = { showHelp = true }) {
                Icon(
                    Icons.Default.HelpOutline,
                    contentDescription = stringResource(R.string.agent_scenarios_help),
                    modifier = Modifier.size(16.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        Spacer(Modifier.height(2.dp))
        Text(
            text = stringResource(R.string.agent_scenarios_usage_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(4.dp))
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            visible.forEach { playbook ->
                AgentScenarioChipWithMenu(
                    playbook = playbook,
                    enabled = enabled,
                    onPick = onPick,
                    onEditScenario = onEditScenario,
                    onCopyScenario = copyScenarioWithFeedback,
                    onDeleteScenario = deleteScenarioWithConfirm,
                    onViewScenarioDetails = onViewScenarioDetails
                )
            }
            if (hiddenCount > 0) {
                AgentScenarioChip(
                    onClick = { onExpandedChange(!expanded) },
                    label = {
                        Text(
                            text = if (expanded) {
                                stringResource(R.string.agent_scenarios_less)
                            } else {
                                stringResource(R.string.agent_scenarios_more, hiddenCount)
                            },
                            style = MaterialTheme.typography.labelSmall
                        )
                    },
                    trailingIcon = {
                        Icon(
                            if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                )
            }
            // Shown exactly when the full playbook list is rendered (expanded
            // or nothing hidden), so the entry point always ends the expanded
            // list rather than the collapsed head.
            if (expanded || hiddenCount == 0) {
                AgentScenarioChip(
                    onClick = onNewScenario,
                    enabled = enabled,
                    leadingIcon = {
                        Icon(
                            Icons.Default.Add,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    label = {
                        Text(
                            text = stringResource(R.string.agent_scenario_add_new),
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                )
            }
        }
        pendingDelete?.let { pending ->
            AlertDialog(
                onDismissRequest = { pendingDelete = null },
                title = { Text(stringResource(R.string.agent_scenario_delete_title)) },
                text = {
                    Text(stringResource(R.string.agent_scenario_delete_confirm, pending.title))
                },
                confirmButton = {
                    TextButton(onClick = {
                        pendingDelete = null
                        onDeleteScenario(pending.id)
                    }) {
                        Text(stringResource(R.string.agent_scenario_delete_confirm_action))
                    }
                },
                dismissButton = {
                    TextButton(onClick = { pendingDelete = null }) {
                        Text(stringResource(R.string.cancel))
                    }
                }
            )
        }
        if (showHelp) {
            AlertDialog(
                onDismissRequest = { showHelp = false },
                title = { Text(stringResource(R.string.agent_scenarios_help_title)) },
                text = {
                    Text(stringResource(R.string.agent_scenarios_help_body))
                },
                confirmButton = {
                    TextButton(onClick = { showHelp = false }) {
                        Text(stringResource(R.string.agent_scenarios_help_close))
                    }
                }
            )
        }
    }
}

/**
 * One scenario chip plus its management menu. Hosting the [DropdownMenu]
 * inside the same [Box] anchors the menu to the chip. The menu opens from a
 * visible trailing ⋮ affordance — long-press still works — so discovery does
 * not hinge on a hidden gesture; entries come from [agentScenarioMenuActions],
 * so a built-in chip never offers edit or delete.
 */
@Composable
private fun AgentScenarioChipWithMenu(
    playbook: AgentPlaybook,
    enabled: Boolean,
    onPick: (AgentPlaybook) -> Unit,
    onEditScenario: (AgentPlaybook) -> Unit,
    onCopyScenario: (String) -> Unit,
    onDeleteScenario: (String) -> Unit,
    onViewScenarioDetails: (AgentPlaybook) -> Unit
) {
    var menuExpanded by remember { mutableStateOf(false) }
    val menuLabel = stringResource(R.string.agent_scenario_menu_open)
    Box {
        AgentScenarioChip(
            onClick = { onPick(playbook) },
            enabled = enabled,
            onLongClick = { menuExpanded = true },
            trailingIcon = {
                // OPT-CHIP-01: the ⋮ used to be a 14.dp clickable inside the
                // chip's combinedClickable area, so a slightly off-centre tap
                // fell through to the chip and started a full analysis run.
                // The clickable now owns a 28.dp box (double the old side,
                // still inside the chip's 32.dp height so nothing else moves);
                // a child of the chip, it consumes pointer input within its
                // own bounds before the chip's combinedClickable sees the tap.
                // The glyph keeps its 14.dp visual size, centred in the box.
                Box(
                    modifier = Modifier
                        .size(28.dp)
                        .clickable(
                            enabled = enabled,
                            onClickLabel = menuLabel,
                            role = Role.Button
                        ) { menuExpanded = true },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Default.MoreVert,
                        contentDescription = menuLabel,
                        modifier = Modifier.size(14.dp)
                    )
                }
            },
            label = { Text(playbook.title, style = MaterialTheme.typography.labelSmall) }
        )
        DropdownMenu(
            expanded = menuExpanded,
            onDismissRequest = { menuExpanded = false }
        ) {
            agentScenarioMenuActions(playbook.origin).forEach { action ->
                DropdownMenuItem(
                    text = { Text(action.menuLabel()) },
                    onClick = {
                        menuExpanded = false
                        action.dispatch(
                            playbook = playbook,
                            onEditScenario = onEditScenario,
                            onCopyScenario = onCopyScenario,
                            onDeleteScenario = onDeleteScenario,
                            onViewScenarioDetails = onViewScenarioDetails
                        )
                    }
                )
            }
        }
    }
}

/** Localized text for one scenario menu action. */
@Composable
private fun AgentScenarioMenuAction.menuLabel(): String = stringResource(
    when (this) {
        AgentScenarioMenuAction.Edit -> R.string.agent_scenario_menu_edit
        AgentScenarioMenuAction.ViewDetails -> R.string.agent_scenario_menu_view_details
        AgentScenarioMenuAction.CopyAsDuplicate -> R.string.agent_scenario_menu_copy_as_duplicate
        AgentScenarioMenuAction.Delete -> R.string.agent_scenario_menu_delete
    }
)

/**
 * Maps one menu action to the callback it triggers; the playbook itself goes
 * to the playbook-typed callbacks, its id to the id-typed ones.
 */
private fun AgentScenarioMenuAction.dispatch(
    playbook: AgentPlaybook,
    onEditScenario: (AgentPlaybook) -> Unit,
    onCopyScenario: (String) -> Unit,
    onDeleteScenario: (String) -> Unit,
    onViewScenarioDetails: (AgentPlaybook) -> Unit
) {
    when (this) {
        AgentScenarioMenuAction.Edit -> onEditScenario(playbook)
        AgentScenarioMenuAction.ViewDetails -> onViewScenarioDetails(playbook)
        AgentScenarioMenuAction.CopyAsDuplicate -> onCopyScenario(playbook.id)
        AgentScenarioMenuAction.Delete -> onDeleteScenario(playbook.id)
    }
}

/**
 * OPT-QUESTION-01: the question a scenario chip submits — [questionPrefix]
 * is the localized `%1$s` format string from the host composition (the chip
 * click itself is not a composable context, so the caller resolves it).
 */
private fun AgentPlaybook.suggestedQuestion(questionPrefix: String): String {
    val intent = intentHints.firstOrNull { it.isNotBlank() } ?: title
    return questionPrefix.format(intent)
}

// ----------------------------------------------------------- conversation

@Composable
private fun AgentMessageBubble(message: AgentConversationItem) {
    val isUser = message.role == AgentConversationRole.User
    val container = when (message.role) {
        AgentConversationRole.User -> MaterialTheme.colorScheme.primaryContainer
        AgentConversationRole.Error -> MaterialTheme.colorScheme.errorContainer
        else -> MaterialTheme.colorScheme.surfaceVariant
    }
    val content = when (message.role) {
        AgentConversationRole.User -> MaterialTheme.colorScheme.onPrimaryContainer
        AgentConversationRole.Error -> MaterialTheme.colorScheme.onErrorContainer
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = if (isUser) Arrangement.End else Arrangement.Start
    ) {
        Surface(
            color = container,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.widthIn(max = 320.dp)
        ) {
            Column(Modifier.padding(horizontal = 11.dp, vertical = 8.dp)) {
                Text(
                    text = agentRoleLabel(message.role, message.toolName),
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Medium,
                    color = content
                )
                Spacer(Modifier.height(3.dp))
                Text(message.content, style = MaterialTheme.typography.bodySmall, color = content)
                // Capture-derived text is labelled so a reader can tell an
                // observation apart from the model's own words.
                if (message.untrustedCaptureData) {
                    Spacer(Modifier.height(3.dp))
                    Text(
                        text = stringResource(R.string.agent_capture_derived),
                        style = MaterialTheme.typography.labelSmall,
                        color = content.copy(alpha = 0.75f)
                    )
                }
            }
        }
    }
}

@Composable
private fun AgentPhaseIndicator(uiState: ProtocolAgentUiState) {
    val phaseText = when (uiState.phase) {
        AgentRunPhase.Preparing -> stringResource(R.string.agent_phase_preparing)
        AgentRunPhase.Investigating -> "Investigating the capture"
        AgentRunPhase.WaitingForModel -> stringResource(R.string.agent_phase_waiting_model)
        AgentRunPhase.RunningTool -> uiState.activeTool
            ?.let { agentToolDisplayName(it.toolName) }
            ?: stringResource(R.string.agent_phase_running_tool)
        AgentRunPhase.ValidatingReport -> stringResource(R.string.agent_phase_validating)
        AgentRunPhase.Finalizing -> "Preparing the final report"
        AgentRunPhase.Revising -> "Correcting report citations"
        else -> stringResource(R.string.analyzing)
    }
    Column(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator(Modifier.size(15.dp), strokeWidth = 2.dp)
            Spacer(Modifier.width(9.dp))
            Text(phaseText, style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1f))
            Text(
                text = stringResource(
                    R.string.agent_steps_progress,
                    uiState.completedSteps,
                    uiState.maxSteps
                ),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(Modifier.height(5.dp))
        LinearProgressIndicator(Modifier.fillMaxWidth())
        uiState.analysisPlan?.let { plan ->
            val nextIndex = uiState.completedPlanSteps
            val next = plan.steps.getOrNull(nextIndex)
            Spacer(Modifier.height(6.dp))
            Text(
                text = if (next != null) {
                    stringResource(
                        R.string.agent_plan_progress,
                        (nextIndex + 1).coerceAtMost(plan.steps.size),
                        plan.steps.size,
                        next.purpose
                    )
                } else {
                    stringResource(R.string.agent_plan_complete, plan.steps.size)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
        if (uiState.streamingText.isNotBlank()) {
            Spacer(Modifier.height(6.dp))
            Text(
                text = uiState.streamingText,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 6,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

// ----------------------------------------------------------------- report

@Composable
private fun AgentFilterPreviewDialog(
    preview: AgentFilterPreviewState,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.agent_filter_preview_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.agent_filter_preview_current, preview.currentFilter.ifBlank { "(none)" }))
                Text(stringResource(R.string.agent_filter_preview_suggested, preview.suggestedFilter))
                Text(
                    stringResource(
                        R.string.agent_filter_preview_scope,
                        preview.currentScope.name,
                        preview.suggestedScope.name
                    ),
                    style = MaterialTheme.typography.bodySmall
                )
                when {
                    preview.isValidating -> Text(stringResource(R.string.agent_filter_preview_validating))
                    preview.error != null -> Text(
                        preview.error.userMessage,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm, enabled = preview.canApply) {
                Text(stringResource(R.string.apply))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

@Composable
private fun AgentCompletenessBadge(completeness: AgentReportCompleteness) {
    val label = when (completeness) {
        AgentReportCompleteness.Partial -> stringResource(R.string.agent_report_completeness_partial)
        AgentReportCompleteness.Incomplete -> stringResource(R.string.agent_report_completeness_incomplete)
        AgentReportCompleteness.Unknown -> stringResource(R.string.agent_report_completeness_unknown)
        AgentReportCompleteness.Complete -> return
    }
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        shape = RoundedCornerShape(6.dp)
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onTertiaryContainer,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp)
        )
    }
}

// ------------------------------------------------------------------ errors

@Composable
private fun AgentErrorCard(error: AgentError, onRetry: () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.ErrorOutline,
                    null,
                    Modifier.size(17.dp),
                    tint = MaterialTheme.colorScheme.onErrorContainer
                )
                Spacer(Modifier.width(7.dp))
                Text(
                    text = stringResource(R.string.agent_phase_failed),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            Spacer(Modifier.height(5.dp))
            Text(
                text = error.userMessage,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = agentErrorSuggestion(error.code),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.agent_error_code, error.code.name),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            error.details["remoteCode"]?.toString()?.takeIf { it.isNotBlank() }?.let { code ->
                Text(
                    text = stringResource(R.string.agent_error_remote_code, code),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            error.details["httpStatus"]?.toString()?.takeIf { it.isNotBlank() }?.let { status ->
                Text(
                    text = stringResource(R.string.agent_error_http_status, status),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            error.details["remoteMessage"]?.toString()?.takeIf { it.isNotBlank() }?.let { reason ->
                Text(
                    text = stringResource(R.string.agent_error_remote_message, reason),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            error.details["reason"]?.toString()?.takeIf { it.isNotBlank() }?.let { reason ->
                Text(
                    text = stringResource(R.string.agent_error_reason, reason),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            error.details["retryCount"]?.toString()?.takeIf { it.isNotBlank() }?.let { count ->
                Text(
                    text = stringResource(R.string.agent_error_retry_count, count),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            error.details["stage"]?.toString()?.takeIf { it.isNotBlank() }?.let { stage ->
                Text(
                    text = stringResource(R.string.agent_error_stage, stage),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            error.details["diagnosticId"]?.toString()?.takeIf { it.isNotBlank() }?.let { id ->
                val clipboard = LocalClipboardManager.current
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = stringResource(R.string.agent_error_diagnostic_id, id),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    IconButton(
                        onClick = { clipboard.setText(AnnotatedString(id)) },
                        modifier = Modifier.size(20.dp)
                    ) {
                        Icon(
                            Icons.Default.ContentCopy,
                            contentDescription = stringResource(R.string.agent_copy_diagnostic_id),
                            modifier = Modifier.size(13.dp),
                            tint = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }
            if (error.retryable) {
                Spacer(Modifier.height(4.dp))
                TextButton(onClick = onRetry) {
                    Icon(Icons.Default.Refresh, null, Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.retry))
                }
            }
        }
    }
}

@Composable
private fun AgentCancelledCard(onRetry: () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(
            Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.agent_phase_cancelled),
                    style = MaterialTheme.typography.titleSmall
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    text = stringResource(R.string.agent_cancelled_keeps_trace),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            TextButton(onClick = onRetry) { Text(stringResource(R.string.retry)) }
        }
    }
}

@Composable
private fun AgentTransientErrorBar(
    error: AgentError,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    // Scenario-layer storage failures are resource-ized here, keyed on the
    // stable reason code the ViewModel puts in [AgentError.details]; every
    // other transient message keeps the ViewModel-supplied wording.
    val message = when (error.details["reason"]) {
        "scenario_save_failed" -> stringResource(R.string.agent_scenario_error_save_failed)
        "scenario_copy_failed" -> stringResource(R.string.agent_scenario_error_copy_failed)
        else -> error.userMessage
    }
    Surface(
        color = MaterialTheme.colorScheme.inverseSurface,
        shape = RoundedCornerShape(8.dp),
        modifier = modifier
            .padding(16.dp)
            .imePadding()
    ) {
        Row(
            Modifier.padding(start = 14.dp, end = 6.dp, top = 4.dp, bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = message,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.inverseOnSurface,
                modifier = Modifier.widthIn(max = 260.dp)
            )
            TextButton(onClick = onDismiss) {
                Text(
                    text = stringResource(R.string.close),
                    color = MaterialTheme.colorScheme.inversePrimary
                )
            }
        }
    }
}

@Composable
private fun AgentNoticeRow(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.tertiary)
        Spacer(Modifier.width(7.dp))
        Text(text, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun AgentInterruptedJobRow(
    job: com.example.layanalyzer.data.AnalysisJobCheckpoint,
    onResume: () -> Unit,
    onDismiss: () -> Unit
) {
    val requiresConfirm =
        job.checkpoint == com.example.layanalyzer.data.AnalysisCheckpoint.ModelRequestStarted
    var showConfirm by rememberSaveable { mutableStateOf(false) }

    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        shape = RoundedCornerShape(6.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Default.Warning,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
                tint = MaterialTheme.colorScheme.onSecondaryContainer
            )
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.agent_interrupted_job_title),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSecondaryContainer
                )
                if (job.question.isNotBlank()) {
                    Text(
                        text = job.question,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                if (requiresConfirm) {
                    Text(
                        text = stringResource(R.string.agent_interrupted_job_billing_warning),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                }
            }
            TextButton(onClick = {
                if (requiresConfirm) showConfirm = true else onResume()
            }) {
                Text(stringResource(R.string.agent_interrupted_job_resume))
            }
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.agent_interrupted_job_dismiss))
            }
        }
    }

    if (showConfirm) {
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            title = { Text(stringResource(R.string.agent_interrupted_job_confirm_title)) },
            text = { Text(stringResource(R.string.agent_interrupted_job_billing_warning)) },
            confirmButton = {
                TextButton(onClick = {
                    showConfirm = false
                    onResume()
                }) {
                    Text(stringResource(R.string.agent_interrupted_job_resume))
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirm = false }) {
                    Text(stringResource(R.string.agent_interrupted_job_dismiss))
                }
            }
        )
    }
}


@Composable
private fun AgentNoCaptureState(modifier: Modifier) {
    Box(modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(
            text = stringResource(R.string.agent_no_capture),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(24.dp)
        )
    }
}

// ---------------------------------------------------------------- composer

/**
 * Shared height of the composer's controls. The privacy chip and the question
 * field agree on it so the row reads as one line rather than a taller input
 * next to a shorter chip; 40dp is what the field needs for one line of
 * [MaterialTheme.typography.bodyMedium] plus a comfortable tap target.
 */
private val ComposerFieldMinHeight = 40.dp

/** Corner radius shared by the question field and the privacy chip. */
private val ComposerCornerRadius = 20.dp

/** The question field grows to this many lines before it scrolls internally. */
private const val AgentQuestionFieldMaxLines = 4

/**
 * The question input and its send/stop control, held to a single row.
 *
 * The composer is pinned outside the LazyColumn so it stays reachable at large
 * font scales, but that is not a licence to spend a third of the viewport on
 * it. Everything it needs now fits one line: the privacy chip that used to own
 * a row above the field sits beside it, and "new conversation" became an icon
 * that only appears once there is a conversation to replace. Compared with the
 * old two-row composer this hands roughly 60dp of height back to the
 * transcript — which is what the user actually came to read.
 */
@Composable
@OptIn(ExperimentalMaterial3Api::class)
private fun AgentComposer(
    question: String,
    onQuestionChange: (String) -> Unit,
    privacyMode: AgentPrivacyMode,
    onPrivacyModeChange: (AgentPrivacyMode) -> Unit,
    privacyModeEnabled: Boolean,
    isRunning: Boolean,
    canSend: Boolean,
    isFollowUp: Boolean,
    canStartNew: Boolean,
    onSend: () -> Unit,
    onCancel: () -> Unit,
    onNewConversation: () -> Unit
) {
    Surface(tonalElevation = 2.dp) {
        Row(
            Modifier
                .fillMaxWidth()
                .imePadding()
                .padding(horizontal = 8.dp, vertical = 6.dp),
            // Bottom-aligned so the actions stay under the thumb while the
            // field grows to its line limit.
            verticalAlignment = Alignment.Bottom
        ) {
            AgentPrivacyModeChip(
                privacyMode = privacyMode,
                onPrivacyModeChange = onPrivacyModeChange,
                enabled = privacyModeEnabled
            )
            Spacer(Modifier.width(6.dp))
            AgentQuestionField(
                question = question,
                onQuestionChange = onQuestionChange,
                enabled = !isRunning,
                isFollowUp = isFollowUp,
                modifier = Modifier.weight(1f)
            )
            if (canStartNew) {
                IconButton(onClick = onNewConversation) {
                    Icon(
                        Icons.Default.Add,
                        contentDescription = stringResource(R.string.agent_new_conversation),
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
            if (isRunning) {
                IconButton(onClick = onCancel) {
                    Icon(
                        Icons.Default.Stop,
                        contentDescription = stringResource(R.string.agent_stop),
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            } else {
                IconButton(onClick = onSend, enabled = canSend) {
                    Icon(
                        Icons.Default.Send,
                        contentDescription = stringResource(R.string.agent_send),
                        tint = if (canSend) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        }
                    )
                }
            }
        }
    }
}

/**
 * The question field: a bare [BasicTextField] inside its own rounded surface.
 *
 * Material's outlined and filled text fields reserve 56dp whether or not the
 * content needs it — most of a row on a phone, for a control that usually holds
 * one short sentence. The decoration box below is what the field actually
 * needs and nothing more: the composer's corner radius, [ComposerFieldMinHeight]
 * at rest, and growth with the text up to [AgentQuestionFieldMaxLines].
 */
@Composable
private fun AgentQuestionField(
    question: String,
    onQuestionChange: (String) -> Unit,
    enabled: Boolean,
    isFollowUp: Boolean,
    modifier: Modifier = Modifier
) {
    val textStyle = MaterialTheme.typography.bodyMedium
    BasicTextField(
        value = question,
        onValueChange = onQuestionChange,
        modifier = modifier
            .heightIn(min = ComposerFieldMinHeight)
            .testTag(AgentTestTags.QUESTION_INPUT),
        enabled = enabled,
        textStyle = textStyle.copy(
            color = if (enabled) {
                MaterialTheme.colorScheme.onSurface
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            }
        ),
        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
        maxLines = AgentQuestionFieldMaxLines,
        decorationBox = { innerTextField ->
            Box(
                Modifier
                    .fillMaxWidth()
                    .background(
                        MaterialTheme.colorScheme.surfaceVariant,
                        RoundedCornerShape(ComposerCornerRadius)
                    )
                    .padding(horizontal = 14.dp, vertical = 9.dp),
                contentAlignment = Alignment.CenterStart
            ) {
                if (question.isEmpty()) {
                    Text(
                        text = stringResource(
                            if (isFollowUp) R.string.agent_follow_up else R.string.agent_question_hint
                        ),
                        style = textStyle,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                innerTextField()
            }
        }
    )
}

/**
 * The redacted/unredacted choice, as one compact chip beside the input.
 *
 * It is deliberately still a chip with words rather than a bare lock icon:
 * whether unredacted metadata leaves the device is not something a user should
 * have to tap to discover, and the error-tinted lock spells the risky state out
 * before the label is read. The chip stays clickable even when the choice is
 * locked: a user who wonders what the current mode is should be able to open
 * the menu and read it, and seeing the alternative greyed out explains *why* it
 * cannot be changed better than an inert label would. Only the menu items carry
 * the enabled state.
 */
@Composable
private fun AgentPrivacyModeChip(
    privacyMode: AgentPrivacyMode,
    onPrivacyModeChange: (AgentPrivacyMode) -> Unit,
    enabled: Boolean
) {
    var expanded by remember { mutableStateOf(false) }
    val unredacted = privacyMode == AgentPrivacyMode.UnredactedMetadata
    val modes = listOf(
        Triple(
            AgentPrivacyMode.RedactedMetadata,
            R.string.agent_privacy_redacted,
            AgentTestTags.PRIVACY_REDACTED
        ),
        Triple(
            AgentPrivacyMode.UnredactedMetadata,
            R.string.agent_privacy_unredacted,
            AgentTestTags.PRIVACY_UNREDACTED
        )
    )

    Box {
        val switchDescription = stringResource(R.string.agent_privacy_switch)
        Surface(
            modifier = Modifier
                .heightIn(min = ComposerFieldMinHeight)
                // The description sits on the chip rather than its icon: the
                // chip is the click target, so that is what a screen reader
                // announces.
                .clickable(role = Role.Button) { expanded = true }
                .semantics { contentDescription = switchDescription },
            shape = RoundedCornerShape(ComposerCornerRadius),
            color = MaterialTheme.colorScheme.surfaceVariant,
            contentColor = if (unredacted) {
                MaterialTheme.colorScheme.error
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            }
        ) {
            Row(
                Modifier.padding(horizontal = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = if (unredacted) {
                        Icons.Default.LockOpen
                    } else {
                        Icons.Default.Lock
                    },
                    // The chip already carries the description; repeating it
                    // here would put two matching nodes in the tree.
                    contentDescription = null,
                    modifier = Modifier.size(14.dp)
                )
                Spacer(Modifier.width(5.dp))
                Text(
                    text = stringResource(
                        if (unredacted) {
                            R.string.agent_privacy_short_unredacted
                        } else {
                            R.string.agent_privacy_short_redacted
                        }
                    ),
                    style = MaterialTheme.typography.labelSmall,
                    maxLines = 1
                )
            }
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            modes.forEach { (mode, label, tag) ->
                DropdownMenuItem(
                    text = { Text(stringResource(label)) },
                    enabled = enabled,
                    onClick = {
                        onPrivacyModeChange(mode)
                        expanded = false
                    },
                    modifier = Modifier
                        .testTag(tag)
                        // The menu item replaces a segmented button, so it has
                        // to keep carrying the selection state that control
                        // exposed; a plain menu item has none.
                        .semantics { selected = privacyMode == mode }
                )
            }
        }
    }
}

// ----------------------------------------------------------------- labels

@Composable
private fun agentRoleLabel(role: AgentConversationRole, toolName: String?): String = when (role) {
    AgentConversationRole.User -> stringResource(R.string.agent_role_you)
    AgentConversationRole.Assistant -> stringResource(R.string.agent_role_assistant)
    AgentConversationRole.Tool -> toolName?.let { agentToolDisplayName(it) }
        ?: stringResource(R.string.agent_role_tool)
    AgentConversationRole.System -> stringResource(R.string.agent_role_system)
    AgentConversationRole.Error -> stringResource(R.string.agent_phase_failed)
    AgentConversationRole.Unknown -> stringResource(R.string.agent_role_system)
}

@Composable
private fun agentPrivacyLabel(mode: AgentPrivacyMode): String = stringResource(
    when (mode) {
        AgentPrivacyMode.LocalOnly -> R.string.agent_privacy_local_only
        AgentPrivacyMode.RedactedMetadata -> R.string.agent_privacy_redacted
        AgentPrivacyMode.UnredactedMetadata -> R.string.agent_privacy_unredacted
        AgentPrivacyMode.SelectedPayload -> R.string.agent_privacy_selected_payload
        AgentPrivacyMode.Unknown -> R.string.agent_privacy_unknown
    }
)

/** Turns an error code into the next thing the user can actually do. */
@Composable
private fun agentErrorSuggestion(code: AgentErrorCode): String = stringResource(
    when (code) {
        AgentErrorCode.NO_CAPTURE -> R.string.agent_error_suggestion_no_capture
        AgentErrorCode.SESSION_CHANGED -> R.string.agent_error_suggestion_session_changed
        AgentErrorCode.FILTER_CONFLICT,
        AgentErrorCode.INVALID_DISPLAY_FILTER -> R.string.agent_error_suggestion_filter
        AgentErrorCode.MODEL_AUTH_FAILED,
        AgentErrorCode.MODEL_RATE_LIMITED,
        AgentErrorCode.MODEL_UNAVAILABLE -> R.string.agent_error_suggestion_model
        AgentErrorCode.PRIVACY_BLOCKED -> R.string.agent_error_suggestion_privacy
        AgentErrorCode.MAX_STEPS_REACHED,
        AgentErrorCode.CONTEXT_LIMIT,
        AgentErrorCode.TOOL_RESULT_TOO_LARGE -> R.string.agent_error_suggestion_budget
        AgentErrorCode.TOOL_TIMEOUT -> R.string.agent_error_suggestion_timeout
        else -> R.string.agent_error_suggestion_retry
    }
)

// ------------------------------------------------------- AI-24 saved analyses

/** One saved analysis in the on-device history. */
@Composable
private fun AgentSavedSessionRow(
    saved: AgentSavedSessionSummary,
    /** True while this row's delete is in flight: buttons lock and show progress. */
    deleting: Boolean,
    onOpen: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(
                text = saved.userQuestion.ifBlank {
                    remember(saved.summary) { ReportMarkdown.preview(saved.summary) }
                },
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(
                    R.string.agent_saved_analysis_meta,
                    saved.findingCount,
                    saved.sizeBytes.formatFileSize()
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            formatAgentSavedSessionTime(saved.savedAtMillis)?.let { savedAt ->
                Text(
                    text = stringResource(R.string.agent_saved_analysis_saved_at, savedAt),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            // Short conversation id the user can quote; tapping copies the full
            // id so a support report can be matched to the exact saved record.
            saved.conversationId.takeIf { it.isNotBlank() }?.let { conversationId ->
                val clipboard = LocalClipboardManager.current
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = stringResource(
                            R.string.agent_saved_analysis_conversation_id,
                            shortConversationId(conversationId)
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    IconButton(
                        onClick = { clipboard.setText(AnnotatedString(conversationId)) },
                        modifier = Modifier.size(20.dp)
                    ) {
                        Icon(
                            Icons.Default.ContentCopy,
                            contentDescription = stringResource(R.string.agent_copy_conversation_id),
                            modifier = Modifier.size(13.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            // Opening a session with a transcript returns to the conversation;
            // an older one can only show its report, so the button says which.
            if (saved.isResumable) {
                Text(
                    text = stringResource(
                        R.string.agent_saved_analysis_resumable,
                        saved.messageCount
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onOpen, enabled = !deleting) {
                    Text(
                        stringResource(
                            if (saved.isResumable) {
                                R.string.agent_saved_analysis_resume
                            } else {
                                R.string.agent_saved_analysis_open
                            }
                        )
                    )
                }
                TextButton(onClick = onDelete, enabled = !deleting) {
                    // A slow flash can keep the in-flight delete alive long
                    // enough for a refreshed list to redraw the row; the
                    // spinner says the first tap landed and refuses a second.
                    if (deleting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(15.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Text(stringResource(R.string.agent_saved_analysis_delete))
                    }
                }
            }
        }
    }
}

/** Short display form of a conversation id: `C-` plus the first 8 hex chars. */
private fun shortConversationId(conversationId: String): String =
    "C-" + conversationId.removePrefix("conv_").take(8)


/**
 * A saved report opened for viewing.
 *
 * When [canOpenFrames] is false the evidence is rendered as plain text rather
 * than as tappable chips: the frame numbers belong to a capture that is not
 * loaded, and tapping one would open an unrelated packet in the current file.
 */
@Composable
private fun AgentSavedSessionDialog(
    saved: AgentSavedSession,
    canOpenFrames: Boolean,
    onFrameClick: (Long) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(stringResource(R.string.agent_restored_title))
        },
        text = {
            // The saved dialog mirrors the live report: host-confirmed tool
            // results stay hidden, the underlying session still keeps them.
            val visibleFindings = saved.report.findings.filterNot { it.isHostConfirmedToolResult }
            LazyColumn(
                modifier = Modifier.height(420.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                if (saved.userQuestion.isNotBlank()) {
                    item {
                        Text(
                            stringResource(R.string.agent_restored_question, saved.userQuestion),
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                if (!canOpenFrames) {
                    item {
                        AgentNoticeRow(
                            icon = Icons.Default.Warning,
                            text = stringResource(R.string.agent_restored_read_only)
                        )
                    }
                }
                if (saved.report.summary.isNotBlank()) {
                    item {
                        AgentMarkdownText(saved.report.summary)
                    }
                }
                items(visibleFindings, key = { it.id.ifBlank { it.title } }) { finding ->
                    AgentFindingCard(
                        finding = finding,
                        onFrameClick = { frame -> if (canOpenFrames) onFrameClick(frame) },
                        onEvidenceClick = { evidence ->
                            if (canOpenFrames) evidence.frameNumber?.let(onFrameClick)
                        },
                        onSaveToWorkspace = null
                    )
                }
                if (saved.report.limitations.isNotEmpty()) {
                    item { AgentLimitationCard(saved.report.limitations) }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.agent_restored_close))
            }
        }
    )
}

// ----------------------------------------------------- multi-round reports

/** One archived round in the earlier-reports list. */
@Composable
private fun AgentPastReportRow(
    round: AgentConversationRound,
    onOpen: () -> Unit
) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(12.dp)) {
            if (round.question.isNotBlank()) {
                Text(
                    text = round.question,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.height(4.dp))
            if (round.report.summary.isNotBlank()) {
                Text(
                    text = remember(round.report.summary) { ReportMarkdown.preview(round.report.summary) },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis
                )
            }
            formatAgentSavedSessionTime(round.completedAtMillis)?.let { completedAt ->
                Spacer(Modifier.height(2.dp))
                Text(
                    text = stringResource(R.string.agent_saved_analysis_saved_at, completedAt),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            TextButton(onClick = onOpen) {
                Text(stringResource(R.string.agent_past_reports_view))
            }
        }
    }
}

/**
 * Read-only view of one finished round's report.
 *
 * Archived rounds belong to the open capture by construction — the archive is
 * reset whenever the conversation's capture changes — so the evidence keeps
 * its normal navigation affordances here.
 */
@Composable
private fun AgentPastReportDialog(
    round: AgentConversationRound,
    onFrameClick: (Long) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.agent_past_reports_dialog_title)) },
        text = {
            val visibleFindings =
                round.report.findings.filterNot { it.isHostConfirmedToolResult }
            LazyColumn(
                modifier = Modifier.height(420.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                if (round.question.isNotBlank()) {
                    item {
                        Text(
                            stringResource(R.string.agent_restored_question, round.question),
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                if (round.report.summary.isNotBlank()) {
                    item {
                        AgentMarkdownText(round.report.summary)
                    }
                }
                items(visibleFindings, key = { it.id.ifBlank { it.title } }) { finding ->
                    AgentFindingCard(
                        finding = finding,
                        onFrameClick = { frame -> frame.let(onFrameClick) },
                        onEvidenceClick = { evidence -> evidence.frameNumber?.let(onFrameClick) },
                        onSaveToWorkspace = null
                    )
                }
                if (round.report.limitations.isNotEmpty()) {
                    item { AgentLimitationCard(round.report.limitations) }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.agent_restored_close))
            }
        }
    )
}

/** Disk usage and the entry point for clearing local Agent data. */
@Composable
private fun AgentLocalDataCard(
    usage: AgentLocalDataUsage,
    onClear: () -> Unit,
    onExportDiagnostics: () -> Unit
) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(12.dp)) {
            AgentSectionLabel(stringResource(R.string.agent_local_data_title))
            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(
                    R.string.agent_local_data_sessions,
                    usage.savedSessionCount,
                    usage.savedSessionBytes.formatFileSize()
                ),
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                stringResource(
                    R.string.agent_local_data_cache,
                    usage.cacheEntryCount,
                    usage.cacheBytes.formatFileSize()
                ),
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                stringResource(R.string.agent_local_data_logs, usage.diagnosticsBytes.formatFileSize()),
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                text = usage.lastClearedAtMillis?.let { millis ->
                    stringResource(R.string.agent_local_data_last_cleared, formatTimestamp(millis))
                } ?: stringResource(R.string.agent_local_data_never_cleared),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            TextButton(
                onClick = onExportDiagnostics,
                enabled = usage.diagnosticsBytes > 0L
            ) {
                Icon(Icons.Default.Share, null, Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.agent_export_diagnostics))
            }
            TextButton(onClick = onClear) {
                Text(stringResource(R.string.agent_local_data_clear))
            }
        }
    }
}

/** Lets the user choose which local Agent data to delete. */
@Composable
private fun AgentClearLocalDataDialog(
    usage: AgentLocalDataUsage,
    onConfirm: (Set<AgentLocalDataCategory>) -> Unit,
    onDismiss: () -> Unit
) {
    var clearSessions by rememberSaveable { mutableStateOf(true) }
    var clearCache by rememberSaveable { mutableStateOf(true) }
    var clearLogs by rememberSaveable { mutableStateOf(true) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.agent_local_data_clear_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                AgentClearToggle(
                    label = stringResource(
                        R.string.agent_local_data_sessions,
                        usage.savedSessionCount,
                        usage.savedSessionBytes.formatFileSize()
                    ),
                    checked = clearSessions,
                    onCheckedChange = { clearSessions = it }
                )
                AgentClearToggle(
                    label = stringResource(
                        R.string.agent_local_data_cache,
                        usage.cacheEntryCount,
                        usage.cacheBytes.formatFileSize()
                    ),
                    checked = clearCache,
                    onCheckedChange = { clearCache = it }
                )
                AgentClearToggle(
                    label = stringResource(
                        R.string.agent_local_data_logs,
                        usage.diagnosticsBytes.formatFileSize()
                    ),
                    checked = clearLogs,
                    onCheckedChange = { clearLogs = it }
                )
                Text(
                    stringResource(R.string.agent_local_data_clear_notice),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = clearSessions || clearCache || clearLogs,
                onClick = {
                    onConfirm(
                        buildSet {
                            if (clearSessions) add(AgentLocalDataCategory.SavedSessions)
                            if (clearCache) add(AgentLocalDataCategory.Cache)
                            if (clearLogs) add(AgentLocalDataCategory.Diagnostics)
                        }
                    )
                }
            ) {
                Text(stringResource(R.string.agent_local_data_clear_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

@Composable
private fun AgentClearToggle(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

/** Short local date/time for the last-cleared line. */
private fun formatTimestamp(millis: Long): String =
    formatAgentDateTime(millis, java.util.Locale.getDefault(), java.util.TimeZone.getDefault())

/** Local save time shown in one current-capture history row. */
internal fun formatAgentSavedSessionTime(
    millis: Long,
    locale: java.util.Locale = java.util.Locale.getDefault(),
    timeZone: java.util.TimeZone = java.util.TimeZone.getDefault()
): String? = millis.takeIf { it > 0L }?.let {
    formatAgentDateTime(it, locale, timeZone)
}

private fun formatAgentDateTime(
    millis: Long,
    locale: java.util.Locale,
    timeZone: java.util.TimeZone
): String = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", locale).run {
    this.timeZone = timeZone
    format(java.util.Date(millis))
}
