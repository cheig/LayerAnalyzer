package com.example.layanalyzer.ui

import com.example.layanalyzer.BuildConfig
import com.example.layanalyzer.LayerAnalyzerApplication
import androidx.activity.compose.BackHandler
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.ui.res.stringResource
import androidx.paging.compose.collectAsLazyPagingItems
import com.example.layanalyzer.R
import com.example.layanalyzer.ai.agent.AgentSettings
import com.example.layanalyzer.ai.client.GatewayAccountUiState
import com.example.layanalyzer.model.AgentConsentPrompt
import com.example.layanalyzer.model.AgentEvidenceScope
import com.example.layanalyzer.model.ExportResult
import com.example.layanalyzer.model.RtpStreamIdentity
import com.example.layanalyzer.model.rtpWavFileName
import com.example.layanalyzer.model.WorkspacePage
import com.example.layanalyzer.media.RtpPlayerState
import com.example.layanalyzer.ui.components.PacketDetailScreen
import com.example.layanalyzer.ui.components.PacketListScreen
import com.example.layanalyzer.ui.components.shareExportResult
import com.example.layanalyzer.ui.components.rtp.rtpExportDestination
import com.example.layanalyzer.viewmodel.PacketDetailViewModel
import com.example.layanalyzer.viewmodel.PacketListViewModel
import com.example.layanalyzer.viewmodel.ProtocolAgentViewModel
import com.example.layanalyzer.viewmodel.RtpViewModel
import com.example.layanalyzer.viewmodel.VoipCallsViewModel
import androidx.compose.ui.platform.LocalContext
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun LayAnalyzerApp(
    listViewModel: PacketListViewModel,
    detailViewModel: PacketDetailViewModel,
    agentViewModel: ProtocolAgentViewModel,
    rtpViewModel: RtpViewModel,
    /** RTP3-UI-01: the VoIP call list; its state is threaded down to `PacketListScreen`. */
    voipCallsViewModel: VoipCallsViewModel,
    agentConfiguration: AgentSettings = AgentSettings(),
    agentConsentPrompt: AgentConsentPrompt? = null,
    gatewayAccount: GatewayAccountUiState = GatewayAccountUiState(),
    onExitConfirmed: () -> Unit = {}
) {
    // RTP1-UI-03 wires this into PacketListScreen.
    val appContext = LocalContext.current.applicationContext
    val exportScope = rememberCoroutineScope()
    // UI language: the ViewModel persists the choice and bumps this counter; we
    // recreate the Activity so Compose re-reads every stringResource.  The
    // counter (not the language itself) is what we key on, so re-selecting the
    // current language — already filtered out one level down — cannot loop.
    val activity = LocalContext.current as? android.app.Activity
    val uiLanguageVersion by listViewModel.uiLanguageChangeVersion.collectAsState()
    LaunchedEffect(uiLanguageVersion) {
        if (uiLanguageVersion > 0L) {
            activity?.recreate()
        }
    }
    val packetItems = listViewModel.packetFlow.collectAsLazyPagingItems()
    // Collected here so the Agent session survives navigation between the list
    // and the detail screen: opening an evidence frame swaps the whole subtree
    // below, and state held inside PacketListScreen would go with it.
    val agentUiState by agentViewModel.uiState.collectAsState()
    val agentJob by agentViewModel.analysisJob.collectAsState()
    val agentRunRecord by agentViewModel.lastRunRecord.collectAsState()
    val agentSavedSessions by agentViewModel.savedSessions.collectAsState()
    val agentDeletingSavedSessions by agentViewModel.deletingSavedSessionIds.collectAsState()
    val agentRestoredSession by agentViewModel.restoredSession.collectAsState()
    val agentInterruptedJob by agentViewModel.interruptedJob.collectAsState()
    val agentLocalDataUsage by agentViewModel.localDataUsage.collectAsState()
    val agentScenarioPackage by agentViewModel.scenarioPackage.collectAsState()
    val agentPlaybooks by agentViewModel.playbooks.collectAsState()
    val agentEditingScenario by agentViewModel.editingScenario.collectAsState()
    val agentScenarioSaveCompleted by agentViewModel.scenarioSaveCompleted.collectAsState()
    // OPT-SAVE-01: the in-flight save flag, collected here so the editor's
    // Save button can disable while a save runs.
    val agentSavingScenario by agentViewModel.savingScenario.collectAsState()
    // OPT-QNT-01: quarantine notices also live here rather than inside
    // PacketListScreen, so the notice is not lost by navigating away from the
    // Agent page between the store's load and the user getting back to it.
    val agentScenarioQuarantineCodes by agentViewModel.scenarioQuarantineCodes.collectAsState()
    val selectedPacket by detailViewModel.selectedPacket.collectAsState()
    val selectedByteRange by detailViewModel.selectedByteRange.collectAsState()
    val selectedField by detailViewModel.selectedField.collectAsState()
    val navigationState by detailViewModel.navigationState.collectAsState()
    val isDetailLoading by detailViewModel.isLoading.collectAsState()
    val followStream by detailViewModel.followStream.collectAsState()
    val isFollowingStream by detailViewModel.isFollowingStream.collectAsState()
    val packetBytesViewer by detailViewModel.packetBytesViewer.collectAsState()
    val currentFile by listViewModel.currentFile.collectAsState()
    val workspacePage by listViewModel.workspacePage.collectAsState()
    val rtpState by rtpViewModel.state.collectAsState()
    val rtpPlayerState by rtpViewModel.playerState.collectAsState()
    val rtpPlaybackState by rtpViewModel.playerPlaybackState.collectAsState()
    val rtpPlayerPositionMs by rtpViewModel.playerPositionMs.collectAsState()
    val rtpExportState by rtpViewModel.exportState.collectAsState()
    val rtpExternalOpenState by rtpViewModel.externalOpenState.collectAsState()
    val rtpHighlightedStreamId by rtpViewModel.highlightedStreamId.collectAsState()
    // RTP5-UI-01: the video half of the streams page — the export/open states it drives,
    // the HEVC notice, and the in-app preview page (RTP5-KT-03).
    val rtpVideoExportState by rtpViewModel.videoExportState.collectAsState()
    val rtpVideoOpenState by rtpViewModel.videoOpenState.collectAsState()
    val rtpHevcDecoderAvailability by rtpViewModel.hevcDecoderAvailability.collectAsState()
    val rtpVideoPreview by rtpViewModel.videoPreview.collectAsState()
    val rtpVideoPreviewAvailability by rtpViewModel.videoPreviewAvailability.collectAsState()
    val rtpVideoPreviewPlaybackState by rtpViewModel.videoPreviewPlaybackState.collectAsState()
    val rtpVideoPreviewPositionMs by rtpViewModel.videoPreviewPositionMs.collectAsState()
    val rtpVideoPreviewDurationMs by rtpViewModel.videoPreviewDurationMs.collectAsState()
    val rtpHeuristicApplyVersion by listViewModel.rtpHeuristicApplyVersion.collectAsState()
    val voipCallsState by voipCallsViewModel.state.collectAsState()
    val voipPlayback by voipCallsViewModel.playback.collectAsState()
    // RTP3-UI-03: the dual-track player's own state (tracks, playback, position, mute).
    val voipDualTrack by voipCallsViewModel.dualTrackPlayback.collectAsState()
    val voipPlayerPlaybackState by voipCallsViewModel.playerPlaybackState.collectAsState()
    val voipPlayerPositionMs by voipCallsViewModel.playerPositionMs.collectAsState()
    val voipPlayerMuteState by voipCallsViewModel.playerMuteState.collectAsState()
    val openProgress by listViewModel.openProgress.collectAsState()
    val openError by listViewModel.openError.collectAsState()
    val espDecryptionNotice by listViewModel.espDecryptionNotice.collectAsState()
    val largeCaptureWarning by listViewModel.largeCaptureWarning.collectAsState()
    val recentFiles by listViewModel.recentFiles.collectAsState()
    val displayFilterUiState by listViewModel.displayFilterUiState.collectAsState()
    val isFiltering by listViewModel.isFiltering.collectAsState()
    val searchState by listViewModel.searchState.collectAsState()
    val expertSummary by listViewModel.expertSummary.collectAsState()
    val statisticsState by listViewModel.statisticsState.collectAsState()
    val httpObjectsState by listViewModel.httpObjectsState.collectAsState()
    val packetContextActions by listViewModel.packetContextActions.collectAsState()
    val highlightedFrames by listViewModel.highlightedFrames.collectAsState()
    val preferences by listViewModel.preferences.collectAsState()
    val listExportState by listViewModel.exportState.collectAsState()
    val decodeAsRules by listViewModel.decodeAsRules.collectAsState()
    val detailExportState by detailViewModel.exportState.collectAsState()
    val liveCaptureState by listViewModel.liveCaptureState.collectAsState()
    val bookmarkedFrames by detailViewModel.bookmarkedFrames.collectAsState()
    val healthSummary by listViewModel.healthSummary.collectAsState()
    val workspace by listViewModel.workspace.collectAsState()
    // EVL-EXPORT-01: whether the evidence-frame export scope may be offered.
    // Derived from the workspace evidence set; fail-closed when it is empty or
    // the frame set cannot be compiled.
    val evidenceFramesScopeAvailability by listViewModel.evidenceFramesScopeAvailability.collectAsState()
    val agentFilterPreview by listViewModel.agentFilterPreview.collectAsState()
    val communicationAnalysis by listViewModel.communicationAnalysis.collectAsState()
    val analysisJob by listViewModel.analysisJob.collectAsState()
    val listState = remember(currentFile?.localPath, displayFilterUiState.appliedExpression) { LazyListState() }
    var showExitConfirmation by rememberSaveable { mutableStateOf(false) }
    var pendingRtpIdentity by remember { mutableStateOf<RtpStreamIdentity?>(null) }

    BackHandler(
        enabled = selectedPacket == null && !isDetailLoading && !showExitConfirmation
    ) {
        showExitConfirmation = true
    }

    LaunchedEffect(selectedPacket?.frameNumber) {
        selectedPacket?.frameNumber?.let { listViewModel.selectWorkspaceFrame(it) }
    }

    LaunchedEffect(
        selectedPacket?.frameNumber,
        displayFilterUiState.appliedExpression,
        displayFilterUiState.visibleCount,
        isFiltering
    ) {
        if (!isFiltering && selectedPacket != null) {
            detailViewModel.refreshNavigation()
        }
    }

    if (selectedPacket == null && !isDetailLoading) {
        PacketListScreen(
            packetItems = packetItems,
            currentFile = currentFile,
            openProgress = openProgress,
            openError = openError,
            espDecryptionNotice = espDecryptionNotice,
            largeCaptureWarning = largeCaptureWarning,
            recentFiles = recentFiles,
            displayFilterUiState = displayFilterUiState,
            isFiltering = isFiltering,
            searchState = searchState,
            expertSummary = expertSummary,
            statisticsState = statisticsState,
            httpObjectsState = httpObjectsState,
            packetContextActions = packetContextActions,
            highlightedFrames = highlightedFrames,
            communicationAnalysis = communicationAnalysis,
            analysisJob = analysisJob,
            agentUiState = agentUiState,
            agentJob = agentJob,
            preferences = preferences,
            exportState = listExportState,
            decodeAsRules = decodeAsRules,
            liveCaptureState = liveCaptureState,
            healthSummary = healthSummary,
            workspace = workspace,
            evidenceFramesScopeAvailability = evidenceFramesScopeAvailability,
            scenarioTemplates = listViewModel.scenarioTemplates,
            listState = listState,
            workspacePage = workspacePage,
            onWorkspacePageChange = listViewModel::selectWorkspacePage,
            onOpenCapture = { listViewModel.openCaptureUri(it) },
            onOpenRecent = { listViewModel.openRecentCapture(it) },
            onDeleteRecent = { listViewModel.deleteRecentCapture(it) },
            onCloseFile = { listViewModel.closeFile() },
            onCancelOpen = { listViewModel.cancelOpen() },
            onDismissError = { listViewModel.clearOpenError() },
            onDismissEspDecryptionNotice = { listViewModel.clearEspDecryptionNotice() },
            onConfirmLargeCapture = { listViewModel.confirmLargeCapture() },
            onDismissLargeCapture = { listViewModel.dismissLargeCaptureWarning() },
            onDisplayFilterChange = { listViewModel.updateDisplayFilter(it) },
            onApplyDisplayFilter = { listViewModel.applyDisplayFilter() },
            onCancelDisplayFilter = { listViewModel.cancelFiltering() },
            onClearDisplayFilter = { listViewModel.clearDisplayFilter() },
            onSearchModeChange = { listViewModel.updateSearchMode(it) },
            onSearchQueryChange = { listViewModel.updateSearchQuery(it) },
            onRunSearch = {
                listViewModel.runSearch { frameNumber ->
                    detailViewModel.loadPacketDetail(frameNumber)
                }
            },
            onCancelSearch = { listViewModel.cancelSearch() },
            onRefreshExpertInfo = { listViewModel.refreshExpertSummary() },
            onCancelExpertInfo = { listViewModel.cancelExpertSummary() },
            onRefreshStatistics = { listViewModel.refreshStatistics() },
            onCancelStatistics = { listViewModel.cancelStatistics() },
            onExportStatisticsCsv = { listViewModel.exportStatisticsCsv(it) },
            onLoadHttpObjects = { listViewModel.loadHttpObjects() },
            onExportHttpObject = { listViewModel.exportHttpObjectForShare(it) },
            onExportAllHttpObjects = { listViewModel.exportAllHttpObjectsForShare() },
            onPreparePacketContextActions = { listViewModel.preparePacketContextActions(it) },
            onApplyPacketFollowFilter = { listViewModel.applyScenarioStep(it) },
            onTogglePacketHighlight = { listViewModel.togglePacketHighlight(it) },
            onRefreshCommunication = { listViewModel.refreshCommunicationAnalysis() },
            onCancelCommunication = { listViewModel.cancelCommunicationAnalysis() },
            onCancelAnalysis = { listViewModel.cancelActiveAnalysis() },
            onStatisticsBucketChange = { listViewModel.setStatisticsBucket(it) },
            onNextSearchResult = {
                listViewModel.nextSearchResult()?.let { detailViewModel.loadPacketDetail(it) }
            },
            onPreviousSearchResult = {
                listViewModel.previousSearchResult()?.let { detailViewModel.loadPacketDetail(it) }
            },
            onPreferencesChange = { listViewModel.updatePreferences(it) },
            onSaveFilteredCapture = { listViewModel.saveFilteredCapture(it) },
            onExportFilteredCapture = { listViewModel.exportFilteredCaptureForShare() },
            onExportDiagnosticReport = { mode, scope -> listViewModel.exportEvidencePackageForShare(mode, scope) },
            onSaveEvidencePackage = { uri, mode, scope -> listViewModel.saveEvidencePackage(uri, mode, scope) },
            onClearExportState = { listViewModel.clearExportState() },
            onAddDecodeAsRule = { scope, transport, source, destination, sourcePort, destinationPort, protocol ->
                listViewModel.addDecodeAsRule(scope, transport, source, destination, sourcePort, destinationPort, protocol)
            },
            onRemoveDecodeAsRule = { listViewModel.removeDecodeAsRule(it) },
            onStartLiveCapture = { listViewModel.startLiveCapture(it) },
            onStopLiveCapture = { listViewModel.stopLiveCapture() },
            onOpenSavedLiveCapture = { listViewModel.openSavedLiveCapture() },
            onClearLiveCaptureError = { listViewModel.clearLiveCaptureError() },
            onRefreshDashboard = { listViewModel.refreshDashboard() },
            onApplyScenarioStep = { listViewModel.applyScenarioStep(it) },
            onToggleFavoriteFilter = { listViewModel.toggleFavoriteFilter(it) },
            onAgentSubmitQuestion = { question, scope, displayFilterOverride, evidenceFrameCount ->
                // EVL-CONTEXT-04: when the run is framed by an evidence
                // override, the packet list must show the same view the agent
                // analyzes.  Apply it through the normal applyDisplayFilter
                // path — its existing error handling surfaces any failure, so
                // an unapplied override is never silently pretended to be in
                // effect.
                if (displayFilterOverride != null &&
                    AgentEvidenceScope.shouldApplyOverrideToPacketList(
                        displayFilterOverride, displayFilterUiState.appliedExpression
                    )
                ) {
                    listViewModel.applyDisplayFilter(displayFilterOverride)
                }
                agentViewModel.submitQuestion(
                    question, scope,
                    displayFilterOverride = displayFilterOverride,
                    evidenceFrameCount = evidenceFrameCount
                )
            },
            onAgentContinueConversation = { agentViewModel.continueConversation(it) },
            onAgentCancel = { agentViewModel.cancel() },
            onAgentRetry = { agentViewModel.retry() },
            onAgentNewConversation = { agentViewModel.startNewConversation() },
            onAgentClearTransientError = { agentViewModel.clearTransientError() },
            agentFilterPreview = agentFilterPreview,
            onAgentEvidenceClick = { evidence, report ->
                when {
                    !evidence.displayFilter.isNullOrBlank() -> {
                        listViewModel.prepareAgentFilterPreview(evidence, report)
                    }
                    evidence.frameNumber != null &&
                        listViewModel.validateAgentEvidence(evidence, report) == null -> {
                        detailViewModel.loadPacketDetail(evidence.frameNumber)
                    }
                }
            },
            onAgentSaveFinding = { finding, report ->
                listViewModel.saveAgentFinding(finding, report)
            },
            onAgentExportReport = { report ->
                listViewModel.exportAgentReportForShare(report, agentRunRecord)
            },
            onConfirmAgentFilterPreview = { listViewModel.applyAgentFilterPreview() },
            onDismissAgentFilterPreview = { listViewModel.dismissAgentFilterPreview() },
            agentSettings = agentConfiguration,
            agentConsentPrompt = agentConsentPrompt,
            gatewayAccount = gatewayAccount,
            onRefreshGatewayAccount = { agentViewModel.refreshGatewayAccount() },
            agentByokEnabled = true,
            agentResponseCaptureAvailable = BuildConfig.DEBUG,
            onAgentClearResponseDumps = {
                (appContext as? LayerAnalyzerApplication)?.clearAgentResponseDebugCaptures()
            },
            onAgentSettingsChange = { agentViewModel.updateSettings(it) },
            onAgentPrivacyModeChange = { agentViewModel.updatePrivacyMode(it) },
            onAgentModelSelectionChange = { providerId, modelId ->
                agentViewModel.selectModel(providerId, modelId)
            },
            onAgentAcceptConsent = { agentViewModel.acceptConsent() },
            onAgentDeclineConsent = { agentViewModel.declineConsent() },
            onAgentSaveProviderKey = { providerId, secret ->
                agentViewModel.saveByokSecret(providerId, secret)
            },
            onAgentClearProviderKey = { providerId ->
                agentViewModel.clearByokSecret(providerId)
            },
            onAgentFetchProviderModels = agentViewModel::fetchProviderModels,
            agentSavedSessions = agentSavedSessions,
            agentDeletingSavedSessions = agentDeletingSavedSessions,
            agentRestoredSession = agentRestoredSession,
            agentRestoredSessionMatchesCapture = agentViewModel.canOpenRestoredEvidence(),
            agentInterruptedJob = agentInterruptedJob,
            onAgentResumeInterruptedJob = { agentViewModel.resumeInterruptedJob() },
            onAgentDismissInterruptedJob = { agentViewModel.dismissInterruptedJob() },
            agentLocalDataUsage = agentLocalDataUsage,
            onAgentOpenSavedSession = { agentViewModel.restoreSavedSession(it) },
            onAgentDeleteSavedSession = { agentViewModel.deleteSavedSession(it) },
            onAgentDismissRestoredSession = { agentViewModel.dismissRestoredSession() },
            onAgentClearLocalData = { agentViewModel.clearLocalData(it) },
            onAgentExportDiagnostics = {
                exportScope.launch {
                    val result = withContext(Dispatchers.IO) {
                        val content = agentViewModel.exportDiagnostics()
                        if (content.isNullOrBlank()) {
                            null
                        } else {
                            runCatching {
                                val directory = File(appContext.filesDir, "exports").apply { mkdirs() }
                                val file = File(
                                    directory,
                                    "agent-diagnostics-${System.currentTimeMillis()}.json"
                                )
                                file.writeText(content, Charsets.UTF_8)
                                ExportResult(
                                    filePath = file.absolutePath,
                                    displayName = file.name,
                                    mimeType = "application/json"
                                )
                            }.getOrNull()
                        }
                    }
                    result?.let { exported ->
                        runCatching { shareExportResult(appContext, exported) }
                    }
                }
            },
            agentScenarioPackage = agentScenarioPackage,
            agentPlaybooks = agentPlaybooks,
            onAgentClearScenarioPackage = { agentViewModel.clearDownloadedScenarioPackage() },
            onAgentPlaybookUsed = agentViewModel::recordPlaybookUsage,
            onAgentEditScenario = agentViewModel::startEditScenario,
            onAgentCopyScenario = agentViewModel::copyScenario,
            onAgentDeleteScenario = agentViewModel::deleteScenario,
            onAgentNewScenario = agentViewModel::startNewScenario,
            onAgentViewScenarioDetails = agentViewModel::startViewScenario,
            agentEditingScenario = agentEditingScenario,
            agentScenarioToolWhitelist = agentViewModel.scenarioToolWhitelist,
            onAgentDismissScenarioEditor = agentViewModel::dismissEditingScenario,
            onAgentSaveScenario = agentViewModel::saveScenario,
            agentScenarioSaving = agentSavingScenario,
            onAgentScenarioPlaybookChange = { playbook ->
                // Controlled editor (OPT-DRAFT-01): the ViewModel's draft is
                // the single source of the editing input, so field changes
                // land there and survive an activity recreation.
                agentViewModel.updateDraft { draft -> draft.copy(playbook = playbook) }
            },
            agentScenarioSaveCompleted = agentScenarioSaveCompleted,
            agentScenarioQuarantineCodes = agentScenarioQuarantineCodes,
            agentRunRecord = agentRunRecord,
            onPacketClick = { frameNumber -> detailViewModel.loadPacketDetail(frameNumber) },
            onSaveWorkspaceNote = listViewModel::saveWorkspaceNote,
            onRemoveEvidence = listViewModel::removeEvidence,
            onRemoveEvidenceFrames = listViewModel::removeEvidenceFrames,
            onClearEvidence = listViewModel::clearEvidence,
            onShowEvidenceFramesOnly = { listViewModel.showEvidenceFramesOnly() },
            rtpState = rtpState,
            rtpHeuristicEnabled = preferences.rtpHeuristicEnabled,
            rtpHighlightedStreamId = rtpHighlightedStreamId,
            rtpOpenRequest = pendingRtpIdentity,
            rtpHeuristicApplyVersion = rtpHeuristicApplyVersion,
            onRtpOpenRequestHandled = { pendingRtpIdentity = null },
            onRtpScan = rtpViewModel::scan,
            onRtpCancel = rtpViewModel::cancel,
            onRtpToggleHeuristic = { enabled -> listViewModel.setRtpHeuristicEnabled(enabled) },
            onRtpSetOverride = rtpViewModel::setOverride,
            onRtpHighlightStream = rtpViewModel::highlightStream,
            rtpPlayerState = rtpPlayerState,
            rtpPlaybackState = rtpPlaybackState,
            rtpPlayerPositionMs = rtpPlayerPositionMs,
            rtpExportState = rtpExportState,
            onRtpOpenPlayer = { stream ->
                rtpViewModel.openPlayer(listOf(stream), autoPlay = false)
            },
            onRtpPlayStream = rtpViewModel::openPlayerStream,
            onRtpPlayStreams = { streams -> rtpViewModel.openPlayer(streams) },
            onRtpExportWav = { streams, destinations ->
                rtpViewModel.exportWav(streams, destinations)
            },
            onRtpExportRaw = { streams, destinations ->
                rtpViewModel.exportRaw(streams, destinations)
            },
            // RTP4-KT-03：导出格式对话框选完格式后的目的地写入，以及「外部打开」的
            // 容器准备（容器优先、WAV 回退的判定在 RtpPlayerScreen 里）。
            onRtpExportFormat = { stream, format, destination ->
                rtpViewModel.exportFormat(stream, format, destination)
            },
            rtpExternalOpenState = rtpExternalOpenState,
            onRtpOpenExternal = { stream -> rtpViewModel.prepareExternalOpen(stream) },
            onRtpClearExternalOpenState = rtpViewModel::clearExternalOpenState,
            onRtpClosePlayer = rtpViewModel::closePlayer,
            onRtpPlayerPlayPause = {
                if (rtpPlaybackState == RtpPlayerState.Playing) {
                    rtpViewModel.pausePlayer()
                } else {
                    rtpViewModel.playPlayer()
                }
            },
            onRtpPlayerSeek = rtpViewModel::seekPlayer,
            onRtpPlayerTimingChange = rtpViewModel::setPlayerTiming,
            onRtpPlayerCancelDecode = rtpViewModel::cancelPlayerDecode,
            onRtpPlayerRetryDecode = rtpViewModel::retryPlayerDecode,
            onRtpPlayerSelectStream = rtpViewModel::selectPlayerStream,
            onRtpPlayerExportWav = { uri ->
                rtpPlayerState.selectedStream?.let { stream ->
                    rtpViewModel.exportWav(
                        streams = listOf(stream),
                        destinations = listOf(
                            rtpExportDestination(
                                context = appContext,
                                uri = uri,
                                displayName = rtpWavFileName(stream)
                            )
                        ),
                        timing = rtpPlayerState.timing
                    )
                }
            },
            onRtpPlayerShareWav = {
                rtpPlayerState.selectedStream?.let { stream ->
                    rtpViewModel.shareWav(
                        streams = listOf(stream),
                        timing = rtpPlayerState.timing
                    )
                }
            },
            onRtpPlayerClearExportState = rtpViewModel::clearExportState,
            voipCallsState = voipCallsState,
            onVoipCallsLoad = { voipCallsViewModel.load() },
            voipPlayback = voipPlayback,
            onVoipPlayCall = { callId -> voipCallsViewModel.selectCall(callId) },
            voipDualTrack = voipDualTrack,
            voipPlayerPlaybackState = voipPlayerPlaybackState,
            voipPlayerPositionMs = voipPlayerPositionMs,
            voipPlayerMuteState = voipPlayerMuteState,
            onVoipPlayerPlayPause = { voipCallsViewModel.playPause() },
            onVoipPlayerSeek = { positionMs -> voipCallsViewModel.seekPlayer(positionMs) },
            onVoipPlayerMute = { left, right -> voipCallsViewModel.setTrackMuted(left, right) },
            onVoipClosePlayer = { voipCallsViewModel.closePlayback() },
            rtpVideoExportState = rtpVideoExportState,
            // 一次点击 = 一条流：卡片菜单的「导出 MP4」「导出裸流」都是单流的（多流视频导出
            // 不在 RTP5-UI-01 的菜单里），目的地也只有一个，所以两个列表各放一项。
            // `paramSets` 故意不传：SDP 的那一路（KT-00 的 `SdpVideoParams.from`）在仓库里
            // 还没有生产者（RTP3-NAT-04 的 `readRtpSetupInfo` 不存在），所以带内没有参数集的
            // 流今天导不出 MP4 —— 那是 ViewModel 里说清楚过的失败，不是这里能绕过的。
            onRtpExportVideo = { stream, format, destination, startAtKeyframe, dropCorrupt ->
                rtpViewModel.exportVideo(
                    streams = listOf(stream),
                    format = format,
                    destinations = listOf(destination),
                    startAtKeyframe = startAtKeyframe,
                    dropCorrupt = dropCorrupt
                )
            },
            onRtpClearVideoExportState = rtpViewModel::clearVideoExportState,
            onRtpCancelVideoExport = rtpViewModel::cancelVideoExport,
            onRtpCancelAudioExport = rtpViewModel::cancelAudioExport,
            rtpVideoOpenState = rtpVideoOpenState,
            // 「外部播放」用 ViewModel 的默认格式（裸流）：卡片只给这一个「打开」入口，
            // KT-02 为它准备的正是 `video/h264` → `application/octet-stream` 的那条回退
            // （`rtp_open_external_video_fallback`），而裸流那条路既不经过封装器也不需要
            // 参数集，是最少前提条件的一条。要 MP4 的用户走「导出 MP4」。
            onRtpOpenVideoExternal = { stream -> rtpViewModel.prepareExternalVideoOpen(stream) },
            onRtpClearVideoOpenState = rtpViewModel::clearVideoOpenState,
            rtpHevcDecoderAvailability = rtpHevcDecoderAvailability,
            onRtpRefreshHevcDecoderAvailability = rtpViewModel::refreshHevcDecoderAvailability,
            rtpVideoPreviewState = rtpVideoPreview,
            rtpVideoPreviewAvailability = rtpVideoPreviewAvailability,
            rtpVideoPreviewPlaybackState = rtpVideoPreviewPlaybackState,
            rtpVideoPreviewPositionMs = rtpVideoPreviewPositionMs,
            rtpVideoPreviewDurationMs = rtpVideoPreviewDurationMs,
            onRtpVideoPreviewAvailable = rtpViewModel::refreshVideoPreviewAvailability,
            onRtpOpenVideoPreview = rtpViewModel::openVideoPreview,
            onRtpPrepareVideoPreview = rtpViewModel::prepareVideoPreview,
            onRtpCloseVideoPreview = rtpViewModel::closeVideoPreview,
            onRtpVideoPreviewPlayPause = {
                if (rtpVideoPreviewPlaybackState == RtpPlayerState.Playing) {
                    rtpViewModel.pauseVideoPreview()
                } else {
                    rtpViewModel.playVideoPreview()
                }
            },
            onRtpVideoPreviewSeek = rtpViewModel::seekVideoPreview,
            // 预览页的 Surface 只能走 ViewModel 这道门：控制器是它的构造参数，宿主拿不到。
            onRtpAttachVideoPreviewSurface = rtpViewModel::attachVideoPreviewSurface,
            onRtpDetachVideoPreviewSurface = rtpViewModel::detachVideoPreviewSurface
        )
    } else {
        BackHandler {
            detailViewModel.clearSelection()
        }
        PacketDetailScreen(
            detailState = selectedPacket,
            isLoading = isDetailLoading,
            selectedByteRange = selectedByteRange,
            selectedField = selectedField,
            navigationState = navigationState,
            followStream = followStream,
            isFollowingStream = isFollowingStream,
            packetBytesViewer = packetBytesViewer,
            exportState = detailExportState,
            defaultTreeExpansionDepth = preferences.defaultTreeExpansionDepth,
            appliedFilter = displayFilterUiState.appliedExpression,
            expertSeverity = selectedPacket?.frameNumber?.let { frame ->
                expertSummary.items
                    .filter { it.frameNumber == frame }
                    .maxByOrNull { if (it.severity.equals("error", true)) 2 else 1 }
                    ?.severity
            } ?: "none",
            isBookmarked = selectedPacket?.frameNumber in bookmarkedFrames || selectedPacket?.frameNumber in (workspace?.bookmarks ?: emptySet()),
            workspaceNote = workspace?.notes?.firstOrNull { it.frameNumber == selectedPacket?.frameNumber }?.text.orEmpty(),
            isEvidence = selectedPacket?.frameNumber in (workspace?.evidenceFrames ?: emptySet()),
            onFieldSelected = { detailViewModel.selectField(it) },
            onShowPacketBytes = { detailViewModel.showPacketBytes(it) },
            onDismissPacketBytesViewer = { detailViewModel.dismissPacketBytesViewer() },
            onByteSelected = { detailViewModel.selectByte(it) },
            onByteRangeSelected = { detailViewModel.selectByteRange(it) },
            onApplyFieldAsFilter = { filter ->
                listViewModel.applyDisplayFilter(filter)
                detailViewModel.clearSelection()
            },
            onPrepareFieldFilter = { filter ->
                listViewModel.updateDisplayFilter(filter)
                detailViewModel.clearSelection()
            },
            onFollowStream = { detailViewModel.followStream(it) },
            onExportPacketDetails = { detailViewModel.exportPacketDetailsForShare() },
            onExportSelectedBytes = { detailViewModel.exportSelectedBytesForShare() },
            onClearExportState = { detailViewModel.clearExportState() },
            onDismissFollowStream = { detailViewModel.clearFollowStream() },
            onStreamPacketClick = { frameNumber ->
                detailViewModel.clearFollowStream()
                detailViewModel.loadPacketDetail(frameNumber)
            },
            onPreviousPacket = { detailViewModel.loadAdjacentPacket(-1) },
            onNextPacket = { detailViewModel.loadAdjacentPacket(1) },
            onToggleBookmark = {
                selectedPacket?.frameNumber?.let { listViewModel.toggleWorkspaceBookmark(it) }
                detailViewModel.toggleBookmark()
            },
            onSaveNote = { text -> selectedPacket?.frameNumber?.let { listViewModel.saveWorkspaceNote(it, text) } },
            onToggleEvidence = { selectedPacket?.frameNumber?.let { listViewModel.toggleEvidence(it) } },
            onAnalyzeRtpStream = { identity ->
                pendingRtpIdentity = identity
                detailViewModel.clearSelection()
            },
            onBack = { detailViewModel.clearSelection() }
        )
    }

    if (showExitConfirmation) {
        AlertDialog(
            onDismissRequest = { showExitConfirmation = false },
            title = { Text(stringResource(R.string.exit_confirmation_title)) },
            text = { Text(stringResource(R.string.exit_confirmation_message)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        showExitConfirmation = false
                        onExitConfirmed()
                    }
                ) {
                    Text(stringResource(R.string.exit_confirmation_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { showExitConfirmation = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}
