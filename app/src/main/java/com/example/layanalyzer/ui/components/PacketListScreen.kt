// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import android.app.Activity
import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.text.format.DateUtils
import android.view.Surface
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.BackHandler
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Stream
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.BookmarkBorder
import androidx.compose.material.icons.filled.EditNote
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.WebAsset
import androidx.compose.material.icons.automirrored.filled.FactCheck
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.MutableState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.example.layanalyzer.R
import com.example.layanalyzer.ai.agent.AgentSettings
import com.example.layanalyzer.ai.agent.AgentProviderConfig
import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.ai.client.GatewayAccountUiState
import com.example.layanalyzer.ai.client.ProviderModelFetchFailure
import com.example.layanalyzer.ai.client.ProviderModelFetchResult
import com.example.layanalyzer.ai.playbook.ScenarioPackageDescription
import com.example.layanalyzer.ai.playbook.AgentPlaybook
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.itemContentType
import androidx.paging.compose.itemKey
import androidx.core.content.FileProvider
import com.example.layanalyzer.model.AnalyzerPreferences
import com.example.layanalyzer.model.DecodeAsRule
import com.example.layanalyzer.model.DecodeAsScope
import com.example.layanalyzer.model.DecodeAsTransport
import com.example.layanalyzer.model.DisplayFilterResult
import com.example.layanalyzer.model.DisplayFilterUiState
import com.example.layanalyzer.model.FilterSyntaxStatus
import com.example.layanalyzer.model.ExportResult
import com.example.layanalyzer.model.ExportUiState
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.ExpertInfoItem
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.EspDecryptionMode
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.LiveCapturePacketPreview
import com.example.layanalyzer.model.LiveCaptureSettings
import com.example.layanalyzer.model.LiveCaptureState
import com.example.layanalyzer.model.OpenProgress
import com.example.layanalyzer.model.PacketSearchMode
import com.example.layanalyzer.model.PacketSearchState
import com.example.layanalyzer.model.PacketSummary
import com.example.layanalyzer.model.RecentCapture
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpExportFormat
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpStreamIdentity
import com.example.layanalyzer.model.RtpTimingMode
import com.example.layanalyzer.model.RtpVideoDecoderAvailability
import com.example.layanalyzer.model.RtpVideoExportFormat
import com.example.layanalyzer.model.RtpVideoPreviewAvailability
import com.example.layanalyzer.model.StatisticsUiState
import com.example.layanalyzer.model.TimeDisplayFormat
import com.example.layanalyzer.model.UiLanguage
import com.example.layanalyzer.model.EvidenceExportMode
import com.example.layanalyzer.model.EvidenceExportScope
import com.example.layanalyzer.data.EvidenceExportScopePolicy
import com.example.layanalyzer.data.EvidenceFrameFilter
import com.example.layanalyzer.data.EvidenceFrameViewDecision
import com.example.layanalyzer.data.EvidenceFrameViewPolicy
import com.example.layanalyzer.data.EvidenceFrameViewRejection
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.AnalysisWorkspace
import com.example.layanalyzer.model.CaptureHealthSummary
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.AnalysisJobState
import com.example.layanalyzer.model.HealthCard
import com.example.layanalyzer.model.HealthSeverity
import com.example.layanalyzer.model.HttpObjectEntry
import com.example.layanalyzer.model.HttpObjectsState
import com.example.layanalyzer.model.PacketContextActionsState
import com.example.layanalyzer.model.ProtocolAgentUiState
import com.example.layanalyzer.model.AgentConsentPrompt
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentFilterPreviewState
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentLocalDataCategory
import com.example.layanalyzer.model.AgentLocalDataUsage
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentSavedSession
import com.example.layanalyzer.model.AgentSavedSessionSummary
import com.example.layanalyzer.model.ScenarioTemplate
import com.example.layanalyzer.model.WorkspacePage
import com.example.layanalyzer.viewmodel.formatFileSize
import com.example.layanalyzer.viewmodel.LargeCaptureWarning
import com.example.layanalyzer.viewmodel.RtpExportDestination
import com.example.layanalyzer.viewmodel.RtpExportUiState
import com.example.layanalyzer.viewmodel.RtpExternalOpenUiState
import com.example.layanalyzer.viewmodel.RtpPlayerUiState
import com.example.layanalyzer.viewmodel.RtpScanUiState
import com.example.layanalyzer.viewmodel.RtpVideoExportUiState
import com.example.layanalyzer.viewmodel.RtpVideoOpenUiState
import com.example.layanalyzer.viewmodel.RtpVideoPreviewUiState
import com.example.layanalyzer.viewmodel.AgentScenarioDraft
import com.example.layanalyzer.viewmodel.VoipCallsUiState
import com.example.layanalyzer.viewmodel.RtpDualTrackPlayback
import com.example.layanalyzer.viewmodel.RtpTrackMuteState
import com.example.layanalyzer.media.RtpPlayerState
import com.example.layanalyzer.ui.components.rtp.RtpCodecMapDialog
import com.example.layanalyzer.ui.components.rtp.RtpDualTrackPlayerScreen
import com.example.layanalyzer.ui.components.rtp.RtpFilterBuilder
import com.example.layanalyzer.ui.components.rtp.RtpPlayerScreen
import com.example.layanalyzer.ui.components.rtp.RtpStreamsScreen
import com.example.layanalyzer.ui.components.rtp.RtpVideoPreviewScreen
import com.example.layanalyzer.ui.components.rtp.RtpVideoPreviewTarget
import com.example.layanalyzer.ui.components.rtp.VoipCallDetailScreen
import com.example.layanalyzer.ui.components.rtp.VoipCallsScreen
import com.example.layanalyzer.ui.components.rtp.VoipFilterBuilder
import com.example.layanalyzer.ui.components.rtp.voipCallTitle
import java.io.File
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

private val CAPTURE_MIME_TYPES = arrayOf(
    "application/vnd.tcpdump.pcap",
    "application/x-pcap",
    "application/octet-stream"
)

/** Evidence-export choices captured when the save picker is launched. */
private data class EvidenceExportSelection(
    val mode: EvidenceExportMode,
    val scope: EvidenceExportScope
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PacketListScreen(
    packetItems: LazyPagingItems<PacketSummary>,
    currentFile: FileSessionInfo?,
    openProgress: OpenProgress?,
    openError: String?,
    /** One-shot ESP decryption message: an error, or a probe that decoded nothing. */
    espDecryptionNotice: String? = null,
    largeCaptureWarning: LargeCaptureWarning?,
    recentFiles: List<RecentCapture>,
    displayFilterUiState: DisplayFilterUiState,
    isFiltering: Boolean,
    searchState: PacketSearchState,
    expertSummary: ExpertInfoSummary,
    statisticsState: StatisticsUiState,
    httpObjectsState: HttpObjectsState,
    packetContextActions: PacketContextActionsState,
    highlightedFrames: Set<Long>,
    communicationAnalysis: CommunicationAnalysis,
    analysisJob: AnalysisJobState,
    agentUiState: ProtocolAgentUiState,
    agentJob: AnalysisJobState,
    preferences: AnalyzerPreferences,
    exportState: ExportUiState,
    decodeAsRules: List<DecodeAsRule>,
    liveCaptureState: LiveCaptureState,
    healthSummary: CaptureHealthSummary,
    workspace: AnalysisWorkspace?,
    /**
     * Whether the evidence-frame export scope may be selected. Computed by the
     * ViewModel with [EvidenceExportScopePolicy]. The default is deliberately
     * fail-closed so a caller that forgets to wire it cannot offer an export
     * that would silently omit evidence.
     */
    evidenceFramesScopeAvailability: EvidenceExportScopePolicy.ScopeAvailability =
        EvidenceExportScopePolicy.ScopeAvailability(
            available = false,
            reasonCode = EvidenceExportScopePolicy.ReasonCode.NoEvidenceFrames
        ),
    scenarioTemplates: List<ScenarioTemplate>,
    listState: LazyListState,
    workspacePage: WorkspacePage,
    onWorkspacePageChange: (WorkspacePage) -> Unit,
    onOpenCapture: (Uri) -> Unit,
    onOpenRecent: (RecentCapture) -> Unit,
    onDeleteRecent: (RecentCapture) -> Unit,
    onCloseFile: () -> Unit,
    onCancelOpen: () -> Unit,
    onDismissError: () -> Unit,
    onDismissEspDecryptionNotice: () -> Unit = {},
    onConfirmLargeCapture: () -> Unit,
    onDismissLargeCapture: () -> Unit,
    onDisplayFilterChange: (String) -> Unit,
    onApplyDisplayFilter: () -> Unit,
    onCancelDisplayFilter: () -> Unit,
    onClearDisplayFilter: () -> Unit,
    onSearchModeChange: (PacketSearchMode) -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onRunSearch: () -> Unit,
    onCancelSearch: () -> Unit,
    onRefreshExpertInfo: () -> Unit,
    onCancelExpertInfo: () -> Unit,
    onRefreshStatistics: () -> Unit,
    onCancelStatistics: () -> Unit,
    onExportStatisticsCsv: (String) -> Unit,
    onLoadHttpObjects: () -> Unit,
    onExportHttpObject: (HttpObjectEntry) -> Unit,
    onExportAllHttpObjects: () -> Unit,
    onPreparePacketContextActions: (Long) -> Unit,
    onApplyPacketFollowFilter: (String) -> Unit,
    onTogglePacketHighlight: (Long) -> Unit,
    onRefreshCommunication: () -> Unit,
    onCancelCommunication: () -> Unit,
    onCancelAnalysis: () -> Unit,
    onStatisticsBucketChange: (Double) -> Unit,
    onNextSearchResult: () -> Unit,
    onPreviousSearchResult: () -> Unit,
    onPreferencesChange: (AnalyzerPreferences) -> Unit,
    onSaveFilteredCapture: (Uri) -> Unit,
    onExportFilteredCapture: () -> Unit,
    onExportDiagnosticReport: (EvidenceExportMode, EvidenceExportScope) -> Unit,
    onSaveEvidencePackage: (Uri, EvidenceExportMode, EvidenceExportScope) -> Unit,
    onClearExportState: () -> Unit,
    onAddDecodeAsRule: (DecodeAsScope, DecodeAsTransport, String, String, Int?, Int?, String) -> Unit,
    onRemoveDecodeAsRule: (DecodeAsRule) -> Unit,
    onStartLiveCapture: (LiveCaptureSettings) -> Unit,
    onStopLiveCapture: () -> Unit,
    onOpenSavedLiveCapture: () -> Unit,
    onClearLiveCaptureError: () -> Unit,
    onRefreshDashboard: () -> Unit,
    onApplyScenarioStep: (String) -> Unit,
    onToggleFavoriteFilter: (String) -> Unit,
    onAgentSubmitQuestion: (String, AnalysisScope, String?, Int?) -> Unit,
    onAgentContinueConversation: (String) -> Unit,
    onAgentCancel: () -> Unit,
    onAgentRetry: () -> Unit,
    onAgentNewConversation: () -> Unit,
    onAgentClearTransientError: () -> Unit,
    agentFilterPreview: AgentFilterPreviewState? = null,
    onAgentEvidenceClick: (AgentEvidence, AgentReport) -> Unit = { _, _ -> },
    onAgentSaveFinding: (AgentFinding, AgentReport) -> Unit = { _, _ -> },
    onAgentExportReport: (AgentReport) -> Unit = {},
    onConfirmAgentFilterPreview: () -> Unit = {},
    onDismissAgentFilterPreview: () -> Unit = {},
    onPacketClick: (Long) -> Unit,
    onSaveWorkspaceNote: (Long, String) -> Unit,
    onRemoveEvidence: (Long) -> Unit,
    onRemoveEvidenceFrames: (Collection<Long>) -> Unit = {},
    onClearEvidence: () -> Unit = {},
    /**
     * EVL-UI-04: frame the packet list with the workspace evidence set. Returns
     * the [EvidenceFrameViewDecision] so the caller can switch pages on
     * [EvidenceFrameViewDecision.Apply] or warn on a rejection without changing
     * the view. Its default is fail-closed so a missing wiring cannot apply a
     * filter.
     */
    onShowEvidenceFramesOnly: () -> EvidenceFrameViewDecision = { EvidenceFrameViewDecision.Reject(EvidenceFrameViewRejection.EmptySet) },
    agentSettings: AgentSettings = AgentSettings(),
    agentConsentPrompt: AgentConsentPrompt? = null,
    onAgentSettingsChange: (AgentSettings) -> Unit = {},
    onAgentPrivacyModeChange: (AgentPrivacyMode) -> Unit = {},
    onAgentModelSelectionChange: (String, String) -> Unit = { _, _ -> },
    onAgentAcceptConsent: () -> Unit = {},
    onAgentDeclineConsent: () -> Unit = {},
    onAgentSaveProviderKey: (AgentProviderConfig, String) -> Unit = { _, _ -> },
    onAgentClearProviderKey: (String) -> Unit = {},
    onAgentFetchProviderModels: suspend (AgentProviderConfig, String) -> ProviderModelFetchResult =
        { _, _ -> ProviderModelFetchResult.Failure(ProviderModelFetchFailure.Network) },
    gatewayAccount: GatewayAccountUiState = GatewayAccountUiState(),
    onRefreshGatewayAccount: () -> Unit = {},
    agentByokEnabled: Boolean = false,
    agentResponseCaptureAvailable: Boolean = false,
    onAgentClearResponseDumps: () -> Unit = {},
    agentSavedSessions: List<AgentSavedSessionSummary> = emptyList(),
    agentDeletingSavedSessions: Set<String> = emptySet(),
    agentRestoredSession: AgentSavedSession? = null,
    agentRestoredSessionMatchesCapture: Boolean = false,
    agentInterruptedJob: com.example.layanalyzer.data.AnalysisJobCheckpoint? = null,
    onAgentResumeInterruptedJob: () -> Unit = {},
    onAgentDismissInterruptedJob: () -> Unit = {},
    agentLocalDataUsage: AgentLocalDataUsage = AgentLocalDataUsage(),
    onAgentOpenSavedSession: (String) -> Unit = {},
    onAgentDeleteSavedSession: (String) -> Unit = {},
    onAgentDismissRestoredSession: () -> Unit = {},
    onAgentClearLocalData: (Set<AgentLocalDataCategory>) -> Unit = {},
    onAgentExportDiagnostics: () -> Unit = {},
    /** AI-26: the active scenario rule package shown on the Agent page. */
    agentScenarioPackage: ScenarioPackageDescription? = null,
    agentPlaybooks: List<AgentPlaybook> = emptyList(),
    onAgentClearScenarioPackage: () -> Unit = {},
    onAgentPlaybookUsed: (String) -> Unit = {},
    /** Scenario chip long-press menu: edit a user scenario. */
    onAgentEditScenario: (AgentPlaybook) -> Unit = {},
    /** Scenario chip long-press menu: copy the scenario as a duplicate. */
    onAgentCopyScenario: (String) -> Unit = {},
    /** Scenario chip long-press menu: delete a user scenario. */
    onAgentDeleteScenario: (String) -> Unit = {},
    /** Scenario chip long-press menu: read-only details; the editor mounts in a later task. */
    onAgentViewScenarioDetails: (AgentPlaybook) -> Unit = {},
    /** "New scenario" chip; the scenario editor mounts in a later task (SRE-EDITOR-01). */
    onAgentNewScenario: () -> Unit = {},
    /** The open scenario editor draft (edit or read-only details); null closes the editor. */
    agentEditingScenario: AgentScenarioDraft? = null,
    /** Tools the scenario editor's Initial tools chips offer; empty renders no chips. */
    agentScenarioToolWhitelist: Set<String> = emptySet(),
    onAgentDismissScenarioEditor: () -> Unit = {},
    /** Persists the ViewModel-held draft; the editor keeps no copy (OPT-DRAFT-01). */
    onAgentSaveScenario: () -> Unit = {},
    /** OPT-SAVE-01: a scenario save is in flight; the editor's Save button disables. */
    agentScenarioSaving: Boolean = false,
    /** Routes an edited scenario playbook into the ViewModel draft (OPT-DRAFT-01). */
    onAgentScenarioPlaybookChange: (AgentPlaybook) -> Unit = {},
    /** Monotonic count of successful scenario saves; raises the saved notice (SRE-EDITOR-06). */
    agentScenarioSaveCompleted: Int = 0,
    /** OPT-QNT-01: distinct quarantine reason codes; each new one raises the notice. */
    agentScenarioQuarantineCodes: List<String> = emptyList(),
    /**
     * EVL-UI-07: the current run's audit record, threaded to the report's
     * evidence-coverage badge. Null suppresses the badge (fail-closed).
     */
    agentRunRecord: AgentRunRecord? = null,
    rtpState: RtpScanUiState = RtpScanUiState.Idle,
    rtpHeuristicEnabled: Boolean = false,
    rtpHighlightedStreamId: String? = null,
    rtpOpenRequest: RtpStreamIdentity? = null,
    rtpHeuristicApplyVersion: Long = 0L,
    onRtpOpenRequestHandled: () -> Unit = {},
    onRtpScan: (Boolean) -> Unit = {},
    onRtpCancel: () -> Unit = {},
    onRtpToggleHeuristic: (Boolean) -> Unit = {},
    onRtpSetOverride: (Int, String, Int) -> Unit = { _, _, _ -> },
    onRtpHighlightStream: (String?) -> Unit = {},
    rtpPlayerState: RtpPlayerUiState = RtpPlayerUiState(),
    rtpPlaybackState: RtpPlayerState = RtpPlayerState.Idle,
    rtpPlayerPositionMs: Long = 0L,
    rtpExportState: RtpExportUiState = RtpExportUiState.Idle,
    onRtpOpenPlayer: (RtpStream) -> Unit = {},
    onRtpPlayStream: (RtpStream) -> Unit = {},
    onRtpPlayStreams: (List<RtpStream>) -> Unit = {},
    onRtpExportWav: (List<RtpStream>, List<RtpExportDestination>) -> Unit = { _, _ -> },
    onRtpExportRaw: (List<RtpStream>, List<RtpExportDestination>) -> Unit = { _, _ -> },
    /** RTP4-KT-03: 导出格式对话框选定后的目的地写入（宿主交给 `RtpViewModel.exportFormat`）。 */
    onRtpExportFormat: (RtpStream, RtpExportFormat, RtpExportDestination) -> Unit =
        { _, _, _ -> },
    /** RTP4-KT-03: 「外部打开」的容器准备状态，见 `RtpViewModel.prepareExternalOpen`。 */
    rtpExternalOpenState: RtpExternalOpenUiState = RtpExternalOpenUiState.Idle,
    onRtpOpenExternal: (RtpStream) -> Unit = {},
    onRtpClearExternalOpenState: () -> Unit = {},
    onRtpClosePlayer: () -> Unit = {},
    onRtpPlayerPlayPause: () -> Unit = {},
    onRtpPlayerSeek: (Long) -> Unit = {},
    onRtpPlayerTimingChange: (RtpTimingMode) -> Unit = {},
    onRtpPlayerCancelDecode: () -> Unit = {},
    onRtpPlayerRetryDecode: () -> Unit = {},
    onRtpPlayerSelectStream: (String) -> Unit = {},
    onRtpPlayerExportWav: (Uri) -> Unit = {},
    onRtpPlayerShareWav: () -> Unit = {},
    onRtpPlayerClearExportState: () -> Unit = {},
    /** RTP3-UI-01: the VoIP call list state; [VoipCallsUiState.Idle] until the user opens the page. */
    voipCallsState: VoipCallsUiState = VoipCallsUiState.Idle,
    /** RTP3-UI-01: asks the host to (re)build the call list for the current session. */
    onVoipCallsLoad: () -> Unit = {},
    /** RTP3-UI-02: the decode result of the call selected with the detail page's Play button. */
    voipPlayback: RtpDecodeResult? = null,
    /** RTP3-UI-02: Play on the detail page; the host forwards it to `VoipCallsViewModel.selectCall`. */
    onVoipPlayCall: (String) -> Unit = {},
    /** RTP3-UI-03: the dual-track player's track input; null while the decode is still running. */
    voipDualTrack: RtpDualTrackPlayback? = null,
    /** RTP3-UI-03: the VoIP audio controller's playback state (idle when no controller is wired). */
    voipPlayerPlaybackState: RtpPlayerState = RtpPlayerState.Idle,
    /** RTP3-UI-03: the VoIP audio controller's playhead, in milliseconds. */
    voipPlayerPositionMs: Long = 0L,
    /** RTP3-UI-03: left/right channel mute of the dual-track player. */
    voipPlayerMuteState: RtpTrackMuteState = RtpTrackMuteState(),
    /** RTP3-UI-03: play/pause the VoIP audio controller. */
    onVoipPlayerPlayPause: () -> Unit = {},
    /** RTP3-UI-03: seek the VoIP audio controller. */
    onVoipPlayerSeek: (Long) -> Unit = {},
    /** RTP3-UI-03: set the left/right channel mute of the dual-track player. */
    onVoipPlayerMute: (Boolean, Boolean) -> Unit = { _, _ -> },
    /** RTP3-UI-03: stop the VoIP audio when the VoIP pages are left. */
    onVoipClosePlayer: () -> Unit = {},
    /** RTP5-UI-01: the video export state, see `RtpViewModel.videoExportState`. */
    rtpVideoExportState: RtpVideoExportUiState = RtpVideoExportUiState.Idle,
    /** RTP5-UI-01: write one video stream to the chosen SAF destination. */
    onRtpExportVideo: (
        RtpStream,
        RtpVideoExportFormat,
        RtpExportDestination,
        Boolean,
        Boolean
    ) -> Unit = { _, _, _, _, _ -> },
    onRtpClearVideoExportState: () -> Unit = {},
    /** Stops a video export or the external-open preparation. Both walk the capture. */
    onRtpCancelVideoExport: () -> Unit = {},
    /** Stops an audio export. */
    onRtpCancelAudioExport: () -> Unit = {},
    /**
     * RTP5-UI-01: 「外部播放」的导出状态。The streams page opens the file itself
     * (it has the `Context`), the same split `RtpPlayerScreen` has for audio.
     */
    rtpVideoOpenState: RtpVideoOpenUiState = RtpVideoOpenUiState.Idle,
    onRtpOpenVideoExternal: (RtpStream) -> Unit = {},
    onRtpClearVideoOpenState: () -> Unit = {},
    /** RTP5-UI-01: the HEVC decoder probe's answer, shown in the export dialog. */
    rtpHevcDecoderAvailability: RtpVideoDecoderAvailability = RtpVideoDecoderAvailability.UNKNOWN,
    onRtpRefreshHevcDecoderAvailability: () -> Unit = {},
    /** RTP5-UI-01: the state of the in-app preview page (RTP5-KT-03). */
    rtpVideoPreviewState: RtpVideoPreviewUiState = RtpVideoPreviewUiState(),
    rtpVideoPreviewAvailability: RtpVideoPreviewAvailability = RtpVideoPreviewAvailability.NoExport,
    rtpVideoPreviewPlaybackState: RtpPlayerState = RtpPlayerState.Idle,
    rtpVideoPreviewPositionMs: Long = 0L,
    rtpVideoPreviewDurationMs: Long = 0L,
    /** RTP5-UI-01: a finished MP4 export, handed to `refreshVideoPreviewAvailability`. */
    onRtpVideoPreviewAvailable: (RtpStream, String, String) -> Unit = { _, _, _ -> },
    /** RTP5-UI-01: open the preview page for a stream the host has a target for. */
    onRtpOpenVideoPreview: (RtpStream, String, String) -> Unit = { _, _, _ -> },
    /**
     * RTP5-UI-01：视频流卡片整块点击、还没有可播 MP4 时，把该流交给
     * `RtpViewModel.prepareVideoPreview` —— 就地封装一份再进预览页。
     */
    onRtpPrepareVideoPreview: (RtpStream) -> Unit = {},
    onRtpCloseVideoPreview: () -> Unit = {},
    onRtpVideoPreviewPlayPause: () -> Unit = {},
    onRtpVideoPreviewSeek: (Long) -> Unit = {},
    /** RTP5-UI-01: the preview `TextureView`'s surface, forwarded to the controller. */
    onRtpAttachVideoPreviewSurface: (Surface) -> Unit = {},
    onRtpDetachVideoPreviewSurface: () -> Unit = {}
) {
    val context = LocalContext.current
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var showExpertDialog by remember { mutableStateOf(false) }
    var showStatisticsDialog by remember { mutableStateOf(false) }
    var showCommunicationDialog by remember { mutableStateOf(false) }
    var showHttpObjects by remember { mutableStateOf(false) }
    var showRtpStreams by remember { mutableStateOf(false) }
    // RTP3-UI-01: the VoIP call list, reachable from the SIP tab of the
    // communication screen and from the RTP stream page's top bar.
    var showVoipCalls by remember { mutableStateOf(false) }
    // Read by RTP3-UI-02 (call detail). Kept next to the flag that opens the
    // list so the detail screen has one obvious place to read it from.
    var selectedVoipCallId by remember { mutableStateOf<String?>(null) }
    // RTP3-UI-03: the dual-track player renders above the detail page while this
    // flag is set, so Back from the player returns to the detail (not out of the
    // VoIP pages). It is cleared whenever the VoIP pages are left.
    var showVoipPlayer by remember { mutableStateOf(false) }
    // RTP3-UI-01/02: reload the call list whenever the VoIP pages are entered.
    // Declared here (rather than inside the page branch) so switching between the
    // list and the detail page does not relaunch it — a relaunch would drop the
    // decode result the Play button just produced. The ViewModel caches the
    // communication analysis per session, so re-entering is cheap, and doing it
    // every time keeps the list honest after a filter / decode-as change that
    // invalidated that cache.
    LaunchedEffect(showVoipCalls) { if (showVoipCalls) onVoipCallsLoad() }
    var selectedRtpCodecStream by remember { mutableStateOf<RtpStream?>(null) }
    var pendingRtpHighlight by remember { mutableStateOf<RtpStreamIdentity?>(null) }
    // RTP5-UI-01: the in-app preview page (RTP5-KT-03) renders above the stream list
    // while this flag is set, so Back returns to the list.
    var showVideoPreview by remember { mutableStateOf(false) }
    // RTP5-UI-01: which stream has a previewable MP4 and where those two files are.
    // It is the host's ledger rather than the streams page's, because opening the
    // preview swaps that page out (the branch below returns) and KT-03 requires the
    // menu entry to survive that — `RtpViewModel.closeVideoPreview` says so explicitly.
    // A session change clears it: the stream ids ("s0", "s1", …) are per-scan, so a
    // ledger carried across captures could name a different stream.
    var videoPreviewTargets by remember {
        mutableStateOf<Map<String, RtpVideoPreviewTarget>>(emptyMap())
    }
    LaunchedEffect(rtpState) {
        if (rtpState !is RtpScanUiState.Done) videoPreviewTargets = emptyMap()
    }
    var showPreferencesDialog by remember { mutableStateOf(false) }
    var showAgentModelSettings by remember { mutableStateOf(false) }
    var showDecodeAsDialog by remember { mutableStateOf(false) }
    var showLiveCaptureDialog by remember { mutableStateOf(false) }
    var showSearch by rememberSaveable { mutableStateOf(false) }
    var showFileActions by remember { mutableStateOf(false) }
    var showEvidenceExportDialog by remember { mutableStateOf(false) }
    var pendingEvidenceSelection by remember {
        mutableStateOf(EvidenceExportSelection(EvidenceExportMode.Redacted, EvidenceExportScope.CurrentView))
    }
    var pendingCaptureSettings by remember { mutableStateOf<LiveCaptureSettings?>(null) }
    var pendingNotificationCaptureSettings by remember { mutableStateOf<LiveCaptureSettings?>(null) }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) onOpenCapture(uri)
    }
    val saveCaptureLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.tcpdump.pcap")
    ) { uri ->
        if (uri != null) onSaveFilteredCapture(uri)
    }
    val saveEvidenceLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip")
    ) { uri ->
        if (uri != null) {
            onSaveEvidencePackage(uri, pendingEvidenceSelection.mode, pendingEvidenceSelection.scope)
        }
    }
    val vpnPermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val settings = pendingCaptureSettings
        pendingCaptureSettings = null
        if (result.resultCode == Activity.RESULT_OK && settings != null) {
            onStartLiveCapture(settings)
        }
    }
    val requestVpnPermission: (LiveCaptureSettings) -> Unit = { settings ->
        val permissionIntent = VpnService.prepare(context)
        if (permissionIntent != null) {
            pendingCaptureSettings = settings
            vpnPermissionLauncher.launch(permissionIntent)
        } else {
            onStartLiveCapture(settings)
        }
    }
    val notificationPermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        val settings = pendingNotificationCaptureSettings
        pendingNotificationCaptureSettings = null
        if (settings != null) requestVpnPermission(settings)
    }
    val requestCaptureStart: (LiveCaptureSettings) -> Unit = { settings ->
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            pendingNotificationCaptureSettings = settings
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            requestVpnPermission(settings)
        }
    }

    LaunchedEffect(openError) {
        if (openError != null) {
            snackbarHostState.showSnackbar(openError)
            onDismissError()
        }
    }

    LaunchedEffect(espDecryptionNotice) {
        if (espDecryptionNotice != null) {
            snackbarHostState.showSnackbar(espDecryptionNotice)
            onDismissEspDecryptionNotice()
        }
    }

    LaunchedEffect(exportState.error, exportState.message) {
        val message = exportState.error ?: exportState.message
        if (message != null) snackbarHostState.showSnackbar(message)
    }

    LaunchedEffect(exportState.shareResult) {
        exportState.shareResult?.let { result ->
            shareExportResult(context, result)
            onClearExportState()
        }
    }

    LaunchedEffect(rtpOpenRequest) {
        val request = rtpOpenRequest ?: return@LaunchedEffect
        pendingRtpHighlight = request
        showRtpStreams = true
        onRtpScan(false)
        onRtpOpenRequestHandled()
    }

    LaunchedEffect(rtpHeuristicApplyVersion, showRtpStreams) {
        if (showRtpStreams && rtpHeuristicApplyVersion > 0L) onRtpScan(false)
    }

    LaunchedEffect(rtpState, pendingRtpHighlight) {
        val request = pendingRtpHighlight ?: return@LaunchedEffect
        when (val state = rtpState) {
            is RtpScanUiState.Done -> {
                val match = state.result.streams.firstOrNull(request::matches)
                if (match != null) onRtpHighlightStream(match.id)
                pendingRtpHighlight = null
            }
            is RtpScanUiState.Error, RtpScanUiState.Cancelled -> pendingRtpHighlight = null
            else -> Unit
        }
    }

    LaunchedEffect(liveCaptureState.error) {
        liveCaptureState.error?.let { error ->
            snackbarHostState.showSnackbar(error)
            onClearLiveCaptureError()
        }
    }

    if (showExpertDialog) {
        LaunchedEffect(expertSummary.analyzed, expertSummary.isLoading) {
            if (!expertSummary.analyzed && !expertSummary.isLoading) onRefreshExpertInfo()
        }
        ExpertInfoScreen(
            summary = expertSummary,
            onCancel = onCancelExpertInfo,
            onPacketClick = { showExpertDialog = false; onPacketClick(it) },
            onBack = { showExpertDialog = false }
        )
        return
    }
    if (showStatisticsDialog) {
        StatisticsScreen(
            state = statisticsState,
            onRefresh = onRefreshStatistics,
            onCancel = onCancelStatistics,
            onBucketChange = onStatisticsBucketChange,
            onPacketClick = { showStatisticsDialog = false; onPacketClick(it) },
            onApplyFilter = { showStatisticsDialog = false; onApplyScenarioStep(it) },
            onExportTable = onExportStatisticsCsv,
            onBack = { showStatisticsDialog = false }
        )
        return
    }
    if (showCommunicationDialog) {
        CommunicationScreen(
            state = communicationAnalysis,
            onRefresh = onRefreshCommunication,
            onCancel = onCancelCommunication,
            onPacketClick = { showCommunicationDialog = false; onPacketClick(it) },
            onApplyFilter = { showCommunicationDialog = false; onApplyScenarioStep(it) },
            onOpenRtpStreams = {
                showCommunicationDialog = false
                showRtpStreams = true
                onRtpScan(false)
            },
            onOpenVoipCalls = {
                showCommunicationDialog = false
                showVoipCalls = true
            },
            onBack = { showCommunicationDialog = false }
        )
        return
    }
    if (showHttpObjects) {
        LaunchedEffect(httpObjectsState.analyzed, httpObjectsState.isLoading, httpObjectsState.error) {
            if (!httpObjectsState.analyzed && !httpObjectsState.isLoading && httpObjectsState.error == null) {
                onLoadHttpObjects()
            }
        }
        HttpObjectsScreen(
            state = httpObjectsState,
            exportState = exportState,
            onRefresh = onLoadHttpObjects,
            onExport = onExportHttpObject,
            onExportAll = onExportAllHttpObjects,
            onPacketClick = onPacketClick,
            onBack = { showHttpObjects = false }
        )
        return
    }
    if (rtpPlayerState.isOpen) {
        RtpPlayerScreen(
            state = rtpPlayerState,
            playbackState = rtpPlaybackState,
            positionMs = rtpPlayerPositionMs,
            exportState = rtpExportState,
            onBack = {
                onRtpClosePlayer()
                showRtpStreams = true
            },
            onPlayPause = onRtpPlayerPlayPause,
            onSeek = onRtpPlayerSeek,
            onTimingChange = onRtpPlayerTimingChange,
            onCancelDecode = onRtpPlayerCancelDecode,
            onRetryDecode = onRtpPlayerRetryDecode,
            onSelectStream = onRtpPlayerSelectStream,
            onPacketClick = onPacketClick,
            onExportWav = onRtpPlayerExportWav,
            onShareWav = onRtpPlayerShareWav,
            onClearExportState = onRtpPlayerClearExportState,
            externalOpenState = rtpExternalOpenState,
            onOpenExternal = onRtpOpenExternal,
            onClearExternalOpenState = onRtpClearExternalOpenState
        )
        return
    }
    if (showVoipCalls) {
        // RTP3-UI-02: the detail page reads the selected call id written by UI-01's seam. It is
        // resolved against the same Ready state, so a reload/filter change that drops the call
        // falls back to the list instead of leaving a stale detail page on screen.
        val ready = voipCallsState as? VoipCallsUiState.Ready
        val selectedCall = selectedVoipCallId?.let { id -> ready?.calls?.firstOrNull { it.callId == id } }
        if (selectedCall == null && selectedVoipCallId != null) {
            SideEffect {
                selectedVoipCallId = null
                showVoipPlayer = false
                onVoipClosePlayer()
            }
        }
        if (selectedCall != null && showVoipPlayer) {
            // RTP3-UI-03: rendered above the detail page; Back returns to it.
            RtpDualTrackPlayerScreen(
                title = voipCallTitle(selectedCall.from, selectedCall.to),
                playback = voipDualTrack,
                errorMessage = voipPlayback?.error?.takeIf { it.isNotBlank() },
                unsupported = voipPlayback?.unsupported.orEmpty(),
                playbackState = voipPlayerPlaybackState,
                positionMs = voipPlayerPositionMs,
                muteState = voipPlayerMuteState,
                onBack = { showVoipPlayer = false },
                onPlayPause = onVoipPlayerPlayPause,
                onSeek = onVoipPlayerSeek,
                onTrackMuted = onVoipPlayerMute,
                onPacketClick = { frameNumber ->
                    // Leave the VoIP pages before opening the packet, so the player
                    // cannot reappear on top of it.
                    showVoipPlayer = false
                    showVoipCalls = false
                    selectedVoipCallId = null
                    onVoipClosePlayer()
                    onPacketClick(frameNumber)
                },
                onRetry = { onVoipPlayCall(selectedCall.callId) },
                onCancel = {
                    showVoipPlayer = false
                    onVoipClosePlayer()
                }
            )
            return
        }
        if (selectedCall != null) {
            // RTP3-UI-04: the filter string is computed once per selected call (not per
            // recomposition) and is the single source of truth for the button's enabled state
            // and the truncation hint.
            val callFilter = remember(selectedCall) { VoipFilterBuilder.forCall(selectedCall) }
            VoipCallDetailScreen(
                call = selectedCall,
                timeline = ready?.dialogs?.firstOrNull { it.callId == selectedCall.callId },
                filter = callFilter,
                playback = voipPlayback,
                onBack = {
                    selectedVoipCallId = null
                    showVoipPlayer = false
                    onVoipClosePlayer()
                },
                onPacketClick = { frameNumber ->
                    // Same order as the RtpStreamsScreen branch below: leave the VoIP pages first,
                    // so the detail screen cannot reappear on top of the packet being opened.
                    showVoipPlayer = false
                    showVoipCalls = false
                    selectedVoipCallId = null
                    onVoipClosePlayer()
                    onPacketClick(frameNumber)
                },
                onPlayCall = {
                    onVoipPlayCall(selectedCall.callId)
                    showVoipPlayer = true
                },
                onFilterCall = {
                    // Same house path as onFilterStream below: leave the VoIP pages, apply the
                    // string as the display filter, then land on the packet list. Guarded so an
                    // empty filter can never silently clear the user's current display filter.
                    if (callFilter.filter.isNotBlank()) {
                        showVoipPlayer = false
                        showVoipCalls = false
                        selectedVoipCallId = null
                        onVoipClosePlayer()
                        onApplyScenarioStep(callFilter.filter)
                        onWorkspacePageChange(WorkspacePage.Packets)
                    }
                }
            )
            return
        }
        VoipCallsScreen(
            state = voipCallsState,
            onLoad = onVoipCallsLoad,
            onBack = {
                showVoipPlayer = false
                showVoipCalls = false
                onVoipClosePlayer()
            },
            onOpenCall = { callId -> selectedVoipCallId = callId },
            onOpenRtpStreams = {
                showVoipPlayer = false
                showVoipCalls = false
                onVoipClosePlayer()
                showRtpStreams = true
                onRtpScan(false)
            }
        )
        return
    }
    // RTP5-UI-01: the preview page only shows once there is something to show.
    // `RtpViewModel.openVideoPreview` reads the `.vidx` before it publishes the page state,
    // so there is one IO hop between the tap and `isOpen` becoming true. Painting the page
    // during that hop would have it say "there is no exported MP4 to preview" (the page's
    // own `!isOpen` branch) about a file that is there — so wait for the state to land.
    // Both outcomes land: the successful `isOpen`, or the `errorMessage` of the two
    // non-Ready ones. If the open job is cancelled (a session change) nothing lands and
    // the stream list simply stays up, which is the honest thing for a dead session.
    // RTP5-UI-01（修）：`Preparing` **不能**算作「页面该出现了」。
    //
    // 它曾经被加进来，是为了让封装期间有点反馈；但 `RtpVideoPreviewScreen` 在
    // `!state.isOpen` 时仍然会挂 `RtpPreviewTextureView`，而那个 TextureView 带
    // `SurfaceTextureListener` + `DisposableEffect`。在一个「还没有 mp4Path」的子树
    // 里挂载再卸载它，会让 Compose 的 SlotTable 在 Scaffold 的 subcompose 中失衡：
    //
    //   java.lang.ArrayIndexOutOfBoundsException: length=0; index=-5
    //     at androidx.compose.runtime.SlotTableKt.key(SlotTable.kt:3522)
    //     at androidx.compose.runtime.ComposerImpl.end(Composer.kt:2357)
    //     ... androidx.compose.material3.ScaffoldKt...subcompose(Scaffold.kt:285)
    //
    // 整个栈里没有应用自己的帧，因为崩在**结构**上而不是某个表达式上。
    //
    // 所以页面只在「真的有内容」时挂：播成了（`isOpen`），或者失败了
    //（`errorMessage`）。封装期间不给页面，但**给进度**——`videoPreparing` 那条
    // `ExportProgressBanner` 就在流列表页上（见本文件 `videoPreparing` 分支），
    // 用户看到的是「正在封装视频」而不是「点了没反应」。
    val videoPreviewReady = rtpVideoPreviewState.isOpen ||
        rtpVideoPreviewState.errorMessage != null
    if (showVideoPreview && videoPreviewReady) {
        // RTP5-UI-01: RTP5-KT-03's page, fed by `RtpViewModel`. It renders even when
        // `state.isOpen` is false — the page itself says which of the two non-Ready
        // outcomes happened, which is more honest than a blank screen (README §4.5.4).
        RtpVideoPreviewScreen(
            state = rtpVideoPreviewState,
            playbackState = rtpVideoPreviewPlaybackState,
            positionMs = rtpVideoPreviewPositionMs,
            durationMs = rtpVideoPreviewDurationMs,
            onBack = {
                showVideoPreview = false
                onRtpCloseVideoPreview()
            },
            onPlayPause = onRtpVideoPreviewPlayPause,
            onSeek = onRtpVideoPreviewSeek,
            onJumpToPacket = { frameNumber ->
                // Same order as the audio player's branch: leave the page first, so it
                // cannot reappear on top of the packet being opened.
                showVideoPreview = false
                onRtpCloseVideoPreview()
                onPacketClick(frameNumber)
            },
            onAttachSurface = onRtpAttachVideoPreviewSurface,
            onDetachSurface = onRtpDetachVideoPreviewSurface
        )
        return
    }
    if (showRtpStreams) {
        RtpStreamsScreen(
            state = rtpState,
            heuristicEnabled = rtpHeuristicEnabled,
            onScan = onRtpScan,
            onCancel = onRtpCancel,
            onToggleHeuristic = onRtpToggleHeuristic,
            onFilterStream = { stream ->
                showRtpStreams = false
                onApplyScenarioStep(RtpFilterBuilder.forStream(stream))
                onWorkspacePageChange(WorkspacePage.Packets)
            },
            onMapCodec = { stream -> selectedRtpCodecStream = stream },
            onOpenVoipCalls = {
                showRtpStreams = false
                showVoipCalls = true
            },
            onBack = {
                showRtpStreams = false
                pendingRtpHighlight = null
                onRtpHighlightStream(null)
            },
            onOpenPlayer = { stream ->
                showRtpStreams = false
                onRtpOpenPlayer(stream)
            },
            highlightedStreamId = rtpHighlightedStreamId,
            onPlayStream = { stream ->
                showRtpStreams = false
                onRtpPlayStream(stream)
            },
            onPlayStreams = { streams ->
                showRtpStreams = false
                onRtpPlayStreams(streams)
            },
            onExportWav = onRtpExportWav,
            onExportRaw = onRtpExportRaw,
            onExportFormat = onRtpExportFormat,
            exportState = rtpExportState,
            onClearExportState = onRtpPlayerClearExportState,
            // RTP5-UI-01: the video half of the streams page. The ledger write and the
            // ViewModel's availability question are one action — they must not be able
            // to disagree about which stream the files belong to.
            videoExportState = rtpVideoExportState,
            onExportVideo = onRtpExportVideo,
            onClearVideoExportState = onRtpClearVideoExportState,
            onCancelVideoExport = onRtpCancelVideoExport,
            onCancelAudioExport = onRtpCancelAudioExport,
            videoOpenState = rtpVideoOpenState,
            onOpenVideoExternal = onRtpOpenVideoExternal,
            onClearVideoOpenState = onRtpClearVideoOpenState,
            hevcDecoderAvailability = rtpHevcDecoderAvailability,
            onRefreshHevcDecoderAvailability = onRtpRefreshHevcDecoderAvailability,
            videoPreviewStreamIds = videoPreviewTargets.keys,
            videoPreviewAvailability = rtpVideoPreviewAvailability,
            onVideoPreviewAvailable = { stream, mp4Path, indexPath ->
                videoPreviewTargets = videoPreviewTargets +
                    (stream.id to RtpVideoPreviewTarget(mp4Path, indexPath))
                onRtpVideoPreviewAvailable(stream, mp4Path, indexPath)
            },
            onOpenVideoPreview = { stream ->
                // The host resolves the paths: `RtpVideoPreviewAvailability.Ready` has
                // no stream id, so "which MP4 is this stream's" only the ledger knows.
                videoPreviewTargets[stream.id]?.let { target ->
                    showVideoPreview = true
                    onRtpOpenVideoPreview(stream, target.mp4Path, target.indexPath)
                }
            },
            onPrepareVideoPreview = { stream ->
                // No MP4 for this stream yet: show the page straight away. Whether it
                // can actually play is `RtpVideoPreviewAvailability`'s answer, and the
                // preview screen already renders every branch of it -- gating the
                // navigation on it here would show nothing at all while the export
                // runs, which is the same "no visible cause" failure as before.
                showVideoPreview = true
                onRtpPrepareVideoPreview(stream)
            }
        )
        selectedRtpCodecStream?.let { stream ->
            RtpCodecMapDialog(
                stream = stream,
                onConfirm = { pt, codecId, clockRate ->
                    selectedRtpCodecStream = null
                    onRtpSetOverride(pt, codecId, clockRate)
                },
                onDismiss = { selectedRtpCodecStream = null }
            )
        }
        return
    }
    if (showLiveCaptureDialog) {
        LiveCaptureScreen(
            state = liveCaptureState,
            onStart = requestCaptureStart,
            onStop = onStopLiveCapture,
            onOpenSavedCapture = {
                showLiveCaptureDialog = false
                onOpenSavedLiveCapture()
            },
            onBack = { showLiveCaptureDialog = false }
        )
        return
    }

    val configuration = LocalConfiguration.current
    // A phone held in landscape is only ~360dp tall. The two-line title bar and
    // the 80dp bottom navigation bar would leave room for about three packet
    // rows, so the chrome collapses: a single-line title bar, and the page
    // switcher moves into a side rail that spends width instead of height.
    val isCompactChrome = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE &&
        configuration.screenHeightDp < 600
    val workspaceTitle = when {
        currentFile == null -> stringResource(R.string.app_name)
        workspacePage == WorkspacePage.Packets -> currentFile.displayName
        workspacePage == WorkspacePage.Insights -> stringResource(R.string.insights)
        workspacePage == WorkspacePage.Agent -> stringResource(R.string.agent)
        else -> stringResource(R.string.evidence)
    }
    val topBarActions: @Composable RowScope.() -> Unit = {
        IconButton(onClick = { showPreferencesDialog = true }) {
            Icon(Icons.Default.Settings, contentDescription = stringResource(R.string.preferences))
        }
        if (currentFile != null) {
            if (workspacePage == WorkspacePage.Packets) {
                IconButton(onClick = { showSearch = !showSearch }) {
                    Icon(
                        Icons.Default.Search,
                        contentDescription = stringResource(R.string.search_packets),
                        tint = if (showSearch || searchState.results.isNotEmpty()) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Box {
                IconButton(onClick = { showFileActions = true }) {
                    Icon(Icons.Default.MoreVert, contentDescription = stringResource(R.string.more_file_actions))
                }
                DropdownMenu(
                    expanded = showFileActions,
                    onDismissRequest = { showFileActions = false }
                ) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.open_capture)) },
                        onClick = { showFileActions = false; filePicker.launch(CAPTURE_MIME_TYPES) },
                        leadingIcon = { Icon(Icons.Default.FolderOpen, contentDescription = null) }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.http_objects)) },
                        onClick = { showFileActions = false; showHttpObjects = true },
                        leadingIcon = { Icon(Icons.Default.WebAsset, contentDescription = null) }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.rtp_streams_title)) },
                        onClick = {
                            showFileActions = false
                            showRtpStreams = true
                            onRtpScan(false)
                        },
                        leadingIcon = { Icon(Icons.Default.Stream, contentDescription = null) }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.vpn_snapshot_title)) },
                        onClick = { showFileActions = false; showLiveCaptureDialog = true },
                        leadingIcon = { Icon(if (liveCaptureState.isCapturing) Icons.Default.Stop else Icons.Default.PlayArrow, contentDescription = null) }
                    )
                    HorizontalDivider()
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.export_filtered_capture)) },
                        onClick = {
                            showFileActions = false
                            val baseName = currentFile.displayName.substringBeforeLast('.', currentFile.displayName)
                            saveCaptureLauncher.launch("$baseName-filtered.pcap")
                        },
                        enabled = !exportState.isExporting,
                        leadingIcon = { Icon(Icons.Default.Download, contentDescription = null) }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.share_filtered_capture)) },
                        onClick = {
                            showFileActions = false
                            onExportFilteredCapture()
                        },
                        enabled = !exportState.isExporting,
                        leadingIcon = { Icon(Icons.Default.Share, contentDescription = null) }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.generate_diagnostic_report)) },
                        onClick = {
                            showFileActions = false
                            showEvidenceExportDialog = true
                        },
                        enabled = !exportState.isExporting,
                        leadingIcon = { Icon(Icons.Default.Description, contentDescription = null) }
                    )
                    HorizontalDivider()
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.preferences)) },
                        onClick = {
                            showFileActions = false
                            showPreferencesDialog = true
                        },
                        leadingIcon = { Icon(Icons.Default.Settings, contentDescription = null) }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.close_file)) },
                        onClick = {
                            showFileActions = false
                            onCloseFile()
                        },
                        leadingIcon = { Icon(Icons.Default.Close, contentDescription = null) }
                    )
                }
            }
        }
    }

    Scaffold(
        topBar = {
            if (isCompactChrome) {
                CompactTopBar(title = workspaceTitle, actions = topBarActions)
            } else {
                TopAppBar(
                    title = {
                        Column {
                            Text(
                                text = workspaceTitle,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            if (currentFile != null) {
                                Text(
                                    text = stringResource(R.string.capture_file_summary, currentFile.fileType.uppercase(), currentFile.sizeBytes.formatFileSize(), currentFile.frameCount),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    },
                    actions = topBarActions
                )
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            if (currentFile != null && !isCompactChrome) {
                NavigationBar {
                    NavigationBarItem(
                        selected = workspacePage == WorkspacePage.Packets,
                        onClick = { onWorkspacePageChange(WorkspacePage.Packets) },
                        icon = { Icon(Icons.Default.Description, contentDescription = null) },
                        label = { Text(stringResource(R.string.packets)) }
                    )
                    NavigationBarItem(
                        selected = workspacePage == WorkspacePage.Insights,
                        onClick = {
                            if (workspacePage != WorkspacePage.Insights) onRefreshDashboard()
                            onWorkspacePageChange(WorkspacePage.Insights)
                        },
                        icon = { Icon(Icons.Default.Dashboard, contentDescription = null) },
                        label = { Text(stringResource(R.string.insights)) }
                    )
                    NavigationBarItem(
                        selected = workspacePage == WorkspacePage.Agent,
                        onClick = { onWorkspacePageChange(WorkspacePage.Agent) },
                        icon = { Icon(Icons.Default.AutoAwesome, contentDescription = null) },
                        label = { Text(stringResource(R.string.agent)) }
                    )
                    NavigationBarItem(
                        selected = workspacePage == WorkspacePage.Evidence,
                        onClick = { onWorkspacePageChange(WorkspacePage.Evidence) },
                        icon = { Icon(Icons.AutoMirrored.Filled.FactCheck, contentDescription = null) },
                        label = { Text(stringResource(R.string.evidence)) }
                    )
                }
            }
        }
    ) { paddingValues ->
        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            if (currentFile != null && isCompactChrome) {
                WorkspaceNavigationRail(
                    workspacePage = workspacePage,
                    onWorkspacePageChange = onWorkspacePageChange,
                    onRefreshDashboard = onRefreshDashboard
                )
            }
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxSize()
            ) {
                // Each ViewModel owns its own job state, so the banner shows the one
                // belonging to the page in view rather than letting an Agent run and
                // a filter scan overwrite each other's progress.
                if (workspacePage == WorkspacePage.Agent) {
                    AnalysisJobBanner(agentJob, onAgentCancel)
                } else {
                    AnalysisJobBanner(analysisJob, onCancelAnalysis)
                }
                if (openProgress != null) {
                    OpenProgressBar(openProgress, onCancelOpen)
                }

                if (currentFile == null) {
                    EmptyCaptureState(
                        recentFiles = recentFiles,
                        onOpenCapture = { filePicker.launch(CAPTURE_MIME_TYPES) },
                        onOpenLiveCapture = { showLiveCaptureDialog = true },
                        onOpenRecent = onOpenRecent,
                        onDeleteRecent = onDeleteRecent
                    )
                } else {
                    when (workspacePage) {
                        WorkspacePage.Packets -> {
                            WorkspaceFilterToolbar(
                                filterState = displayFilterUiState,
                                isFiltering = isFiltering,
                                showSearch = showSearch,
                                searchState = searchState,
                                workspace = workspace,
                                templates = scenarioTemplates,
                                onDisplayFilterChange = onDisplayFilterChange,
                                onApplyDisplayFilter = onApplyDisplayFilter,
                                onCancelDisplayFilter = onCancelDisplayFilter,
                                onClearDisplayFilter = onClearDisplayFilter,
                                onSearchModeChange = onSearchModeChange,
                                onSearchQueryChange = onSearchQueryChange,
                                onRunSearch = onRunSearch,
                                onCancelSearch = onCancelSearch,
                                onNextSearchResult = onNextSearchResult,
                                onPreviousSearchResult = onPreviousSearchResult,
                                onToggleFavoriteFilter = onToggleFavoriteFilter,
                                onPacketClick = onPacketClick,
                                compact = isCompactChrome
                            )
                            HealthSummaryBar(healthSummary, compact = isCompactChrome) {
                                onWorkspacePageChange(WorkspacePage.Insights)
                            }
                            PacketTable(
                                packetItems = packetItems,
                                listState = listState,
                                expertSummary = expertSummary,
                                colorRulesEnabled = preferences.colorRulesEnabled,
                                selectedFrame = workspace?.selectedFrame,
                                bookmarkedFrames = workspace?.bookmarks.orEmpty(),
                                evidenceFrames = workspace?.evidenceFrames.orEmpty(),
                                noteFrames = workspace?.notes?.mapTo(mutableSetOf()) { it.frameNumber }.orEmpty(),
                                searchFrames = searchState.results.toSet(),
                                packetContextActions = packetContextActions,
                                highlightedFrames = highlightedFrames,
                                onPrepareContextActions = onPreparePacketContextActions,
                                onApplyFollowFilter = onApplyPacketFollowFilter,
                                onToggleHighlight = onTogglePacketHighlight,
                                onPacketClick = onPacketClick
                            )
                        }
                        WorkspacePage.Insights -> InsightsWorkspace(
                            healthSummary = healthSummary,
                            workspace = workspace,
                            templates = scenarioTemplates,
                            expertSummary = expertSummary,
                            onRefresh = onRefreshDashboard,
                            onApplyFilter = {
                                onApplyScenarioStep(it)
                                onWorkspacePageChange(WorkspacePage.Packets)
                            },
                            onToggleFavoriteFilter = onToggleFavoriteFilter,
                            onPacketClick = onPacketClick,
                            onShowExpert = { showExpertDialog = true },
                            onShowStatistics = {
                                showStatisticsDialog = true
                                if (statisticsState.statistics == null && !statisticsState.isLoading) onRefreshStatistics()
                            },
                            onShowCommunication = {
                                showCommunicationDialog = true
                                if (communicationAnalysis.calls.isEmpty() && communicationAnalysis.streams.isEmpty() && !communicationAnalysis.isLoading) onRefreshCommunication()
                            },
                            onShowDecodeAs = { showDecodeAsDialog = true },
                            onShowHttpObjects = { showHttpObjects = true },
                            onShowRtpStreams = {
                                showRtpStreams = true
                                onRtpScan(false)
                            },
                            onCollapse = { onWorkspacePageChange(WorkspacePage.Packets) }
                        )
                        WorkspacePage.Agent -> ProtocolAgentScreen(
                            uiState = agentUiState,
                            currentFile = currentFile,
                            displayFilter = displayFilterUiState,
                            settings = agentSettings,
                            onPrivacyModeChange = onAgentPrivacyModeChange,
                            consentPrompt = agentConsentPrompt,
                            gatewayAccount = gatewayAccount,
                            onRefreshGatewayAccount = onRefreshGatewayAccount,
                            onSubmitQuestion = onAgentSubmitQuestion,
                            onContinueConversation = onAgentContinueConversation,
                            onCancel = onAgentCancel,
                            onRetry = onAgentRetry,
                            onNewConversation = onAgentNewConversation,
                            onClearTransientError = onAgentClearTransientError,
                            onModelSelectionChange = onAgentModelSelectionChange,
                            onAcceptConsent = onAgentAcceptConsent,
                            onDeclineConsent = onAgentDeclineConsent,
                            agentFilterPreview = agentFilterPreview,
                            onEvidenceClick = onAgentEvidenceClick,
                            onSaveFinding = onAgentSaveFinding,
                            onExportReport = onAgentExportReport,
                            onConfirmAgentFilterPreview = onConfirmAgentFilterPreview,
                            onDismissAgentFilterPreview = onDismissAgentFilterPreview,
                            savedSessions = agentSavedSessions,
                            deletingSavedSessions = agentDeletingSavedSessions,
                            restoredSession = agentRestoredSession,
                            restoredSessionMatchesCapture = agentRestoredSessionMatchesCapture,
                            interruptedJob = agentInterruptedJob,
                            onResumeInterruptedJob = onAgentResumeInterruptedJob,
                            onDismissInterruptedJob = onAgentDismissInterruptedJob,
                            localDataUsage = agentLocalDataUsage,
                            onOpenSavedSession = onAgentOpenSavedSession,
                            onDeleteSavedSession = onAgentDeleteSavedSession,
                            onDismissRestoredSession = onAgentDismissRestoredSession,
                            onClearLocalData = onAgentClearLocalData,
                            onExportDiagnostics = onAgentExportDiagnostics,
                            scenarioPackage = agentScenarioPackage,
                            playbooks = agentPlaybooks,
                            onClearScenarioPackage = onAgentClearScenarioPackage,
                            onPlaybookUsed = onAgentPlaybookUsed,
                            onEditScenario = onAgentEditScenario,
                            onCopyScenario = onAgentCopyScenario,
                            onDeleteScenario = onAgentDeleteScenario,
                            onViewScenarioDetails = onAgentViewScenarioDetails,
                            onNewScenario = onAgentNewScenario,
                            editingScenario = agentEditingScenario,
                            scenarioToolWhitelist = agentScenarioToolWhitelist,
                            onDismissScenarioEditor = onAgentDismissScenarioEditor,
                            onSaveScenario = onAgentSaveScenario,
                            scenarioSaving = agentScenarioSaving,
                            onScenarioPlaybookChange = onAgentScenarioPlaybookChange,
                            scenarioSaveCompleted = agentScenarioSaveCompleted,
                            scenarioQuarantineCodes = agentScenarioQuarantineCodes,
                            evidenceCoverageRun = agentRunRecord,
                            // Opening a frame leaves the workspace for the detail
                            // screen; the Agent session keeps running because it
                            // lives in its own ViewModel, not in this composable.
                            onFrameClick = onPacketClick
                        )
                        WorkspacePage.Evidence -> {
                            val evidenceAnalyzeQuestion = stringResource(R.string.evidence_analyze_question)
                            // EVL-UI-05: submit the compiled evidence filter as the
                            // analysis scope and switch to the Agent tab. Fail-closed:
                            // EvidenceWorkspace only calls this when the entry is
                            // enabled, so a blank/rejected filter can never reach here.
                            val onAnalyzeWithEvidence: (String, Int) -> Unit = { filter, frameCount ->
                                onAgentSubmitQuestion(
                                    evidenceAnalyzeQuestion,
                                    AnalysisScope.CurrentFilter,
                                    filter,
                                    frameCount
                                )
                                onWorkspacePageChange(WorkspacePage.Agent)
                            }
                            EvidenceWorkspace(
                            workspace = workspace,
                            frameCount = currentFile?.frameCount ?: 0,
                            onPacketClick = onPacketClick,
                            onSaveWorkspaceNote = onSaveWorkspaceNote,
                            onRemoveEvidence = onRemoveEvidence,
                            onRemoveEvidenceFrames = onRemoveEvidenceFrames,
                            onClearEvidence = onClearEvidence,
                            onExport = { showEvidenceExportDialog = true },
                            agentIsRunning = agentUiState.isRunning,
                            onAnalyzeWithEvidence = onAnalyzeWithEvidence,
                            onShowFramesOnly = {
                                when (val decision = onShowEvidenceFramesOnly()) {
                                    is EvidenceFrameViewDecision.Apply ->
                                        onWorkspacePageChange(WorkspacePage.Packets)
                                    is EvidenceFrameViewDecision.Reject ->
                                        scope.launch {
                                            snackbarHostState.showSnackbar(
                                                evidenceFrameViewRejectionMessage(decision, context)
                                            )
                                        }
                                }
                            }
                        )
                        }
                    }
                }
            }
        }
    }

    if (showExpertDialog) {
        LaunchedEffect(expertSummary.analyzed, expertSummary.isLoading) {
            if (!expertSummary.analyzed && !expertSummary.isLoading) {
                onRefreshExpertInfo()
            }
        }
        ExpertInfoDialog(
            summary = expertSummary,
            onCancel = onCancelExpertInfo,
            onPacketClick = onPacketClick,
            onDismiss = { showExpertDialog = false }
        )
    }

    if (showStatisticsDialog) {
        StatisticsDialog(
            state = statisticsState,
            onRefresh = onRefreshStatistics,
            onCancel = onCancelStatistics,
            onBucketChange = onStatisticsBucketChange,
            onPacketClick = onPacketClick,
            onApplyFilter = { filter ->
                showStatisticsDialog = false
                onApplyScenarioStep(filter)
            },
            onExportTable = onExportStatisticsCsv,
            onDismiss = { showStatisticsDialog = false }
        )
    }

    if (showCommunicationDialog) {
        CommunicationDialog(
            state = communicationAnalysis,
            onRefresh = onRefreshCommunication,
            onCancel = onCancelCommunication,
            onPacketClick = onPacketClick,
            onApplyFilter = { filter ->
                showCommunicationDialog = false
                onApplyScenarioStep(filter)
            },
            onOpenRtpStreams = {
                showCommunicationDialog = false
                showRtpStreams = true
                onRtpScan(false)
            },
            onOpenVoipCalls = {
                showCommunicationDialog = false
                showVoipCalls = true
            },
            onDismiss = { showCommunicationDialog = false }
        )
    }

    if (showPreferencesDialog) {
        PreferencesDialog(
            preferences = preferences,
            onPreferencesChange = onPreferencesChange,
            onOpenAgentModelSettings = {
                showAgentModelSettings = true
            },
            onDismiss = { showPreferencesDialog = false }
        )
    }

    if (showAgentModelSettings) {
        AgentModelSettingsDialog(
            settings = agentSettings,
            byokEnabled = agentByokEnabled,
            onSettingsChange = onAgentSettingsChange,
            onSaveProviderKey = onAgentSaveProviderKey,
            onClearProviderKey = onAgentClearProviderKey,
            onFetchProviderModels = onAgentFetchProviderModels,
            onDismiss = { showAgentModelSettings = false },
            debugResponseCaptureAvailable = agentResponseCaptureAvailable,
            onClearResponseDumps = onAgentClearResponseDumps
        )
    }

    if (showDecodeAsDialog) {
        DecodeAsDialog(
            rules = decodeAsRules,
            onAddRule = onAddDecodeAsRule,
            onRemoveRule = onRemoveDecodeAsRule,
            onDismiss = { showDecodeAsDialog = false }
        )
    }

    if (showLiveCaptureDialog) {
        LiveCaptureDialog(
            state = liveCaptureState,
            onStart = requestCaptureStart,
            onStop = onStopLiveCapture,
            onOpenSavedCapture = {
                showLiveCaptureDialog = false
                onOpenSavedLiveCapture()
            },
            onDismiss = { showLiveCaptureDialog = false }
        )
    }

    if (showEvidenceExportDialog) {
        EvidenceExportDialog(
            evidenceFramesScopeAvailability = evidenceFramesScopeAvailability,
            onExport = { mode, scope ->
                showEvidenceExportDialog = false
                onExportDiagnosticReport(mode, scope)
            },
            onSave = { mode, scope ->
                pendingEvidenceSelection = EvidenceExportSelection(mode, scope)
                showEvidenceExportDialog = false
                saveEvidenceLauncher.launch("layeranalyzer-evidence-${System.currentTimeMillis()}.zip")
            },
            onDismiss = { showEvidenceExportDialog = false }
        )
    }
    if (largeCaptureWarning != null) {
        LargeCaptureWarningDialog(largeCaptureWarning, onConfirmLargeCapture, onDismissLargeCapture)
    }
}

@Composable
private fun LargeCaptureWarningDialog(warning: LargeCaptureWarning, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.large_capture_title)) },
        text = { Text(stringResource(R.string.large_capture_message, warning.displayName, warning.sizeBytes.formatFileSize(), (warning.sizeBytes * 2).formatFileSize())) },
        confirmButton = { Button(onClick = onConfirm) { Text(stringResource(R.string.open_anyway)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}

@Composable
private fun EvidenceExportDialog(
    evidenceFramesScopeAvailability: EvidenceExportScopePolicy.ScopeAvailability,
    onExport: (EvidenceExportMode, EvidenceExportScope) -> Unit,
    onSave: (EvidenceExportMode, EvidenceExportScope) -> Unit,
    onDismiss: () -> Unit
) {
    var mode by remember { mutableStateOf(EvidenceExportMode.Redacted) }
    var scope by remember { mutableStateOf(EvidenceExportScope.CurrentView) }
    // Fail-closed: the current view is always available; the evidence-frame
    // scope only when the policy says so. The confirm/save buttons disable
    // otherwise rather than silently exporting the current view instead.
    val selectedScopeAvailable = scope == EvidenceExportScope.CurrentView ||
        evidenceFramesScopeAvailability.available
    val evidenceFramesUnavailableReason =
        evidenceFramesScopeUnavailableReason(evidenceFramesScopeAvailability)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.export_evidence_package)) },
        text = {
            Column {
                Text(
                    stringResource(R.string.evidence_scope_title),
                    style = MaterialTheme.typography.labelLarge
                )
                Spacer(Modifier.height(4.dp))
                EvidenceOption(
                    selected = scope,
                    option = EvidenceExportScope.EvidenceFrames,
                    title = stringResource(R.string.evidence_scope_frames_title),
                    description = evidenceFramesUnavailableReason
                        ?: stringResource(R.string.evidence_scope_frames_description),
                    enabled = evidenceFramesScopeAvailability.available
                ) { scope = it }
                EvidenceOption(
                    selected = scope,
                    option = EvidenceExportScope.CurrentView,
                    title = stringResource(R.string.evidence_scope_current_view_title),
                    description = stringResource(R.string.evidence_scope_current_view_description)
                ) { scope = it }
                Spacer(Modifier.height(12.dp))
                Text(stringResource(R.string.export_privacy_intro), style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                EvidenceOption(mode, EvidenceExportMode.Original, stringResource(R.string.evidence_original_title), stringResource(R.string.evidence_original_description)) { mode = it }
                EvidenceOption(mode, EvidenceExportMode.Redacted, stringResource(R.string.evidence_redacted_title), stringResource(R.string.evidence_redacted_description)) { mode = it }
                EvidenceOption(mode, EvidenceExportMode.MetadataOnly, stringResource(R.string.evidence_metadata_title), stringResource(R.string.evidence_metadata_description)) { mode = it }
            }
        },
        confirmButton = {
            Button(onClick = { onExport(mode, scope) }, enabled = selectedScopeAvailable) {
                Text(stringResource(R.string.generate_and_share))
            }
        },
        dismissButton = {
            Row {
                TextButton(onClick = { onSave(mode, scope) }, enabled = selectedScopeAvailable) {
                    Text(stringResource(R.string.save))
                }
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
            }
        }
    )
}

/**
 * Maps the structural [EvidenceExportScopePolicy.ScopeAvailability] onto a
 * localised reason, or `null` when the evidence-frame scope is available. The
 * data layer deliberately carries no display text, so the mapping lives here.
 */
@Composable
private fun evidenceFramesScopeUnavailableReason(
    availability: EvidenceExportScopePolicy.ScopeAvailability
): String? {
    if (availability.available) return null
    return when (availability.reasonCode) {
        EvidenceExportScopePolicy.ReasonCode.NoEvidenceFrames ->
            stringResource(R.string.evidence_scope_frames_empty)

        EvidenceExportScopePolicy.ReasonCode.FilterRejected -> {
            val actual = availability.actual
            val limit = availability.limit
            if (actual != null && limit != null) {
                stringResource(R.string.evidence_scope_frames_rejected_limit, actual, limit)
            } else {
                stringResource(R.string.evidence_scope_frames_rejected_invalid)
            }
        }

        null -> null
    }
}

@Composable
private fun <T> EvidenceOption(
    selected: T,
    option: T,
    title: String,
    description: String,
    enabled: Boolean = true,
    onSelect: (T) -> Unit
) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled) { onSelect(option) }
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.Top
    ) {
        RadioButton(selected = selected == option, onClick = { onSelect(option) }, enabled = enabled)
        Column(Modifier.padding(top = 10.dp)) {
            Text(
                title,
                style = MaterialTheme.typography.labelLarge,
                color = if (enabled) {
                    MaterialTheme.colorScheme.onSurface
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                }
            )
            Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun PreferencesDialog(
    preferences: AnalyzerPreferences,
    onPreferencesChange: (AnalyzerPreferences) -> Unit,
    onOpenAgentModelSettings: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var draft by remember(preferences) { mutableStateOf(preferences) }
    var showNotices by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }
    if (showNotices) {
        val noticeParagraphs = remember {
            runCatching {
                val notices = context.assets.open("THIRD_PARTY_NOTICES.txt")
                    .bufferedReader(Charsets.UTF_8).use { it.readText() }.replace("\r\n", "\n")
                val texts = buildList {
                    add(notices)
                    context.assets.list("licenses").orEmpty().filter { it.endsWith(".txt") }
                        .sorted().forEach { name ->
                            val license = context.assets.open("licenses/$name")
                                .bufferedReader(Charsets.UTF_8).use { it.readText() }
                                .replace("\r\n", "\n")
                            if (!notices.contains(license.trim())) {
                                add("$name\n\n$license")
                            }
                        }
                }
                // A single Text for all licenses can exceed Compose's layout height limit.
                // Keep the existing dialog while measuring only visible paragraphs.
                texts.flatMap { it.split(Regex("\n[ \\t]*\n")) }.filter { it.isNotBlank() }
            }.getOrElse { listOf(context.getString(R.string.notices_unavailable)) }
        }
        AlertDialog(
            onDismissRequest = { showNotices = false },
            confirmButton = { TextButton(onClick = { showNotices = false }) { Text(stringResource(R.string.close)) } },
            title = { Text(stringResource(R.string.third_party_notices)) },
            text = {
                LazyColumn(
                    modifier = Modifier.height(420.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(noticeParagraphs) { paragraph ->
                        Text(paragraph, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        )
        return
    }
    if (showAbout) {
        AboutDialog(
            onOpenNotices = { showNotices = true },
            onDismiss = { showAbout = false }
        )
        return
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            Button(onClick = {
                onPreferencesChange(draft)
                onDismiss()
            }) {
                Text(stringResource(R.string.apply))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
        title = { Text(stringResource(R.string.preferences_title)) },
        text = {
            Column(modifier = Modifier.widthIn(max = 520.dp).verticalScroll(rememberScrollState())) {
                // Resolved here rather than inside EnumMenu's display lambda:
                // that lambda is not a @Composable scope, so stringResource
                // cannot be called from it.  Same pattern as timeLabels below.
                val uiLanguageLabels = mapOf(
                    UiLanguage.SYSTEM to stringResource(R.string.ui_language_system),
                    UiLanguage.CHINESE to stringResource(R.string.ui_language_chinese),
                    UiLanguage.ENGLISH to stringResource(R.string.ui_language_english)
                )
                EnumMenu(
                    label = stringResource(R.string.ui_language),
                    value = draft.uiLanguage,
                    values = UiLanguage.values().toList(),
                    display = { uiLanguageLabels[it].orEmpty() },
                    onValueChange = { draft = draft.copy(uiLanguage = it) }
                )
                val timeLabels = mapOf(
                    TimeDisplayFormat.Relative to stringResource(R.string.time_relative),
                    TimeDisplayFormat.Delta to stringResource(R.string.time_delta),
                    TimeDisplayFormat.Absolute to stringResource(R.string.time_absolute),
                    TimeDisplayFormat.Utc to stringResource(R.string.time_utc)
                )
                EnumMenu(
                    label = stringResource(R.string.time_display),
                    value = draft.timeDisplayFormat,
                    values = TimeDisplayFormat.values().toList(),
                    display = { timeLabels[it].orEmpty() },
                    onValueChange = { draft = draft.copy(timeDisplayFormat = it) }
                )
                PreferenceSwitch(stringResource(R.string.name_resolution), draft.nameResolutionEnabled) {
                    draft = draft.copy(nameResolutionEnabled = it)
                }
                Text(
                    stringResource(R.string.name_resolution_privacy),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                PreferenceSwitch(stringResource(R.string.color_rules), draft.colorRulesEnabled) {
                    draft = draft.copy(colorRulesEnabled = it)
                }
                val espDecryptionLabels = mapOf(
                    EspDecryptionMode.Probe to stringResource(R.string.esp_decryption_probe),
                    EspDecryptionMode.All to stringResource(R.string.esp_decryption_all),
                    EspDecryptionMode.Off to stringResource(R.string.esp_decryption_off)
                )
                EnumMenu(
                    label = stringResource(R.string.esp_decryption),
                    value = draft.espDecryptionMode,
                    values = EspDecryptionMode.values().toList(),
                    display = { espDecryptionLabels[it].orEmpty() },
                    onValueChange = { draft = draft.copy(espDecryptionMode = it) }
                )
                Text(
                    stringResource(R.string.esp_decryption_description),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                TextButton(onClick = onOpenAgentModelSettings) {
                    Icon(Icons.Default.AutoAwesome, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.agent_model_settings_title))
                }
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.tree_expansion_depth), modifier = Modifier.weight(1f))
                    TextButton(onClick = { draft = draft.copy(defaultTreeExpansionDepth = (draft.defaultTreeExpansionDepth - 1).coerceAtLeast(0)) }) {
                        Text("-")
                    }
                    Text(draft.defaultTreeExpansionDepth.toString(), modifier = Modifier.padding(horizontal = 12.dp))
                    TextButton(onClick = { draft = draft.copy(defaultTreeExpansionDepth = (draft.defaultTreeExpansionDepth + 1).coerceAtMost(5)) }) {
                        Text("+")
                    }
                }
                TextButton(onClick = { showAbout = true }) {
                    Text(stringResource(R.string.about_title))
                }
                TextButton(onClick = { showNotices = true }) {
                    Text(stringResource(R.string.third_party_notices))
                }
            }
        }
    )
}

@Composable
private fun DecodeAsDialog(
    rules: List<DecodeAsRule>,
    onAddRule: (DecodeAsScope, DecodeAsTransport, String, String, Int?, Int?, String) -> Unit,
    onRemoveRule: (DecodeAsRule) -> Unit,
    onDismiss: () -> Unit
) {
    val scope = DecodeAsScope.Port
    var transport by remember { mutableStateOf(DecodeAsTransport.TCP) }
    var source by remember { mutableStateOf("") }
    var destination by remember { mutableStateOf("") }
    var sourcePort by remember { mutableStateOf("") }
    var destinationPort by remember { mutableStateOf("") }
    var protocol by remember { mutableStateOf("http") }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            Button(
                onClick = {
                    onAddRule(
                        scope,
                        transport,
                        source,
                        destination,
                        sourcePort.toIntOrNull(),
                        destinationPort.toIntOrNull(),
                        protocol
                    )
                },
                enabled = protocol.isNotBlank() && (sourcePort.toIntOrNull() != null || destinationPort.toIntOrNull() != null)
            ) {
                Text(stringResource(R.string.add))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) } },
        title = { Text(stringResource(R.string.decode_as)) },
        text = {
            Column(modifier = Modifier.widthIn(max = 560.dp)) {
                Text(
                    stringResource(R.string.decode_as_scope_notice),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    EnumMenu(
                        label = stringResource(R.string.transport),
                        value = transport,
                        values = DecodeAsTransport.values().toList(),
                        display = { it.label },
                        onValueChange = { transport = it }
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = sourcePort,
                        onValueChange = { sourcePort = it.filter(Char::isDigit) },
                        label = { Text(stringResource(R.string.source_port)) },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    OutlinedTextField(
                        value = destinationPort,
                        onValueChange = { destinationPort = it.filter(Char::isDigit) },
                        label = { Text(stringResource(R.string.destination_port)) },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                }
                OutlinedTextField(
                    value = protocol,
                    onValueChange = { protocol = it.trim() },
                    label = { Text(stringResource(R.string.protocol_dissector)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                Spacer(modifier = Modifier.height(8.dp))
                if (rules.isEmpty()) {
                    Text(stringResource(R.string.no_decode_rules), color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    LazyColumn(modifier = Modifier.height(180.dp)) {
                        items(rules, key = { it.id }) { rule ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    stringResource(R.string.decode_as_rule_summary, rule.transport.label, rule.ports.joinToString(","), rule.protocol),
                                    modifier = Modifier.weight(1f),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                IconButton(onClick = { onRemoveRule(rule) }) {
                                    Icon(Icons.Default.Close, contentDescription = stringResource(R.string.remove_rule))
                                }
                            }
                            HorizontalDivider()
                        }
                    }
                }
            }
        }
    )
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
private fun LiveCaptureScreen(
    state: LiveCaptureState,
    onStart: (LiveCaptureSettings) -> Unit,
    onStop: () -> Unit,
    onOpenSavedCapture: () -> Unit,
    onBack: () -> Unit
) {
    BackHandler(onBack = onBack)
    val context = LocalContext.current
    var settings by remember { mutableStateOf(LiveCaptureSettings()) }
    val installedApplications = remember { queryCaptureApplications(context) }
    var showApplicationPicker by remember { mutableStateOf(false) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.vpn_snapshot_title)) },
                navigationIcon = { IconButton(onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) } },
                actions = {
                    TextButton(onClick = onOpenSavedCapture, enabled = state.hasSavedCapture) { Text(stringResource(R.string.open_saved)) }
                }
            )
        },
        bottomBar = {
            Surface(tonalElevation = 3.dp) {
                Row(Modifier.fillMaxWidth().padding(10.dp), horizontalArrangement = Arrangement.End) {
                    Button(onClick = if (state.isCapturing) onStop else { { onStart(settings) } }) {
                        Icon(if (state.isCapturing) Icons.Default.Stop else Icons.Default.PlayArrow, contentDescription = null)
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(if (state.isCapturing) R.string.stop else R.string.start))
                    }
                }
            }
        }
    ) { padding ->
        LazyColumn(Modifier.padding(padding).fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                Text(stringResource(R.string.vpn_scope_notice), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(R.string.vpn_storage_notice), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 6.dp))
            }
            item {
                PreferenceSwitch(stringResource(R.string.exclude_layer_analyzer), settings.excludeSelf) { settings = settings.copy(excludeSelf = it) }
                PreferenceSwitch(stringResource(R.string.capture_ipv6_route), settings.captureIpv6) { settings = settings.copy(captureIpv6 = it) }
            }
            item {
                Button({ showApplicationPicker = true }, enabled = !state.isCapturing) {
                    Text(if (settings.allowedApplications.isEmpty()) stringResource(R.string.capture_apps_all) else stringResource(R.string.capture_apps_selected, settings.allowedApplications.size))
                }
                Text(
                    if (settings.allowedApplications.isEmpty()) stringResource(R.string.capture_apps_all_description) else settings.allowedApplications.joinToString(),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis
                )
            }
            item {
                SettingStepper(stringResource(R.string.auto_stop), stringResource(R.string.minutes_short, settings.maxDurationMinutes)) {
                    settings = settings.copy(maxDurationMinutes = when (settings.maxDurationMinutes) { 5 -> 15; 15 -> 30; else -> 5 })
                }
                SettingStepper(stringResource(R.string.capture_limit), stringResource(R.string.megabytes_short, settings.maxSizeMegabytes)) {
                    val next = when (settings.maxSizeMegabytes) { 64 -> 256; 256 -> 512; else -> 64 }
                    settings = settings.copy(maxSizeMegabytes = next, segmentSizeMegabytes = settings.segmentSizeMegabytes.coerceAtMost(next))
                }
                SettingStepper(stringResource(R.string.segment_rotation), stringResource(R.string.segment_size, settings.segmentSizeMegabytes)) {
                    settings = settings.copy(segmentSizeMegabytes = when (settings.segmentSizeMegabytes) { 32 -> 64; 64 -> 128; else -> 32 }.coerceAtMost(settings.maxSizeMegabytes))
                }
            }
            item {
                HorizontalDivider()
                Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(if (state.isCapturing) stringResource(R.string.capture_status_running) else stringResource(R.string.capture_status_stopped), Modifier.weight(1f), color = if (state.isCapturing) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(stringResource(R.string.captured_packets_bytes, state.packetCount, state.byteCount.formatFileSize()), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelMedium)
                }
                if (state.offeredPacketCount > 0L || state.droppedPacketCount > 0L || state.ioErrorCount > 0L) {
                    Text(
                        when { state.isCapturing -> stringResource(R.string.capture_writing_status, state.packetCount, state.offeredPacketCount); state.captureIsComplete -> stringResource(R.string.capture_complete_status, state.packetCount); else -> stringResource(R.string.capture_incomplete_status, state.droppedPacketCount, state.ioErrorCount) },
                        color = if (state.captureIsComplete || state.isCapturing) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.labelMedium
                    )
                }
                state.lastIoError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall) }
            }
            if (!state.outputPath.isNullOrBlank()) item {
                val output = File(state.outputPath)
                Text(output.name, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                val report = File(output.parentFile, "${output.name}.report.json")
                TextButton({ shareExportResult(context, ExportResult(report.absolutePath, report.name, "application/json")) }, enabled = report.isFile) { Text(stringResource(R.string.open_integrity_report)) }
                if (state.segmentPaths.size > 1) Text(stringResource(R.string.rotated_segments_notice, state.segmentPaths.size), style = MaterialTheme.typography.labelSmall)
            }
            item { Text(stringResource(R.string.recent_packets), style = MaterialTheme.typography.titleMedium) }
            if (state.recentPackets.isEmpty()) item { Text(stringResource(R.string.no_packets_captured), color = MaterialTheme.colorScheme.onSurfaceVariant) }
            else items(state.recentPackets, key = { it.number }) { packet -> LiveCapturePacketRow(packet); HorizontalDivider() }
            item { Text(stringResource(R.string.adb_capture_workflow), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
    if (showApplicationPicker) {
        AlertDialog(
            onDismissRequest = { showApplicationPicker = false },
            title = { Text(stringResource(R.string.capture_apps)) },
            text = {
                LazyColumn(Modifier.height(420.dp)) {
                    items(installedApplications, key = { it.packageName }) { application ->
                        val selected = application.packageName in settings.allowedApplications
                        Row(Modifier.fillMaxWidth().clickable {
                            val next = settings.allowedApplications.toMutableSet().apply { if (!add(application.packageName)) remove(application.packageName) }
                            settings = settings.copy(allowedApplications = next.sorted())
                        }.padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(selected, null)
                            Column { Text(application.label); Text(application.packageName, style = MaterialTheme.typography.labelSmall) }
                        }
                    }
                }
            },
            confirmButton = { Button({ showApplicationPicker = false }) { Text(stringResource(R.string.done)) } },
            dismissButton = { TextButton({ settings = settings.copy(allowedApplications = emptyList()) }) { Text(stringResource(R.string.clear_all_apps)) } }
        )
    }
}

@Composable
private fun SettingStepper(label: String, value: String, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().height(48.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f))
        TextButton(onClick) { Text(value) }
    }
}

@Composable
private fun LiveCaptureDialog(
    state: LiveCaptureState,
    onStart: (LiveCaptureSettings) -> Unit,
    onStop: () -> Unit,
    onOpenSavedCapture: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var settings by remember { mutableStateOf(LiveCaptureSettings()) }
    val installedApplications = remember { queryCaptureApplications(context) }
    var showApplicationPicker by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            if (state.isCapturing) {
                Button(onClick = onStop) {
                    Icon(Icons.Default.Stop, contentDescription = null)
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.stop))
                }
            } else {
                Button(onClick = { onStart(settings) }) {
                    Icon(Icons.Default.PlayArrow, contentDescription = null)
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.start))
                }
            }
        },
        dismissButton = {
            Row {
                TextButton(onClick = onOpenSavedCapture, enabled = state.hasSavedCapture) {
                    Text(stringResource(R.string.open_saved))
                }
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.close))
                }
            }
        },
        title = { Text(stringResource(R.string.vpn_snapshot_title)) },
        text = {
            Column(modifier = Modifier.widthIn(max = 620.dp)) {
                Text(
                    stringResource(R.string.vpn_scope_notice),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    stringResource(R.string.vpn_storage_notice),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(8.dp))
                PreferenceSwitch(stringResource(R.string.exclude_layer_analyzer), settings.excludeSelf) {
                    settings = settings.copy(excludeSelf = it)
                }
                PreferenceSwitch(stringResource(R.string.capture_ipv6_route), settings.captureIpv6) {
                    settings = settings.copy(captureIpv6 = it)
                }
                Button(onClick = { showApplicationPicker = true }, enabled = !state.isCapturing) {
                    Text(if (settings.allowedApplications.isEmpty()) stringResource(R.string.capture_apps_all) else stringResource(R.string.capture_apps_selected, settings.allowedApplications.size))
                }
                Text(
                    if (settings.allowedApplications.isEmpty()) stringResource(R.string.capture_apps_all_description) else settings.allowedApplications.joinToString(),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.auto_stop), modifier = Modifier.weight(1f))
                    TextButton(onClick = {
                        settings = settings.copy(maxDurationMinutes = when (settings.maxDurationMinutes) {
                            5 -> 15
                            15 -> 30
                            else -> 5
                        })
                    }) {
                        Text(stringResource(R.string.minutes_short, settings.maxDurationMinutes))
                    }
                    TextButton(onClick = {
                        val nextMax = when (settings.maxSizeMegabytes) {
                            64 -> 256
                            256 -> 512
                            else -> 64
                        }
                        settings = settings.copy(
                            maxSizeMegabytes = nextMax,
                            segmentSizeMegabytes = settings.segmentSizeMegabytes.coerceAtMost(nextMax)
                        )
                    }) {
                        Text(stringResource(R.string.megabytes_short, settings.maxSizeMegabytes))
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.segment_rotation), modifier = Modifier.weight(1f))
                    TextButton(onClick = {
                        settings = settings.copy(segmentSizeMegabytes = when (settings.segmentSizeMegabytes) {
                            32 -> 64
                            64 -> 128
                            else -> 32
                        }.coerceAtMost(settings.maxSizeMegabytes))
                    }) { Text(stringResource(R.string.segment_size, settings.segmentSizeMegabytes)) }
                }
                Spacer(modifier = Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        if (state.isCapturing) stringResource(R.string.capture_status_running) else stringResource(R.string.capture_status_stopped),
                        color = if (state.isCapturing) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f)
                    )
                    Text(stringResource(R.string.captured_packets_bytes, state.packetCount, state.byteCount.formatFileSize()))
                }
                if (state.offeredPacketCount > 0L || state.droppedPacketCount > 0L || state.ioErrorCount > 0L) {
                    val status = when {
                        state.isCapturing -> stringResource(R.string.capture_writing_status, state.packetCount, state.offeredPacketCount)
                        state.captureIsComplete -> stringResource(R.string.capture_complete_status, state.packetCount)
                        else -> stringResource(R.string.capture_incomplete_status, state.droppedPacketCount, state.ioErrorCount)
                    }
                    Text(
                        status,
                        style = MaterialTheme.typography.labelMedium,
                        color = if (state.captureIsComplete || state.isCapturing) {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        } else {
                            MaterialTheme.colorScheme.error
                        }
                    )
                    state.lastIoError?.let { message ->
                        Text(message, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
                    }
                }
                if (!state.outputPath.isNullOrBlank()) {
                    Text(
                        File(state.outputPath).name,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    val report = File(File(state.outputPath).parentFile, "${File(state.outputPath).name}.report.json")
                    TextButton(onClick = {
                        shareExportResult(context, ExportResult(report.absolutePath, report.name, "application/json"))
                    }, enabled = report.isFile) { Text(stringResource(R.string.open_integrity_report)) }
                    if (state.segmentPaths.size > 1) {
                        Text(
                            stringResource(R.string.rotated_segments_notice, state.segmentPaths.size),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Spacer(modifier = Modifier.height(10.dp))
                Text(stringResource(R.string.recent_packets), style = MaterialTheme.typography.titleSmall)
                if (state.recentPackets.isEmpty()) {
                    Text(stringResource(R.string.no_packets_captured), color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    LazyColumn(modifier = Modifier.height(220.dp)) {
                        items(state.recentPackets, key = { it.number }) { packet ->
                            LiveCapturePacketRow(packet)
                            HorizontalDivider()
                        }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    stringResource(R.string.adb_capture_workflow),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    )

    if (showApplicationPicker) {
        AlertDialog(
            onDismissRequest = { showApplicationPicker = false },
            title = { Text(stringResource(R.string.capture_apps)) },
            text = {
                LazyColumn(Modifier.height(420.dp)) {
                    items(installedApplications, key = { it.packageName }) { application ->
                        val selected = application.packageName in settings.allowedApplications
                        Row(
                            Modifier.fillMaxWidth().clickable {
                                val next = settings.allowedApplications.toMutableSet().apply {
                                    if (!add(application.packageName)) remove(application.packageName)
                                }
                                settings = settings.copy(allowedApplications = next.sorted())
                            }.padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(checked = selected, onCheckedChange = null)
                            Column {
                                Text(application.label)
                                Text(application.packageName, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            },
            confirmButton = { Button(onClick = { showApplicationPicker = false }) { Text(stringResource(R.string.done)) } },
            dismissButton = {
                TextButton(onClick = { settings = settings.copy(allowedApplications = emptyList()) }) { Text(stringResource(R.string.clear_all_apps)) }
            }
        )
    }
}

private data class CaptureApplication(val label: String, val packageName: String)

private fun queryCaptureApplications(context: Context): List<CaptureApplication> {
    val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    return context.packageManager.queryIntentActivities(launcherIntent, 0)
        .map { info -> CaptureApplication(info.loadLabel(context.packageManager).toString(), info.activityInfo.packageName) }
        .distinctBy { it.packageName }
        .filterNot { it.packageName == context.packageName }
        .sortedBy { it.label.lowercase() }
}

@Composable
private fun LiveCapturePacketRow(packet: LiveCapturePacketPreview) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text("#${packet.number}", modifier = Modifier.width(64.dp), style = MaterialTheme.typography.labelMedium)
        Column(modifier = Modifier.weight(1f)) {
            Text(
                "${packet.source} -> ${packet.destination}",
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                "IPv${packet.ipVersion} ${packet.protocol}  ${packet.length} B",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelSmall
            )
        }
    }
}

@Composable
private fun PreferenceSwitch(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun <T> EnumMenu(
    label: String,
    value: T,
    values: List<T>,
    display: (T) -> String,
    onValueChange: (T) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        FilterChip(
            selected = true,
            onClick = { expanded = true },
            label = { Text("$label: ${display(value)}") }
        )
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            values.forEach { item ->
                DropdownMenuItem(
                    text = { Text(display(item)) },
                    onClick = {
                        expanded = false
                        onValueChange(item)
                    }
                )
            }
        }
    }
}

@Composable
private fun OpenProgressBar(
    progress: OpenProgress,
    onCancelOpen: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(horizontal = 16.dp, vertical = 10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(progress.message, style = MaterialTheme.typography.bodyMedium)
                if (progress.framesIndexed > 0) {
                    Text(
                        stringResource(R.string.frames_indexed, progress.framesIndexed),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            TextButton(onClick = onCancelOpen) {
                Text(stringResource(R.string.cancel_action))
            }
        }
        val fraction = progress.progressFraction
        if (fraction == null) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        } else {
            LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun EmptyCaptureState(
    recentFiles: List<RecentCapture>,
    onOpenCapture: () -> Unit,
    onOpenLiveCapture: () -> Unit,
    onOpenRecent: (RecentCapture) -> Unit,
    onDeleteRecent: (RecentCapture) -> Unit
) {
    var pendingDelete by remember { mutableStateOf<RecentCapture?>(null) }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(20.dp))
        Button(onClick = onOpenCapture, modifier = Modifier.fillMaxWidth().height(52.dp)) {
            Icon(Icons.Default.FolderOpen, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text(stringResource(R.string.open_pcap_description))
        }
        Spacer(modifier = Modifier.height(8.dp))
        TextButton(onClick = onOpenLiveCapture, modifier = Modifier.fillMaxWidth().height(48.dp)) {
            Icon(Icons.Default.PlayArrow, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text(stringResource(R.string.vpn_snapshot_experimental))
        }
        Spacer(modifier = Modifier.height(10.dp))
        Text(
            stringResource(R.string.local_analysis_privacy),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(22.dp))
        if (recentFiles.isNotEmpty()) {
            Text(
                stringResource(R.string.continue_analysis),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            LazyColumn(modifier = Modifier.fillMaxWidth()) {
                items(recentFiles, key = { it.localPath }) { recent ->
                    RecentFileRow(
                        recent,
                        onClick = { onOpenRecent(recent) },
                        onDelete = { pendingDelete = recent }
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 0.5.dp)
                }
            }
        }
    }
    pendingDelete?.let { recent ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(stringResource(R.string.delete_capture_title)) },
            text = { Text(stringResource(R.string.delete_capture_message, recent.displayName)) },
            confirmButton = {
                TextButton(onClick = { pendingDelete = null; onDeleteRecent(recent) }) {
                    Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text(stringResource(R.string.cancel)) } }
        )
    }
}

@Composable
private fun RecentFileRow(recent: RecentCapture, onClick: () -> Unit, onDelete: () -> Unit) {
    var menuExpanded by remember { mutableStateOf(false) }
    val framesLabel = stringResource(R.string.frames_short)
    val workspaceSavedLabel = stringResource(R.string.workspace_saved)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Default.FolderOpen,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(20.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(recent.displayName, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                buildString {
                    append(recent.displayName.substringAfterLast('.', "capture").uppercase())
                    append("  ${recent.sizeBytes.formatFileSize()}")
                    if (recent.frameCount > 0) append("  ${recent.frameCount} $framesLabel")
                    if (recent.hasSavedWorkspace) append("  · $workspaceSavedLabel")
                    append("  ${DateUtils.getRelativeTimeSpanString(recent.openedAtMillis)}")
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Box {
            IconButton(onClick = { menuExpanded = true }) {
                Icon(Icons.Default.MoreVert, contentDescription = stringResource(R.string.more_file_actions))
            }
            DropdownMenu(menuExpanded, { menuExpanded = false }) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.delete)) },
                    onClick = { menuExpanded = false; onDelete() },
                    leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null) }
                )
            }
        }
    }
}

/** Landscape page switcher; costs width instead of the bottom bar's height. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun WorkspaceNavigationRail(
    workspacePage: WorkspacePage,
    onWorkspacePageChange: (WorkspacePage) -> Unit,
    onRefreshDashboard: () -> Unit
) {
    NavigationRail(
        // Scaffold's inner padding already carries the system bar insets.
        windowInsets = WindowInsets(0, 0, 0, 0)
    ) {
        NavigationRailItem(
            selected = workspacePage == WorkspacePage.Packets,
            onClick = { onWorkspacePageChange(WorkspacePage.Packets) },
            icon = { Icon(Icons.Default.Description, contentDescription = null) },
            label = { Text(stringResource(R.string.packets), style = MaterialTheme.typography.labelSmall) }
        )
        NavigationRailItem(
            selected = workspacePage == WorkspacePage.Insights,
            onClick = {
                if (workspacePage != WorkspacePage.Insights) onRefreshDashboard()
                onWorkspacePageChange(WorkspacePage.Insights)
            },
            icon = { Icon(Icons.Default.Dashboard, contentDescription = null) },
            label = { Text(stringResource(R.string.insights), style = MaterialTheme.typography.labelSmall) }
        )
        NavigationRailItem(
            selected = workspacePage == WorkspacePage.Agent,
            onClick = { onWorkspacePageChange(WorkspacePage.Agent) },
            icon = { Icon(Icons.Default.AutoAwesome, contentDescription = null) },
            label = { Text(stringResource(R.string.agent), style = MaterialTheme.typography.labelSmall) }
        )
        NavigationRailItem(
            selected = workspacePage == WorkspacePage.Evidence,
            onClick = { onWorkspacePageChange(WorkspacePage.Evidence) },
            icon = { Icon(Icons.AutoMirrored.Filled.FactCheck, contentDescription = null) },
            label = { Text(stringResource(R.string.evidence), style = MaterialTheme.typography.labelSmall) }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun WorkspaceFilterToolbar(
    filterState: DisplayFilterUiState,
    isFiltering: Boolean,
    showSearch: Boolean,
    searchState: PacketSearchState,
    workspace: AnalysisWorkspace?,
    templates: List<ScenarioTemplate>,
    onDisplayFilterChange: (String) -> Unit,
    onApplyDisplayFilter: () -> Unit,
    onCancelDisplayFilter: () -> Unit,
    onClearDisplayFilter: () -> Unit,
    onSearchModeChange: (PacketSearchMode) -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onRunSearch: () -> Unit,
    onCancelSearch: () -> Unit,
    onNextSearchResult: () -> Unit,
    onPreviousSearchResult: () -> Unit,
    onToggleFavoriteFilter: (String) -> Unit,
    onPacketClick: (Long) -> Unit,
    /** Landscape mode: the summary row and its buttons shrink to fit. */
    compact: Boolean = false
) {
    var showEditor by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(filterState.hasUnappliedChanges, isFiltering) {
        if (filterState.hasUnappliedChanges) showEditor = true
        else if (!isFiltering) showEditor = false
    }
    val rowHeight = if (compact) 36.dp else 48.dp
    Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface)) {
        Row(
            Modifier.fillMaxWidth().height(rowHeight).clickable { showEditor = true }.padding(start = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            FilterStatusIcon(filterState, isFiltering)
            Text(
                filterState.appliedExpression.ifBlank { stringResource(R.string.all_packets) },
                Modifier.weight(1f).padding(horizontal = 8.dp),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            if (filterState.hasUnappliedChanges) {
                Text(stringResource(R.string.unapplied), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary)
            }
            Text(
                "${filterState.visibleCount} / ${filterState.totalCount}",
                Modifier.padding(horizontal = 6.dp),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (filterState.appliedExpression.isNotBlank() || filterState.draftExpression.isNotBlank()) {
                IconButton(onClick = onClearDisplayFilter, modifier = Modifier.size(rowHeight)) {
                    Icon(
                        Icons.Default.Close,
                        stringResource(R.string.clear_filter),
                        modifier = Modifier.size(if (compact) 18.dp else 24.dp)
                    )
                }
            }
        }
        HorizontalDivider()
        if (showSearch) {
            SearchWorkspaceBar(
                searchState,
                onSearchModeChange,
                onSearchQueryChange,
                onRunSearch,
                onCancelSearch,
                onPreviousSearchResult,
                onNextSearchResult,
                onPacketClick
            )
        }
    }

    if (showEditor) {
        ModalBottomSheet(onDismissRequest = { showEditor = false }) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp).padding(bottom = 20.dp)) {
                Text(stringResource(R.string.display_filter), style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = filterState.draftExpression,
                    onValueChange = onDisplayFilterChange,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.display_filter)) },
                    placeholder = { Text(stringResource(R.string.display_filter_examples)) },
                    minLines = 2,
                    maxLines = 5,
                    isError = filterState.syntaxStatus == FilterSyntaxStatus.Invalid,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(onDone = {
                        if (filterState.syntaxStatus != FilterSyntaxStatus.Invalid) onApplyDisplayFilter()
                    })
                )
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    FilterStatusIcon(filterState, isFiltering)
                    Text(
                        when {
                            isFiltering -> stringResource(R.string.filtering)
                            filterState.syntaxStatus == FilterSyntaxStatus.Checking -> stringResource(R.string.checking_syntax)
                            filterState.syntaxStatus == FilterSyntaxStatus.Valid -> stringResource(R.string.syntax_valid)
                            filterState.syntaxStatus == FilterSyntaxStatus.Invalid -> filterState.syntaxError ?: stringResource(R.string.syntax_invalid)
                            else -> stringResource(R.string.syntax_unchecked)
                        },
                        Modifier.weight(1f).padding(8.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (filterState.syntaxStatus == FilterSyntaxStatus.Invalid) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Button(
                        onClick = if (isFiltering) onCancelDisplayFilter else {
                            { onApplyDisplayFilter(); showEditor = false }
                        },
                        enabled = isFiltering || filterState.syntaxStatus != FilterSyntaxStatus.Invalid
                    ) {
                        Text(stringResource(if (isFiltering) R.string.stop else R.string.apply))
                    }
                }
                val favoriteFilters = workspace?.favoriteFilters.orEmpty()
                if (favoriteFilters.isNotEmpty()) {
                    FilterSuggestionRow(stringResource(R.string.favorite_filters), favoriteFilters.toList(), onDisplayFilterChange)
                }
                workspace?.filterHistory?.takeIf { it.isNotEmpty() }?.let {
                    FilterSuggestionRow(stringResource(R.string.recent_filters), it.take(12), onDisplayFilterChange, onToggleFavoriteFilter, favoriteFilters)
                }
                templates.forEach { template ->
                    FilterSuggestionRow(template.title, template.steps.map { it.filter }, onDisplayFilterChange)
                }
            }
        }
    }
}

@Composable
private fun FilterStatusIcon(state: DisplayFilterUiState, isFiltering: Boolean) {
    when {
        isFiltering || state.syntaxStatus == FilterSyntaxStatus.Checking -> CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
        state.syntaxStatus == FilterSyntaxStatus.Valid -> Icon(Icons.Default.CheckCircle, null, Modifier.size(20.dp), tint = MaterialTheme.colorScheme.primary)
        state.syntaxStatus == FilterSyntaxStatus.Invalid -> Icon(Icons.Default.ErrorOutline, null, Modifier.size(20.dp), tint = MaterialTheme.colorScheme.error)
        else -> Icon(Icons.Default.Schedule, null, Modifier.size(20.dp), tint = MaterialTheme.colorScheme.outline)
    }
}

@Composable
private fun FilterSuggestionRow(
    title: String,
    filters: List<String>,
    onSelect: (String) -> Unit,
    onFavorite: ((String) -> Unit)? = null,
    favorites: Set<String> = emptySet()
) {
    Text(title, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 8.dp))
    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        filters.distinct().forEach { filter ->
            AssistChip(
                onClick = { onSelect(filter) },
                label = { Text(filter, maxLines = 1, fontFamily = FontFamily.Monospace) },
                trailingIcon = if (onFavorite == null) null else {
                    { IconButton({ onFavorite(filter) }, Modifier.size(24.dp)) { Icon(if (filter in favorites) Icons.Default.Bookmark else Icons.Default.BookmarkBorder, null, Modifier.size(16.dp)) } }
                }
            )
        }
    }
}

@Composable
private fun SearchWorkspaceBar(
    state: PacketSearchState,
    onModeChange: (PacketSearchMode) -> Unit,
    onQueryChange: (String) -> Unit,
    onRun: () -> Unit,
    onCancel: () -> Unit,
    onPrevious: () -> Unit,
    onNext: () -> Unit,
    onPacketClick: (Long) -> Unit
) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SearchModeMenu(state.mode, onModeChange)
            Spacer(Modifier.width(6.dp))
            CompactToolbarInput(state.query, onQueryChange, stringResource(R.string.search), Modifier.weight(1f), state.error != null)
            IconButton(if (state.isSearching) onCancel else onRun) {
                Icon(if (state.isSearching) Icons.Default.Stop else Icons.Default.Search, stringResource(R.string.search_packets))
            }
        }
        if (state.error != null || state.isSearching || state.hasSearched) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.End) {
                val status = state.error ?: if (state.isSearching) stringResource(R.string.searching) else if (state.results.isEmpty()) stringResource(R.string.no_search_results) else null
                status?.let { Text(it, Modifier.weight(1f), style = MaterialTheme.typography.labelSmall, color = if (state.error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant) }
                if (state.results.isNotEmpty()) {
                    IconButton(onPrevious, Modifier.size(36.dp)) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.previous_result)) }
                    TextButton({ state.selectedFrame?.let(onPacketClick) }) { Text("${state.selectedResultIndex + 1} / ${state.results.size}") }
                    IconButton(onNext, Modifier.size(36.dp)) { Icon(Icons.AutoMirrored.Filled.ArrowForward, stringResource(R.string.next_result)) }
                }
            }
        }
    }
}

@Composable
private fun AnalysisToolbar(
    displayFilter: String,
    filterResult: DisplayFilterResult?,
    isFiltering: Boolean,
    searchState: PacketSearchState,
    expertSummary: ExpertInfoSummary,
    nameResolutionEnabled: Boolean,
    preferences: AnalyzerPreferences,
    onDisplayFilterChange: (String) -> Unit,
    onApplyDisplayFilter: () -> Unit,
    onCancelDisplayFilter: () -> Unit,
    onClearDisplayFilter: () -> Unit,
    onSearchModeChange: (PacketSearchMode) -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onRunSearch: () -> Unit,
    onCancelSearch: () -> Unit,
    onShowStatistics: () -> Unit,
    onShowCommunication: () -> Unit,
    onNextSearchResult: () -> Unit,
    onPreviousSearchResult: () -> Unit,
    onShowExpertInfo: () -> Unit,
    onShowDecodeAs: () -> Unit,
    onShowDashboard: () -> Unit,
    onNameResolutionChange: (Boolean) -> Unit,
    onPacketClick: (Long) -> Unit
) {
    var showSearch by rememberSaveable {
        mutableStateOf(searchState.query.isNotBlank() || searchState.hasSearched)
    }
    var showAnalysisTools by remember { mutableStateOf(false) }
    val namesResolved = nameResolutionEnabled && preferences.nameResolutionEnabled
    val filterStatusText = when {
        isFiltering -> stringResource(R.string.filtering)
        filterResult?.success == true -> stringResource(R.string.filtered_packet_count, filterResult.filteredCount)
        !filterResult?.error.isNullOrBlank() -> filterResult?.error
        else -> null
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            CompactToolbarInput(
                value = displayFilter,
                onValueChange = onDisplayFilterChange,
                modifier = Modifier
                    .weight(1f),
                placeholder = stringResource(R.string.display_filter),
                isError = filterResult?.success == false
            )
            IconButton(
                onClick = if (isFiltering) onCancelDisplayFilter else onApplyDisplayFilter,
                modifier = Modifier.size(40.dp)
            ) {
                Icon(
                    if (isFiltering) Icons.Default.Stop else Icons.Default.FilterAlt,
                    contentDescription = if (isFiltering) stringResource(R.string.filtering) else stringResource(R.string.apply),
                    tint = if (isFiltering || displayFilter.isNotBlank()) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )
            }
            if (displayFilter.isNotBlank()) {
                IconButton(onClick = onClearDisplayFilter, modifier = Modifier.size(40.dp)) {
                    Icon(Icons.Default.Close, contentDescription = stringResource(R.string.clear_filter))
                }
            }
            IconButton(
                onClick = { showSearch = !showSearch },
                modifier = Modifier.size(40.dp)
            ) {
                Icon(
                    Icons.Default.Search,
                    contentDescription = stringResource(R.string.search_packets),
                    tint = if (showSearch || searchState.results.isNotEmpty()) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )
            }
            Box {
                IconButton(
                    onClick = { showAnalysisTools = true },
                    modifier = Modifier.size(40.dp)
                ) {
                    Icon(
                        Icons.Default.Tune,
                        contentDescription = stringResource(R.string.analysis_tools),
                        tint = if (expertSummary.errorPackets > 0 || expertSummary.error != null) {
                            MaterialTheme.colorScheme.error
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        }
                    )
                }
                DropdownMenu(
                    expanded = showAnalysisTools,
                    onDismissRequest = { showAnalysisTools = false }
                ) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.show_dashboard)) },
                        onClick = {
                            showAnalysisTools = false
                            onShowDashboard()
                        },
                        leadingIcon = { Icon(Icons.Default.Dashboard, contentDescription = null) }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.statistics)) },
                        onClick = {
                            showAnalysisTools = false
                            onShowStatistics()
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.sip_rtp)) },
                        onClick = {
                            showAnalysisTools = false
                            onShowCommunication()
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.decode_as)) },
                        onClick = {
                            showAnalysisTools = false
                            onShowDecodeAs()
                        }
                    )
                    DropdownMenuItem(
                        text = {
                            val expertText = when {
                                expertSummary.isLoading -> stringResource(R.string.expert_analyzing_short)
                                expertSummary.error != null -> stringResource(R.string.expert_error_short)
                                !expertSummary.analyzed -> stringResource(R.string.expert_not_analyzed_short)
                                else -> stringResource(R.string.expert_summary_short, expertSummary.errorPackets, expertSummary.warningPackets)
                            }
                            Text(
                                text = expertText,
                                color = if (expertSummary.errorPackets > 0 || expertSummary.error != null) {
                                    MaterialTheme.colorScheme.error
                                } else {
                                    MaterialTheme.colorScheme.onSurface
                                }
                            )
                        },
                        onClick = {
                            showAnalysisTools = false
                            onShowExpertInfo()
                        }
                    )
                    HorizontalDivider()
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.resolve_names)) },
                        onClick = { onNameResolutionChange(!namesResolved) },
                        trailingIcon = {
                            Checkbox(checked = namesResolved, onCheckedChange = null)
                        }
                    )
                }
            }
        }
        if (filterStatusText != null) {
            Text(
                text = filterStatusText,
                modifier = Modifier
                    .padding(horizontal = 4.dp)
                    .padding(top = 2.dp),
                style = MaterialTheme.typography.labelSmall,
                color = if (filterResult?.success == false) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        if (showSearch) {
            Spacer(modifier = Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                SearchModeMenu(searchState.mode, onSearchModeChange)
                Spacer(modifier = Modifier.width(6.dp))
                CompactToolbarInput(
                    value = searchState.query,
                    onValueChange = onSearchQueryChange,
                    modifier = Modifier.weight(1f),
                    placeholder = stringResource(R.string.search),
                    isError = searchState.error != null
                )
                IconButton(
                    onClick = if (searchState.isSearching) onCancelSearch else onRunSearch,
                    modifier = Modifier.size(40.dp)
                ) {
                    Icon(
                        if (searchState.isSearching) Icons.Default.Stop else Icons.Default.Search,
                        contentDescription = if (searchState.isSearching) stringResource(R.string.cancel_search) else stringResource(R.string.search_packets)
                    )
                }
            }

            val searchStatusText = when {
                searchState.error != null -> searchState.error
                searchState.isSearching -> stringResource(R.string.searching)
                searchState.hasSearched && searchState.results.isEmpty() -> stringResource(R.string.no_search_results)
                else -> null
            }
            if (searchStatusText != null) {
                Text(
                    text = searchStatusText,
                    modifier = Modifier
                        .padding(horizontal = 4.dp)
                        .padding(top = 2.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (searchState.error != null) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            if (searchState.results.isNotEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(
                        onClick = onPreviousSearchResult,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.previous_result))
                    }
                    TextButton(
                        onClick = { searchState.selectedFrame?.let(onPacketClick) },
                        enabled = searchState.selectedFrame != null
                    ) {
                        val indexText = if (searchState.selectedResultIndex >= 0) searchState.selectedResultIndex + 1 else 0
                        Text(stringResource(R.string.search_result_position, indexText, searchState.results.size))
                    }
                    IconButton(
                        onClick = onNextSearchResult,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = stringResource(R.string.next_result))
                    }
                }
            }
        }
    }
}

@Composable
private fun CompactToolbarInput(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    modifier: Modifier = Modifier,
    isError: Boolean = false
) {
    val borderColor = when {
        isError -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.outline
    }
    val textStyle = MaterialTheme.typography.bodyMedium.copy(
        color = MaterialTheme.colorScheme.onSurface
    )

    BasicTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier
            .height(40.dp)
            .border(1.dp, borderColor, RoundedCornerShape(4.dp))
            .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(4.dp))
            .padding(horizontal = 12.dp),
        singleLine = true,
        textStyle = textStyle,
        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
        decorationBox = { innerTextField ->
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.CenterStart
            ) {
                if (value.isEmpty()) {
                    Text(
                        text = placeholder,
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

@Composable
private fun SearchModeMenu(
    mode: PacketSearchMode,
    onModeChange: (PacketSearchMode) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        FilterChip(
            selected = true,
            onClick = { expanded = true },
            label = { Text(mode.label) }
        )
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            PacketSearchMode.values().forEach { item ->
                DropdownMenuItem(
                    text = { Text(item.label) },
                    onClick = {
                        expanded = false
                        onModeChange(item)
                    }
                )
            }
        }
    }
}

@Composable
private fun HealthSummaryBar(summary: CaptureHealthSummary, compact: Boolean = false, onOpenInsights: () -> Unit) {
    val errors = summary.cards.count { it.severity == HealthSeverity.Error }
    val warnings = summary.cards.count { it.severity == HealthSeverity.Warning }
    Row(
        Modifier.fillMaxWidth().height(if (compact) 30.dp else 40.dp).clickable(onClick = onOpenInsights).padding(horizontal = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            if (errors > 0) Icons.Default.ErrorOutline else if (warnings > 0) Icons.Default.Warning else Icons.Default.CheckCircle,
            contentDescription = null,
            modifier = Modifier.size(if (compact) 14.dp else 18.dp),
            tint = if (errors > 0) MaterialTheme.colorScheme.error else if (warnings > 0) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.primary
        )
        Text(
            when {
                summary.isLoading -> stringResource(R.string.analyzing)
                summary.error != null -> summary.error
                errors > 0 || warnings > 0 -> stringResource(R.string.health_issue_summary, errors, warnings)
                else -> stringResource(R.string.health_no_issues)
            },
            Modifier.weight(1f).padding(horizontal = 8.dp),
            style = if (compact) MaterialTheme.typography.labelSmall else MaterialTheme.typography.labelMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            stringResource(R.string.insights),
            style = if (compact) MaterialTheme.typography.labelSmall else MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
private fun InsightsWorkspace(
    healthSummary: CaptureHealthSummary,
    workspace: AnalysisWorkspace?,
    templates: List<ScenarioTemplate>,
    expertSummary: ExpertInfoSummary,
    onRefresh: () -> Unit,
    onApplyFilter: (String) -> Unit,
    onToggleFavoriteFilter: (String) -> Unit,
    onPacketClick: (Long) -> Unit,
    onShowExpert: () -> Unit,
    onShowStatistics: () -> Unit,
    onShowCommunication: () -> Unit,
    onShowDecodeAs: () -> Unit,
    onShowHttpObjects: () -> Unit,
    onShowRtpStreams: () -> Unit,
    onCollapse: () -> Unit
) {
    LazyColumn(Modifier.fillMaxSize()) {
        item {
            AnalysisDashboard(
                summary = healthSummary,
                workspace = workspace,
                templates = templates,
                onRefresh = onRefresh,
                onApplyFilter = onApplyFilter,
                onToggleFavoriteFilter = onToggleFavoriteFilter,
                onPacketClick = onPacketClick,
                onCollapse = onCollapse
            )
        }
        item {
            Text(stringResource(R.string.analysis_tools), style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp))
        }
        item { InsightDestinationRow(stringResource(R.string.expert_info), stringResource(R.string.expert_summary_short, expertSummary.errorPackets, expertSummary.warningPackets), onShowExpert) }
        item { InsightDestinationRow(stringResource(R.string.statistics), stringResource(R.string.current_filter_scope), onShowStatistics) }
        item { InsightDestinationRow(stringResource(R.string.communication_analysis_title), stringResource(R.string.current_filter_scope), onShowCommunication) }
        item { InsightDestinationRow(stringResource(R.string.http_objects), stringResource(R.string.current_filter_scope), onShowHttpObjects) }
        item { InsightDestinationRow(stringResource(R.string.rtp_streams_title), stringResource(R.string.current_filter_scope), onShowRtpStreams) }
        item { InsightDestinationRow(stringResource(R.string.decode_as), stringResource(R.string.decode_as_scope_notice), onShowDecodeAs) }
    }
}

@Composable
private fun InsightDestinationRow(title: String, subtitle: String, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.labelLarge)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null)
    }
    HorizontalDivider()
}

/**
 * EVL-UI-04: resolves the localised warning for a rejected "show evidence frames
 * only" action. Kept outside the coroutine that shows the snackbar — [Context]
 * resolution is done here, not inside [SnackbarHostState.showSnackbar], because
 * that launch block is not a composable scope and cannot call [stringResource].
 *
 * Fail-closed message choice: the limit rejections use the structured
 * `actual` / `limit` when both are present; any other shape (including the
 * fallback for an unexpected null) reports the generic "cannot be compiled"
 * string rather than inventing numbers.
 */
private fun evidenceFrameViewRejectionMessage(
    decision: EvidenceFrameViewDecision.Reject,
    context: Context
): String = when (decision.reason) {
    EvidenceFrameViewRejection.EmptySet ->
        context.getString(R.string.evidence_scope_frames_empty)

    EvidenceFrameViewRejection.TooManyFrames, EvidenceFrameViewRejection.TooManyRanges ->
        if (decision.actual != null && decision.limit != null) {
            context.getString(R.string.evidence_scope_frames_rejected_limit, decision.actual, decision.limit)
        } else {
            context.getString(R.string.evidence_scope_frames_rejected_invalid)
        }

    EvidenceFrameViewRejection.InvalidFilter ->
        context.getString(R.string.evidence_scope_frames_rejected_invalid)
}

/**
 * Localised explanation of why the "analyze with this evidence" entry is greyed
 * out, or `null` when the entry is enabled.
 *
 * Mirrors [evidenceFrameViewRejectionMessage]: it resolves strings from [Context]
 * (not [stringResource]) so it stays a plain function, and it forwards the
 * `(actual, limit)` pair for the limit-based rejections. [EvidenceAnalyzeBlockReason.AgentRunning]
 * has its own copy because it is unrelated to the filter compiler.
 */
private fun evidenceAnalyzeBlockMessage(
    state: EvidenceAnalyzeActionState,
    context: Context
): String? = when (state.reason) {
    null -> null

    EvidenceAnalyzeBlockReason.AgentRunning ->
        context.getString(R.string.evidence_analyze_agent_running)

    EvidenceAnalyzeBlockReason.EmptySet ->
        context.getString(R.string.evidence_scope_frames_empty)

    EvidenceAnalyzeBlockReason.TooManyFrames, EvidenceAnalyzeBlockReason.TooManyRanges ->
        context.getString(
            R.string.evidence_scope_frames_rejected_limit,
            state.actual ?: 0,
            state.limit ?: 0
        )

    EvidenceAnalyzeBlockReason.InvalidFilter ->
        context.getString(R.string.evidence_scope_frames_rejected_invalid)
}

/**
 * Header of the evidence page: the workspace summary plus the three page-level
 * actions, stacked in descending weight.
 *
 * The actions used to share one line with the summary text, which had two
 * visible consequences on a phone: the summary collapsed towards zero width and
 * the three equally-weighted buttons ran off the right edge. Here the summary
 * gets its own line, the primary filled button owns a full-width row so the
 * page has exactly one obvious entry, and the two secondary actions wrap in a
 * [FlowRow] so a long localised label (zh-CN is the longest) reflows instead of
 * being clipped. The "why is analyze disabled" reason renders directly under the
 * entry it explains, and is absent while the entry is enabled.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun EvidenceHeaderCard(
    summary: String,
    analyzeEnabled: Boolean,
    onAnalyze: () -> Unit,
    analyzeBlockMessage: String?,
    framesOnlyEnabled: Boolean,
    onShowFramesOnly: () -> Unit,
    onExport: () -> Unit
) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp)) {
        Text(
            summary,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(10.dp))
        Button(
            onClick = onAnalyze,
            enabled = analyzeEnabled,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.AutoAwesome, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.evidence_analyze_with_evidence))
        }
        Spacer(Modifier.height(8.dp))
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilledTonalButton(onClick = onShowFramesOnly, enabled = framesOnlyEnabled) {
                Icon(Icons.Default.FilterAlt, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.evidence_view_frames_only))
            }
            OutlinedButton(onClick = onExport) {
                Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.export))
            }
        }
        if (analyzeBlockMessage != null) {
            Spacer(Modifier.height(8.dp))
            Text(
                analyzeBlockMessage,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
    HorizontalDivider()
}

@Composable
private fun EvidenceWorkspace(
    workspace: AnalysisWorkspace?,
    frameCount: Int,
    onPacketClick: (Long) -> Unit,
    onSaveWorkspaceNote: (Long, String) -> Unit,
    onRemoveEvidence: (Long) -> Unit,
    onRemoveEvidenceFrames: (Collection<Long>) -> Unit = {},
    onClearEvidence: () -> Unit = {},
    onExport: () -> Unit,
    /** EVL-UI-04: frame the packet list with the workspace evidence set. */
    onShowFramesOnly: () -> Unit,
    /** EVL-UI-05: start an agent run framed by the compiled evidence filter. */
    agentIsRunning: Boolean,
    /**
     * Submits the analyze entry with the verbatim compiled [filter] and its
     * [frameCount]. The caller guarantees this is only invoked when the entry is
     * enabled, so a blank or rejected filter is never handed to the agent.
     */
    onAnalyzeWithEvidence: (String, Int) -> Unit
) {
    // Single source of truth for the open row-menu and the open note editor, keyed
    // by frame number so at most one menu (and one editor) is ever open, and a
    // long-press on a different row cannot leak into another row's menu.
    val openMenuFrame = remember { mutableStateOf<Long?>(null) }
    val editingNoteFrame = remember { mutableStateOf<Long?>(null) }
    val selectedFrames = remember { mutableStateOf(emptySet<Long>()) }
    val showClearConfirm = remember { mutableStateOf(false) }
    var groupOrdinal by rememberSaveable { mutableStateOf(EvidenceGroup.All.ordinal) }
    val group = EvidenceGroup.entries[groupOrdinal]
    val evidenceRows = remember(
        workspace?.evidenceItems,
        workspace?.notes,
        workspace?.agentFindings,
        frameCount,
        group
    ) {
        EvidenceWorkbench.rows(
            items = workspace?.evidenceItems.orEmpty(),
            notes = workspace?.notes.orEmpty(),
            findings = workspace?.agentFindings.orEmpty(),
            frameCount = frameCount,
            group = group
        )
    }
    // EVL-UI-06: rows for the [All] group — the authority for "is the whole
    // evidence set empty" and for the stale-frame hint. The visible (grouped)
    // rows above are a subset of this for every group except [All].
    val allEvidenceRows = remember(
        workspace?.evidenceItems,
        workspace?.notes,
        workspace?.agentFindings,
        frameCount
    ) {
        EvidenceWorkbench.rows(
            items = workspace?.evidenceItems.orEmpty(),
            notes = workspace?.notes.orEmpty(),
            findings = workspace?.agentFindings.orEmpty(),
            frameCount = frameCount,
            group = EvidenceGroup.All
        )
    }
    val emptyState = remember(allEvidenceRows, evidenceRows) {
        EvidenceWorkbench.emptyState(allEvidenceRows, evidenceRows)
    }
    // Stale frames still appear in the list (row-level isStale badge); this count
    // is only an at-a-glance hint above the list and never hides a still-present
    // evidence frame.
    val staleFrameCount = remember(allEvidenceRows) { EvidenceWorkbench.staleCount(allEvidenceRows) }
    // The set of frames selectable for the current group, derived once per row set.
    val visibleFrameSet = remember(evidenceRows) { EvidenceWorkbench.visibleFrames(evidenceRows).toSet() }
    // Selection convergence: when the rows change (group switch, removal, clear, or
    // any workspace edit) the selection must collapse to frames still visible in the
    // current group. Without this, a stale selection can read "N selected" while the
    // list shows fewer rows. Intersecting keeps it a subset of the now-visible frames.
    LaunchedEffect(evidenceRows) {
        if (selectedFrames.value.isNotEmpty()) {
            selectedFrames.value = selectedFrames.value.intersect(visibleFrameSet)
        }
    }
    val allVisibleSelected = visibleFrameSet.isNotEmpty() && selectedFrames.value == visibleFrameSet
    val hasAnyEvidence = workspace?.evidenceItems.orEmpty().isNotEmpty()
    val evidenceCount = workspace?.evidenceFrames.orEmpty().size
    val bookmarks = workspace?.bookmarks.orEmpty().sorted()
    val notes = workspace?.notes.orEmpty().sortedByDescending { it.updatedAtMillis }
    val context = LocalContext.current
    // EVL-UI-05: decide whether the analyze entry may run from the compiled
    // evidence filter. Fail-closed — an empty or rejected evidence set yields a
    // disabled entry with a reason, never a submittable blank filter.
    val analyzeState = remember(workspace, agentIsRunning) {
        EvidenceWorkbench.analyzeAction(
            decision = EvidenceFrameViewPolicy.decide(
                EvidenceFrameFilter.compileOrNull(workspace?.evidenceFrames.orEmpty())
            ),
            isAgentRunning = agentIsRunning
        )
    }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 16.dp)) {
        item {
            EvidenceHeaderCard(
                summary = stringResource(
                    R.string.evidence_scope_summary,
                    evidenceCount,
                    bookmarks.size,
                    notes.size
                ),
                // EVL-UI-05: primary entry. Disabled (and never submitting) when
                // the analyze decision is not enabled — running, empty, or a
                // rejected evidence set. On click the compiled filter is handed to
                // the agent and the page switches to the Agent tab.
                analyzeEnabled = analyzeState.enabled,
                onAnalyze = {
                    if (analyzeState.enabled) {
                        onAnalyzeWithEvidence(analyzeState.filter!!, analyzeState.frameCount)
                    }
                },
                // EVL-UI-05: explain why the entry is greyed out. Nothing renders
                // when the entry is enabled, so a working run is never cluttered.
                analyzeBlockMessage = evidenceAnalyzeBlockMessage(analyzeState, context),
                // EVL-UI-04: frame the packet list with the evidence set. Disabled
                // only when there is no workspace at all; an empty evidence set
                // stays clickable because the rejection path still explains why.
                framesOnlyEnabled = workspace != null,
                onShowFramesOnly = onShowFramesOnly,
                onExport = onExport
            )
        }
        // EVL-UI-06: the group filters and the list toolbar only earn their space
        // once there is evidence to partition. On a wholly empty set the guidance
        // below is the single call to action, and a strip of disabled controls
        // above it would only add noise.
        if (emptyState != EvidenceEmptyState.NoEvidence) {
            item {
                Row(
                    Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilterChip(
                        selected = group == EvidenceGroup.All,
                        onClick = { groupOrdinal = EvidenceGroup.All.ordinal },
                        label = { Text(stringResource(R.string.evidence_group_all)) }
                    )
                    FilterChip(
                        selected = group == EvidenceGroup.Manual,
                        onClick = { groupOrdinal = EvidenceGroup.Manual.ordinal },
                        label = { Text(stringResource(R.string.evidence_group_manual)) }
                    )
                    FilterChip(
                        selected = group == EvidenceGroup.FromFindings,
                        onClick = { groupOrdinal = EvidenceGroup.FromFindings.ordinal },
                        label = { Text(stringResource(R.string.evidence_group_from_findings)) }
                    )
                }
            }
            item {
                // List toolbar. The section title claims the free width with a real
                // `weight` — this Row is *not* scrollable, so the weight is honoured
                // (unlike the previous version, where the mutable count/actions sat in
                // a `horizontalScroll` Row and the count collapsed to zero).
                Row(
                    Modifier.fillMaxWidth().padding(start = 12.dp, end = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        stringResource(R.string.evidence_frames),
                        Modifier.weight(1f),
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    // Select-all toggles to "Clear selection" once every visible frame in
                    // the current group is selected; otherwise it selects them all.
                    TextButton(
                        enabled = visibleFrameSet.isNotEmpty(),
                        onClick = {
                            selectedFrames.value = if (allVisibleSelected) emptySet() else visibleFrameSet
                        }
                    ) {
                        Text(stringResource(if (allVisibleSelected) R.string.evidence_clear_selection else R.string.evidence_select_all))
                    }
                    // Clear wipes the entire evidence set, so it is disabled when there is
                    // nothing to wipe (avoids a pointless destructive confirmation) and
                    // tinted with the error role so it reads as destructive without
                    // competing with the page's single filled primary.
                    TextButton(
                        enabled = hasAnyEvidence,
                        onClick = { showClearConfirm.value = true }
                    ) {
                        Text(
                            stringResource(R.string.evidence_clear_all),
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
        }
        // Batch-selection bar. Present only while a selection exists, so it reads as
        // a mode switch instead of a fourth toolbar row, and it is NOT placed in a
        // scrollable Row: the count needs a finite width to claim.
        if (selectedFrames.value.isNotEmpty()) {
            item {
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Row(
                        Modifier.fillMaxWidth().padding(start = 14.dp, end = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            stringResource(R.string.evidence_selected_count, selectedFrames.value.size),
                            Modifier.weight(1f),
                            style = MaterialTheme.typography.labelLarge
                        )
                        TextButton(
                            onClick = {
                                onRemoveEvidenceFrames(selectedFrames.value)
                                selectedFrames.value = emptySet()
                            }
                        ) {
                            Text(stringResource(R.string.evidence_remove_selected))
                        }
                    }
                }
            }
        }
        // EVL-UI-06: stale-frame hint above the list. Stale frames remain listed
        // (row-level isStale badge); this is only an at-a-glance count, shown for
        // >0 only and never hides a still-present evidence frame.
        if (staleFrameCount > 0) {
            item {
                Text(
                    stringResource(R.string.evidence_stale_frames_hint, staleFrameCount),
                    Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 2.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        // EVL-UI-06: evidence-list empty states. [None] renders the rows; [NoEvidence]
        // (whole set empty) invites the user to add frames; [GroupEmpty] (active
        // group filtered everything out) explains the group is empty without
        // nudging the user to re-annotate.
        when (emptyState) {
            EvidenceEmptyState.None -> {
                items(evidenceRows, key = { "evrow-${it.frameNumber}" }) { row ->
                    EvidenceWorkbenchRow(
                        row = row,
                        onClick = onPacketClick,
                        onLongClick = { openMenuFrame.value = it },
                        openMenuFrame = openMenuFrame,
                        onEditNote = { editingNoteFrame.value = it },
                        onRemove = onRemoveEvidence
                    )
                }
            }
            EvidenceEmptyState.NoEvidence -> {
                item {
                    Text(
                        stringResource(R.string.evidence_empty_guidance),
                        Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 32.dp),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                }
            }
            EvidenceEmptyState.GroupEmpty -> {
                item {
                    Text(
                        stringResource(R.string.evidence_group_empty),
                        Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 32.dp),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                }
            }
        }
        if (bookmarks.isNotEmpty()) {
            item { EvidenceSectionTitle(stringResource(R.string.bookmarks)) }
            items(bookmarks, key = { "bookmark-$it" }) { frame -> EvidenceFrameRow(frame, Icons.Default.Bookmark, null, onPacketClick) }
        }
        if (notes.isNotEmpty()) {
            item { EvidenceSectionTitle(stringResource(R.string.notes)) }
            items(notes, key = { "note-${it.frameNumber}" }) { note -> EvidenceFrameRow(note.frameNumber, Icons.Default.EditNote, note.text, onPacketClick) }
        }
    }
    if (editingNoteFrame.value != null) {
        val noteFrame = editingNoteFrame.value!!
        EvidenceNoteEditDialog(
            frameNumber = noteFrame,
            initialText = workspace?.notes?.firstOrNull { it.frameNumber == noteFrame }?.text.orEmpty(),
            onDismiss = { editingNoteFrame.value = null },
            onSave = { text ->
                onSaveWorkspaceNote(noteFrame, text)
                editingNoteFrame.value = null
            }
        )
    }
    if (showClearConfirm.value) {
        AlertDialog(
            onDismissRequest = { showClearConfirm.value = false },
            title = { Text(stringResource(R.string.evidence_clear_confirm_title)) },
            text = { Text(stringResource(R.string.evidence_clear_confirm_message)) },
            confirmButton = {
                Button(
                    onClick = {
                        showClearConfirm.value = false
                        onClearEvidence()
                        selectedFrames.value = emptySet()
                    }
                ) { Text(stringResource(R.string.evidence_clear_confirm_action)) }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirm.value = false }) { Text(stringResource(R.string.cancel)) }
            }
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun EvidenceWorkbenchRow(
    row: EvidenceRow,
    onClick: (Long) -> Unit,
    onLongClick: (Long) -> Unit,
    openMenuFrame: MutableState<Long?>,
    onEditNote: (Long) -> Unit,
    onRemove: (Long) -> Unit
) {
    val badge = if (row.source == EvidenceSource.Manual) {
        stringResource(R.string.evidence_source_manual)
    } else {
        row.sourceFindingTitle ?: stringResource(R.string.evidence_source_finding)
    }
    Box {
        Row(
            Modifier
                .fillMaxWidth()
                .combinedClickable(
                    onClick = { onClick(row.frameNumber) },
                    onLongClick = { onLongClick(row.frameNumber) }
                )
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.AutoMirrored.Filled.FactCheck, null, Modifier.size(19.dp), tint = MaterialTheme.colorScheme.primary)
            Text("#${row.frameNumber}", Modifier.padding(horizontal = 10.dp), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelLarge)
            Text(badge, Modifier.padding(end = 8.dp), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (row.noteText != null) {
                Text(row.noteText, Modifier.weight(1f), maxLines = 2, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall)
            } else {
                Spacer(Modifier.weight(1f))
            }
            if (row.isStale) {
                Text(stringResource(R.string.evidence_frame_stale), Modifier.padding(start = 8.dp), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
            }
        }
        DropdownMenu(
            expanded = openMenuFrame.value == row.frameNumber,
            onDismissRequest = { openMenuFrame.value = null }
        ) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.evidence_action_open_frame)) },
                onClick = {
                    openMenuFrame.value = null
                    onClick(row.frameNumber)
                }
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.evidence_action_edit_note)) },
                onClick = {
                    openMenuFrame.value = null
                    onEditNote(row.frameNumber)
                }
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.evidence_action_remove)) },
                onClick = {
                    openMenuFrame.value = null
                    onRemove(row.frameNumber)
                }
            )
        }
    }
    HorizontalDivider()
}

/**
 * Edit dialog for a frame's workspace note, mirroring the one used on the packet
 * detail page. Saving an empty string delegates to [onSave], which routes through
 * the existing note semantics (blank text removes the note) — no parallel path.
 */
@Composable
private fun EvidenceNoteEditDialog(
    frameNumber: Long,
    initialText: String,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit
) {
    var note by remember(frameNumber, initialText) { mutableStateOf(initialText) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.frame_note_title, frameNumber)) },
        text = {
            OutlinedTextField(
                value = note,
                onValueChange = { note = it.take(2000) },
                label = { Text(stringResource(R.string.note_hint)) },
                minLines = 3
            )
        },
        confirmButton = {
            Button(onClick = { onSave(note) }) { Text(stringResource(R.string.save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

@Composable
private fun EvidenceSectionTitle(title: String) {
    Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant).padding(horizontal = 12.dp, vertical = 7.dp))
}

@Composable
private fun EvidenceFrameRow(frame: Long, icon: androidx.compose.ui.graphics.vector.ImageVector, note: String?, onClick: (Long) -> Unit) {
    Row(Modifier.fillMaxWidth().clickable { onClick(frame) }.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, null, Modifier.size(19.dp), tint = MaterialTheme.colorScheme.primary)
        Text("#$frame", Modifier.padding(horizontal = 10.dp), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelLarge)
        note?.let { Text(it, Modifier.weight(1f), maxLines = 2, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall) }
    }
    HorizontalDivider()
}

@Composable
private fun PacketTable(
    packetItems: LazyPagingItems<PacketSummary>,
    listState: LazyListState,
    expertSummary: ExpertInfoSummary,
    colorRulesEnabled: Boolean,
    selectedFrame: Long?,
    bookmarkedFrames: Set<Long>,
    evidenceFrames: Set<Long>,
    noteFrames: Set<Long>,
    searchFrames: Set<Long>,
    packetContextActions: PacketContextActionsState,
    highlightedFrames: Set<Long>,
    onPrepareContextActions: (Long) -> Unit,
    onApplyFollowFilter: (String) -> Unit,
    onToggleHighlight: (Long) -> Unit,
    onPacketClick: (Long) -> Unit
) {
    val isCompactLayout = LocalConfiguration.current.screenWidthDp < 600
    val expertSeverityByFrame = remember(expertSummary.items) {
        expertSummary.items.fold(mutableMapOf<Long, String>()) { acc, item ->
            val current = acc[item.frameNumber] ?: "none"
            if (severityRank(item.severity) > severityRank(current)) {
                acc[item.frameNumber] = item.severity
            }
            acc
        }
    }
    Column(modifier = Modifier.fillMaxSize()) {
        if (!isCompactLayout) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(8.dp)
            ) {
                HeaderCell(stringResource(R.string.column_number), 60.dp)
                HeaderCell(stringResource(R.string.time_display), 110.dp)
                HeaderCell(stringResource(R.string.column_source_port), 150.dp)
                HeaderCell(stringResource(R.string.column_destination_port), 150.dp)
                HeaderCell(stringResource(R.string.column_protocol_short), 80.dp)
                HeaderCell(stringResource(R.string.column_length_short), 60.dp)
                HeaderCell(stringResource(R.string.column_info), weight = 1f)
            }
        }

        when (val refresh = packetItems.loadState.refresh) {
            is LoadState.Loading -> LoadingState()
            is LoadState.Error -> ErrorState(refresh.error.message ?: stringResource(R.string.unable_load_packets)) {
                packetItems.retry()
            }
            is LoadState.NotLoading -> {
                if (packetItems.itemCount == 0) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(stringResource(R.string.no_packets_found))
                    }
                } else {
                    Box(modifier = Modifier.fillMaxSize()) {
                        LazyColumn(
                            state = listState,
                            modifier = Modifier.fillMaxSize()
                        ) {
                            items(
                                count = packetItems.itemCount,
                                key = packetItems.itemKey { it.frameNumber },
                                contentType = packetItems.itemContentType { "Packet" }
                            ) { index ->
                                val packet = packetItems[index]
                                if (packet != null) {
                                    if (isCompactLayout) {
                                        CompactPacketRow(
                                            packet = packet,
                                            severity = expertSeverityByFrame[packet.frameNumber] ?: "none",
                                            colorRulesEnabled = colorRulesEnabled,
                                            isSelected = packet.frameNumber == selectedFrame,
                                            isBookmarked = packet.frameNumber in bookmarkedFrames,
                                            isEvidence = packet.frameNumber in evidenceFrames,
                                            hasNote = packet.frameNumber in noteFrames,
                                            isSearchMatch = packet.frameNumber in searchFrames,
                                            isHighlighted = packet.frameNumber in highlightedFrames,
                                            contextActions = packetContextActions,
                                            onPrepareContextActions = { onPrepareContextActions(packet.frameNumber) },
                                            onApplyFollowFilter = onApplyFollowFilter,
                                            onToggleHighlight = { onToggleHighlight(packet.frameNumber) },
                                            onClick = { onPacketClick(packet.frameNumber) }
                                        )
                                    } else {
                                        PacketRow(
                                            packet = packet,
                                            severity = expertSeverityByFrame[packet.frameNumber] ?: "none",
                                            colorRulesEnabled = colorRulesEnabled,
                                            isHighlighted = packet.frameNumber in highlightedFrames,
                                            contextActions = packetContextActions,
                                            onPrepareContextActions = { onPrepareContextActions(packet.frameNumber) },
                                            onApplyFollowFilter = onApplyFollowFilter,
                                            onToggleHighlight = { onToggleHighlight(packet.frameNumber) },
                                            onClick = { onPacketClick(packet.frameNumber) }
                                        )
                                    }
                                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 0.5.dp)
                                } else {
                                    PacketPlaceholderRow(isCompactLayout)
                                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 0.5.dp)
                                }
                            }

                            when (val append = packetItems.loadState.append) {
                                is LoadState.Loading -> item { LoadingAppendRow() }
                                is LoadState.Error -> item {
                                    ErrorAppendRow(append.error.message ?: stringResource(R.string.unable_load_more_packets)) {
                                        packetItems.retry()
                                    }
                                }
                                is LoadState.NotLoading -> Unit
                            }
                        }
                        PacketFastScrollbar(
                            listState = listState,
                            itemCount = packetItems.itemCount,
                            labelProvider = { index ->
                                packetItems.peek(index)?.let { "#${it.frameNumber} · ${it.time}" } ?: "${index + 1} / ${packetItems.itemCount}"
                            },
                            modifier = Modifier.align(Alignment.CenterEnd)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun PacketPlaceholderRow(isCompactLayout: Boolean) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(if (isCompactLayout) 68.dp else 32.dp)
            .background(MaterialTheme.colorScheme.surface)
    )
}

@Composable
private fun PacketFastScrollbar(
    listState: LazyListState,
    itemCount: Int,
    labelProvider: (Int) -> String,
    modifier: Modifier = Modifier
) {
    if (itemCount <= 1) return

    val scope = rememberCoroutineScope()
    var isDragging by remember { mutableStateOf(false) }
    var scrollJob by remember { mutableStateOf<Job?>(null) }
    val handleWidth by animateDpAsState(if (isDragging) 22.dp else 12.dp, label = "fastScrollbarWidth")
    val strokeWidth by animateDpAsState(if (isDragging) 2.5.dp else 1.5.dp, label = "fastScrollbarStroke")
    val trackAlpha by animateFloatAsState(if (isDragging) 0.88f else 0.42f, label = "fastScrollbarAlpha")
    val progress by remember(listState, itemCount) {
        derivedStateOf {
            (listState.firstVisibleItemIndex.toFloat() / (itemCount - 1).toFloat()).coerceIn(0f, 1f)
        }
    }
    val currentLabel by remember(listState, itemCount) {
        derivedStateOf { labelProvider(listState.firstVisibleItemIndex) }
    }

    fun scrollToPosition(y: Float, height: Int) {
        if (height <= 0) return
        val targetIndex = ((y / height.toFloat()).coerceIn(0f, 1f) * (itemCount - 1)).roundToInt()
        scrollJob?.cancel()
        scrollJob = scope.launch {
            listState.scrollToItem(targetIndex.coerceIn(0, itemCount - 1))
        }
    }

    Box(
        modifier = modifier
            .width(36.dp)
            .fillMaxSize()
            .pointerInput(itemCount) {
                detectVerticalDragGestures(
                    onDragStart = { offset ->
                        isDragging = true
                        scrollToPosition(offset.y, size.height)
                    },
                    onVerticalDrag = { change, _ ->
                        scrollToPosition(change.position.y, size.height)
                    },
                    onDragEnd = {
                        isDragging = false
                        scrollJob = null
                    },
                    onDragCancel = {
                        isDragging = false
                        scrollJob = null
                    }
                )
            },
        contentAlignment = Alignment.CenterEnd
    ) {
        if (isDragging) {
            Surface(
                modifier = Modifier.align(Alignment.CenterEnd).padding(end = 30.dp),
                shape = RoundedCornerShape(4.dp),
                color = MaterialTheme.colorScheme.inverseSurface
            ) {
                Text(
                    currentLabel,
                    Modifier.padding(horizontal = 8.dp, vertical = 5.dp),
                    style = MaterialTheme.typography.labelMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.inverseOnSurface
                )
            }
        }
        val inactiveColor = MaterialTheme.colorScheme.outline.copy(alpha = trackAlpha)
        val activeColor = MaterialTheme.colorScheme.primary.copy(alpha = if (isDragging) 0.95f else 0.7f)
        Canvas(
            modifier = Modifier
                .width(handleWidth)
                .fillMaxSize()
                .padding(vertical = 8.dp)
        ) {
            val gap = 4.dp.toPx()
            val stroke = strokeWidth.toPx()
            val segmentStep = gap + stroke
            val segmentCount = (size.height / segmentStep).roundToInt().coerceAtLeast(8)
            val activeSegment = (progress * (segmentCount - 1)).roundToInt().coerceIn(0, segmentCount - 1)
            val baseLength = size.width * 0.55f
            val activeLength = size.width
            val endX = size.width

            repeat(segmentCount) { index ->
                val y = if (segmentCount == 1) {
                    size.height / 2f
                } else {
                    index * (size.height / (segmentCount - 1))
                }
                val isActive = index == activeSegment
                val length = if (isActive) activeLength else baseLength
                drawLine(
                    color = if (isActive) activeColor else inactiveColor,
                    start = Offset(endX - length, y),
                    end = Offset(endX, y),
                    strokeWidth = stroke,
                    cap = StrokeCap.Round
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ExpertInfoScreen(
    summary: ExpertInfoSummary,
    onCancel: () -> Unit,
    onPacketClick: (Long) -> Unit,
    onBack: () -> Unit
) {
    BackHandler(onBack = onBack)
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.expert_info)) },
                navigationIcon = { IconButton(onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) } },
                actions = {
                    if (summary.isLoading) IconButton(onCancel) { Icon(Icons.Default.Stop, stringResource(R.string.cancel_analysis)) }
                }
            )
        }
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            Text(stringResource(R.string.current_filter_scope), Modifier.padding(horizontal = 12.dp, vertical = 4.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            when {
                summary.isLoading -> Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator(Modifier.size(24.dp)); Text(stringResource(R.string.analyzing_expert))
                }
                summary.error != null -> Text(summary.error, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.error)
                !summary.analyzed -> Text(stringResource(R.string.expert_not_analyzed), Modifier.padding(16.dp))
                else -> {
                    Text(stringResource(R.string.expert_message_counts, summary.errorPackets, summary.warningPackets, summary.totalItems), Modifier.padding(horizontal = 12.dp, vertical = 6.dp), style = MaterialTheme.typography.bodyMedium)
                    if (summary.truncated) Text(stringResource(R.string.expert_truncated_notice, summary.items.size), Modifier.padding(horizontal = 12.dp), color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.bodySmall)
                    if (summary.items.isEmpty()) Text(stringResource(R.string.no_expert_messages), Modifier.padding(16.dp))
                    else LazyColumn(Modifier.weight(1f)) {
                        items(summary.items, key = { "${it.frameNumber}-${it.start}-${it.label}" }) { item ->
                            ExpertInfoRow(item) { onPacketClick(item.frameNumber) }
                            HorizontalDivider()
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ExpertInfoDialog(
    summary: ExpertInfoSummary,
    onCancel: () -> Unit,
    onPacketClick: (Long) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            Button(onClick = onDismiss) {
                Text(stringResource(R.string.close))
            }
        },
        dismissButton = if (summary.isLoading) {
            { TextButton(onClick = onCancel) { Text(stringResource(R.string.cancel_analysis)) } }
        } else null,
        title = { Text(stringResource(R.string.expert_info)) },
        text = {
            Column(modifier = Modifier.widthIn(max = 560.dp)) {
                when {
                    summary.isLoading -> {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(24.dp))
                            Text(stringResource(R.string.analyzing_expert))
                        }
                    }
                    summary.error != null -> {
                        Text(summary.error, color = MaterialTheme.colorScheme.error)
                    }
                    !summary.analyzed -> {
                        Text(stringResource(R.string.expert_not_analyzed))
                    }
                    else -> {
                        Text(
                            stringResource(R.string.expert_message_counts, summary.errorPackets, summary.warningPackets, summary.totalItems),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (summary.truncated) {
                            Text(
                                stringResource(R.string.expert_truncated_notice, summary.items.size),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.tertiary
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        if (summary.items.isEmpty()) {
                            Text(stringResource(R.string.no_expert_messages))
                        } else {
                            LazyColumn(modifier = Modifier.height(420.dp)) {
                                items(summary.items) { item ->
                                    ExpertInfoRow(
                                        item = item,
                                        onClick = {
                                            onDismiss()
                                            onPacketClick(item.frameNumber)
                                        }
                                    )
                                    HorizontalDivider()
                                }
                            }
                        }
                    }
                }
            }
        }
    )
}

@Composable
private fun ExpertInfoRow(item: ExpertInfoItem, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            "#${item.frameNumber}",
            modifier = Modifier.width(64.dp),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                item.label,
                style = MaterialTheme.typography.bodySmall,
                color = severityTextColor(item.severity),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            if (!item.filter.isNullOrBlank()) {
                Text(
                    item.filter,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun LoadingState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
private fun ErrorState(message: String, onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(message, color = MaterialTheme.colorScheme.error)
        Spacer(modifier = Modifier.height(8.dp))
        Button(onClick = onRetry) {
            Icon(Icons.Default.Refresh, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text(stringResource(R.string.retry))
        }
    }
}

@Composable
private fun LoadingAppendRow() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator(modifier = Modifier.size(24.dp))
    }
}

@Composable
private fun ErrorAppendRow(message: String, onRetry: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            message,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.weight(1f)
        )
        TextButton(onClick = onRetry) {
            Text(stringResource(R.string.retry))
        }
    }
}

@Composable
private fun CompactPacketHeader() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(3.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(R.string.column_number),
                modifier = Modifier.widthIn(min = 44.dp),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = stringResource(R.string.column_protocol),
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = stringResource(R.string.column_length),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold
            )
        }
        Text(
            text = stringResource(R.string.column_endpoints),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = stringResource(R.string.column_info),
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun RowScope.HeaderCell(text: String, width: Dp? = null, weight: Float? = null) {
    val modifier = if (weight != null) Modifier.weight(weight) else Modifier.width(width!!)
    Text(
        text = text,
        fontWeight = FontWeight.Bold,
        style = MaterialTheme.typography.bodySmall,
        modifier = modifier.padding(horizontal = 4.dp)
    )
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun CompactPacketRow(
    packet: PacketSummary,
    severity: String = "none",
    colorRulesEnabled: Boolean = true,
    isSelected: Boolean = false,
    isBookmarked: Boolean = false,
    isEvidence: Boolean = false,
    hasNote: Boolean = false,
    isSearchMatch: Boolean = false,
    isHighlighted: Boolean = false,
    contextActions: PacketContextActionsState = PacketContextActionsState(),
    onPrepareContextActions: () -> Unit = {},
    onApplyFollowFilter: (String) -> Unit = {},
    onToggleHighlight: () -> Unit = {},
    onClick: () -> Unit
) {
    val ports = packetPorts(packet)
    val sourceLabel = formatEndpoint(packet.source, ports?.first)
    val destinationLabel = formatEndpoint(packet.destination, ports?.second)
    val protocolLabel = displayProtocol(packet)
    var menuExpanded by remember { mutableStateOf(false) }
    val rowColor = when {
        isSelected -> MaterialTheme.colorScheme.secondaryContainer
        isHighlighted -> MaterialTheme.colorScheme.tertiaryContainer
        colorRulesEnabled -> getProtocolColor(protocolLabel, "none").copy(alpha = 0.32f)
        else -> MaterialTheme.colorScheme.surface
    }
    Box {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(68.dp)
                .background(rowColor)
                .combinedClickable(
                    onClick = onClick,
                    onLongClick = {
                        menuExpanded = true
                        onPrepareContextActions()
                    }
                ),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                Modifier.width(4.dp).height(68.dp).background(
                    when (severity.lowercase()) {
                        "error" -> MaterialTheme.colorScheme.error
                        "warn" -> MaterialTheme.colorScheme.tertiary
                        else -> if (isSelected) MaterialTheme.colorScheme.primary else Color.Transparent
                    }
                )
            )
            Column(Modifier.weight(1f).padding(horizontal = 8.dp, vertical = 5.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text("#${packet.frameNumber}", Modifier.widthIn(min = 50.dp), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelMedium)
                    Text(packet.time, Modifier.weight(1f), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    PacketMarkerIcons(severity, isBookmarked, isEvidence, hasNote, isSearchMatch)
                    Spacer(Modifier.width(6.dp))
                    Text(protocolLabel, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, maxLines = 1)
                    Spacer(Modifier.width(8.dp))
                    Text("${packet.length} B", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(sourceLabel, Modifier.weight(1f), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(" -> ", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(destinationLabel, Modifier.weight(1f), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Text(
                    packet.info.ifBlank { "-" },
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
        if (menuExpanded) {
            PacketContextMenu(
                state = contextActions.takeIf { it.frameNumber == packet.frameNumber },
                isHighlighted = isHighlighted,
                onDismiss = { menuExpanded = false },
                onApplyFollowFilter = onApplyFollowFilter,
                onToggleHighlight = onToggleHighlight
            )
        }
    }
}

@Composable
private fun PacketMarkerIcons(severity: String, bookmark: Boolean, evidence: Boolean, note: Boolean, search: Boolean) {
    when (severity.lowercase()) {
        "error" -> Icon(Icons.Default.ErrorOutline, null, Modifier.size(15.dp), tint = MaterialTheme.colorScheme.error)
        "warn" -> Icon(Icons.Default.Warning, null, Modifier.size(15.dp), tint = MaterialTheme.colorScheme.tertiary)
    }
    if (bookmark) Icon(Icons.Default.Bookmark, null, Modifier.size(14.dp), tint = MaterialTheme.colorScheme.primary)
    if (evidence) Icon(Icons.AutoMirrored.Filled.FactCheck, null, Modifier.size(14.dp), tint = MaterialTheme.colorScheme.primary)
    if (note) Icon(Icons.Default.EditNote, null, Modifier.size(14.dp), tint = MaterialTheme.colorScheme.secondary)
    if (search) Icon(Icons.Default.Search, null, Modifier.size(14.dp), tint = MaterialTheme.colorScheme.tertiary)
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun PacketRow(
    packet: PacketSummary,
    severity: String = "none",
    colorRulesEnabled: Boolean = true,
    isHighlighted: Boolean = false,
    contextActions: PacketContextActionsState = PacketContextActionsState(),
    onPrepareContextActions: () -> Unit = {},
    onApplyFollowFilter: (String) -> Unit = {},
    onToggleHighlight: () -> Unit = {},
    onClick: () -> Unit
) {
    val protocolLabel = displayProtocol(packet)
    val ports = packetPorts(packet)
    val sourceLabel = formatEndpoint(packet.source, ports?.first)
    val destinationLabel = formatEndpoint(packet.destination, ports?.second)
    var menuExpanded by remember { mutableStateOf(false) }
    Box {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .combinedClickable(
                    onClick = onClick,
                    onLongClick = {
                        menuExpanded = true
                        onPrepareContextActions()
                    }
                )
                .background(
                    if (isHighlighted) MaterialTheme.colorScheme.tertiaryContainer
                    else if (colorRulesEnabled) getProtocolColor(protocolLabel, severity)
                    else MaterialTheme.colorScheme.surface
                )
                .padding(vertical = 4.dp, horizontal = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
        Text(
            text = packet.frameNumber.toString(),
            modifier = Modifier.width(60.dp).padding(horizontal = 2.dp),
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            text = packet.time,
            modifier = Modifier.width(110.dp).padding(horizontal = 2.dp),
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1
        )
        Text(
            text = sourceLabel,
            modifier = Modifier.width(150.dp).padding(horizontal = 2.dp),
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = destinationLabel,
            modifier = Modifier.width(150.dp).padding(horizontal = 2.dp),
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = protocolLabel,
            modifier = Modifier.width(80.dp).padding(horizontal = 2.dp),
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = packet.length.toString(),
            modifier = Modifier.width(60.dp).padding(horizontal = 2.dp),
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            text = packet.info,
            modifier = Modifier.weight(1f).padding(horizontal = 2.dp),
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        }
        if (menuExpanded) {
            PacketContextMenu(
                state = contextActions.takeIf { it.frameNumber == packet.frameNumber },
                isHighlighted = isHighlighted,
                onDismiss = { menuExpanded = false },
                onApplyFollowFilter = onApplyFollowFilter,
                onToggleHighlight = onToggleHighlight
            )
        }
    }
}

@Composable
private fun PacketContextMenu(
    state: PacketContextActionsState?,
    isHighlighted: Boolean,
    onDismiss: () -> Unit,
    onApplyFollowFilter: (String) -> Unit,
    onToggleHighlight: () -> Unit
) {
    val filters = state?.followFilters
    DropdownMenu(expanded = true, onDismissRequest = onDismiss) {
        FollowFilterMenuItem(R.string.follow_sip_call, filters?.sipCall, onDismiss, onApplyFollowFilter)
        FollowFilterMenuItem(R.string.follow_udp_filter, filters?.udpStream, onDismiss, onApplyFollowFilter)
        FollowFilterMenuItem(R.string.follow_tcp_filter, filters?.tcpStream, onDismiss, onApplyFollowFilter)
        HorizontalDivider()
        DropdownMenuItem(
            text = { Text(stringResource(if (isHighlighted) R.string.remove_packet_highlight else R.string.highlight_packet)) },
            leadingIcon = { Icon(Icons.Default.Star, contentDescription = null) },
            onClick = {
                onDismiss()
                onToggleHighlight()
            }
        )
        when {
            state?.isLoading == true -> DropdownMenuItem(
                text = { Text(stringResource(R.string.inspecting_packet)) },
                onClick = {},
                enabled = false
            )
            state?.error != null -> DropdownMenuItem(
                text = { Text(state.error) },
                onClick = {},
                enabled = false
            )
            state != null && state.followFilters.isEmpty -> DropdownMenuItem(
                text = { Text(stringResource(R.string.no_followable_stream)) },
                onClick = {},
                enabled = false
            )
        }
    }
}

@Composable
private fun FollowFilterMenuItem(
    label: Int,
    filter: String?,
    onDismiss: () -> Unit,
    onApplyFollowFilter: (String) -> Unit
) {
    DropdownMenuItem(
        text = { Text(stringResource(label)) },
        leadingIcon = { Icon(Icons.Default.FilterAlt, contentDescription = null) },
        enabled = filter != null,
        onClick = {
            filter?.let {
                onDismiss()
                onApplyFollowFilter(it)
            }
        }
    )
}

@Composable
fun getProtocolColor(protocol: String, severity: String = "none"): Color {
    when (severity.lowercase()) {
        "error" -> return MaterialTheme.colorScheme.errorContainer
        "warn" -> return MaterialTheme.colorScheme.tertiaryContainer
    }
    return when (protocol.uppercase()) {
        "TCP" -> MaterialTheme.colorScheme.primaryContainer
        "UDP" -> MaterialTheme.colorScheme.secondaryContainer
        "DNS", "HTTP" -> MaterialTheme.colorScheme.tertiaryContainer
        "ICMP", "ARP", "TLS", "SSL" -> MaterialTheme.colorScheme.surfaceVariant
        else -> MaterialTheme.colorScheme.surface
    }
}

private fun extractPacketPorts(info: String): Pair<Int, Int>? {
    val match = PACKET_PORT_PAIR_REGEX.find(info) ?: return null
    val source = match.groupValues[1].toIntOrNull()
    val destination = match.groupValues[2].toIntOrNull()
    return if (source != null && destination != null && source <= 65535 && destination <= 65535) {
        source to destination
    } else {
        null
    }
}

private fun packetPorts(packet: PacketSummary): Pair<Int, Int>? {
    val sourcePort = packet.sourcePort
    val destinationPort = packet.destinationPort
    if (sourcePort != null && destinationPort != null) {
        return sourcePort to destinationPort
    }
    return extractPacketPorts(packet.info)
}

private fun displayProtocol(packet: PacketSummary): String {
    val protocol = packet.protocol.trim()
    if (protocol.isNotEmpty() && !protocol.equals("unknown", ignoreCase = true)) {
        return protocol
    }
    val info = packet.info.trim()
    val upperInfo = info.uppercase()
    return when {
        upperInfo.startsWith("HTTP/") || HTTP_METHODS.any { upperInfo.startsWith(it) } -> "HTTP"
        "TLS" in upperInfo || "SSL" in upperInfo || "CLIENT HELLO" in upperInfo || "SERVER HELLO" in upperInfo -> "TLS"
        "DNS" in upperInfo || "QUERY" in upperInfo || "STANDARD QUERY" in upperInfo -> "DNS"
        "ARP" in upperInfo -> "ARP"
        "ICMP" in upperInfo -> "ICMP"
        "UDP" in upperInfo -> "UDP"
        "TCP" in upperInfo || PACKET_PORT_PAIR_REGEX.containsMatchIn(info) -> "TCP"
        else -> "Unknown"
    }
}

private fun formatEndpoint(address: String, port: Int?): String {
    if (port == null) return address
    return if (address.contains(":") && !address.startsWith("[")) {
        "[$address]:$port"
    } else {
        "$address:$port"
    }
}

private fun severityRank(severity: String): Int {
    return when (severity.lowercase()) {
        "error" -> 3
        "warn" -> 2
        "note" -> 1
        else -> 0
    }
}

@Composable
private fun severityTextColor(severity: String): Color {
    return when (severity.lowercase()) {
        "error" -> MaterialTheme.colorScheme.error
        "warn" -> Color(0xFF8A5A00)
        "note" -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.onSurface
    }
}

fun shareExportResult(context: Context, result: ExportResult) {
    val file = File(result.filePath)
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = result.mimeType
        putExtra(Intent.EXTRA_STREAM, uri)
        putExtra(Intent.EXTRA_TITLE, result.displayName)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, context.getString(R.string.share_file, result.displayName)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}

private val PACKET_PORT_PAIR_REGEX = Regex("""\b(\d+)\s*(?:→|->|>)\s*(\d+)\b""")
private val HTTP_METHODS = listOf("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ")
