// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import android.content.Context
import android.net.Uri
import android.view.Surface
import androidx.compose.material3.Surface
import com.example.layanalyzer.ai.agent.AgentProviderConfig
import com.example.layanalyzer.ai.agent.AgentSettings
import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.ai.client.GatewayAccountUiState
import com.example.layanalyzer.ai.client.ProviderModelFetchFailure
import com.example.layanalyzer.ai.client.ProviderModelFetchResult
import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.ScenarioPackageDescription
import com.example.layanalyzer.capture.TlsStartBlockReason
import com.example.layanalyzer.capture.tls.TlsCaState
import com.example.layanalyzer.capture.tls.TlsConnectionSnapshot
import com.example.layanalyzer.data.SavedCaptureOpenInfo
import com.example.layanalyzer.media.RtpPlayerState
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
import com.example.layanalyzer.model.AnalysisJobState
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.ExportUiState
import com.example.layanalyzer.model.LiveCaptureSettings
import com.example.layanalyzer.model.LiveCaptureState
import com.example.layanalyzer.model.ProtocolAgentUiState
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpExportFormat
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpStreamIdentity
import com.example.layanalyzer.model.RtpTimingMode
import com.example.layanalyzer.model.RtpVideoDecoderAvailability
import com.example.layanalyzer.model.RtpVideoExportFormat
import com.example.layanalyzer.model.RtpVideoPreviewAvailability
import com.example.layanalyzer.ui.components.rtp.RtpPlayerScreen
import com.example.layanalyzer.viewmodel.AgentScenarioDraft
import com.example.layanalyzer.viewmodel.RtpDualTrackPlayback
import com.example.layanalyzer.viewmodel.RtpExportDestination
import com.example.layanalyzer.viewmodel.RtpExportUiState
import com.example.layanalyzer.viewmodel.RtpExternalOpenUiState
import com.example.layanalyzer.viewmodel.RtpPlayerUiState
import com.example.layanalyzer.viewmodel.RtpScanUiState
import com.example.layanalyzer.viewmodel.RtpTrackMuteState
import com.example.layanalyzer.viewmodel.RtpVideoExportUiState
import com.example.layanalyzer.viewmodel.RtpVideoOpenUiState
import com.example.layanalyzer.viewmodel.RtpVideoPreviewUiState
import com.example.layanalyzer.viewmodel.TlsConnectionSummary
import com.example.layanalyzer.viewmodel.TlsFollowViewerState
import com.example.layanalyzer.viewmodel.VoipCallsUiState

/**
 * Grouped inputs of [PacketListScreen].
 *
 * The screen used to take every one of its ~236 inputs as a separate parameter.
 * That is not only unwieldy: a compiled method may use at most 255 parameter
 * slots (JVMS 4.3.3), and the parameter list had grown to 274 slots (five of the
 * parameters are `Long`s and take two slots each). The class file was therefore
 * invalid, D8 wrote the call's `invoke-static/range` argument count truncated to
 * `274 mod 256 = 18`, and ART rejected the class at verification, so the app
 * could not start at all on a device:
 *
 *   java.lang.VerifyError: Verifier rejected class
 *   com.example.layanalyzer.ui.LayAnalyzerAppKt ... expected 18 argument
 *   registers, method signature has 19 or more
 *
 * Grouping the inputs into the four objects below keeps each function well under
 * the limit (the screen now has 78 individual parameters plus these four) and
 * gives the domain boundaries a name. Field names are deliberately identical to
 * the old parameter names, so the screen body is unchanged: it unpacks them with
 * a `val <name> = <group>.<name>` block at the top.
 */

/**
 * TLS interception, live capture and capture import/export inputs of
 * [PacketListScreen] (TLS-301..TLS-315 usage).
 */
internal data class PacketListTlsInputs(
    val tlsKeyLogImportState: com.example.layanalyzer.viewmodel.TlsKeyLogImportState,
    val onBeginTlsKeyLogSelection: () -> Boolean,
    val onImportTlsKeyLog: (Uri?) -> Unit,
    val onClearTlsKeyLog: () -> Unit,
    val onCancelTlsKeyLogImport: () -> Unit,
    val liveCaptureState: LiveCaptureState,
    /** TLS-308: the open TLS follow viewer, or null. Its dedicated screen replaces the list. */
    val tlsFollowViewer: TlsFollowViewerState? = null,
    /** TLS-308: the bounded full-stream export state (progress, digest message, share result). */
    val tlsFollowExportState: ExportUiState = ExportUiState(),
    /** TLS-308: open the dedicated TLS follow for a frame (the context action). */
    val onFollowTlsStream: (Long) -> Unit = {},
    val onCloseTlsFollow: () -> Unit = {},
    val onExportTlsFollow: () -> Unit = {},
    val onCancelTlsFollowExport: () -> Unit = {},
    val onClearTlsFollowExportState: () -> Unit = {},
    /**
     * TLS-310: the one-shot summary of the last saved-capture open (scope, drops, key
     * completeness, vantage), or null. Default null so an ordinary URI/recent open shows
     * nothing rather than a stale summary.
     */
    val savedCaptureOpenInfo: SavedCaptureOpenInfo? = null,
    /** TLS-310: dismiss the summary without touching the opened session. */
    val onDismissSavedCaptureOpenInfo: () -> Unit = {},
    val onPrepareCaptureExport: (com.example.layanalyzer.data.TlsCaptureExportKind, Boolean) -> Boolean = { _, _ -> false },
    val onSaveCaptureExport: (Uri?) -> Unit = {},
    val onImportCaptureBundle: (Uri) -> Unit = {},
    val onCancelCaptureExport: () -> Unit = {},
    val onStartLiveCapture: (LiveCaptureSettings) -> Unit,
    val onStopLiveCapture: () -> Unit,
    val onOpenSavedLiveCapture: () -> Unit,
    val onClearLiveCaptureError: () -> Unit,
    /** The saved VPN capture settings that seed the TLS settings draft (TLS-304). */
    val liveCaptureSettings: LiveCaptureSettings = LiveCaptureSettings(),
    /**
     * The live TLS summary the service publishes (TLS-306), or null when no
     * capture is intercepting. Default null so the preview shows the honest
     * "not running" state rather than a stale one.
     */
    val tlsConnectionSnapshot: TlsConnectionSnapshot? = null,
    /** The ViewModel's projection of [tlsConnectionSnapshot] onto the §10.2 counts. */
    val tlsConnectionSummary: TlsConnectionSummary? = null,
    /** Reads the local CA state for the TLS settings block; never generates or resets. */
    val loadTlsCaState: suspend () -> TlsCaState = { TlsCaState.MISSING },
    /**
     * TLS-315: why the last start request for an intercepted capture was refused
     * (feature, configuration, CA material or storage), or null. Default null so a
     * caller that has not wired the start gate shows no notice.
     */
    val tlsStartBlock: TlsStartBlockReason? = null,
    /** TLS-315: clear the refusal notice, e.g. once the user opens the CA wizard. */
    val onDismissTlsStartBlock: () -> Unit = {},
)

/**
 * Protocol-agent page inputs of [PacketListScreen] (AI-* usage): the agent
 * state, its consent/settings surface and every agent callback.
 */
internal data class PacketListAgentInputs(
    val agentUiState: ProtocolAgentUiState,
    val agentJob: AnalysisJobState,
    val onAgentSubmitQuestion: (String, AnalysisScope, String?, Int?) -> Unit,
    val onAgentContinueConversation: (String) -> Unit,
    val onAgentCancel: () -> Unit,
    val onAgentRetry: () -> Unit,
    val onAgentNewConversation: () -> Unit,
    val onAgentClearTransientError: () -> Unit,
    val agentFilterPreview: AgentFilterPreviewState? = null,
    val onAgentEvidenceClick: (AgentEvidence, AgentReport) -> Unit = { _, _ -> },
    val onAgentSaveFinding: (AgentFinding, AgentReport) -> Unit = { _, _ -> },
    val onAgentExportReport: (AgentReport) -> Unit = {},
    val onConfirmAgentFilterPreview: () -> Unit = {},
    val onDismissAgentFilterPreview: () -> Unit = {},
    val agentSettings: AgentSettings = AgentSettings(),
    val agentConsentPrompt: AgentConsentPrompt? = null,
    val onAgentSettingsChange: (AgentSettings) -> Unit = {},
    val onAgentPrivacyModeChange: (AgentPrivacyMode) -> Unit = {},
    val onAgentModelSelectionChange: (String, String) -> Unit = { _, _ -> },
    val onAgentAcceptConsent: () -> Unit = {},
    val onAgentDeclineConsent: () -> Unit = {},
    val onAgentSaveProviderKey: (AgentProviderConfig, String) -> Unit = { _, _ -> },
    val onAgentClearProviderKey: (String) -> Unit = {},
    val onAgentFetchProviderModels: suspend (AgentProviderConfig, String) -> ProviderModelFetchResult =
        { _, _ -> ProviderModelFetchResult.Failure(ProviderModelFetchFailure.Network) },
    val gatewayAccount: GatewayAccountUiState = GatewayAccountUiState(),
    val onRefreshGatewayAccount: () -> Unit = {},
    val agentByokEnabled: Boolean = false,
    val agentResponseCaptureAvailable: Boolean = false,
    val onAgentClearResponseDumps: () -> Unit = {},
    val agentSavedSessions: List<AgentSavedSessionSummary> = emptyList(),
    val agentDeletingSavedSessions: Set<String> = emptySet(),
    val agentRestoredSession: AgentSavedSession? = null,
    val agentRestoredSessionMatchesCapture: Boolean = false,
    val agentInterruptedJob: com.example.layanalyzer.data.AnalysisJobCheckpoint? = null,
    val onAgentResumeInterruptedJob: () -> Unit = {},
    val onAgentDismissInterruptedJob: () -> Unit = {},
    val agentLocalDataUsage: AgentLocalDataUsage = AgentLocalDataUsage(),
    val onAgentOpenSavedSession: (String) -> Unit = {},
    val onAgentDeleteSavedSession: (String) -> Unit = {},
    val onAgentDismissRestoredSession: () -> Unit = {},
    val onAgentClearLocalData: (Set<AgentLocalDataCategory>) -> Unit = {},
    val onAgentExportDiagnostics: () -> Unit = {},
    /** AI-26: the active scenario rule package shown on the Agent page. */
    val agentScenarioPackage: ScenarioPackageDescription? = null,
    val agentPlaybooks: List<AgentPlaybook> = emptyList(),
    val onAgentClearScenarioPackage: () -> Unit = {},
    val onAgentPlaybookUsed: (String) -> Unit = {},
    /** Scenario chip long-press menu: edit a user scenario. */
    val onAgentEditScenario: (AgentPlaybook) -> Unit = {},
    /** Scenario chip long-press menu: copy the scenario as a duplicate. */
    val onAgentCopyScenario: (String) -> Unit = {},
    /** Scenario chip long-press menu: delete a user scenario. */
    val onAgentDeleteScenario: (String) -> Unit = {},
    /** Scenario chip long-press menu: read-only details; the editor mounts in a later task. */
    val onAgentViewScenarioDetails: (AgentPlaybook) -> Unit = {},
    /** "New scenario" chip; the scenario editor mounts in a later task (SRE-EDITOR-01). */
    val onAgentNewScenario: () -> Unit = {},
    /** The open scenario editor draft (edit or read-only details); null closes the editor. */
    val agentEditingScenario: AgentScenarioDraft? = null,
    /** Tools the scenario editor's Initial tools chips offer; empty renders no chips. */
    val agentScenarioToolWhitelist: Set<String> = emptySet(),
    val onAgentDismissScenarioEditor: () -> Unit = {},
    /** Persists the ViewModel-held draft; the editor keeps no copy (OPT-DRAFT-01). */
    val onAgentSaveScenario: () -> Unit = {},
    /** OPT-SAVE-01: a scenario save is in flight; the editor's Save button disables. */
    val agentScenarioSaving: Boolean = false,
    /** Routes an edited scenario playbook into the ViewModel draft (OPT-DRAFT-01). */
    val onAgentScenarioPlaybookChange: (AgentPlaybook) -> Unit = {},
    /** Monotonic count of successful scenario saves; raises the saved notice (SRE-EDITOR-06). */
    val agentScenarioSaveCompleted: Int = 0,
    /** OPT-QNT-01: distinct quarantine reason codes; each new one raises the notice. */
    val agentScenarioQuarantineCodes: List<String> = emptyList(),
    /**
     * EVL-UI-07: the current run's audit record, threaded to the report's
     * evidence-coverage badge. Null suppresses the badge (fail-closed).
     */
    val agentRunRecord: AgentRunRecord? = null,
)

/**
 * RTP/VoIP analysis and playback inputs of [PacketListScreen] (RTP*-UI-*),
 * from the stream scan down to the video preview page.
 */
internal data class PacketListRtpInputs(
    val rtpState: RtpScanUiState = RtpScanUiState.Idle,
    val rtpHeuristicEnabled: Boolean = false,
    val rtpHighlightedStreamId: String? = null,
    val rtpOpenRequest: RtpStreamIdentity? = null,
    val rtpHeuristicApplyVersion: Long = 0L,
    val onRtpOpenRequestHandled: () -> Unit = {},
    val onRtpScan: (Boolean) -> Unit = {},
    val onRtpCancel: () -> Unit = {},
    val onRtpToggleHeuristic: (Boolean) -> Unit = {},
    val onRtpSetOverride: (Int, String, Int) -> Unit = { _, _, _ -> },
    val onRtpHighlightStream: (String?) -> Unit = {},
    val rtpPlayerState: RtpPlayerUiState = RtpPlayerUiState(),
    val rtpPlaybackState: RtpPlayerState = RtpPlayerState.Idle,
    val rtpPlayerPositionMs: Long = 0L,
    val rtpExportState: RtpExportUiState = RtpExportUiState.Idle,
    val onRtpOpenPlayer: (RtpStream) -> Unit = {},
    val onRtpPlayStream: (RtpStream) -> Unit = {},
    val onRtpPlayStreams: (List<RtpStream>) -> Unit = {},
    val onRtpExportWav: (List<RtpStream>, List<RtpExportDestination>) -> Unit = { _, _ -> },
    val onRtpExportRaw: (List<RtpStream>, List<RtpExportDestination>) -> Unit = { _, _ -> },
    /** RTP4-KT-03: 导出格式对话框选定后的目的地写入（宿主交给 `RtpViewModel.exportFormat`）。 */
    val onRtpExportFormat: (RtpStream, RtpExportFormat, RtpExportDestination) -> Unit =
        { _, _, _ -> },
    /** RTP4-KT-03: 「外部打开」的容器准备状态，见 `RtpViewModel.prepareExternalOpen`。 */
    val rtpExternalOpenState: RtpExternalOpenUiState = RtpExternalOpenUiState.Idle,
    val onRtpOpenExternal: (RtpStream) -> Unit = {},
    val onRtpClearExternalOpenState: () -> Unit = {},
    val onRtpClosePlayer: () -> Unit = {},
    val onRtpPlayerPlayPause: () -> Unit = {},
    val onRtpPlayerSeek: (Long) -> Unit = {},
    val onRtpPlayerTimingChange: (RtpTimingMode) -> Unit = {},
    val onRtpPlayerCancelDecode: () -> Unit = {},
    val onRtpPlayerRetryDecode: () -> Unit = {},
    val onRtpPlayerSelectStream: (String) -> Unit = {},
    val onRtpPlayerExportWav: (Uri) -> Unit = {},
    val onRtpPlayerShareWav: () -> Unit = {},
    val onRtpPlayerClearExportState: () -> Unit = {},
    /** RTP5-UI-01: the video export state, see `RtpViewModel.videoExportState`. */
    val rtpVideoExportState: RtpVideoExportUiState = RtpVideoExportUiState.Idle,
    /** RTP5-UI-01: write one video stream to the chosen SAF destination. */
    val onRtpExportVideo: (
        RtpStream,
        RtpVideoExportFormat,
        RtpExportDestination,
        Boolean,
        Boolean
    ) -> Unit = { _, _, _, _, _ -> },
    val onRtpClearVideoExportState: () -> Unit = {},
    /** Stops a video export or the external-open preparation. Both walk the capture. */
    val onRtpCancelVideoExport: () -> Unit = {},
    /** Stops an audio export. */
    val onRtpCancelAudioExport: () -> Unit = {},
    /**
     * RTP5-UI-01: 「外部播放」的导出状态。The streams page opens the file itself
     * (it has the `Context`), the same split `RtpPlayerScreen` has for audio.
     */
    val rtpVideoOpenState: RtpVideoOpenUiState = RtpVideoOpenUiState.Idle,
    val onRtpOpenVideoExternal: (RtpStream) -> Unit = {},
    val onRtpClearVideoOpenState: () -> Unit = {},
    /** RTP5-UI-01: the HEVC decoder probe's answer, shown in the export dialog. */
    val rtpHevcDecoderAvailability: RtpVideoDecoderAvailability = RtpVideoDecoderAvailability.UNKNOWN,
    val onRtpRefreshHevcDecoderAvailability: () -> Unit = {},
    /** RTP5-UI-01: the state of the in-app preview page (RTP5-KT-03). */
    val rtpVideoPreviewState: RtpVideoPreviewUiState = RtpVideoPreviewUiState(),
    val rtpVideoPreviewAvailability: RtpVideoPreviewAvailability = RtpVideoPreviewAvailability.NoExport,
    val rtpVideoPreviewPlaybackState: RtpPlayerState = RtpPlayerState.Idle,
    val rtpVideoPreviewPositionMs: Long = 0L,
    val rtpVideoPreviewDurationMs: Long = 0L,
    /** RTP5-UI-01: a finished MP4 export, handed to `refreshVideoPreviewAvailability`. */
    val onRtpVideoPreviewAvailable: (RtpStream, String, String) -> Unit = { _, _, _ -> },
    /** RTP5-UI-01: open the preview page for a stream the host has a target for. */
    val onRtpOpenVideoPreview: (RtpStream, String, String) -> Unit = { _, _, _ -> },
    /**
     * RTP5-UI-01：视频流卡片整块点击、还没有可播 MP4 时，把该流交给
     * `RtpViewModel.prepareVideoPreview` —— 就地封装一份再进预览页。
     */
    val onRtpPrepareVideoPreview: (RtpStream) -> Unit = {},
    val onRtpCloseVideoPreview: () -> Unit = {},
    val onRtpVideoPreviewPlayPause: () -> Unit = {},
    val onRtpVideoPreviewSeek: (Long) -> Unit = {},
    /** RTP5-UI-01: the preview `TextureView`'s surface, forwarded to the controller. */
    val onRtpAttachVideoPreviewSurface: (Surface) -> Unit = {},
    val onRtpDetachVideoPreviewSurface: () -> Unit = {}
)

/**
 * VoIP call-list inputs of [PacketListScreen] (RTP3-UI-*).
 */
internal data class PacketListVoipInputs(
    /** RTP3-UI-01: the VoIP call list state; [VoipCallsUiState.Idle] until the user opens the page. */
    val voipCallsState: VoipCallsUiState = VoipCallsUiState.Idle,
    /** RTP3-UI-01: asks the host to (re)build the call list for the current session. */
    val onVoipCallsLoad: () -> Unit = {},
    /** RTP3-UI-02: the decode result of the call selected with the detail page's Play button. */
    val voipPlayback: RtpDecodeResult? = null,
    /** RTP3-UI-02: Play on the detail page; the host forwards it to `VoipCallsViewModel.selectCall`. */
    val onVoipPlayCall: (String) -> Unit = {},
    /** RTP3-UI-03: the dual-track player's track input; null while the decode is still running. */
    val voipDualTrack: RtpDualTrackPlayback? = null,
    /** RTP3-UI-03: the VoIP audio controller's playback state (idle when no controller is wired). */
    val voipPlayerPlaybackState: RtpPlayerState = RtpPlayerState.Idle,
    /** RTP3-UI-03: the VoIP audio controller's playhead, in milliseconds. */
    val voipPlayerPositionMs: Long = 0L,
    /** RTP3-UI-03: left/right channel mute of the dual-track player. */
    val voipPlayerMuteState: RtpTrackMuteState = RtpTrackMuteState(),
    /** RTP3-UI-03: play/pause the VoIP audio controller. */
    val onVoipPlayerPlayPause: () -> Unit = {},
    /** RTP3-UI-03: seek the VoIP audio controller. */
    val onVoipPlayerSeek: (Long) -> Unit = {},
    /** RTP3-UI-03: set the left/right channel mute of the dual-track player. */
    val onVoipPlayerMute: (Boolean, Boolean) -> Unit = { _, _ -> },
    /** RTP3-UI-03: stop the VoIP audio when the VoIP pages are left. */
    val onVoipClosePlayer: () -> Unit = {},
)
