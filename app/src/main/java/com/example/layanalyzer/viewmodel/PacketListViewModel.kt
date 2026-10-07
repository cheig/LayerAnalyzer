// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.StatFs
import android.provider.OpenableColumns
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.R
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import androidx.annotation.StringRes
import com.example.layanalyzer.data.PacketPagingSource
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.data.CaptureFileValidator
import com.example.layanalyzer.data.SearchQueryValidator
import com.example.layanalyzer.data.AnalysisWorkspaceStore
import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.ai.export.AgentReportExport
import com.example.layanalyzer.ai.export.AgentReportExporter
import com.example.layanalyzer.data.CaptureHealthAnalyzer
import com.example.layanalyzer.data.EvidencePackageWriter
import com.example.layanalyzer.data.EvidenceExportScopePolicy
import com.example.layanalyzer.data.EvidenceExportPlanner
import com.example.layanalyzer.data.EvidenceExportManifestFields
import com.example.layanalyzer.data.EvidenceExportReportSections
import com.example.layanalyzer.data.EvidenceFrameCountGuard
import com.example.layanalyzer.data.EvidenceFrameCountVerification
import com.example.layanalyzer.data.EvidenceFrameFilter
import com.example.layanalyzer.data.EvidenceFrameViewDecision
import com.example.layanalyzer.data.EvidenceFrameViewPolicy
import com.example.layanalyzer.data.MetadataRedactor
import com.example.layanalyzer.data.ScenarioTemplateStore
import com.example.layanalyzer.ai.audit.AgentDiagnosticsRecorder
import com.example.layanalyzer.model.AnalyzerPreferences
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.AnalysisJobPhase
import com.example.layanalyzer.model.AnalysisJobState
import com.example.layanalyzer.model.AnalysisWorkspace
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentFilterPreviewState
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentSavedFinding
import com.example.layanalyzer.model.EvidenceExportMode
import com.example.layanalyzer.model.EvidenceExportScope
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.CaptureHealthSummary
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.ScenarioTemplate
import com.example.layanalyzer.model.WorkspaceNote
import com.example.layanalyzer.model.WorkspacePage
import com.example.layanalyzer.model.DecodeAsRule
import com.example.layanalyzer.model.DecodeAsScope
import com.example.layanalyzer.model.DecodeAsTransport
import com.example.layanalyzer.model.DisplayFilterResult
import com.example.layanalyzer.model.DisplayFilterUiState
import com.example.layanalyzer.model.EspDecryptionMode
import com.example.layanalyzer.model.EspDecryptionResult
import com.example.layanalyzer.model.FilterSyntaxStatus
import com.example.layanalyzer.model.ExportResult
import com.example.layanalyzer.model.ExportUiState
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.HttpObjectEntry
import com.example.layanalyzer.model.HttpObjectsState
import com.example.layanalyzer.model.LiveCaptureSettings
import com.example.layanalyzer.model.LiveCaptureState
import com.example.layanalyzer.model.OpenProgress
import com.example.layanalyzer.model.PacketSearchMode
import com.example.layanalyzer.model.PacketSearchState
import com.example.layanalyzer.model.PacketContextActionsState
import com.example.layanalyzer.model.PacketSummary
import com.example.layanalyzer.model.RecentCapture
import com.example.layanalyzer.model.StatisticsUiState
import com.example.layanalyzer.model.TimeDisplayFormat
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

data class CaptureOpenRequest(
    val uri: Uri,
    val displayName: String? = null
)

data class LargeCaptureWarning(
    val uri: Uri,
    val displayName: String,
    val sizeBytes: Long,
    val fallbackName: String? = null
)

@OptIn(ExperimentalCoroutinesApi::class)
class PacketListViewModel(
    private val repository: PacketRepository,
    private val sessionCoordinator: CaptureSessionCoordinator,
    context: Context,
    private val agentDiagnostics: AgentDiagnosticsRecorder? = null
) : ViewModel() {
    private val appContext = context.applicationContext
    private fun text(@StringRes id: Int, vararg args: Any): String = appContext.getString(id, *args)
    private val prefs = appContext.getSharedPreferences("recent_captures", Context.MODE_PRIVATE)
    private val sessionPrefs = appContext.getSharedPreferences("active_session", Context.MODE_PRIVATE)
    private val analyzerPrefs =
        appContext.getSharedPreferences(RtpHeuristicPreferenceOps.PREFERENCE_FILE, Context.MODE_PRIVATE)
    private val workspaceStore = AnalysisWorkspaceStore(appContext)
    private val templateStore = ScenarioTemplateStore(appContext)
    private var openJob: Job? = null
    private var filterJob: Job? = null
    private var filterValidationJob: Job? = null
    private var searchJob: Job? = null
    private var expertJob: Job? = null
    private var statisticsJob: Job? = null
    private var communicationJob: Job? = null
    private var httpObjectsJob: Job? = null
    private var packetContextJob: Job? = null
    private var pendingEvidenceDestination: Uri? = null
    private var preferencesJob: Job? = null
    private var analysisGeneration: Long = 0
    private var searchRequestGeneration: Long = 0
    private var preferencesRequestGeneration: Long = 0
    private var sessionGeneration: Long = 0
    private val preferencesMutex = Mutex()

    private val pagerGeneration = MutableStateFlow(0)

    val packetFlow: Flow<PagingData<PacketSummary>> = pagerGeneration.flatMapLatest {
        Pager(
            PagingConfig(pageSize = 50, initialLoadSize = 100, enablePlaceholders = true)
        ) {
            PacketPagingSource(repository)
        }.flow
    }.cachedIn(viewModelScope)

    private val _currentFile = MutableStateFlow<FileSessionInfo?>(repository.currentFile())
    val currentFile = _currentFile.asStateFlow()

    private val _workspacePage = MutableStateFlow(WorkspacePage.Packets)
    val workspacePage = _workspacePage.asStateFlow()

    private val _openProgress = MutableStateFlow<OpenProgress?>(null)
    val openProgress = _openProgress.asStateFlow()

    private val _openError = MutableStateFlow<String?>(null)
    val openError = _openError.asStateFlow()

    private val _largeCaptureWarning = MutableStateFlow<LargeCaptureWarning?>(null)
    val largeCaptureWarning = _largeCaptureWarning.asStateFlow()

    private val _recentFiles = MutableStateFlow(loadRecentFiles())
    val recentFiles = _recentFiles.asStateFlow()

    private val _displayFilter = MutableStateFlow("")
    val displayFilter = _displayFilter.asStateFlow()

    private val _displayFilterUiState = MutableStateFlow(DisplayFilterUiState())
    val displayFilterUiState = _displayFilterUiState.asStateFlow()

    private val _filterResult = MutableStateFlow<DisplayFilterResult?>(null)
    val filterResult = _filterResult.asStateFlow()

    private val _isFiltering = MutableStateFlow(false)
    val isFiltering = _isFiltering.asStateFlow()

    private val _searchState = MutableStateFlow(PacketSearchState())
    val searchState = _searchState.asStateFlow()

    private val _expertSummary = MutableStateFlow(ExpertInfoSummary())
    val expertSummary = _expertSummary.asStateFlow()

    private val _statisticsState = MutableStateFlow(StatisticsUiState())
    val statisticsState = _statisticsState.asStateFlow()

    private val _httpObjectsState = MutableStateFlow(HttpObjectsState())
    val httpObjectsState = _httpObjectsState.asStateFlow()

    private val _packetContextActions = MutableStateFlow(PacketContextActionsState())
    val packetContextActions = _packetContextActions.asStateFlow()

    private val _highlightedFrames = MutableStateFlow<Set<Long>>(emptySet())
    val highlightedFrames = _highlightedFrames.asStateFlow()

    /** Increments after an RTP heuristic toggle has been applied natively. */
    private val _rtpHeuristicApplyVersion = MutableStateFlow(0L)
    val rtpHeuristicApplyVersion = _rtpHeuristicApplyVersion.asStateFlow()

    private val _preferences = MutableStateFlow(loadAnalyzerPreferences())
    val preferences = _preferences.asStateFlow()

    /**
     * 语言变更后递增，供 UI 侧收集并重建 Activity。
     *
     * 用计数器而不是 `UiLanguage?` 事件，是因为重复选同一个语言也要能收敛：
     * `UiLanguagePreferenceOps.changed` 已经滤掉了"没变"，这里只保证
     * "变了就一定有一次重建"，且重建后再次 collect 不会误触发。
     */
    private val _uiLanguageChangeVersion = MutableStateFlow(0L)
    val uiLanguageChangeVersion = _uiLanguageChangeVersion.asStateFlow()

    private val _nameResolutionEnabled = MutableStateFlow(_preferences.value.nameResolutionEnabled)
    val nameResolutionEnabled = _nameResolutionEnabled.asStateFlow()

    /**
     * One-shot error message about the last ESP NULL-decryption attempt. Null
     * when there is nothing to say; cleared by [clearEspDecryptionNotice] after
     * it has been shown.
     */
    private val _espDecryptionNotice = MutableStateFlow<String?>(null)
    val espDecryptionNotice = _espDecryptionNotice.asStateFlow()

    private val _exportState = MutableStateFlow(ExportUiState())
    val exportState = _exportState.asStateFlow()

    private val _decodeAsRules = MutableStateFlow<List<DecodeAsRule>>(emptyList())
    val decodeAsRules = _decodeAsRules.asStateFlow()

    private val _healthSummary = MutableStateFlow(CaptureHealthSummary())
    val healthSummary = _healthSummary.asStateFlow()

    private val _communicationAnalysis = MutableStateFlow(CommunicationAnalysis())
    val communicationAnalysis = _communicationAnalysis.asStateFlow()

    private val _analysisJob = MutableStateFlow(AnalysisJobState(phase = AnalysisJobPhase.Completed))
    val analysisJob = _analysisJob.asStateFlow()

    private val _workspace = MutableStateFlow<AnalysisWorkspace?>(null)
    val workspace = _workspace.asStateFlow()

    /**
     * EVL-EXPORT-01: whether the evidence-frame export scope may be selected.
     *
     * Pure, read-only derivation over the workspace evidence set: the compile +
     * policy logic has no Android dependency, so it is unit-tested directly.
     * Fail-closed — an empty evidence set, or one that cannot be compiled,
     * reports unavailable rather than falling back to the current view.
     */
    val evidenceFramesScopeAvailability =
        _workspace
            .map { workspace ->
                EvidenceExportScopePolicy.evaluate(
                    EvidenceExportScope.EvidenceFrames,
                    EvidenceFrameFilter.compileOrNull(workspace?.evidenceFrames.orEmpty())
                )
            }
            .stateIn(
                viewModelScope,
                SharingStarted.Eagerly,
                EvidenceExportScopePolicy.evaluate(
                    EvidenceExportScope.EvidenceFrames,
                    EvidenceFrameFilter.CompileResult.Empty
                )
            )

    private val _agentFilterPreview = MutableStateFlow<AgentFilterPreviewState?>(null)
    val agentFilterPreview = _agentFilterPreview.asStateFlow()

    val scenarioTemplates: List<ScenarioTemplate> = templateStore.load()

    val liveCaptureState = LiveCaptureStore.state.stateIn(
        viewModelScope,
        SharingStarted.Eagerly,
        LiveCaptureState()
    )

    val hasOpenFile = currentFile.stateIn(
        viewModelScope,
        SharingStarted.Eagerly,
        repository.currentFile()
    )

    init {
        viewModelScope.launch {
            sessionCoordinator.filterRefreshEvents.collect { refresh ->
                val session = refresh.session
                if (session.sessionHandle != repository.currentSessionHandle()) return@collect
                _displayFilter.value = session.appliedDisplayFilter
                _filterResult.value = DisplayFilterResult(
                    success = false,
                    filteredCount = session.visibleFrameCount,
                    error = text(R.string.error_filter_restore_conflict)
                )
                _displayFilterUiState.value = DisplayFilterUiState(
                    draftExpression = session.appliedDisplayFilter,
                    appliedExpression = session.appliedDisplayFilter,
                    syntaxStatus = FilterSyntaxStatus.Valid,
                    visibleCount = session.visibleFrameCount,
                    totalCount = session.frameCount
                )
                _searchState.value = PacketSearchState()
                pagerGeneration.value += 1
            }
        }

        val restoredFile = repository.currentFile()
        val restoredFilter = sessionPrefs.getString("displayFilter", "").orEmpty()
        if (restoredFile != null && restoredFilter.isNotBlank()) {
            _displayFilter.value = restoredFilter
            val activeFilter = repository.getAppliedDisplayFilter()
            _displayFilterUiState.value = DisplayFilterUiState(
                draftExpression = restoredFilter,
                appliedExpression = activeFilter,
                syntaxStatus = FilterSyntaxStatus.Valid,
                visibleCount = repository.getVisibleFrameCount(),
                totalCount = repository.getFrameCount()
            )
            applyDisplayFilter()
        } else if (restoredFile != null) {
            _displayFilterUiState.value = DisplayFilterUiState(
                syntaxStatus = FilterSyntaxStatus.Valid,
                visibleCount = repository.getVisibleFrameCount(),
                totalCount = repository.getFrameCount()
            )
        }
    }

    fun openCaptureUri(uri: Uri, fallbackName: String? = null, confirmedLargeFile: Boolean = false) {
        if (!confirmedLargeFile) {
            viewModelScope.launch {
                val metadata = runCatching { withContext(Dispatchers.IO) { queryMetadata(uri, fallbackName) } }.getOrNull()
                if (metadata != null && metadata.sizeBytes > LARGE_FILE_WARNING_BYTES) {
                    _largeCaptureWarning.value = LargeCaptureWarning(uri, metadata.displayName, metadata.sizeBytes, fallbackName)
                } else {
                    openCaptureUri(uri, fallbackName, confirmedLargeFile = true)
                }
            }
            return
        }
        openJob?.cancel()
        prepareForFileSwitch()
        openJob = viewModelScope.launch {
            _openError.value = null
            _openProgress.value = OpenProgress(text(R.string.progress_preparing_file))
            try {
                val prepared = withContext(Dispatchers.IO) {
                    copyUriToPrivateStorage(uri, fallbackName)
                }
                try {
                    openPreparedFile(prepared)
                } catch (error: Throwable) {
                    prepared.file.delete()
                    throw error
                }
            } catch (e: CancellationException) {
                _openProgress.value = null
            } catch (e: Exception) {
                _openProgress.value = null
                _openError.value = e.message ?: text(R.string.error_open_capture)
            }
        }
    }

    fun confirmLargeCapture() {
        val warning = _largeCaptureWarning.value ?: return
        _largeCaptureWarning.value = null
        openCaptureUri(warning.uri, warning.fallbackName, confirmedLargeFile = true)
    }

    fun dismissLargeCaptureWarning() {
        _largeCaptureWarning.value = null
    }

    fun openRecentCapture(recent: RecentCapture) {
        openJob?.cancel()
        prepareForFileSwitch()
        openJob = viewModelScope.launch {
            _openError.value = null
            _openProgress.value = OpenProgress(text(R.string.progress_opening_file, recent.displayName))
            try {
                openPreparedFile(
                    PreparedCapture(
                        file = File(recent.localPath),
                        displayName = recent.displayName,
                        sizeBytes = recent.sizeBytes
                    )
                )
            } catch (e: CancellationException) {
                _openProgress.value = null
            } catch (e: Exception) {
                _openProgress.value = null
            _openError.value = e.message ?: text(R.string.error_open_recent_capture)
            }
        }
    }

    fun cancelOpen() {
        openJob?.cancel()
        openJob = null
        _openProgress.value = null
    }

    fun clearOpenError() {
        _openError.value = null
    }

    fun selectWorkspacePage(page: WorkspacePage) {
        _workspacePage.value = page
    }

    fun deleteRecentCapture(recent: RecentCapture) {
        if (repository.currentFile()?.localPath == recent.localPath) {
            _openError.value = text(R.string.error_close_before_delete)
            return
        }
        val file = File(recent.localPath)
        val deleted = !file.exists() || file.delete()
        if (!deleted) {
            _openError.value = text(R.string.error_delete_capture, recent.displayName)
            return
        }
        File(file.parentFile, "${file.name}.report.json").delete()
        _recentFiles.value = _recentFiles.value.filterNot { it.localPath == recent.localPath }
        persistRecentFiles(_recentFiles.value)
    }

    fun closeFile() {
        sessionGeneration++
        sessionCoordinator.invalidateSession()
        openJob?.cancel()
        filterJob?.cancel()
        markAnalysisStale()
        _isFiltering.value = false
        repository.closeFile()
        sessionPrefs.edit().clear().apply()
        _currentFile.value = null
        _workspacePage.value = WorkspacePage.Packets
        _openProgress.value = null
        _displayFilter.value = ""
        _displayFilterUiState.value = DisplayFilterUiState()
        _filterResult.value = null
        _searchState.value = PacketSearchState()
        _decodeAsRules.value = emptyList()
        _packetContextActions.value = PacketContextActionsState()
        _highlightedFrames.value = emptySet()
        _healthSummary.value = CaptureHealthSummary()
        _workspace.value = null
        _agentFilterPreview.value = null
        pagerGeneration.value += 1
    }

    private fun markAnalysisStale(cancelNative: Boolean = true) {
        analysisGeneration++
        filterJob?.cancel()
        filterJob = null
        _isFiltering.value = false
        cancelSearchRequest()
        _searchState.value = _searchState.value.copy(
            results = emptyList(),
            selectedResultIndex = -1,
            isSearching = false,
            hasSearched = false,
            error = null
        )
        if (cancelNative) repository.cancelLongRunningOperations()
        expertJob?.cancel()
        statisticsJob?.cancel()
        communicationJob?.cancel()
        httpObjectsJob?.cancel()
        packetContextJob?.cancel()
        _expertSummary.value = ExpertInfoSummary()
        _statisticsState.value = StatisticsUiState(bucketSeconds = _statisticsState.value.bucketSeconds)
        _httpObjectsState.value = HttpObjectsState()
        _packetContextActions.value = PacketContextActionsState()
        _healthSummary.value = CaptureHealthSummary()
        _communicationAnalysis.value = CommunicationAnalysis()
    }

    fun updateDisplayFilter(filter: String) {
        _displayFilter.value = filter
        filterValidationJob?.cancel()
        _displayFilterUiState.value = _displayFilterUiState.value.copy(
            draftExpression = filter,
            syntaxStatus = if (filter.isBlank()) FilterSyntaxStatus.Valid else FilterSyntaxStatus.Checking,
            syntaxError = null
        )
        if (filter.isBlank()) return
        val expectedSession = sessionCoordinator.currentToken()
        filterValidationJob = viewModelScope.launch {
            delay(FILTER_VALIDATION_DEBOUNCE_MS)
            val result = withContext(Dispatchers.IO) {
                sessionCoordinator.validateDisplayFilter(filter, expectedSession)
            }
            if (_displayFilterUiState.value.draftExpression != filter) return@launch
            _displayFilterUiState.value = _displayFilterUiState.value.copy(
                syntaxStatus = if (result.isSuccess) FilterSyntaxStatus.Valid else FilterSyntaxStatus.Invalid,
                syntaxError = result.exceptionOrNull()?.message
            )
        }
    }

    fun applyDisplayFilter(filter: String) {
        updateDisplayFilter(filter)
        applyDisplayFilter()
    }

    /**
     * EVL-UI-04: frame the packet list with the workspace evidence set.
     * Fail-closed — an empty or uncompilable evidence set applies nothing.
     *
     * Compiles the workspace evidence frames and asks [EvidenceFrameViewPolicy]
     * whether the result may be applied. Only a [EvidenceFrameViewDecision.Apply]
     * reaches [applyDisplayFilter]; rejections are returned for the UI to warn
     * about without changing the current view. Apply success also records the
     * filter in `workspace.filterHistory` (handled by [applyDisplayFilter]), so
     * this function must not call [addFilterHistory] itself.
     */
    fun showEvidenceFramesOnly(): EvidenceFrameViewDecision {
        val decision = EvidenceFrameViewPolicy.decide(
            EvidenceFrameFilter.compileOrNull(_workspace.value?.evidenceFrames.orEmpty())
        )
        if (decision is EvidenceFrameViewDecision.Apply) {
            applyDisplayFilter(decision.filter)
        }
        return decision
    }

    fun applyDisplayFilter() {
        // Native cancellation is issued by the coordinator after it owns the
        // filter mutex, so a queued UI request cannot cancel an Agent lease.
        markAnalysisStale(cancelNative = false)
        val requestedFilter = _displayFilterUiState.value.draftExpression.trim()
        val generation = analysisGeneration
        val expectedSession = sessionCoordinator.currentToken()
        beginAnalysisJob(AnalysisScope.CurrentFilter, text(R.string.job_applying_filter), repository.getVisibleFrameCount().toLong())
        filterJob = viewModelScope.launch {
            _isFiltering.value = true
            try {
                val result = withContext(Dispatchers.IO) {
                    sessionCoordinator.applyUserFilter(requestedFilter, expectedSession)
                }
                if (!isActive || generation != analysisGeneration) return@launch
                _filterResult.value = result
                _analysisJob.value = if (result.success) {
                    _analysisJob.value.copy(phase = AnalysisJobPhase.Completed, processed = result.filteredCount.toLong(), message = text(R.string.job_filter_ready))
                } else {
                    _analysisJob.value.copy(phase = AnalysisJobPhase.Failed, errorCode = "FILTER_FAILED", message = result.error)
                }
                if (result.success) {
                    _displayFilter.value = requestedFilter
                    _displayFilterUiState.value = _displayFilterUiState.value.copy(
                        draftExpression = requestedFilter,
                        appliedExpression = requestedFilter,
                        syntaxStatus = FilterSyntaxStatus.Valid,
                        syntaxError = null,
                        visibleCount = result.filteredCount,
                        totalCount = repository.getFrameCount()
                    )
                    sessionPrefs.edit().putString("displayFilter", requestedFilter).apply()
                    _workspace.value?.let { workspace ->
                        val history = if (requestedFilter.isBlank()) workspace.filterHistory else
                            (listOf(requestedFilter) + workspace.filterHistory.filterNot { it == requestedFilter }).take(20)
                        updateWorkspace(workspace.copy(displayFilter = requestedFilter, filterHistory = history))
                    }
                    _searchState.value = PacketSearchState()
                    pagerGeneration.value += 1
                } else {
                    _displayFilterUiState.value = _displayFilterUiState.value.copy(
                        syntaxStatus = FilterSyntaxStatus.Invalid,
                        syntaxError = result.error,
                        visibleCount = repository.getVisibleFrameCount(),
                        totalCount = repository.getFrameCount()
                    )
                }
            } finally {
                if (generation == analysisGeneration) {
                    _isFiltering.value = false
                    filterJob = null
                }
            }
        }
    }

    fun clearDisplayFilter() {
        updateDisplayFilter("")
        applyDisplayFilter()
    }

    fun cancelFiltering() {
        analysisGeneration++
        filterJob?.cancel()
        filterJob = null
        repository.cancelLongRunningOperations()
        _isFiltering.value = false
        _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Cancelled, message = text(R.string.job_cancelled))
    }

    fun updateSearchMode(mode: PacketSearchMode) {
        cancelSearchRequest()
        _searchState.value = _searchState.value.copy(
            mode = mode,
            results = emptyList(),
            selectedResultIndex = -1,
            hasSearched = false,
            error = null
        )
    }

    fun updateSearchQuery(query: String) {
        cancelSearchRequest()
        _searchState.value = _searchState.value.copy(
            query = query,
            results = emptyList(),
            selectedResultIndex = -1,
            hasSearched = false,
            error = null
        )
    }

    fun runSearch(onFirstResult: (Long) -> Unit = {}) {
        val state = _searchState.value
        val query = state.query.trim()
        cancelSearchRequest()
        if (query.isBlank()) {
            _searchState.value = state.copy(
                results = emptyList(),
                selectedResultIndex = -1,
                isSearching = false,
                hasSearched = true,
                error = text(R.string.error_enter_search_term)
            )
            return
        }
        if (state.mode == PacketSearchMode.Hex) {
            SearchQueryValidator.validateHex(query)?.let { validationError ->
                _searchState.value = state.copy(
                    results = emptyList(),
                    selectedResultIndex = -1,
                    isSearching = false,
                    hasSearched = true,
                    error = validationError
                )
                return
            }
        }
        val requestGeneration = searchRequestGeneration
        val generation = analysisGeneration
        beginAnalysisJob(AnalysisScope.CurrentFilter, text(R.string.job_searching_packets), repository.getVisibleFrameCount().toLong())
        searchJob = viewModelScope.launch {
            _searchState.value = state.copy(isSearching = true, error = null)
            try {
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        repository.searchPackets(state.mode, query)
                    }
                }
                if (
                    !isActive ||
                    generation != analysisGeneration ||
                    requestGeneration != searchRequestGeneration
                ) {
                    return@launch
                }
                result.fold(
                    onSuccess = { results ->
                        _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Completed, processed = results.size.toLong(), message = text(R.string.job_search_ready))
                        _searchState.value = state.copy(
                            query = query,
                            results = results,
                            selectedResultIndex = if (results.isNotEmpty()) 0 else -1,
                            isSearching = false,
                            hasSearched = true,
                            error = null
                        )
                        results.firstOrNull()?.let(onFirstResult)
                    },
                    onFailure = { throwable ->
                        _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Failed, errorCode = "SEARCH_FAILED", message = throwable.message)
                        _searchState.value = state.copy(
                            query = query,
                            results = emptyList(),
                            selectedResultIndex = -1,
                            isSearching = false,
                            hasSearched = true,
                            error = throwable.message ?: text(R.string.error_search_failed)
                        )
                    }
                )
            } finally {
                if (
                    generation == analysisGeneration &&
                    requestGeneration == searchRequestGeneration
                ) {
                    if (_searchState.value.isSearching) {
                        _searchState.value = _searchState.value.copy(isSearching = false)
                    }
                    searchJob = null
                }
            }
        }
    }

    private fun cancelSearchRequest() {
        searchRequestGeneration++
        searchJob?.cancel()
        searchJob = null
        repository.cancelSearch()
    }

    fun cancelSearch() {
        cancelSearchRequest()
        _searchState.value = _searchState.value.copy(isSearching = false)
        _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Cancelled, message = text(R.string.job_cancelled))
    }

    fun nextSearchResult(): Long? {
        val state = _searchState.value
        if (state.results.isEmpty()) return null
        val nextIndex = (state.selectedResultIndex + 1).floorMod(state.results.size)
        _searchState.value = state.copy(selectedResultIndex = nextIndex)
        return state.results.getOrNull(nextIndex)
    }

    fun previousSearchResult(): Long? {
        val state = _searchState.value
        if (state.results.isEmpty()) return null
        val previousIndex = (state.selectedResultIndex - 1).floorMod(state.results.size)
        _searchState.value = state.copy(selectedResultIndex = previousIndex)
        return state.results.getOrNull(previousIndex)
    }

    fun setNameResolutionEnabled(enabled: Boolean) {
        updatePreferences(_preferences.value.copy(nameResolutionEnabled = enabled))
    }

    fun setRtpHeuristicEnabled(enabled: Boolean) {
        updatePreferences(_preferences.value.copy(rtpHeuristicEnabled = enabled))
    }

    fun setEspDecryptionMode(mode: EspDecryptionMode) {
        updatePreferences(_preferences.value.copy(espDecryptionMode = mode))
    }

    fun clearEspDecryptionNotice() {
        _espDecryptionNotice.value = null
    }

    /**
     * Turns a native ESP-decryption result into the user-facing notice. Only a
     * rejection is worth saying out loud; a `Probe` that decoded nothing stays
     * silent, so a capture with no ESP says nothing at all.
     */
    private fun reportEspDecryptionOutcome(result: EspDecryptionResult) {
        _espDecryptionNotice.value = if (!result.isSuccess) result.error else null
    }

    fun updatePreferences(preferences: AnalyzerPreferences) {
        preferencesJob?.cancel()
        val requestGeneration = ++preferencesRequestGeneration
        val next = preferences.copy(defaultTreeExpansionDepth = preferences.defaultTreeExpansionDepth.coerceIn(0, 5))
        val previous = _preferences.value
        val nameResolutionChanged =
            previous.nameResolutionEnabled != next.nameResolutionEnabled
        val heuristicChanged = RtpHeuristicPreferenceOps.changed(previous, next)
        val espDecryptionChanged = EspDecryptionPreferenceOps.changed(previous, next)
        // The UI language is presentation only: it must not bump the analysis
        // config version and must not mark the analysis stale, or switching
        // language would throw away the very results the user is reading.
        val uiLanguageChanged = UiLanguagePreferenceOps.changed(previous.uiLanguage, next.uiLanguage)
        _preferences.value = next
        _nameResolutionEnabled.value = next.nameResolutionEnabled
        saveAnalyzerPreferences(next)
        repository.setTimeDisplayFormat(next.timeDisplayFormat)
        // Name resolution rewrites addresses in dissection output, so it is an
        // analysis fact and invalidates the Agent tool cache.  The other
        // preferences here are presentation only and deliberately do not.
        if (nameResolutionChanged) sessionCoordinator.bumpAnalysisConfigVersion()
        // The RTP heuristics decide which UDP flows the engine dissects as RTP,
        // so flipping them is an analysis fact as well (RTP1-KT-03).
        if (heuristicChanged) sessionCoordinator.bumpAnalysisConfigVersion()
        // ESP decryption reveals the payload under ESP, so it is the same kind
        // of analysis fact.
        if (espDecryptionChanged) sessionCoordinator.bumpAnalysisConfigVersion()
        if (uiLanguageChanged) _uiLanguageChangeVersion.value++
        // Changing only the UI language leaves every analysis fact untouched, so
        // it must not invalidate the results the user is currently reading.
        if (nameResolutionChanged || heuristicChanged || espDecryptionChanged) {
            markAnalysisStale()
        }
        preferencesJob = viewModelScope.launch {
            try {
                preferencesMutex.withLock {
                    if (!isActive || requestGeneration != preferencesRequestGeneration) {
                        return@withLock
                    }
                    withContext(Dispatchers.IO) {
                        repository.setNameResolutionEnabled(next.nameResolutionEnabled)
                    }
                }
                if (
                    !isActive ||
                    requestGeneration != preferencesRequestGeneration
                ) {
                    return@launch
                }
                if (espDecryptionChanged) {
                    val espResult = withContext(Dispatchers.IO) {
                        repository.setEspDecryptionMode(next.espDecryptionMode)
                    }
                    if (!espResult.isSuccess) {
                        // fail-closed：原生拒绝了就回滚，内存与持久化都要回到旧值
                        _preferences.value =
                            EspDecryptionPreferenceOps.resolve(previous, next, espResult.error)
                        saveAnalyzerPreferences(_preferences.value)
                        _espDecryptionNotice.value = espResult.error
                        return@launch
                    }
                    reportEspDecryptionOutcome(espResult)
                }
                if (heuristicChanged) {
                    val result = withContext(Dispatchers.IO) {
                        repository.setRtpHeuristicEnabled(next.rtpHeuristicEnabled)
                    }
                    if (!result.isSuccess) {
                        // fail-closed：原生拒绝了就回滚，内存与持久化都要回到旧值
                        _preferences.value = RtpHeuristicPreferenceOps.resolve(previous, next, result.error)
                        saveAnalyzerPreferences(_preferences.value)
                        _exportState.value = ExportUiState(error = result.error)
                        _rtpHeuristicApplyVersion.value += 1
                        return@launch
                    }
                    val filterToReapply = _displayFilterUiState.value.appliedExpression
                    sessionCoordinator.applyUserFilter(filterToReapply, sessionCoordinator.currentToken())
                    _rtpHeuristicApplyVersion.value += 1
                }
                pagerGeneration.value += 1
            } finally {
                if (requestGeneration == preferencesRequestGeneration) {
                    preferencesJob = null
                }
            }
        }
    }

    fun exportFilteredCaptureForShare() {
        viewModelScope.launch {
            beginAnalysisJob(currentScope(), text(R.string.job_exporting_capture), repository.getVisibleFrameCount().toLong())
            _exportState.value = ExportUiState(isExporting = true)
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val fileName = "filtered-${System.currentTimeMillis()}.pcap"
                    val file = createExportFile(fileName)
                    repository.exportFilteredCapture(file)
                    ExportResult(file.absolutePath, fileName, "application/vnd.tcpdump.pcap")
                }
            }
            _exportState.value = result.fold(
                onSuccess = { _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Completed, message = text(R.string.job_export_ready)); ExportUiState(message = text(R.string.export_filtered_complete), shareResult = it) },
                onFailure = { _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Failed, errorCode = "EXPORT_FAILED", message = it.message); ExportUiState(error = it.message ?: text(R.string.error_export_filtered_capture)) }
            )
        }
    }

    fun exportStatisticsCsv(table: String) {
        val statistics = _statisticsState.value.statistics ?: return
        viewModelScope.launch(Dispatchers.IO) {
            _exportState.value = ExportUiState(isExporting = true)
            val result = runCatching {
                val file = createExportFile("$table-${System.currentTimeMillis()}.csv")
                file.bufferedWriter().use { writer ->
                    if (table == "conversations") {
                        writer.appendLine("type,endpoint_a,port_a,endpoint_b,port_b,packets,bytes,start_time,duration,a_to_b,b_to_a")
                        statistics.conversations.forEach { row ->
                            writer.appendLine(listOf(row.type, row.endpointA, row.portA, row.endpointB, row.portB, row.packets, row.bytes, row.startTime, row.duration, row.aToBPackets, row.bToAPackets).joinToString(",") { csvCell(it) })
                        }
                    } else {
                        writer.appendLine("type,address,port,packets,bytes,sent_packets,received_packets")
                        statistics.endpoints.forEach { row ->
                            writer.appendLine(listOf(row.type, row.address, row.port, row.packets, row.bytes, row.sentPackets, row.receivedPackets).joinToString(",") { csvCell(it) })
                        }
                    }
                }
                ExportResult(file.absolutePath, file.name, "text/csv")
            }
            _exportState.value = result.fold(
                onSuccess = { ExportUiState(message = text(R.string.export_csv_complete), shareResult = it) },
                onFailure = { ExportUiState(error = it.message ?: text(R.string.error_export_csv)) }
            )
        }
    }

    fun exportDiagnosticReportForShare() {
        exportEvidencePackageForShare(EvidenceExportMode.MetadataOnly)
    }

    fun exportEvidencePackageForShare(
        mode: EvidenceExportMode,
        scope: EvidenceExportScope = EvidenceExportScope.CurrentView
    ) {
        exportEvidencePackageForShare(mode, scope, agentExport = null)
    }

    /** Export a reviewed Agent report only when it still belongs to this capture. */
    fun exportAgentReportForShare(
        report: AgentReport,
        runRecord: AgentRunRecord?,
        mode: EvidenceExportMode = EvidenceExportMode.Redacted
    ) {
        val error = validateAgentReport(report)
        if (error != null) {
            _exportState.value = ExportUiState(error = error.userMessage)
            return
        }
        exportEvidencePackageForShare(
            mode = mode,
            scope = EvidenceExportScope.CurrentView,
            agentExport = AgentReportExporter().export(report, runRecord, mode)
        )
    }

    private fun exportEvidencePackageForShare(
        mode: EvidenceExportMode,
        scope: EvidenceExportScope,
        agentExport: AgentReportExport?
    ) {
        val info = _currentFile.value ?: return
        val plan = EvidenceExportPlanner.planFor(mode, scope)
        viewModelScope.launch {
            beginAnalysisJob(currentScope(), text(R.string.job_building_evidence), repository.getVisibleFrameCount().toLong())
            _exportState.value = ExportUiState(isExporting = true)
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val workspace = _workspace.value
                    // Fail closed before any work: the evidence-frame scope
                    // re-checks the compile decision even though the dialog
                    // already greys it out. The UI is not a trust boundary, so a
                    // stale selection must be refused here — never silently
                    // downgraded to the current view.
                    val evidenceCompile: EvidenceFrameFilter.CompileResult.Compiled? =
                        if (plan.applyEvidenceTemporaryFilter) {
                            val compiled = EvidenceFrameFilter.compileOrNull(
                                workspace?.evidenceFrames.orEmpty()
                            )
                            val availability = EvidenceExportScopePolicy.evaluate(
                                EvidenceExportScope.EvidenceFrames,
                                compiled
                            )
                            if (!availability.available) {
                                throw IllegalStateException(
                                    evidenceScopeUnavailableText(availability)
                                )
                            }
                            // `available` is true exactly for Compiled, guaranteed
                            // by EvidenceExportScopePolicy.
                            compiled as EvidenceFrameFilter.CompileResult.Compiled
                        } else {
                            null
                        }
                    // Export reads the live native session.  The UI summaries are
                    // lazy and may still be empty when the user exports right
                    // after opening a capture, which previously produced 0/N.
                    val statistics = repository.buildCaptureStatistics()
                    val expert = repository.getExpertInfoSummary()
                    val diagnosticJson = agentDiagnostics?.exportRedacted()
                    val fingerprint = workspace?.fileFingerprint
                        ?: workspaceStore.fingerprint(File(info.localPath))
                    val redactor = if (mode == EvidenceExportMode.Original) null else MetadataRedactor(fingerprint)
                    val generatedAt = System.currentTimeMillis()
                    val report = JSONObject()
                        .put("schemaVersion", 1)
                        .put("exportMode", mode.name)
                        .put("generatedBy", "LayerAnalyzer ${appVersion()}")
                        .put("generatedAtMillis", generatedAt)
                        .put("inputSha256", fingerprint)
                        .put("displayName", info.displayName)
                        .put("fileType", info.fileType)
                        .put("inputBytes", info.sizeBytes)
                        .put("frameCount", info.frameCount)
                        .put("scope", currentScope().name)
                        .put("displayFilter", when (mode) {
                            EvidenceExportMode.Original -> _displayFilterUiState.value.appliedExpression
                            EvidenceExportMode.Redacted -> redactor?.redact(_displayFilterUiState.value.appliedExpression).orEmpty()
                            EvidenceExportMode.MetadataOnly -> JSONObject.NULL
                        })
                        .put("analyzedPackets", statistics.packetCount)
                        .put("analyzedBytes", statistics.byteCount)
                        .put("capturedBytes", statistics.capturedByteCount)
                        .put("truncatedPacketCount", statistics.truncatedPacketCount)
                        .put("originalLengthBytes", statistics.byteCount)
                        .put("capturedLengthBytes", statistics.capturedByteCount)
                        .put("captureFormat", info.fileType)
                        .put("encapsulation", info.encapsulation)
                        .put("startTime", statistics.startTime)
                        .put("endTime", statistics.endTime)
                        .put("expertErrors", expert.errorPackets)
                        .put("expertWarnings", expert.warningPackets)
                        .put("expertReturned", expert.items.size)
                        .put("expertTotal", expert.totalItems)
                        .put("expertTruncated", expert.truncated)
                        .put("healthMetrics", JSONObject()
                            .put("dns", JSONObject().put("queries", statistics.dnsQueries).put("responses", statistics.dnsResponses).put("failures", statistics.dnsFailureTotal).put("averageResponseMs", statistics.dnsAverageResponseMs))
                            .put("tcp", JSONObject().put("syn", statistics.tcpSyn).put("synAck", statistics.tcpSynAck).put("retransmissions", statistics.tcpRetransmissions).put("duplicateAcks", statistics.tcpDuplicateAcks).put("resets", statistics.tcpResets).put("zeroWindows", statistics.tcpZeroWindows).put("averageRttMs", statistics.tcpAverageRttMs))
                            .put("tls", JSONObject().put("alerts", statistics.tlsAlertTotal).put("versions", JSONObject(statistics.tlsVersions)).put("sniCount", statistics.tlsSni.size))
                            .put("http", JSONObject().put("errors", statistics.httpErrorTotal).put("statusCodes", JSONObject(statistics.httpStatusCodes)).put("hostCount", statistics.httpHosts.size)))
                        .put("evidenceFrames", JSONArray(workspace?.evidenceFrames?.sorted().orEmpty()))
                        .put("notes", when (mode) {
                            EvidenceExportMode.MetadataOnly -> JSONArray().apply {
                                workspace?.notes.orEmpty().forEach { note -> put(JSONObject().put("frameNumber", note.frameNumber)) }
                            }
                            else -> JSONArray().apply {
                                workspace?.notes.orEmpty().forEach { note ->
                                    put(JSONObject().put("frameNumber", note.frameNumber).put("text", redactor?.redact(note.text) ?: note.text).put("updatedAtMillis", note.updatedAtMillis))
                                }
                            }
                        })
                        .put("payloadIncluded", mode == EvidenceExportMode.Original)
                        .put("redactionMappingPersisted", false)
                    // Provenance for the evidence loop (EVL-EXPORT-03): which
                    // scope was requested, the filter that actually applied, the
                    // de-duplicated evidence count, per-frame origin, and whether
                    // the attached capture is the evidence set only. Built by a
                    // pure, JVM-testable helper — this call is only wiring.
                    EvidenceExportManifestFields.applyTo(
                        manifest = report,
                        scope = scope,
                        plan = plan,
                        evidenceFilter = evidenceCompile?.filter,
                        items = workspace?.evidenceItems.orEmpty(),
                        notes = workspace?.notes.orEmpty(),
                        mode = mode,
                        redactor = redactor
                    )
                    val frames = JSONArray()
                    // One element per evidence frame, ascending by frame number,
                    // each carrying the same provenance object the manifest uses
                    // (EVL-EXPORT-04): its origin, finding id and — unless the
                    // mode forbids note text — its note. Frames stay
                    // de-duplicated by frame number, and a frame whose protocol
                    // tree cannot be read is still skipped, as it always was.
                    val notesByFrame = workspace?.notes.orEmpty()
                        .associateBy { note -> note.frameNumber }
                    workspace?.evidenceItems.orEmpty()
                        .sortedBy { item -> item.frameNumber }
                        .distinctBy { item -> item.frameNumber }
                        .forEach { item ->
                            repository.getPacketDetails(item.frameNumber)?.let { root ->
                                val node = protocolNodeJson(item.frameNumber, root, mode, redactor)
                                node.put(
                                    "provenance",
                                    EvidenceExportManifestFields.provenanceObject(
                                        item = item,
                                        note = notesByFrame[item.frameNumber],
                                        mode = mode,
                                        redactor = redactor
                                    )
                                )
                                frames.put(node)
                            }
                        }
                    val baseName = "evidence-${System.currentTimeMillis()}"
                    val markdown = buildString {
                        appendLine("# LayerAnalyzer 快速诊断报告")
                        appendLine()
                        appendLine("- 导出模式：${mode.name}")
                        appendLine("- 版本：${appVersion()}")
                        appendLine("- 输入 SHA-256：`$fingerprint`")
                        appendLine("- 文件：${info.displayName} (${info.fileType}, ${info.sizeBytes} bytes)")
                        val appliedFilter = _displayFilterUiState.value.appliedExpression
                        appendLine("- 作用域：${currentScope().name}${if (appliedFilter.isBlank() || mode == EvidenceExportMode.MetadataOnly) "" else " (`${redactor?.redact(appliedFilter) ?: appliedFilter}`)"}")
                        appendLine("- 帧：${statistics.packetCount}/${info.frameCount}")
                        appendLine("- 长度：orig ${statistics.byteCount} bytes / cap ${statistics.capturedByteCount} bytes；截断帧 ${statistics.truncatedPacketCount}")
                        appendLine("- 捕获格式：${info.fileType}；链路封装：${info.encapsulation}")
                        appendLine("- Expert：${expert.errorPackets} errors, ${expert.warningPackets} warnings (${expert.items.size}/${expert.totalItems}${if (expert.truncated) ", truncated" else ""})")
                        appendLine()
                        appendLine("## 证据帧")
                        appendLine(
                            EvidenceExportReportSections.evidenceFramesTable(
                                items = workspace?.evidenceItems.orEmpty(),
                                notes = workspace?.notes.orEmpty(),
                                findings = workspace?.agentFindings.orEmpty(),
                                mode = mode,
                                redactor = redactor
                            )
                        )
                        appendLine()
                        appendLine("## 备注")
                        workspace?.notes.orEmpty().forEach { note ->
                            appendLine(if (mode == EvidenceExportMode.MetadataOnly) "- Frame ${note.frameNumber}" else "- Frame ${note.frameNumber}: ${redactor?.redact(note.text) ?: note.text}")
                        }
                    }
                    var capture: File? = null
                    if (evidenceCompile != null) {
                        // The evidence frames are selected by the compiler, so
                        // the pcap must be produced while that filter is applied.
                        // It goes through the one lease protocol, which restores
                        // the user's view afterwards — no second restore path.
                        // The frame count is re-checked under the lease: a
                        // mismatch means the capture is not the evidence set and
                        // must not be exported.
                        val lease = sessionCoordinator.withTemporaryFilter(evidenceCompile.filter) {
                            if (plan.attachCapture) {
                                val file = createExportFile("$baseName.pcap")
                                capture = file
                                repository.exportFilteredCapture(file)
                            }
                            EvidenceFrameCountGuard.verify(
                                expected = evidenceCompile.frameCount,
                                actual = repository.getVisibleFrameCount()
                            )
                        }
                        when (lease) {
                            is AgentAnalysisResult.Success -> {
                                val verification = lease.value
                                if (verification is EvidenceFrameCountVerification.Mismatch) {
                                    capture?.delete()
                                    throw IllegalStateException(
                                        text(
                                            R.string.evidence_scope_frames_count_mismatch,
                                            verification.expected,
                                            verification.actual
                                        )
                                    )
                                }
                            }

                            is AgentAnalysisResult.Failure -> {
                                // The evidence filter never took hold, or the
                                // user's view could not be restored. Fail closed:
                                // no capture is exported.
                                capture?.delete()
                                throw IllegalStateException(lease.error.userMessage)
                            }
                        }
                    } else if (plan.attachCapture) {
                        capture = createExportFile("$baseName.pcap").also { repository.exportFilteredCapture(it) }
                    }
                    val packageFile = createExportFile("$baseName.zip")
                    val additionalEntries = buildMap {
                        putAll(agentExport?.entries.orEmpty())
                        diagnosticJson?.takeIf { it.isNotBlank() }?.let {
                            put("agent-diagnostics.json", it)
                        }
                    }
                    EvidencePackageWriter().write(
                        output = packageFile,
                        manifestJson = report.toString(2),
                        reportMarkdown = markdown,
                        framesJson = frames.toString(2),
                        captureFile = capture,
                        additionalEntries = additionalEntries
                    )
                    capture?.delete()
                    ExportResult(packageFile.absolutePath, packageFile.name, "application/zip")
                }
            }
            _exportState.value = result.fold(
                onSuccess = { generated ->
                    _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Completed, message = text(R.string.job_evidence_ready))
                    val destination = pendingEvidenceDestination.also { pendingEvidenceDestination = null }
                    if (destination == null) {
                        ExportUiState(message = text(R.string.evidence_package_complete, mode.name), shareResult = generated)
                    } else {
                        runCatching {
                            withContext(Dispatchers.IO) {
                                appContext.contentResolver.openOutputStream(destination, "w")?.use { output ->
                                    File(generated.filePath).inputStream().use { input -> input.copyTo(output) }
                                } ?: throw IllegalStateException(text(R.string.error_write_destination))
                            }
                        }.fold(
                            onSuccess = { ExportUiState(message = "证据包已保存到所选位置。") },
                            onFailure = { ExportUiState(error = it.message ?: text(R.string.error_save_evidence)) }
                        )
                    }
                },
                onFailure = { _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Failed, errorCode = "EVIDENCE_EXPORT_FAILED", message = it.message); ExportUiState(error = it.message ?: text(R.string.error_generate_evidence)) }
            )
        }
    }

    /**
     * Execution-side fail-closed message for an evidence-frame scope the policy
     * refused. Mirrors the dialog's localisation in PacketListScreen, but returns
     * a plain string because the ViewModel is not a Composable. Called only when
     * [EvidenceExportScopePolicy.ScopeAvailability.available] is `false`, so the
     * `null` reason code is structurally unreachable.
     */
    private fun evidenceScopeUnavailableText(
        availability: EvidenceExportScopePolicy.ScopeAvailability
    ): String = when (availability.reasonCode) {
        EvidenceExportScopePolicy.ReasonCode.NoEvidenceFrames ->
            text(R.string.evidence_scope_frames_empty)

        EvidenceExportScopePolicy.ReasonCode.FilterRejected -> {
            val actual = availability.actual
            val limit = availability.limit
            if (actual != null && limit != null) {
                text(R.string.evidence_scope_frames_rejected_limit, actual, limit)
            } else {
                text(R.string.evidence_scope_frames_rejected_invalid)
            }
        }

        null -> text(R.string.evidence_scope_frames_rejected_invalid)
    }

    fun saveEvidencePackage(
        uri: Uri,
        mode: EvidenceExportMode,
        scope: EvidenceExportScope = EvidenceExportScope.CurrentView
    ) {
        pendingEvidenceDestination = uri
        exportEvidencePackageForShare(mode, scope)
    }

    private fun protocolNodeJson(
        frameNumber: Long,
        node: com.example.layanalyzer.model.ProtocolNode,
        mode: EvidenceExportMode,
        redactor: MetadataRedactor?
    ): JSONObject {
        val metadataOnly = mode == EvidenceExportMode.MetadataOnly
        val label = if (metadataOnly) node.filter ?: node.label.substringBefore(':') else redactor?.redact(node.label) ?: node.label
        val value = if (metadataOnly) JSONObject.NULL else node.value?.let { redactor?.redact(it) ?: it } ?: JSONObject.NULL
        return JSONObject()
            .put("frameNumber", frameNumber)
            .put("label", label)
            .put("value", value)
            .put("filter", node.filter ?: JSONObject.NULL)
            .put("start", node.start)
            .put("length", node.length)
            .put("severity", node.severity)
            .put("children", JSONArray().apply {
                node.children.forEach { child -> put(protocolNodeJson(frameNumber, child, mode, redactor)) }
            })
    }

    fun toggleWorkspaceBookmark(frameNumber: Long) {
        val current = _workspace.value ?: return
        val next = current.bookmarks.toMutableSet().apply { if (!add(frameNumber)) remove(frameNumber) }
        updateWorkspace(current.copy(bookmarks = next))
    }

    fun saveFilteredCapture(uri: Uri) {
        val info = _currentFile.value ?: return
        viewModelScope.launch {
            _exportState.value = ExportUiState(isExporting = true)
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val temporary = createExportFile(".${UUID.randomUUID()}.pcap")
                    try {
                        repository.exportFilteredCapture(temporary)
                        appContext.contentResolver.openOutputStream(uri, "w")?.use { output ->
                            temporary.inputStream().use { input -> input.copyTo(output) }
                        } ?: throw IllegalStateException(text(R.string.error_write_destination))
                    } finally {
                        temporary.delete()
                    }
                }
                ExportUiState(message = text(R.string.export_saved_location, info.displayName))
            }
            _exportState.value = result.getOrElse {
                ExportUiState(error = it.message ?: text(R.string.error_save_filtered_capture))
            }
        }
    }

    fun clearExportState() {
        _exportState.value = ExportUiState()
    }

    fun startLiveCapture(settings: LiveCaptureSettings) {
        val intent = Intent(appContext, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, settings.excludeSelf)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, settings.captureIpv6)
            putExtra(LiveCaptureVpnService.EXTRA_MAX_DURATION_MINUTES, settings.maxDurationMinutes)
            putExtra(LiveCaptureVpnService.EXTRA_MAX_SIZE_MEGABYTES, settings.maxSizeMegabytes)
            putExtra(LiveCaptureVpnService.EXTRA_SEGMENT_SIZE_MEGABYTES, settings.segmentSizeMegabytes)
            putStringArrayListExtra(
                LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS,
                ArrayList(settings.allowedApplications)
            )
        }
        ContextCompat.startForegroundService(appContext, intent)
    }

    fun stopLiveCapture() {
        val intent = Intent(appContext, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP)
        appContext.startService(intent)
    }

    fun openSavedLiveCapture() {
        val path = LiveCaptureStore.state.value.outputPath ?: return
        val file = File(path)
        if (!file.exists()) {
            _openError.value = text(R.string.error_saved_capture_missing)
            return
        }
        openJob?.cancel()
        prepareForFileSwitch()
        openJob = viewModelScope.launch {
            _openError.value = null
                _openProgress.value = OpenProgress(text(R.string.progress_opening_file, file.name))
            try {
                openPreparedFile(
                    PreparedCapture(
                        file = file,
                        displayName = file.name,
                        sizeBytes = file.length()
                    )
                )
            } catch (e: CancellationException) {
                _openProgress.value = null
            } catch (e: Exception) {
                _openProgress.value = null
                _openError.value = e.message ?: text(R.string.error_open_live_capture)
            }
        }
    }

    fun clearLiveCaptureError() {
        LiveCaptureStore.clearError()
    }

    fun preparePacketContextActions(frameNumber: Long) {
        packetContextJob?.cancel()
        _packetContextActions.value = PacketContextActionsState(
            frameNumber = frameNumber,
            isLoading = true
        )
        packetContextJob = viewModelScope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) { repository.getPacketFollowFilters(frameNumber) }
            }
            if (result.exceptionOrNull() is CancellationException) return@launch
            if (_packetContextActions.value.frameNumber != frameNumber) return@launch
            _packetContextActions.value = result.fold(
                onSuccess = { PacketContextActionsState(frameNumber = frameNumber, followFilters = it) },
                onFailure = {
                    PacketContextActionsState(
                        frameNumber = frameNumber,
                        error = it.message ?: text(R.string.error_inspect_packet)
                    )
                }
            )
        }
    }

    fun togglePacketHighlight(frameNumber: Long) {
        _highlightedFrames.value = _highlightedFrames.value.toMutableSet().apply {
            if (!add(frameNumber)) remove(frameNumber)
        }
    }

    fun loadHttpObjects() {
        if (_currentFile.value == null || _httpObjectsState.value.isLoading) return
        httpObjectsJob?.cancel()
        val generation = analysisGeneration
        httpObjectsJob = viewModelScope.launch {
            _httpObjectsState.value = _httpObjectsState.value.copy(isLoading = true, error = null)
            val result = runCatching {
                withContext(Dispatchers.IO) { repository.getHttpObjects() }
            }
            if (result.exceptionOrNull() is CancellationException) return@launch
            if (generation != analysisGeneration) return@launch
            _httpObjectsState.value = result.fold(
                onSuccess = { HttpObjectsState(analyzed = true, objects = it) },
                onFailure = {
                    HttpObjectsState(error = it.message ?: text(R.string.error_find_http_objects))
                }
            )
        }
    }

    fun exportHttpObjectForShare(entry: HttpObjectEntry) {
        viewModelScope.launch {
            _exportState.value = ExportUiState(isExporting = true)
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val payload = repository.getHttpObjectPayload(entry.id)
                    check(payload.isNotEmpty() || entry.size == 0L) {
                        text(R.string.error_http_object_payload)
                    }
                    val displayName = sanitizeFileName(entry.filename)
                    val file = createExportFile("${System.currentTimeMillis()}-$displayName")
                    file.outputStream().use { it.write(payload) }
                    ExportResult(file.absolutePath, displayName, entry.contentType)
                }
            }
            _exportState.value = result.fold(
                onSuccess = { ExportUiState(message = text(R.string.http_object_exported), shareResult = it) },
                onFailure = { ExportUiState(error = it.message ?: text(R.string.error_export_http_object)) }
            )
        }
    }

    fun exportAllHttpObjectsForShare() {
        val objects = _httpObjectsState.value.objects
        if (objects.isEmpty()) return
        viewModelScope.launch {
            _exportState.value = ExportUiState(isExporting = true)
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val displayName = "http-objects-${System.currentTimeMillis()}.zip"
                    val file = createExportFile(displayName)
                    val usedNames = mutableSetOf<String>()
                    ZipOutputStream(file.outputStream()).use { zip ->
                        objects.forEach { entry ->
                            val payload = repository.getHttpObjectPayload(entry.id)
                            check(payload.isNotEmpty() || entry.size == 0L) {
                                text(R.string.error_http_object_payload)
                            }
                            val baseName = sanitizeFileName(entry.filename)
                            var name = baseName
                            var suffix = 2
                            while (!usedNames.add(name)) {
                                val extension = baseName.substringAfterLast('.', "")
                                val stem = baseName.substringBeforeLast('.', baseName)
                                name = if (extension.isBlank()) "$stem-$suffix" else "$stem-$suffix.$extension"
                                suffix++
                            }
                            zip.putNextEntry(ZipEntry(name))
                            zip.write(payload)
                            zip.closeEntry()
                        }
                    }
                    ExportResult(file.absolutePath, displayName, "application/zip")
                }
            }
            _exportState.value = result.fold(
                onSuccess = { ExportUiState(message = text(R.string.http_objects_exported), shareResult = it) },
                onFailure = { ExportUiState(error = it.message ?: text(R.string.error_export_http_objects)) }
            )
        }
    }

    fun addDecodeAsRule(
        scope: DecodeAsScope,
        transport: DecodeAsTransport,
        source: String,
        destination: String,
        sourcePort: Int?,
        destinationPort: Int?,
        protocol: String
    ) {
        val rule = DecodeAsRule(
            id = UUID.randomUUID().toString(),
            scope = scope,
            transport = transport,
            source = source.trim(),
            destination = destination.trim(),
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            protocol = protocol.trim()
        )
        val conflicts = _decodeAsRules.value.any { existing ->
            existing.transport == rule.transport && existing.ports.any(rule.ports::contains)
        }
        if (conflicts) {
            _exportState.value = ExportUiState(
                error = text(R.string.error_decode_as_conflict)
            )
            return
        }
        val expectedSessionHandle = repository.currentSessionHandle()
        val expectedSession = sessionCoordinator.currentToken()
        val targetSessionGeneration = sessionGeneration
        viewModelScope.launch {
            markAnalysisStale()
            val result = withContext(Dispatchers.IO) {
                repository.applyDecodeAsRule(rule, expectedSessionHandle)
            }
            if (!isActive || targetSessionGeneration != sessionGeneration) return@launch
            if (result.success) {
                // A Decode As rule changes what the engine reports for the same
                // frames, so every Agent tool result cached for this capture is
                // now describing the previous dissection.
                sessionCoordinator.bumpAnalysisConfigVersion()
                val filterToReapply = _displayFilterUiState.value.appliedExpression
                val refreshedFilter = withContext(Dispatchers.IO) {
                    sessionCoordinator.applyUserFilter(filterToReapply, expectedSession)
                }
                if (!isActive || targetSessionGeneration != sessionGeneration) return@launch
                _decodeAsRules.value = _decodeAsRules.value + rule
                if (refreshedFilter.success) {
                    _filterResult.value = refreshedFilter
                }
                pagerGeneration.value += 1
            } else {
                _exportState.value = ExportUiState(error = result.error ?: text(R.string.error_apply_decode_as))
            }
        }
    }

    fun removeDecodeAsRule(rule: DecodeAsRule) {
        val expectedSessionHandle = repository.currentSessionHandle()
        val expectedSession = sessionCoordinator.currentToken()
        val targetSessionGeneration = sessionGeneration
        viewModelScope.launch {
            markAnalysisStale()
            withContext(Dispatchers.IO) {
                repository.resetDecodeAsRule(rule, expectedSessionHandle)
            }
            if (!isActive || targetSessionGeneration != sessionGeneration) return@launch
            sessionCoordinator.bumpAnalysisConfigVersion()
            val filterToReapply = _displayFilterUiState.value.appliedExpression
            val refreshedFilter = withContext(Dispatchers.IO) {
                sessionCoordinator.applyUserFilter(filterToReapply, expectedSession)
            }
            if (!isActive || targetSessionGeneration != sessionGeneration) return@launch
            _decodeAsRules.value = _decodeAsRules.value.filterNot { it.id == rule.id }
            if (refreshedFilter.success) {
                _filterResult.value = refreshedFilter
            }
            pagerGeneration.value += 1
        }
    }

    fun refreshExpertSummary() {
        if (_currentFile.value == null) {
            _expertSummary.value = ExpertInfoSummary()
            return
        }
        expertJob?.cancel()
        val generation = analysisGeneration
        beginAnalysisJob(currentScope(), text(R.string.job_analyzing_expert), repository.getVisibleFrameCount().toLong())
        _expertSummary.value = _expertSummary.value.copy(isLoading = true, error = null)
        expertJob = viewModelScope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    repository.getExpertInfoSummary()
                }
            }
            if (result.exceptionOrNull() is CancellationException) return@launch
            if (generation != analysisGeneration) return@launch
            _expertSummary.value = result.fold(
                onSuccess = {
                    val next = it.copy(isLoading = false, analyzed = true, error = null)
                    _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Completed, processed = next.totalItems.toLong(), message = text(R.string.job_expert_ready))
                    _statisticsState.value.statistics?.let { statistics ->
                        val file = _currentFile.value
                        if (file != null) _healthSummary.value = CaptureHealthAnalyzer.summarize(file, statistics, next, currentScope(), healthCardLabels())
                    }
                    next
                },
                onFailure = {
                    _healthSummary.value = _healthSummary.value.copy(
                        isLoading = false,
                        error = it.message ?: text(R.string.error_build_expert)
                    )
                    _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Failed, errorCode = "EXPERT_FAILED", message = it.message)
                    _expertSummary.value.copy(
                        isLoading = false,
                        analyzed = false,
                        error = it.message ?: text(R.string.error_build_expert)
                    )
                }
            )
        }
    }

    fun cancelExpertSummary() {
        analysisGeneration++
        expertJob?.cancel()
        expertJob = null
        repository.cancelLongRunningOperations()
        _expertSummary.value = _expertSummary.value.copy(isLoading = false)
        _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Cancelled, message = text(R.string.job_cancelled))
    }

    fun refreshStatistics() {
        if (_currentFile.value == null) {
            _statisticsState.value = StatisticsUiState(bucketSeconds = _statisticsState.value.bucketSeconds)
            return
        }
        val bucketSeconds = _statisticsState.value.bucketSeconds
        statisticsJob?.cancel()
        val generation = analysisGeneration
        beginAnalysisJob(currentScope(), text(R.string.job_building_statistics), repository.getVisibleFrameCount().toLong())
        _statisticsState.value = _statisticsState.value.copy(
            isLoading = true,
            error = null,
            job = AnalysisJobState(phase = AnalysisJobPhase.Running, total = repository.getVisibleFrameCount().toLong(), scope = currentScope(), message = text(R.string.job_building_statistics))
        )
        statisticsJob = viewModelScope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    repository.buildCaptureStatistics(bucketSeconds)
                }
            }
            if (result.exceptionOrNull() is CancellationException) return@launch
            if (generation != analysisGeneration) return@launch
            _statisticsState.value = result.fold(
                onSuccess = {
                    val next = StatisticsUiState(statistics = it, bucketSeconds = bucketSeconds)
                    if (generation == analysisGeneration) refreshHealthSummary(it)
                    _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Completed, processed = it.packetCount.toLong(), message = text(R.string.job_statistics_ready))
                    next.copy(job = _statisticsState.value.job.copy(phase = AnalysisJobPhase.Completed, processed = it.packetCount.toLong(), message = text(R.string.job_statistics_ready)))
                },
                onFailure = {
                    _healthSummary.value = _healthSummary.value.copy(
                        isLoading = false,
                        error = it.message ?: text(R.string.error_build_statistics)
                    )
                    _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Failed, errorCode = "STATISTICS_FAILED", message = it.message)
                    StatisticsUiState(error = it.message ?: text(R.string.error_build_statistics), bucketSeconds = bucketSeconds, job = AnalysisJobState(phase = AnalysisJobPhase.Failed, scope = currentScope(), errorCode = "STATISTICS_FAILED", message = it.message))
                }
            )
        }
    }

    private fun refreshHealthSummary(statistics: com.example.layanalyzer.model.CaptureStatistics) {
        val file = _currentFile.value ?: return
        val expert = _expertSummary.value.takeIf { it.analyzed } ?: ExpertInfoSummary()
        _healthSummary.value = CaptureHealthAnalyzer.summarize(
            file, statistics, expert, currentScope(), healthCardLabels()
        )
    }

    /**
     * 体检卡片的界面文案，跟随当前界面语言。
     *
     * 与喂给模型的 [CaptureHealthAnalyzer.DEFAULT_LABELS] 分开：那份必须保持
     * 英文（模型输入），这份必须跟随用户所选语言，两者混用会让其中一边泄漏。
     */
    private fun healthCardLabels(): CaptureHealthAnalyzer.Labels = CaptureHealthAnalyzer.Labels(
        fileHealth = text(R.string.health_card_file),
        noDnsEvents = text(R.string.health_card_no_dns),
        noTlsEvents = text(R.string.health_card_no_tls),
        noHttpEvents = text(R.string.health_card_no_http),
        noExpertInfo = text(R.string.health_card_no_expert),
        tapToViewFrames = text(R.string.health_card_tap_frames)
    )

    private fun currentScope(): AnalysisScope = if (_displayFilterUiState.value.appliedExpression.isBlank()) AnalysisScope.CompleteFile else AnalysisScope.CurrentFilter

    private fun validateAgentReport(report: AgentReport): AgentError? {
        val currentFingerprint = sessionCoordinator.state.value.fileFingerprint
        if (currentFingerprint.isBlank() ||
            report.provenance.captureFingerprint.isBlank() ||
            report.provenance.captureFingerprint != currentFingerprint
        ) {
            return sessionChangedAgentError()
        }
        return null
    }

    private fun sessionChangedAgentError() = AgentError(
        code = AgentErrorCode.SESSION_CHANGED,
        userMessage = "The capture changed, so this Agent evidence is no longer available.",
        retryable = true
    )

    fun refreshDashboard() {
        if (_currentFile.value == null) return
        val needsStatistics = !_statisticsState.value.isLoading && _statisticsState.value.statistics == null
        val needsExpert = !_expertSummary.value.isLoading && !_expertSummary.value.analyzed
        if (!needsStatistics && !needsExpert) return
        _healthSummary.value = _healthSummary.value.copy(isLoading = true, error = null)
        if (needsStatistics) refreshStatistics()
        if (needsExpert) refreshExpertSummary()
    }

    fun applyScenarioStep(stepFilter: String) {
        addFilterHistory(stepFilter)
        applyDisplayFilter(stepFilter)
    }

    fun saveWorkspaceNote(frameNumber: Long, text: String) {
        val current = _workspace.value ?: return
        val notes = current.notes.filterNot { it.frameNumber == frameNumber } + WorkspaceNote(frameNumber, text.trim(), System.currentTimeMillis())
        updateWorkspace(current.copy(notes = notes.filter { it.text.isNotBlank() }.takeLast(100)))
    }

    fun toggleEvidence(frameNumber: Long) {
        val current = _workspace.value ?: return
        val next = WorkspaceEvidenceOps.toggle(
            items = current.evidenceItems,
            frameNumber = frameNumber,
            nowMillis = System.currentTimeMillis()
        )
        updateWorkspace(current.copy(evidenceItems = next))
    }

    /**
     * Drop a frame from the evidence set. The frame's note (if any) is left
     * untouched — notes are independent of evidence membership, so removing
     * evidence never silently discards a note.
     */
    fun removeEvidence(frameNumber: Long) {
        val current = _workspace.value ?: return
        updateWorkspace(
            current.copy(
                evidenceItems = WorkspaceEvidenceOps.remove(current.evidenceItems, frameNumber)
            )
        )
    }

    /**
     * Batch-remove the given evidence frames. Routes through [updateWorkspace] so
     * the workspace and its persisted copy stay consistent. An empty collection is
     * a deliberate no-op: it returns before touching the workspace, so it never
     * triggers a redundant persistence write. Notes, bookmarks, findings, and
     * filter history are left untouched — only [AnalysisWorkspace.evidenceItems]
     * changes.
     */
    fun removeEvidenceFrames(frameNumbers: Collection<Long>) {
        if (frameNumbers.isEmpty()) return
        val current = _workspace.value ?: return
        updateWorkspace(
            current.copy(
                evidenceItems = WorkspaceEvidenceOps.removeAll(current.evidenceItems, frameNumbers)
            )
        )
    }

    /**
     * Clear every evidence frame in the workspace (all groups, all selections).
     * Routes through [updateWorkspace] for persistence. When the evidence set is
     * already empty this is a no-op that does not write. Notes, bookmarks,
     * findings, and filter history are intentionally left untouched.
     */
    fun clearEvidence() {
        val current = _workspace.value ?: return
        if (current.evidenceItems.isEmpty()) return
        updateWorkspace(current.copy(evidenceItems = emptyList()))
    }

    /**
     * Re-check a model citation against the active capture before navigation or
     * workspace writes. A source call id must come from this validated report.
     */
    fun validateAgentEvidence(evidence: AgentEvidence, report: AgentReport): AgentError? {
        validateAgentReport(report)?.let { return it }
        if (evidence.sourceToolCallId.isBlank() || evidence.sourceToolCallId !in report.provenance.toolCallIds) {
            return AgentError(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "This evidence is not linked to a completed analysis step."
            )
        }
        evidence.frameNumber?.let { frame ->
            val frameCount = _currentFile.value?.frameCount ?: 0
            if (frame !in 1L..frameCount.toLong()) {
                return AgentError(
                    code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                    userMessage = "This evidence frame is outside the current capture."
                )
            }
        }
        return null
    }

    /** Add a confirmed Agent frame without the toggle behavior used by manual evidence. */
    fun addAgentEvidence(evidence: AgentEvidence, report: AgentReport): Boolean {
        if (validateAgentEvidence(evidence, report) != null) return false
        val frame = evidence.frameNumber ?: return false
        val current = _workspace.value ?: return false
        if (current.evidenceItems.none { it.frameNumber == frame }) {
            updateWorkspace(
                current.copy(
                    evidenceItems = WorkspaceEvidenceOps.add(
                        items = current.evidenceItems,
                        frameNumber = frame,
                        source = EvidenceSource.Manual,
                        sourceFindingId = null,
                        nowMillis = System.currentTimeMillis()
                    )
                )
            )
        }
        return true
    }

    /** Save an explicitly selected Finding and its verified frame evidence. */
    fun saveAgentFinding(finding: AgentFinding, report: AgentReport): Boolean {
        if (validateAgentReport(report) != null || finding.evidence.isEmpty()) return false
        if (finding.evidence.any { validateAgentEvidence(it, report) != null }) return false
        val current = _workspace.value ?: return false
        val sourceId = finding.id.ifBlank { finding.evidence.first().sourceToolCallId }
        val evidenceFrames = finding.evidence.mapNotNull { it.frameNumber }.toSet()
        val saved = AgentSavedFinding(
            findingId = finding.id,
            title = finding.title,
            summary = finding.conclusion,
            sourceId = sourceId,
            sourceToolCallIds = finding.evidence.map { it.sourceToolCallId }.distinct(),
            evidenceFrames = evidenceFrames,
            savedAtMillis = System.currentTimeMillis()
        )
        val findings = (current.agentFindings.filterNot { it.sourceId == sourceId } + saved)
            .takeLast(MAX_SAVED_AGENT_FINDINGS)
        val newEvidenceItems = WorkspaceEvidenceOps.addAll(
            items = current.evidenceItems,
            frameNumbers = evidenceFrames,
            source = EvidenceSource.AgentFinding,
            sourceFindingId = sourceId,
            nowMillis = System.currentTimeMillis()
        )
        updateWorkspace(
            current.copy(
                evidenceItems = newEvidenceItems,
                agentFindings = findings
            )
        )
        return true
    }

    /** Validate first, then show a proposal. This function never changes the filter. */
    fun prepareAgentFilterPreview(evidence: AgentEvidence, report: AgentReport) {
        val filter = evidence.displayFilter?.trim().orEmpty()
        val error = validateAgentEvidence(evidence, report) ?: when {
            filter.isBlank() -> AgentError(
                code = AgentErrorCode.INVALID_DISPLAY_FILTER,
                userMessage = "The evidence does not contain a display filter."
            )
            else -> null
        }
        val session = sessionCoordinator.state.value
        val preview = AgentFilterPreviewState(
            evidence = evidence,
            captureFingerprint = report.provenance.captureFingerprint,
            currentFilter = session.appliedDisplayFilter,
            suggestedFilter = filter,
            currentScope = currentScope(),
            suggestedScope = if (filter.isBlank()) AnalysisScope.CompleteFile else AnalysisScope.CurrentFilter,
            isValidating = error == null,
            error = error
        )
        _agentFilterPreview.value = preview
        if (error != null) return

        val token = sessionCoordinator.currentToken()
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                sessionCoordinator.validateDisplayFilter(filter, token)
            }
            val current = _agentFilterPreview.value
            if (current?.evidence != evidence) return@launch
            val stillCurrent = sessionCoordinator.state.value.fileFingerprint == report.provenance.captureFingerprint
            _agentFilterPreview.value = current.copy(
                isValidating = false,
                error = when {
                    !stillCurrent -> sessionChangedAgentError()
                    result.isFailure -> AgentError(
                        code = AgentErrorCode.INVALID_DISPLAY_FILTER,
                        userMessage = "The suggested display filter is invalid."
                    )
                    else -> null
                }
            )
        }
    }

    fun dismissAgentFilterPreview() {
        _agentFilterPreview.value = null
    }

    /** Only the preview confirmation reaches the shared user-filter coordinator. */
    fun applyAgentFilterPreview() {
        val preview = _agentFilterPreview.value ?: return
        if (!preview.canApply) return
        if (sessionCoordinator.state.value.fileFingerprint != preview.captureFingerprint) {
            _agentFilterPreview.value = preview.copy(error = sessionChangedAgentError())
            return
        }
        _agentFilterPreview.value = null
        applyDisplayFilter(preview.suggestedFilter)
    }

    fun selectWorkspaceFrame(frameNumber: Long?) {
        val current = _workspace.value ?: return
        if (current.selectedFrame == frameNumber) return
        updateWorkspace(current.copy(selectedFrame = frameNumber))
    }

    fun addFilterHistory(filter: String) {
        val normalized = filter.trim()
        if (normalized.isBlank()) return
        val current = _workspace.value ?: return
        val history = (listOf(normalized) + current.filterHistory.filterNot { it == normalized }).take(20)
        updateWorkspace(current.copy(filterHistory = history))
    }

    fun toggleFavoriteFilter(filter: String) {
        val normalized = filter.trim()
        val current = _workspace.value ?: return
        if (normalized.isBlank()) return
        val favorites = current.favoriteFilters.toMutableSet().apply { if (!add(normalized)) remove(normalized) }
        updateWorkspace(current.copy(favoriteFilters = favorites))
    }

    fun updateWorkspace(workspace: AnalysisWorkspace) {
        _workspace.value = workspace
        val hasSavedState = workspace.displayFilter.isNotBlank() ||
            workspace.selectedFrame != null || workspace.bookmarks.isNotEmpty() ||
            workspace.notes.isNotEmpty() || workspace.evidenceFrames.isNotEmpty() ||
            workspace.agentFindings.isNotEmpty()
        _currentFile.value?.localPath?.let { path ->
            _recentFiles.value = _recentFiles.value.map { recent ->
                if (recent.localPath == path) recent.copy(hasSavedWorkspace = hasSavedState) else recent
            }
            persistRecentFiles(_recentFiles.value)
        }
        viewModelScope.launch(Dispatchers.IO) { workspaceStore.save(workspace) }
    }

    fun setStatisticsBucket(seconds: Double) {
        _statisticsState.value = _statisticsState.value.copy(bucketSeconds = seconds)
        refreshStatistics()
    }

    fun cancelStatistics() {
        analysisGeneration++
        statisticsJob?.cancel()
        statisticsJob = null
        repository.cancelLongRunningOperations()
        _statisticsState.value = _statisticsState.value.copy(isLoading = false, job = _statisticsState.value.job.copy(phase = AnalysisJobPhase.Cancelled, message = text(R.string.job_cancelled)))
        _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Cancelled, message = text(R.string.job_cancelled))
    }

    fun refreshCommunicationAnalysis() {
        if (_currentFile.value == null) {
            _communicationAnalysis.value = CommunicationAnalysis()
            return
        }
        communicationJob?.cancel()
        val generation = analysisGeneration
        communicationJob = viewModelScope.launch {
            beginAnalysisJob(currentScope(), text(R.string.job_analyzing_communication), repository.getVisibleFrameCount().toLong())
            _communicationAnalysis.value = _communicationAnalysis.value.copy(isLoading = true, error = null)
            val result = runCatching {
                withContext(Dispatchers.IO) { repository.buildCommunicationAnalysis() }
            }
            if (result.exceptionOrNull() is CancellationException || generation != analysisGeneration) return@launch
            _communicationAnalysis.value = result.fold(
                onSuccess = { _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Completed, processed = it.sipTotal.toLong() + it.rtpTotal + it.rtcpTotal + it.coreTotal, message = text(R.string.job_communication_ready)); it.copy(isLoading = false, error = null) },
                onFailure = { _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Failed, errorCode = "COMMUNICATION_FAILED", message = it.message); CommunicationAnalysis(isLoading = false, error = it.message ?: text(R.string.error_analyze_communication)) }
            )
        }
    }

    fun cancelCommunicationAnalysis() {
        analysisGeneration++
        communicationJob?.cancel()
        communicationJob = null
        repository.cancelLongRunningOperations()
        _communicationAnalysis.value = _communicationAnalysis.value.copy(isLoading = false, error = text(R.string.analysis_cancelled))
        _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Cancelled, message = text(R.string.job_cancelled))
    }

    fun cancelActiveAnalysis() {
        analysisGeneration++
        filterJob?.cancel(); searchJob?.cancel(); expertJob?.cancel(); statisticsJob?.cancel(); communicationJob?.cancel()
        filterJob = null; searchJob = null; expertJob = null; statisticsJob = null; communicationJob = null
        repository.cancelLongRunningOperations()
        _isFiltering.value = false
        _searchState.value = _searchState.value.copy(isSearching = false)
        _expertSummary.value = _expertSummary.value.copy(isLoading = false)
        _statisticsState.value = _statisticsState.value.copy(isLoading = false)
        _healthSummary.value = _healthSummary.value.copy(isLoading = false)
        _communicationAnalysis.value = _communicationAnalysis.value.copy(isLoading = false)
        _analysisJob.value = _analysisJob.value.copy(phase = AnalysisJobPhase.Cancelled, message = text(R.string.job_cancelled))
    }

    private suspend fun openPreparedFile(prepared: PreparedCapture) {
        if (!prepared.file.exists()) {
            throw IllegalStateException(text(R.string.error_file_missing, prepared.displayName))
        }

        val result = withContext(Dispatchers.IO) {
            @Suppress("ApplySharedPref")
            sessionPrefs.edit().clear().commit()
            repository.openFile(
                path = prepared.file.absolutePath,
                displayName = prepared.displayName,
                sizeBytes = prepared.sizeBytes
            ) { framesIndexed, bytesRead, totalBytes ->
                _openProgress.value = OpenProgress(
                    message = text(R.string.progress_indexing_file, prepared.displayName),
                    framesIndexed = framesIndexed,
                    bytesRead = bytesRead,
                    totalBytes = totalBytes
                )
                openJob?.isActive != false
            }
        }

        val info = result.getOrThrow()
        val coordinatorToken = sessionCoordinator.onSessionOpened(info)
        repository.setTimeDisplayFormat(_preferences.value.timeDisplayFormat)
        repository.setNameResolutionEnabled(_preferences.value.nameResolutionEnabled)
        // Process-wide native state, so it has to be re-synced for every new
        // session. `Probe` is per-capture by definition: it samples *this*
        // capture and only leaves decryption on when the sample decodes.
        withContext(Dispatchers.IO) {
            repository.setEspDecryptionMode(_preferences.value.espDecryptionMode)
        }.let { reportEspDecryptionOutcome(it) }
        _currentFile.value = info
        _workspacePage.value = WorkspacePage.Packets
        _openProgress.value = null
        _displayFilter.value = ""
        _filterResult.value = DisplayFilterResult(success = true, filteredCount = info.frameCount)
        _displayFilterUiState.value = DisplayFilterUiState(
            syntaxStatus = FilterSyntaxStatus.Valid,
            visibleCount = info.frameCount,
            totalCount = info.frameCount
        )
        _searchState.value = PacketSearchState()
        _decodeAsRules.value = emptyList()
        _healthSummary.value = CaptureHealthSummary()
        rememberRecent(info)
        sessionPrefs.edit()
            .putString("path", info.localPath)
            .putString("displayName", info.displayName)
            .putLong("sizeBytes", info.sizeBytes)
            .putString("displayFilter", "")
            .remove("selectedFrame")
            .apply()
        pagerGeneration.value += 1
        viewModelScope.launch(Dispatchers.IO) {
            val fingerprint = sessionCoordinator.prepareFingerprint(coordinatorToken, prepared.file)
                .getOrNull() ?: return@launch
            val restored = workspaceStore.load(fingerprint) ?: AnalysisWorkspace(fingerprint, info.displayName)
            withContext(Dispatchers.Main) {
                if (sessionCoordinator.isCurrent(coordinatorToken) &&
                    repository.currentFile()?.localPath == info.localPath
                ) {
                    _workspace.value = restored
                    if (restored.displayFilter.isNotBlank()) {
                        updateDisplayFilter(restored.displayFilter)
                        applyDisplayFilter()
                    }
                }
            }
        }
    }

    private fun prepareForFileSwitch() {
        sessionGeneration++
        sessionCoordinator.invalidateSession()
        filterJob?.cancel()
        markAnalysisStale()
        _highlightedFrames.value = emptySet()
        _isFiltering.value = false
    }

    private fun copyUriToPrivateStorage(uri: Uri, fallbackName: String?): PreparedCapture {
        val metadata = queryMetadata(uri, fallbackName)
        val capturesDir = File(appContext.filesDir, "captures").apply { mkdirs() }
        cleanupPartialImports(capturesDir)
        val requiredBytes = metadata.sizeBytes.coerceAtLeast(0L)
        val availableBytes = StatFs(appContext.filesDir.absolutePath).availableBytes
        check(requiredBytes == 0L || availableBytes >= requiredBytes + MIN_FREE_SPACE_BYTES) {
            text(R.string.error_private_storage)
        }
        enforceCaptureQuota(capturesDir, requiredBytes)
        val target = uniqueCaptureFile(capturesDir, metadata.displayName)
        val temporary = File(capturesDir, ".${target.name}.${UUID.randomUUID()}.partial")
        val totalBytes = metadata.sizeBytes
        var copiedBytes = 0L

        try {
            appContext.contentResolver.openInputStream(uri)?.use { input ->
                temporary.outputStream().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        if (openJob?.isActive == false) throw CancellationException()
                        val read = input.read(buffer)
                        if (read == -1) break
                        output.write(buffer, 0, read)
                        copiedBytes += read
                        _openProgress.value = OpenProgress(
                            message = text(R.string.progress_copying_file, metadata.displayName),
                            bytesRead = copiedBytes,
                            totalBytes = totalBytes
                        )
                    }
                }
            } ?: throw IllegalStateException(text(R.string.error_read_selected_file))

            validateCaptureHeader(temporary)
            check(temporary.renameTo(target)) { text(R.string.error_finish_import) }
        } finally {
            temporary.delete()
        }

        return PreparedCapture(
            file = target,
            displayName = metadata.displayName,
            sizeBytes = if (totalBytes > 0L) totalBytes else target.length()
        )
    }

    private fun validateCaptureHeader(file: File) {
        val header = ByteArray(4)
        val read = file.inputStream().use { it.read(header) }
        if (read < header.size || !CaptureFileValidator.isSupportedMagic(header)) {
            throw IllegalArgumentException(
                text(R.string.error_unsupported_capture)
            )
        }
    }

    private fun queryMetadata(uri: Uri, fallbackName: String?): PreparedMetadata {
        var displayName = fallbackName ?: uri.lastPathSegment ?: "capture.pcap"
        var size = -1L
        appContext.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (cursor.moveToFirst()) {
                if (nameIndex >= 0) displayName = cursor.getString(nameIndex) ?: displayName
                if (sizeIndex >= 0) size = cursor.getLong(sizeIndex)
            }
        }
        return PreparedMetadata(sanitizeFileName(displayName), size)
    }

    private fun uniqueCaptureFile(dir: File, displayName: String): File {
        val base = displayName.substringBeforeLast('.', displayName)
        val ext = displayName.substringAfterLast('.', "")
        var index = 0
        while (true) {
            val name = if (index == 0) {
                displayName
            } else if (ext.isBlank()) {
                "$base-$index"
            } else {
                "$base-$index.$ext"
            }
            val candidate = File(dir, name)
            if (!candidate.exists()) return candidate
            index++
        }
    }

    private fun sanitizeFileName(name: String): String {
        val sanitized = name.replace(Regex("[\\\\/:*?\"<>|]"), "_").trim()
        return sanitized.ifBlank { "capture.pcap" }
    }

    private fun createExportFile(fileName: String): File {
        val dir = File(appContext.filesDir, "exports").apply { mkdirs() }
        var totalBytes = dir.listFiles().orEmpty().filter { it.isFile }.sumOf { it.length() }
        dir.listFiles().orEmpty()
            .filter { it.isFile }
            .sortedBy { it.lastModified() }
            .forEach { file ->
                val length = file.length()
                if (totalBytes > EXPORT_QUOTA_BYTES && file.delete()) {
                    totalBytes -= length
                }
            }
        return File(dir, sanitizeFileName(fileName))
    }

    private fun appVersion(): String = runCatching {
        @Suppress("DEPRECATION")
        appContext.packageManager.getPackageInfo(appContext.packageName, 0).versionName
    }.getOrNull().orEmpty().ifBlank { "unknown" }

    private fun csvCell(value: Any?): String {
        val text = value?.toString().orEmpty()
        return if (text.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) "\"${text.replace("\"", "\"\"")}\"" else text
    }

    private fun beginAnalysisJob(scope: AnalysisScope, message: String, total: Long) {
        _analysisJob.value = AnalysisJobState(phase = AnalysisJobPhase.Running, scope = scope, total = total, message = message)
    }

    private fun cleanupPartialImports(capturesDir: File) {
        capturesDir.listFiles().orEmpty()
            .filter { it.isFile && it.name.endsWith(".partial") }
            .forEach { it.delete() }
    }

    private fun enforceCaptureQuota(capturesDir: File, requiredBytes: Long) {
        val protectedPaths = buildSet {
            repository.currentFile()?.localPath?.let(::add)
            LiveCaptureStore.state.value.outputPath?.let(::add)
        }
        var totalBytes = capturesDir.listFiles().orEmpty()
            .filter { it.isFile }
            .sumOf { it.length() }
        val candidates = capturesDir.listFiles().orEmpty()
            .filter { it.isFile && it.absolutePath !in protectedPaths && !it.name.endsWith(".partial") }
            .sortedBy { it.lastModified() }
        for (file in candidates) {
            if (totalBytes + requiredBytes <= CAPTURE_QUOTA_BYTES) break
            val length = file.length()
            if (file.delete()) totalBytes -= length
        }
        check(totalBytes + requiredBytes <= CAPTURE_QUOTA_BYTES) {
            text(R.string.error_capture_quota)
        }
    }

    private fun loadAnalyzerPreferences(): AnalyzerPreferences {
        return AnalyzerPreferences(
            timeDisplayFormat = runCatching {
                val stored = analyzerPrefs.getString("timeDisplayFormat", TimeDisplayFormat.Relative.name)!!
                if (stored == "Seconds") TimeDisplayFormat.Relative else TimeDisplayFormat.valueOf(stored)
            }.getOrDefault(TimeDisplayFormat.Relative),
            nameResolutionEnabled = analyzerPrefs.getBoolean("nameResolutionEnabled", false),
            colorRulesEnabled = analyzerPrefs.getBoolean("colorRulesEnabled", true),
            defaultTreeExpansionDepth = analyzerPrefs.getInt("defaultTreeExpansionDepth", 1),
            rtpHeuristicEnabled = analyzerPrefs.getBoolean(RtpHeuristicPreferenceOps.PREFERENCE_KEY, false),
            espDecryptionMode = EspDecryptionPreferenceOps.parse(
                analyzerPrefs.getString(EspDecryptionPreferenceOps.PREFERENCE_KEY, null)
            ),
            uiLanguage = UiLanguagePreferenceOps.parse(
                analyzerPrefs.getString(UiLanguagePreferenceOps.PREFERENCE_KEY, null)
            )
        )
    }

    private fun saveAnalyzerPreferences(preferences: AnalyzerPreferences) {
        analyzerPrefs.edit()
            .putString("timeDisplayFormat", preferences.timeDisplayFormat.name)
            .putBoolean("nameResolutionEnabled", preferences.nameResolutionEnabled)
            .putBoolean("colorRulesEnabled", preferences.colorRulesEnabled)
            .putInt("defaultTreeExpansionDepth", preferences.defaultTreeExpansionDepth)
            .putBoolean(RtpHeuristicPreferenceOps.PREFERENCE_KEY, preferences.rtpHeuristicEnabled)
            .putString(
                EspDecryptionPreferenceOps.PREFERENCE_KEY,
                preferences.espDecryptionMode.name
            )
            .putString(
                UiLanguagePreferenceOps.PREFERENCE_KEY,
                UiLanguagePreferenceOps.persistValue(preferences.uiLanguage)
            )
            .apply()
    }

    private fun rememberRecent(info: FileSessionInfo) {
        val previous = _recentFiles.value.firstOrNull { it.localPath == info.localPath }
        val next = listOf(
            RecentCapture(
                displayName = info.displayName,
                sizeBytes = info.sizeBytes,
                localPath = info.localPath,
                openedAtMillis = System.currentTimeMillis(),
                frameCount = info.frameCount,
                hasSavedWorkspace = previous?.hasSavedWorkspace == true
            )
        ).plus(
            _recentFiles.value.filter {
                it.localPath != info.localPath && File(it.localPath).exists()
            }
        )
            .take(10)

        _recentFiles.value = next
        persistRecentFiles(next)
    }

    private fun persistRecentFiles(items: List<RecentCapture>) {
        val json = JSONArray()
        items.forEach { recent ->
            json.put(
                JSONObject()
                    .put("displayName", recent.displayName)
                    .put("sizeBytes", recent.sizeBytes)
                    .put("localPath", recent.localPath)
                    .put("openedAtMillis", recent.openedAtMillis)
                    .put("frameCount", recent.frameCount)
                    .put("hasSavedWorkspace", recent.hasSavedWorkspace)
            )
        }
        prefs.edit().putString("items", json.toString()).apply()
    }

    private fun loadRecentFiles(): List<RecentCapture> {
        val raw = prefs.getString("items", null) ?: return emptyList()
        return runCatching {
            val array = JSONArray(raw)
            buildList {
                for (i in 0 until array.length()) {
                    val item = array.getJSONObject(i)
                    val path = item.getString("localPath")
                    if (File(path).exists()) {
                        add(
                            RecentCapture(
                                displayName = item.getString("displayName"),
                                sizeBytes = item.optLong("sizeBytes", File(path).length()),
                                localPath = path,
                                openedAtMillis = item.optLong("openedAtMillis"),
                                frameCount = item.optInt("frameCount", 0),
                                hasSavedWorkspace = item.optBoolean("hasSavedWorkspace", false)
                            )
                        )
                    }
                }
            }
        }.getOrDefault(emptyList())
    }

    override fun onCleared() {
        sessionGeneration++
        openJob?.cancel()
        filterJob?.cancel()
        filterValidationJob?.cancel()
        searchJob?.cancel()
        expertJob?.cancel()
        statisticsJob?.cancel()
        httpObjectsJob?.cancel()
        packetContextJob?.cancel()
        preferencesJob?.cancel()
        repository.cancelLongRunningOperations()
        super.onCleared()
    }

    private data class PreparedMetadata(
        val displayName: String,
        val sizeBytes: Long
    )

    private data class PreparedCapture(
        val file: File,
        val displayName: String,
        val sizeBytes: Long
    )
}

private const val CAPTURE_QUOTA_BYTES = 1_024L * 1024L * 1024L
private const val EXPORT_QUOTA_BYTES = 256L * 1024L * 1024L
private const val LARGE_FILE_WARNING_BYTES = 500L * 1024L * 1024L
private const val MIN_FREE_SPACE_BYTES = 16L * 1024L * 1024L
private const val FILTER_VALIDATION_DEBOUNCE_MS = 275L
private const val MAX_SAVED_AGENT_FINDINGS = 100

private fun Int.floorMod(modulus: Int): Int = ((this % modulus) + modulus) % modulus

fun Long.formatFileSize(): String {
    if (this < 0L) return "Unknown size"
    if (this < 1024L) return "$this B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var value = this.toDouble() / 1024.0
    var unitIndex = 0
    while (value >= 1024.0 && unitIndex < units.lastIndex) {
        value /= 1024.0
        unitIndex++
    }
    return String.format(Locale.US, "%.1f %s", value, units[unitIndex])
}
