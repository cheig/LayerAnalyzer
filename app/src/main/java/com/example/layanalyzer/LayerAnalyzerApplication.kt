// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.app.Application
import android.content.Context
import android.util.Log
import androidx.multidex.MultiDexApplication
import com.example.layanalyzer.ai.agent.AndroidKeystoreSecretStore
import com.example.layanalyzer.ai.agent.AgentChatResponseFormat
import com.example.layanalyzer.ai.agent.AgentReasoningEffort
import com.example.layanalyzer.ai.agent.AgentModelBackend
import com.example.layanalyzer.ai.agent.AgentSettings
import com.example.layanalyzer.ai.agent.AgentSettingsStore
import com.example.layanalyzer.ai.agent.AndroidKeystoreGatewaySessionStore
import com.example.layanalyzer.ai.agent.SharedPreferencesAgentSettingsStore
import com.example.layanalyzer.ai.agent.ProtocolAnalysisAgent
import com.example.layanalyzer.ai.agent.selectModelBackend
import com.example.layanalyzer.ai.audit.AgentDiagnosticsRecorder
import com.example.layanalyzer.ai.cache.AgentToolCache
import com.example.layanalyzer.ai.playbook.AgentPlaybookStore
import com.example.layanalyzer.ai.playbook.ScenarioQuarantineEvent
import com.example.layanalyzer.ai.playbook.ScenarioQuarantineEventChannel
import com.example.layanalyzer.ai.playbook.ScenarioRulesOverlay
import com.example.layanalyzer.ai.playbook.UserScenarioPlaybookStore
import com.example.layanalyzer.ai.playbook.UserScenarioStore
import com.example.layanalyzer.ai.playbook.VersionedScenarioPackageStore
import com.example.layanalyzer.ai.client.AiModelCapabilities
import com.example.layanalyzer.ai.client.AiModelCapabilitiesResolver
import com.example.layanalyzer.ai.client.GatewayAccountRepository
import com.example.layanalyzer.ai.client.GatewayAiModelClient
import com.example.layanalyzer.ai.client.CloudAiModelClient
import com.example.layanalyzer.ai.client.MockAiModelClient
import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.ai.client.OkHttpAgentHttpTransport
import com.example.layanalyzer.ai.client.ProviderModelFetcher
import com.example.layanalyzer.ai.client.AgentResponseDebugCapture
import com.example.layanalyzer.ai.client.AndroidDeviceResourceProbe
import com.example.layanalyzer.ai.client.OpenAiCompatibleModelClient
import com.example.layanalyzer.ai.client.OpenAiResponsesModelClient
import com.example.layanalyzer.ai.client.AnthropicModelClient
import com.example.layanalyzer.ai.client.UnavailableAiModelClient
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.data.AgentAnalysisRepository
import com.example.layanalyzer.data.AgentSessionStore
import com.example.layanalyzer.data.CaptureFingerprintCalculator
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.radio.RadioRepository
import com.example.layanalyzer.data.radio.CommunicationRadioSourceAdapter
import com.example.layanalyzer.data.radio.TelephonyRadioSourceAdapter
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.model.EspDecryptionMode
import com.example.layanalyzer.ui.UiLanguageApplier
import com.example.layanalyzer.viewmodel.EspDecryptionPreferenceOps
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class LayerAnalyzerApplication : MultiDexApplication() {
    val rtpMediaCache: RtpMediaCache by lazy {
        RtpMediaCache(File(cacheDir, "rtp"))
    }
    val repository = PacketRepository { rtpMediaCache }
    val captureFingerprintCalculator = CaptureFingerprintCalculator()
    val sessionCoordinator = CaptureSessionCoordinator(
        dataSource = repository,
        fingerprintCalculator = captureFingerprintCalculator
    )
    val captureSessionCoordinator: CaptureSessionCoordinator
        get() = sessionCoordinator
    val radioRepository = RadioRepository(
        adapters = listOf(
            TelephonyRadioSourceAdapter(this),
            CommunicationRadioSourceAdapter { repository.buildCommunicationAnalysis() }
        )
    )
    val agentAnalysisRepository = AgentAnalysisRepository(
        dataSource = repository,
        coordinator = sessionCoordinator,
        radioRepository = radioRepository
    )

    /** User-editable configuration; only non-secret settings are persisted here. */
    val agentSettings: SharedPreferencesAgentSettingsStore by lazy {
        SharedPreferencesAgentSettingsStore(this)
    }
    val agentSettingsStore: AgentSettingsStore
        get() = agentSettings
    val agentSecretStore: AndroidKeystoreSecretStore by lazy {
        AndroidKeystoreSecretStore(this)
    }
    /** Login/session code writes short-lived tokens here; settings never hold them. */
    val gatewaySessionStore: AndroidKeystoreGatewaySessionStore by lazy {
        AndroidKeystoreGatewaySessionStore(this)
    }
    val gatewayAccountRepository: GatewayAccountRepository by lazy {
        GatewayAccountRepository(::createGatewayModelClient)
    }
    val agentToolRegistry: AgentToolRegistry = AgentToolRegistry.phase3()

    /** AI-26: the versioned, signed scenario rule package that backs the playbooks. */
    val scenarioPackageStore: VersionedScenarioPackageStore by lazy {
        VersionedScenarioPackageStore(
            context = this,
            registry = agentToolRegistry,
            nativeBuildMarker = { runCatching { NativeEngine.getVersion() }.getOrDefault("") }
        )
    }
    /**
     * OPT-QNT-01: the application-scoped quarantine notice buffer.  Owned here
     * (not in the store) because the user scenario layer can quarantine a
     * corrupt file while this object graph is being built — long before any
     * ViewModel exists — and the event must survive until the Agent ViewModel
     * collects it.  Construction allocates a channel only; no disk, no log.
     */
    val scenarioQuarantineEvents = ScenarioQuarantineEventChannel()

    /**
     * SRE-QA-01: the on-device user scenario layer at
     * `filesDir/scenario_rules/user_playbooks.json`.  User data stays under
     * filesDir only; construction touches no disk — reads and writes happen
     * when the editor saves or a layer reload runs, from Dispatchers.IO.
     */
    val agentUserScenarioStore: UserScenarioStore by lazy {
        UserScenarioPlaybookStore(
            directory = File(filesDir, UserScenarioStore.DIRECTORY_NAME),
            // The same whitelist every playbook boundary validates against, so
            // the editor chips offer exactly what a save accepts.
            availableTools = scenarioPackageStore.availableTools,
            // OPT-QNT-01: quarantine becomes visible to the user.  The log
            // contract is unchanged — same tag, same reason-code-only warning
            // as the store's default sink — and the code additionally goes to
            // [scenarioQuarantineEvents] for the Agent page to surface as a
            // notice.  Still just the stable code: never a file name, never
            // playbook content.
            onQuarantine = { reason ->
                Log.w(UserScenarioPlaybookStore.LOG_TAG, reason)
                scenarioQuarantineEvents.publish(ScenarioQuarantineEvent(reason))
            },
            // Built-in layers only — never the merged list, which also holds
            // user ids: re-saving an edited user scenario must not collide
            // with its own id.  Re-consulted on every save so a scenario
            // package update is picked up while this store lives.
            builtInPlaybookIds = {
                runCatching {
                    scenarioPackageStore.active().content.playbooks.map { it.id }.toSet()
                }.getOrDefault(emptySet())
            }
        )
    }
    val agentPlaybookStore: AgentPlaybookStore by lazy {
        AgentPlaybookStore(
            assetLoader = { scenarioPackageStore.loadActivePlaybooksJson() },
            availableTools = scenarioPackageStore.availableTools,
            overlay = runCatching { scenarioPackageStore.activeOverlay() }
                .getOrDefault(ScenarioRulesOverlay.EMPTY),
            userScenarios = agentUserScenarioStore
        )
    }

    /** AI-24 local stores. Each owns exactly one directory the user can clear. */
    val agentSessionStore: AgentSessionStore by lazy { AgentSessionStore(this) }
    val agentToolCache: AgentToolCache by lazy { AgentToolCache(this) }
    val agentDiagnosticsRecorder: AgentDiagnosticsRecorder by lazy {
        AgentDiagnosticsRecorder(this)
    }
    val agentJobStore: com.example.layanalyzer.data.AnalysisJobStore by lazy {
        com.example.layanalyzer.data.AnalysisJobStore(this)
    }
    /** Debug-only raw response capture kept outside Android backup. */
    val agentResponseDebugCapture: AgentResponseDebugCapture by lazy {
        AgentResponseDebugCapture(
            directory = File(noBackupFilesDir, "agent_response_dumps"),
            continuousEnabledProvider = {
                agentSettings.settings.rawResponseCaptureEnabled
            }
        )
    }

    /** Lists the models a BYOK provider advertises via its `/models` endpoint. */
    val providerModelFetcher: ProviderModelFetcher by lazy {
        ProviderModelFetcher(
            transport = OkHttpAgentHttpTransport(debugCapture = agentResponseDebugCapture)
        )
    }

    fun armNextAgentResponseDebugCapture(): Boolean =
        if (BuildConfig.DEBUG) agentResponseDebugCapture.armNextResponse() else false

    fun clearAgentResponseDebugCaptures() {
        agentResponseDebugCapture.clear()
    }

    val protocolAnalysisAgent: ProtocolAnalysisAgent by lazy {
        ProtocolAnalysisAgent(
            repository = agentAnalysisRepository,
            registry = agentToolRegistry,
            // The first client is only a placeholder. A provider is selected at
            // run start, so changing settings cannot mutate an active session.
            modelClient = MockAiModelClient.of(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS),
            modelRetryCountProvider = { agentSettings.settings.maxModelRetries },
            modelRequestTimeoutMillisProvider = {
                agentSettings.settings.maxModelRequestTimeoutSeconds * 1000L
            },
            modelClientProvider = ::createAgentModelClient,
            playbookStore = agentPlaybookStore,
            toolCache = agentToolCache,
            diagnostics = agentDiagnosticsRecorder,
            // Read lazily: the engine is initialized after this object graph is
            // built, and a failed read must not prevent an analysis from running.
            nativeBuildMarker = { runCatching { NativeEngine.getVersion() }.getOrDefault("") }
        )
    }

    /**
     * The one in-flight Agent run, owned here on an Application-scoped
     * coroutine so an analysis survives the Activity that started it.  The
     * foreground service is only told to raise/lower process priority; it
     * never owns the run.
     */
    val agentRunCoordinator: com.example.layanalyzer.ai.background.AgentRunCoordinator by lazy {
        com.example.layanalyzer.ai.background.AgentRunCoordinator(
            agent = protocolAnalysisAgent,
            scope = agentRunScope,
            jobStore = agentJobStore,
            captureSourceProvider = {
                val state = sessionCoordinator.state.value
                if (!state.hasSession) null else
                    com.example.layanalyzer.ai.background.CaptureSourceInfo(
                        fingerprint = state.fileFingerprint,
                        localPath = state.localPathIdentity,
                        sizeBytes = 0L
                    )
            },
            onRunActiveChanged = { active ->
                if (active) {
                    val intent = com.example.layanalyzer.ai.background.AgentAnalysisService
                        .startIntent(
                            this,
                            agentRunCoordinator.activeIdentity?.conversationId.orEmpty()
                        )
                    runCatching { androidx.core.content.ContextCompat.startForegroundService(this, intent) }
                } else {
                    runCatching {
                        startService(
                            com.example.layanalyzer.ai.background.AgentAnalysisService.stopIntent(this)
                        )
                    }
                }
            }
        )
    }

    private fun createAgentModelClient(): com.example.layanalyzer.ai.client.AiModelClient {
        val settings = agentSettings.settings.normalized()
        val activeModel = settings.activeModel
        fun configuredCapabilities(defaults: AiModelCapabilities): AiModelCapabilities {
            val configuredModel = activeModel ?: return defaults
            return if (configuredModel.contextLimitTokens != null ||
                configuredModel.outputLimitTokens != null
            ) {
                AiModelCapabilitiesResolver.resolve(
                    modelId = settings.modelId,
                    adapterDefaults = defaults,
                    userContextLimitTokens = configuredModel.contextLimitTokens,
                    userOutputLimitTokens = configuredModel.outputLimitTokens
                )
            } else {
                defaults
            }
        }
        val providerSecretStore = agentSecretStore.forAlias(settings.activeProvider?.secretKeyAlias)
        return when (val backend = settings.selectModelBackend()) {
            is AgentModelBackend.Mock -> MockAiModelClient.of(backend.scriptId)
            AgentModelBackend.OpenAiCompatibleByok -> OpenAiCompatibleModelClient(
                apiBaseUrl = settings.gatewayBaseUrl,
                transport = OkHttpAgentHttpTransport(debugCapture = agentResponseDebugCapture),
                providerId = settings.providerId,
                modelId = settings.modelId,
                apiKeyProvider = providerSecretStore::read,
                responseFormat = settings.activeProvider?.chatResponseFormat
                    ?: AgentChatResponseFormat.PROMPT_ONLY,
                reasoningEffort = activeModel?.reasoningEffort
                    ?: AgentReasoningEffort.UNSPECIFIED,
                capabilities = AiModelCapabilitiesResolver.resolve(
                    modelId = settings.modelId,
                    adapterDefaults = AiModelCapabilities.OPENAI_COMPATIBLE_DEFAULT,
                    userContextLimitTokens = activeModel?.contextLimitTokens,
                    userOutputLimitTokens = activeModel?.outputLimitTokens
                )
            )
            AgentModelBackend.OpenAiResponsesByok -> OpenAiResponsesModelClient(
                apiBaseUrl = settings.gatewayBaseUrl,
                transport = OkHttpAgentHttpTransport(debugCapture = agentResponseDebugCapture),
                providerId = settings.providerId,
                modelId = settings.modelId,
                apiKeyProvider = providerSecretStore::read,
                reasoningEffort = activeModel?.reasoningEffort
                    ?: AgentReasoningEffort.UNSPECIFIED,
                capabilities = AiModelCapabilitiesResolver.resolve(
                    modelId = settings.modelId,
                    adapterDefaults = AiModelCapabilities.OPENAI_RESPONSES_DEFAULT,
                    userContextLimitTokens = activeModel?.contextLimitTokens,
                    userOutputLimitTokens = activeModel?.outputLimitTokens
                )
            )
            AgentModelBackend.AnthropicByok -> AnthropicModelClient(
                apiBaseUrl = settings.gatewayBaseUrl,
                transport = OkHttpAgentHttpTransport(debugCapture = agentResponseDebugCapture),
                providerId = settings.providerId,
                modelId = settings.modelId,
                apiKeyProvider = providerSecretStore::read,
                reasoningEffort = activeModel?.reasoningEffort
                    ?: AgentReasoningEffort.UNSPECIFIED,
                capabilities = AiModelCapabilitiesResolver.resolve(
                    modelId = settings.modelId,
                    adapterDefaults = AiModelCapabilities.ANTHROPIC_DEFAULT,
                    userContextLimitTokens = activeModel?.contextLimitTokens,
                    userOutputLimitTokens = activeModel?.outputLimitTokens
                )
            )
            AgentModelBackend.NormalizedByokGateway -> CloudAiModelClient(
                gatewayBaseUrl = settings.gatewayBaseUrl,
                transport = OkHttpAgentHttpTransport(debugCapture = agentResponseDebugCapture),
                providerId = settings.providerId,
                modelId = settings.modelId,
                byokSecretProvider = providerSecretStore::read,
                initialCapabilities = configuredCapabilities(AiModelCapabilities.PHASE0),
                negotiateBeforeRun = true
            )
            AgentModelBackend.AccountGateway -> createGatewayModelClient(settings)
            is AgentModelBackend.LocalModel -> createLocalModelClient(backend.modelId)
            is AgentModelBackend.DesktopGateway -> createDesktopModelClient(backend.deviceId, settings)
            is AgentModelBackend.Unavailable -> UnavailableAiModelClient(
                reason = backend.reason,
                error = backend.error
            )
        }
    }

    /**
     * AI-25: create an on-device local model client.
     *
     * Model lifecycle management (download, hash verification, license, deletion)
     * is delivered in AI-26. This stub ensures the client type works through the
     * unified AiModelClient interface.
     */
    private fun createLocalModelClient(modelId: String): com.example.layanalyzer.ai.client.AiModelClient {
        // AI-25: model files must be within app directories only.
        val modelFile = File(filesDir, "models/$modelId.bin")
        return com.example.layanalyzer.ai.client.LocalAiModelClient(
            configuration = com.example.layanalyzer.ai.client.LocalModelConfiguration(
                modelId = modelId,
                modelPath = modelFile.absolutePath,
                requiresGpu = false,
                minimumRamMb = 512
            ),
            allowedRootPaths = listOf(
                filesDir.absolutePath,
                cacheDir.absolutePath,
                noBackupFilesDir.absolutePath
            ),
            resourceProbe = AndroidDeviceResourceProbe(this),
            inferenceBackend = null  // AI-26 will provide real backend
        )
    }

    /**
     * AI-25: create a desktop/LAN gateway client.
     *
     * Device pairing UI and token management is delivered in AI-26. This wiring
     * ensures the client type works through the unified interface.
     */
    private fun createDesktopModelClient(
        deviceId: String,
        settings: AgentSettings
    ): com.example.layanalyzer.ai.client.AiModelClient {
        return com.example.layanalyzer.ai.client.DesktopAiModelClient(
            configuration = com.example.layanalyzer.ai.client.DesktopModelConfiguration(
                modelId = settings.modelId,
                gatewayBaseUrl = settings.gatewayBaseUrl,
                deviceName = deviceId,
                requireTls = true
            ),
            transport = OkHttpAgentHttpTransport(debugCapture = agentResponseDebugCapture),
            pairingTokenProvider = { null },  // AI-26 will provide pairing UI and store
            onPairingExpired = {},
            initialCapabilities = configuredCapabilitiesFor(settings),
            negotiateBeforeRun = true
        )
    }

    /** Build a fresh gateway client so settings changes affect only new calls. */
    fun createGatewayModelClient(): GatewayAiModelClient? {
        val settings = agentSettings.settings.normalized()
        if (settings.selectModelBackend() != AgentModelBackend.AccountGateway) {
            return null
        }
        return createGatewayModelClient(settings)
    }

    private fun createGatewayModelClient(
        settings: AgentSettings
    ): GatewayAiModelClient = GatewayAiModelClient(
        gatewayBaseUrl = settings.gatewayBaseUrl,
        transport = OkHttpAgentHttpTransport(debugCapture = agentResponseDebugCapture),
        providerId = settings.providerId,
        modelId = settings.modelId,
        accessTokenProvider = gatewaySessionStore::accessToken,
        onAuthenticationRejected = gatewaySessionStore::clear,
        initialCapabilities = configuredCapabilitiesFor(settings),
        negotiateBeforeRun = true
    )

    private fun configuredCapabilitiesFor(settings: AgentSettings): AiModelCapabilities {
        val model = settings.activeModel
        return if (model != null &&
            (model.contextLimitTokens != null || model.outputLimitTokens != null)
        ) {
            AiModelCapabilitiesResolver.resolve(
                modelId = settings.modelId,
                adapterDefaults = AiModelCapabilities.PHASE0,
                userContextLimitTokens = model.contextLimitTokens,
                userOutputLimitTokens = model.outputLimitTokens
            )
        } else {
            AiModelCapabilities.PHASE0
        }
    }

    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * The scope the Agent run executes on, kept separate from [applicationScope]
     * so a cancelled analysis can never cancel engine initialisation or session
     * restore work that shares the other supervisor.
     */
    private val agentRunScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val _engineState = MutableStateFlow<EngineState>(EngineState.Initializing)
    val engineState: StateFlow<EngineState> = _engineState.asStateFlow()

    /**
     * Native indexing progress for the session restore in flight, or null
     * when no restore is running or before the first progress tick.
     */
    private val _restoreProgress = MutableStateFlow<RestoreProgress?>(null)
    val restoreProgress: StateFlow<RestoreProgress?> = _restoreProgress.asStateFlow()

    /** Set to stop the restore index loop at the next native progress tick. */
    @Volatile
    private var restoreCancelRequested = false

    /**
     * 冷启动时把用户选的界面语言应用到基座 context。
     *
     * 必须在 `super.attachBaseContext` **之前**覆写 locale：Activity 的
     * resources 在onCreate 时就已固定，晚一步会让首个界面用错语言，
     * 表现为"重启后仍是旧语言，切换一次才对"。
     *
     * 与 `setApplicationLocales` 的分工：这里只保证进程启动时上下文正确，
     * 运行中切换走那条官方 API（它会自行触发 Activity 重建）。
     */
    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(UiLanguageApplier.apply(base, UiLanguageApplier.stored(base)))
    }

    override fun onCreate() {
        super.onCreate()
        rtpMediaCache.clearAll()
        // A process restart creates a fresh, disarmed capture object. Apply
        // TTL/capacity cleanup without creating the private directory.
        agentResponseDebugCapture.cleanup()
        LiveCaptureStore.initialize(this)
        // Mark any run that survived the previous process as interrupted; the
        // diagnostics recorder uses the same runId for its own RunAbandoned
        // back-fill on the next analysis, so both keyed on the same string.
        agentJobStore.markInterruptedOnStartup()
        initializeEngine()
    }

    fun retryEngineInitialization() {
        if (_engineState.value == EngineState.Initializing || _engineState.value == EngineState.RestoringSession) return
        initializeEngine()
    }

    fun confirmSessionRestore() {
        // A second tap while the restore is already indexing must not start a
        // second concurrent openFile against the same repository.
        if (_engineState.value is EngineState.RestoringSession) return
        val pending = _engineState.value as? EngineState.AwaitingSessionRestore ?: return
        if (repository.currentFile()?.localPath == pending.session.path) {
            _engineState.value = EngineState.Ready
            return
        }
        restoreCancelRequested = false
        _engineState.value = EngineState.RestoringSession
        applicationScope.launch {
            try {
                restoreSession(pending.session)
                _engineState.value = EngineState.Ready
            } catch (cancelled: RestoreCancelledException) {
                _engineState.value = EngineState.AwaitingSessionRestore(session = pending.session)
            } catch (error: Throwable) {
                _engineState.value = EngineState.AwaitingSessionRestore(
                    session = pending.session,
                    errorMessage = error.message ?: "Unknown error"
                )
            } finally {
                _restoreProgress.value = null
            }
        }
    }

    /**
     * Stop the in-flight restore indexing at the next native progress tick
     * and return to the restore-confirmation dialog.
     */
    fun cancelSessionRestore() {
        if (_engineState.value != EngineState.RestoringSession) return
        restoreCancelRequested = true
        NativeEngine.cancelLongRunningOperations()
    }

    fun declineSessionRestore() {
        if (_engineState.value !is EngineState.AwaitingSessionRestore) return
        clearActiveSession()
        sessionCoordinator.invalidateSession()
        repository.closeFile()
        _engineState.value = EngineState.Ready
    }

    fun requestActiveSessionConfirmation() {
        if (_engineState.value != EngineState.Ready) return
        val current = repository.currentFile() ?: return
        _engineState.value = EngineState.AwaitingSessionRestore(
            RestorableSession(
                path = current.localPath,
                displayName = current.displayName,
                sizeBytes = current.sizeBytes
            )
        )
    }

    private fun initializeEngine() {
        _engineState.value = EngineState.Initializing
        applicationScope.launch {
            _engineState.value = runCatching {
                installWiresharkAssets(this@LayerAnalyzerApplication)
                val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE)
                if (connectivityManager != null) {
                    NativeEngine.initCaresAndroid(connectivityManager)
                }
                check(NativeEngine.initEngine(filesDir.absolutePath)) {
                    NativeEngine.getLastError().ifBlank { "Engine initialization failed." }
                }
                // RTP heuristics are a process-wide native setting, so restore
                // them as soon as the engine is up (RTP1-KT-03 / README C18).
                val analyzerPrefs =
                    getSharedPreferences(EspDecryptionPreferenceOps.PREFERENCE_FILE, MODE_PRIVATE)
                NativeEngine.setRtpHeuristicEnabled(
                    analyzerPrefs.getBoolean("rtpHeuristicEnabled", false)
                )
                // ESP NULL decryption is process-wide too. `Probe` has nothing to
                // sample without a capture, so it stays off here and is run by
                // PacketListViewModel.openPreparedFile against the capture being
                // opened; only the explicit modes are worth applying now.
                val espMode = EspDecryptionPreferenceOps.parse(
                    analyzerPrefs.getString(EspDecryptionPreferenceOps.PREFERENCE_KEY, null)
                )
                if (espMode != EspDecryptionMode.Probe) {
                    NativeEngine.setEspDecryptionMode(0L, espMode.nativeValue)
                }
                startupState()
            }.getOrElse { error ->
                EngineState.Failed(error.message ?: "Engine initialization failed.")
            }
        }
    }

    private fun startupState(): EngineState {
        val savedSession = readSavedSession()
        return when (
            val decision = decideSessionStartup(
                savedSession = savedSession,
                fileExists = savedSession?.let { File(it.path).isFile } == true
            )
        ) {
            is SessionStartupDecision.AskToRestore -> EngineState.AwaitingSessionRestore(decision.session)
            SessionStartupDecision.ContinueWithoutRestore -> {
                if (savedSession != null) clearActiveSession()
                EngineState.Ready
            }
        }
    }

    private fun readSavedSession(): RestorableSession? {
        val session = getSharedPreferences("active_session", MODE_PRIVATE)
        val path = session.getString("path", null) ?: return null
        val file = File(path)
        return RestorableSession(
            path = path,
            displayName = session.getString("displayName", file.name) ?: file.name,
            sizeBytes = session.getLong("sizeBytes", file.length())
        )
    }

    private suspend fun restoreSession(session: RestorableSession) {
        val file = File(session.path)
        check(file.isFile) { getString(R.string.error_file_missing, session.displayName) }
        sessionCoordinator.invalidateSession()
        _restoreProgress.value = null
        val result = repository.openFile(
            path = file.absolutePath,
            displayName = session.displayName,
            sizeBytes = session.sizeBytes
        ) { framesIndexed, bytesRead, totalBytes ->
            // Called on the indexing thread; StateFlow publication is
            // thread-safe. Returning false is how a UI-side cancel reaches
            // the native wtap_read loop.
            _restoreProgress.value = RestoreProgress(framesIndexed, bytesRead, totalBytes)
            !restoreCancelRequested
        }
        if (result.isFailure && restoreCancelRequested) throw RestoreCancelledException()
        val info = result.getOrThrow()
        sessionCoordinator.registerOpenedSession(info)
        getSharedPreferences("active_session", MODE_PRIVATE)
            .edit()
            .remove("selectedFrame")
            .apply()
        repository.setNameResolutionEnabled(
            getSharedPreferences(EspDecryptionPreferenceOps.PREFERENCE_FILE, MODE_PRIVATE)
                .getBoolean("nameResolutionEnabled", false)
        )
        // ESP NULL decryption is process-wide native state that has to be
        // re-synced for every new session, and `Probe` is per-capture: it
        // samples *this* capture. Mirrors PacketListViewModel.openPreparedFile.
        repository.setEspDecryptionMode(
            EspDecryptionPreferenceOps.parse(
                getSharedPreferences(EspDecryptionPreferenceOps.PREFERENCE_FILE, MODE_PRIVATE)
                    .getString(EspDecryptionPreferenceOps.PREFERENCE_KEY, null)
            )
        )
    }

    @Suppress("ApplySharedPref")
    private fun clearActiveSession() {
        getSharedPreferences("active_session", MODE_PRIVATE).edit().clear().commit()
    }

    private fun installWiresharkAssets(context: Context) {
        val targetDir = File(context.filesDir, ASSET_DIRECTORY)
        val marker = File(targetDir, ASSET_MARKER)
        if (marker.readTextOrNull() == ASSET_VERSION) return

        val stagingDir = File(context.filesDir, "$ASSET_DIRECTORY.installing")
        stagingDir.deleteRecursively()
        check(stagingDir.mkdirs()) { "Unable to prepare Wireshark data directory." }
        try {
            copyAssetFolder(context, ASSET_DIRECTORY, stagingDir)
            File(stagingDir, ASSET_MARKER).writeText(ASSET_VERSION)
            targetDir.deleteRecursively()
            check(stagingDir.renameTo(targetDir)) { "Unable to install Wireshark data files." }
        } finally {
            stagingDir.deleteRecursively()
        }
    }

    private fun copyAssetFolder(context: Context, assetPath: String, target: File) {
        val children = context.assets.list(assetPath).orEmpty()
        if (children.isEmpty()) {
            target.parentFile?.mkdirs()
            context.assets.open(assetPath).use { input ->
                target.outputStream().use(input::copyTo)
            }
            return
        }
        check(target.isDirectory || target.mkdirs()) { "Unable to create ${target.name}." }
        children.forEach { child ->
            copyAssetFolder(context, "$assetPath/$child", File(target, child))
        }
    }

    private fun File.readTextOrNull(): String? = runCatching { readText() }.getOrNull()

    private companion object {
        const val ASSET_DIRECTORY = "wireshark-data"
        const val ASSET_MARKER = ".asset-version"
        const val ASSET_VERSION = "wireshark-4.0.10-v1"
    }
}

sealed interface EngineState {
    data object Initializing : EngineState
    data class AwaitingSessionRestore(
        val session: RestorableSession,
        val errorMessage: String? = null
    ) : EngineState
    data object RestoringSession : EngineState
    data object Ready : EngineState
    data class Failed(val message: String) : EngineState
}

/**
 * Native indexing progress for a session restore in flight.  [bytesRead] /
 * [totalBytes] drive the determinate bar; [framesIndexed] is shown as text.
 */
data class RestoreProgress(
    val framesIndexed: Int,
    val bytesRead: Long,
    val totalBytes: Long
) {
    val fraction: Float
        get() = if (totalBytes > 0L) {
            (bytesRead.toFloat() / totalBytes.toFloat()).coerceIn(0f, 1f)
        } else {
            0f
        }
}

/** Raised when the user cancels an in-flight session restore. */
private class RestoreCancelledException : Exception("Session restore cancelled.")
