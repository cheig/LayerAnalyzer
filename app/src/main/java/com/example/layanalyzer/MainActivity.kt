package com.example.layanalyzer

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Build
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.layanalyzer.ai.agent.AgentSettingsStore
import com.example.layanalyzer.ai.agent.SecretStore
import com.example.layanalyzer.ai.agent.ProtocolAnalysisAgent
import com.example.layanalyzer.ai.audit.AgentDiagnosticsRecorder
import com.example.layanalyzer.ai.cache.AgentToolCache
import com.example.layanalyzer.ai.client.GatewayAccountRepository
import com.example.layanalyzer.ai.playbook.VersionedScenarioPackageStore
import com.example.layanalyzer.ai.playbook.AgentPlaybookStore
import com.example.layanalyzer.ai.playbook.SharedPreferencesPlaybookUsageStore
import com.example.layanalyzer.ai.playbook.UserScenarioStore
import com.example.layanalyzer.data.AgentSessionStore
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.media.AndroidAudioFocusFacade
import com.example.layanalyzer.media.AndroidMediaPlayerFacade
import com.example.layanalyzer.media.AndroidVideoPreviewPlayerFacade
import com.example.layanalyzer.media.RtpAudioPlayerController
import com.example.layanalyzer.media.RtpVideoPreviewController
import com.example.layanalyzer.ui.LayAnalyzerApp
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.CaptureOpenRequest
import com.example.layanalyzer.viewmodel.PacketDetailViewModel
import com.example.layanalyzer.viewmodel.PacketListViewModel
import com.example.layanalyzer.viewmodel.ProtocolAgentViewModel
import com.example.layanalyzer.viewmodel.RtpViewModel
import com.example.layanalyzer.viewmodel.VoipCallsViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

class MainActivity : ComponentActivity() {
    private val pendingOpenRequests = mutableStateListOf<CaptureOpenRequest>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) {
            collectOpenRequests(intent)
        }
        handlePerfExportIntent(intent)
        val layerAnalyzerApplication = application as LayerAnalyzerApplication
        if (
            shouldRequestActiveSessionConfirmation(
                isFreshActivityLaunch = savedInstanceState == null,
                hasExplicitOpenRequest = pendingOpenRequests.isNotEmpty(),
                hasOpenSession = layerAnalyzerApplication.repository.currentFile() != null
            )
        ) {
            layerAnalyzerApplication.requestActiveSessionConfirmation()
        }

        setContent {
            LayerAnalyzerTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    LayAnalyzerRoot(
                        application = layerAnalyzerApplication,
                        context = applicationContext,
                        pendingOpenRequests = pendingOpenRequests,
                        onExitConfirmed = { finish() }
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        collectOpenRequests(intent)
    }

    /**
     * [PERF-export] T0 基线任务：G4 对拍导出入口（仅 Debug 构建）。
     *
     * 用法：adb shell am start -n <pkg>/.MainActivity --es perf_export <标签>
     * 应用启动后等会话恢复（由 active_session 预制），再调用
     * [PacketRepository.exportPerfResults] 把结果写入 files/perf_export/<标签>/，
     * 完成后日志输出 [PERF-export] DONE/FAILED 并自动 finish，便于脚本判定。
     * Release 构建不编译此逻辑（native 符号也不存在）。
     */
    private fun handlePerfExportIntent(intent: Intent?) {
        if (!BuildConfig.DEBUG) return
        val tag = intent?.getStringExtra("perf_export")?.takeIf { it.isNotBlank() } ?: return
        // 本入口只为 perf_export 自动化服务，不要把它当成"用户打开了新文件"
        intent?.data = null
        val app = application as LayerAnalyzerApplication
        CoroutineScope(Dispatchers.Main).launch {
            // 等待引擎就绪并完成会话恢复（最多 5 分钟，1M 帧索引需要时间）。
            // 屏幕常亮保证前台扫描不被系统打断。
            window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            val deadline = System.currentTimeMillis() + 300_000
            var restored = false
            while (System.currentTimeMillis() < deadline) {
                val state = app.engineState.value
                if (state is EngineState.AwaitingSessionRestore) {
                    // 对拍导出总是恢复预制会话，无需人工确认
                    app.confirmSessionRestore()
                }
                if (state is EngineState.Ready && app.repository.currentFile() != null) {
                    restored = true
                    break
                }
                delay(500)
            }
            val outputDir = File(filesDir, "perf_export/$tag").apply { mkdirs() }
            if (!restored) {
                Log.e("LayAnalyzer", "[PERF-export] FAILED: session not restored in time")
                finish()
                return@launch
            }
            val report = withContext(Dispatchers.IO) {
                app.repository.exportPerfResults(outputDir.absolutePath)
            }
            val success = runCatching {
                JSONObject(report).optBoolean("success", false)
            }.getOrDefault(false)
            if (success) {
                Log.i("LayAnalyzer", "[PERF-export] DONE tag=$tag dir=${outputDir.absolutePath}")
            } else {
                Log.e("LayAnalyzer", "[PERF-export] FAILED tag=$tag report=$report")
            }
            finish()
        }
    }

    private fun collectOpenRequests(intent: Intent?) {
        if (intent == null) return
        when (intent.action) {
            Intent.ACTION_VIEW -> intent.data?.let { uri ->
                pendingOpenRequests.add(CaptureOpenRequest(uri))
            }
            Intent.ACTION_SEND -> {
                val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
                }
                if (uri != null) pendingOpenRequests.add(CaptureOpenRequest(uri))
            }
        }
    }
}

@Composable
fun LayAnalyzerRoot(
    application: LayerAnalyzerApplication,
    context: Context,
    pendingOpenRequests: MutableList<CaptureOpenRequest>,
    onExitConfirmed: () -> Unit
) {
    val engineState by application.engineState.collectAsState()

    when (val state = engineState) {
        EngineState.Ready -> {
            val factory = remember {
                PacketViewModelFactory(
                    application.repository,
                    application.sessionCoordinator,
                    context,
                    application.protocolAnalysisAgent,
                    application.agentSettings,
                    application.agentSecretStore,
                    application.gatewayAccountRepository,
                    application.agentSessionStore,
                    application.agentToolCache,
                    application.agentDiagnosticsRecorder,
                    application.scenarioPackageStore,
                    application.agentPlaybookStore,
                    application.agentUserScenarioStore,
                    application.agentRunCoordinator,
                    application.agentJobStore,
                    application.providerModelFetcher,
                    // OPT-QNT-01: the app-scoped quarantine notice channel the
                    // user scenario store's sink publishes to.
                    scenarioQuarantineEvents = application.scenarioQuarantineEvents
                )
            }
            val listViewModel: PacketListViewModel = viewModel(factory = factory)
            val detailViewModel: PacketDetailViewModel = viewModel(factory = factory)
            val agentViewModel: ProtocolAgentViewModel = viewModel(factory = factory)
            val rtpViewModel: RtpViewModel = viewModel(factory = factory)
            val voipCallsViewModel: VoipCallsViewModel = viewModel(factory = factory)

            LaunchedEffect(pendingOpenRequests.size) {
                val request = pendingOpenRequests.firstOrNull()
                if (request != null) {
                    pendingOpenRequests.removeAt(0)
                    listViewModel.openCaptureUri(request.uri, request.displayName)
                }
            }

            val agentConfiguration by agentViewModel.configuration.collectAsState()
            val agentConsentPrompt by agentViewModel.consentPrompt.collectAsState()
            val gatewayAccount by agentViewModel.gatewayAccount.collectAsState()
            LayAnalyzerApp(
                listViewModel = listViewModel,
                detailViewModel = detailViewModel,
                agentViewModel = agentViewModel,
                rtpViewModel = rtpViewModel,
                voipCallsViewModel = voipCallsViewModel,
                agentConfiguration = agentConfiguration,
                agentConsentPrompt = agentConsentPrompt,
                gatewayAccount = gatewayAccount,
                onExitConfirmed = onExitConfirmed
            )
        }
        EngineState.Initializing -> InitializationScreen()
        EngineState.RestoringSession -> {
            val restoreProgress by application.restoreProgress.collectAsState()
            InitializationScreen(
                progressMessage = stringResource(R.string.restoring_session),
                progress = restoreProgress,
                onCancel = application::cancelSessionRestore
            )
        }
        is EngineState.AwaitingSessionRestore -> {
            if (pendingOpenRequests.isNotEmpty()) {
                LaunchedEffect(state.session.path, pendingOpenRequests.size) {
                    application.declineSessionRestore()
                }
                InitializationScreen()
            } else {
                SessionRestoreDialog(
                    session = state.session,
                    errorMessage = state.errorMessage,
                    onConfirm = application::confirmSessionRestore,
                    onDecline = application::declineSessionRestore
                )
            }
        }
        is EngineState.Failed -> InitializationScreen(
            error = state.message,
            onRetry = application::retryEngineInitialization
        )
    }
}

class PacketViewModelFactory(
    private val repository: PacketRepository,
    private val sessionCoordinator: CaptureSessionCoordinator,
    private val context: Context,
    private val agent: ProtocolAnalysisAgent,
    private val agentSettings: AgentSettingsStore,
    private val secretStore: SecretStore? = null,
    private val gatewayAccount: GatewayAccountRepository? = null,
    private val agentSessionStore: AgentSessionStore? = null,
    private val agentToolCache: AgentToolCache? = null,
    private val agentDiagnostics: AgentDiagnosticsRecorder? = null,
    private val scenarioPackageStore: VersionedScenarioPackageStore? = null,
    private val playbookStore: AgentPlaybookStore? = null,
    /** SRE-QA-01: the same user layer instance [playbookStore] was built with. */
    private val userScenarios: UserScenarioStore? = null,
    private val runCoordinator: com.example.layanalyzer.ai.background.AgentRunCoordinator? = null,
    private val agentJobStore: com.example.layanalyzer.data.AnalysisJobStore? = null,
    private val providerModelFetcher: com.example.layanalyzer.ai.client.ProviderModelFetcher? = null,
    /**
     * OPT-QNT-01: the Application-scoped quarantine notice channel; the Agent
     * ViewModel subscribes to it so a silent store-level reset reaches the UI.
     */
    private val scenarioQuarantineEvents: com.example.layanalyzer.ai.playbook.ScenarioQuarantineEventChannel? = null
) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(PacketListViewModel::class.java)) {
            return PacketListViewModel(repository, sessionCoordinator, context, agentDiagnostics) as T
        }
        if (modelClass.isAssignableFrom(PacketDetailViewModel::class.java)) {
            return PacketDetailViewModel(repository, context) as T
        }
        if (modelClass.isAssignableFrom(RtpViewModel::class.java)) {
            val rtpCacheRoot = File(context.applicationContext.cacheDir, "rtp")
            return RtpViewModel(
                repository = RtpRepository(repository),
                sessionCoordinator = sessionCoordinator,
                audioPlayerController = RtpAudioPlayerController(
                    facade = AndroidMediaPlayerFacade(context.applicationContext),
                    scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate),
                    audioFocus = AndroidAudioFocusFacade(context.applicationContext)
                ),
                // RTP5-KT-03：应用内预览的播放器；与音频播放器同一个容器作用域，
                // 所以屏幕被销毁时它还在（状态与位置因此能活过一次配置变化）。
                videoPreviewController = RtpVideoPreviewController(
                    facade = AndroidVideoPreviewPlayerFacade(context.applicationContext),
                    scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
                ),
                mediaCache = RtpMediaCache(rtpCacheRoot),
                cacheRoot = rtpCacheRoot
            ) as T
        }
        if (modelClass.isAssignableFrom(VoipCallsViewModel::class.java)) {
            val rtpCacheRoot = File(context.applicationContext.cacheDir, "rtp")
            return VoipCallsViewModel(
                rtpRepository = RtpRepository(repository),
                packetRepository = repository,
                sessionCoordinator = sessionCoordinator,
                mediaCache = RtpMediaCache(rtpCacheRoot),
                // RTP3-UI-03：与 RtpViewModel 完全同构的播放器接线（同一个音源约束：
                // 一次只放一个文件——立体声 mix.wav，没有 mix 时退化为主方向的单声道）。
                audioPlayerController = RtpAudioPlayerController(
                    facade = AndroidMediaPlayerFacade(context.applicationContext),
                    scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate),
                    audioFocus = AndroidAudioFocusFacade(context.applicationContext)
                )
            ) as T
        }
        if (modelClass.isAssignableFrom(ProtocolAgentViewModel::class.java)) {
            return ProtocolAgentViewModel(
                agent = agent,
                coordinator = sessionCoordinator,
                settings = agentSettings,
                secretStore = secretStore,
                gatewayAccountRepository = gatewayAccount,
                sessionStore = agentSessionStore,
                toolCache = agentToolCache,
                diagnostics = agentDiagnostics,
                jobStore = agentJobStore,
                scenarioPackageStore = scenarioPackageStore,
                playbookStore = playbookStore,
                userScenarios = userScenarios,
                playbookUsageStore = SharedPreferencesPlaybookUsageStore(context),
                runCoordinator = runCoordinator,
                providerModelFetcher = providerModelFetcher,
                quarantineEvents = scenarioQuarantineEvents
            ) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}

@Composable
fun SessionRestoreDialog(
    session: RestorableSession,
    errorMessage: String?,
    onConfirm: () -> Unit,
    onDecline: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDecline,
        title = { Text(stringResource(R.string.restore_session_title)) },
        text = {
            Column {
                Text(stringResource(R.string.restore_session_message, session.displayName))
                if (errorMessage != null) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = stringResource(R.string.restore_session_error, errorMessage),
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.restore_session_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDecline) {
                Text(stringResource(R.string.restore_session_decline))
            }
        }
    )
}

@Composable
fun InitializationScreen(
    error: String? = null,
    progressMessage: String? = null,
    progress: RestoreProgress? = null,
    onCancel: () -> Unit = {},
    onRetry: () -> Unit = {}
) {
    Box(modifier = Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            if (error == null) {
                if (progress != null) {
                    // Indexing is a long CPU-bound operation; show real
                    // progress so the screen cannot read as frozen.
                    LinearProgressIndicator(
                        progress = { progress.fraction },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "$progressMessage (${progress.framesIndexed})",
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(24.dp))
                    Button(onClick = onCancel) {
                        Text(stringResource(R.string.cancel))
                    }
                } else {
                    CircularProgressIndicator()
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(progressMessage ?: stringResource(R.string.starting_engine))
                }
            } else {
                Text("!", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.displayLarge)
                Spacer(modifier = Modifier.height(16.dp))
                Text(error)
                Spacer(modifier = Modifier.height(16.dp))
                Button(onClick = onRetry) {
                    Text(stringResource(R.string.retry))
                }
            }
        }
    }
}
