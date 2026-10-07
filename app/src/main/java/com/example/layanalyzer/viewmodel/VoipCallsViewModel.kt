// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.CaptureSessionState
import com.example.layanalyzer.data.CaptureSessionToken
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpCallLinker
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.data.RtpStreamDirection
import com.example.layanalyzer.data.SipCallSetupAnalyzer
import com.example.layanalyzer.data.SipTransactionCorrelator
import com.example.layanalyzer.data.VoipCall
import com.example.layanalyzer.media.RtpAudioPlayerController
import com.example.layanalyzer.media.RtpPlayerState
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.RtpDecodeRequest
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpDecodedItem
import com.example.layanalyzer.model.RtpMixRequest
import com.example.layanalyzer.model.RtpMixResult
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpTimingMode
import com.example.layanalyzer.model.SipCallSetupAnalysis
import com.example.layanalyzer.model.SipCallSetupCaptureRange
import com.example.layanalyzer.model.SipDialogTimeline
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 「VoIP 呼叫」列表的状态（RTP3-KT-02）。[Idle] 是初始状态，也是会话失效后的状态。
 *
 * [Ready.setup] 是 RTP3-KT-02 对卡片接口的**追加**字段（带默认值，卡片里的
 * `Ready(calls, unlinked, sipTruncated, warnings)` 调用形状不变）：呼叫建立阶段的分析结果，
 * 由只读复用的 [SipCallSetupAnalyzer] 产出，UI-02 的概况区可以直接用。
 *
 * [Ready.dialogs] 是 RTP3-UI-02 的**追加**字段（同样带默认值）：[buildReady] 本来就算出了
 * `SipTransactionCorrelator.correlate(...).dialogs` 却只拿它喂关联器，这里把它一并发布出来，
 * 呼叫详情页才能在 `callId` 上找回自己那条 `SipDialogTimeline`（含 `events`）。默认空表保证
 * RTP3-KT-02 的测试原样编译通过。
 */
sealed interface VoipCallsUiState {
    data object Idle : VoipCallsUiState
    data object Loading : VoipCallsUiState
    data class Ready(
        val calls: List<VoipCall>,
        val unlinked: List<RtpStream>,
        val sipTruncated: Boolean,
        val warnings: List<String>,
        val setup: SipCallSetupAnalysis? = null,
        /** RTP3-UI-02：`callId` → dialog 的原始列表，详情页按 `callId` 取用。 */
        val dialogs: List<SipDialogTimeline> = emptyList()
    ) : VoipCallsUiState
    data class Error(val message: String) : VoipCallsUiState
}

/**
 * 左右声道的静音状态（RTP3-UI-03）。`true` 表示该声道静音。
 *
 * 这是界面与 [RtpAudioPlayerController.setMuted] 之间的**单一来源**：控制器自己也记一份，
 * 但界面只读这里，避免两边各记一份之后开关位置与实际音量不一致。
 */
data class RtpTrackMuteState(
    val left: Boolean = false,
    val right: Boolean = false
)

/**
 * 双轨播放器的一条轨道（RTP3-UI-03）。
 *
 * [offsetMs] 是该轨道在混音共享时间轴上的前置静音时长：原生层给的两条单声道文件都是
 * **各自从本流首包开始**的（见 `RtpJni.cpp` 里 `mix.peaksLeftPath` 直接取自该流的
 * `peaks_path`），共享轴上它自身的时间 `t` 落在 `offsetMs + t`。
 *
 * [stream] 一并带上，是为了让导出用 `rtpWavFileName(stream)` 这个既有的命名口径，
 * 而不是在界面里另造一套文件名。
 */
data class RtpPlayerTrackSource(
    val item: RtpDecodedItem,
    val stream: RtpStream,
    val offsetMs: Long
)

/**
 * 双轨播放器的输入（RTP3-UI-03）。
 *
 * [left] / [right] 是已经按「FORWARD → 左、REVERSE → 右」整理好的两条轨道；[right] 为
 * `null`（或 [mix] 为 `null`）时界面退化为 M2 的单声道呈现——那两种情况都没有对齐过的
 * 立体声可放，硬画第二条轨道只会给出错误的相对时间。
 *
 * [playback] 为 `null` 表示本次选呼叫的解码还没结束（或者从未开始）；解码失败走
 * [VoipCallsViewModel.playback] 的 `error` 字段，不走这里。
 */
data class RtpDualTrackPlayback(
    val callId: String,
    val left: RtpPlayerTrackSource?,
    val right: RtpPlayerTrackSource?,
    val mix: RtpMixResult?
) {
    /** 只有两轨齐备且原生层真的合成了立体声时才是双轨；否则按单声道退化。 */
    val isDualTrack: Boolean get() = mix != null && left != null && right != null
}

/**
 * VoIP 呼叫视图的 ViewModel（RTP3-KT-02）。
 *
 * 一次 [load] 做四件事：并行取通信分析与 RTP 扫描 → 用 [SipTransactionCorrelator] 关联 SIP 事务
 * → [RtpCallLinker] 把流挂到呼叫上 → [SipCallSetupAnalyzer] 产出建立阶段分析。后两步是只读复用，
 * 本类不修改任何分析器的行为，也不新增原生入口。
 *
 * ### 会话失效
 *
 * 与 `RtpViewModel` 完全同构：`sessionHandle` / `sessionGeneration` / `analysisConfigVersion`
 * 任一变化（以及 `limitToDisplayFilter=true` 时 `filterRevision` 变化）都取消在途请求、
 * 丢弃缓存的通信分析、清空 [playback] 并把状态重置为 [Idle]；第一次收到的会话状态只记录，
 * 不做重置（构造完立刻空跑一次没有意义）。
 *
 * ### 并行与线程
 *
 * 所有 JNI 调用都在 `withContext(ioDispatcher)` 里，`ioDispatcher` 与 `externalScope` 都是构造参数
 * （JVM 单测没有 Main dispatcher）。**不使用** `CaptureSessionCoordinator.withNativeSession`：
 * 那是 Agent 专用的单线程调度器，长扫描会挡住 Agent。
 *
 * ### 与 `PacketListViewModel` 的通信分析缓存
 *
 * 卡片要求「复用现有的通信分析结果」，但本仓库没有应用级的共享 `CommunicationAnalysis` 持有者：
 * `PacketViewModelFactory` 无法拿到由 `viewModel(factory = …)` 在 composable 里创建的
 * `PacketListViewModel` 实例（工厂先于实例存在）。因此这里用 [analysisSource] 这个可注入的
 * 取值入口代替——默认实现就是 `packetRepository.buildCommunicationAnalysis()`，
 * 结果按会话三元组缓存在本 ViewModel 内，同一会话内连续 [load] 不会重复触发原生遍历；
 * 换文件或换分析配置（Decode As / 名称解析）会连同缓存一起失效。
 */
class VoipCallsViewModel(
    private val rtpRepository: RtpRepository,
    private val packetRepository: PacketRepository,
    private val sessionCoordinator: CaptureSessionCoordinator,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val externalScope: CoroutineScope? = null,
    /**
     * 解码输出目录的提供者。为 `null` 时 [selectCall] 会直接给出「缓存未配置」的错误，
     * 不会调用原生层（与 `RtpViewModel` 的 `PLAYER_CACHE_UNAVAILABLE_MESSAGE` 同口径）。
     */
    private val mediaCache: RtpMediaCache? = null,
    /**
     * 通信分析的取值入口；默认走 [packetRepository]。存在的理由有二：
     * ① `PacketRepository` 是 final 类，JVM 单测没法给它造假实现；
     * ② 卡片要求复用已有结果，留给上层将来注入共享缓存的口子。
     */
    private val analysisSource: (suspend () -> CommunicationAnalysis)? = null,
    /**
     * `callId` → `(from, to)` 显示名的来源。
     *
     * 卡片说这些名字来自 RTP3-NAT-04 的 `readRtpSetupInfo`，而**该 JNI 入口在本仓库里还不存在**
     * （`RtpJni.cpp` 里只有一条 TODO）。所以这里默认 `null`：`fromTo` 是空表，
     * `VoipCall.from` / `VoipCall.to` 为空串（联接器已经按缺失处理）。本类**不**自造原生调用、
     * **不**自己解析 SIP，也**不**拿端点地址顶替姓名——留好接缝，等 NAT-04 落地后再注入。
     */
    private val fromToProvider: (suspend (List<String>) -> Map<String, Pair<String, String>>)? = null,
    /**
     * RTP3-UI-03：双轨播放器的音频控制器。
     *
     * 默认 `null`（RTP3-KT-02 的测试按默认值构造）：此时播放相关的状态恒为
     * [RtpPlayerState.Idle] / `0`，播放方法全是空操作，**解码与关联行为一字不变**。
     * 有控制器时，本类只在解码成功后装载 `mix.wavPath`（没有 mix 时退化为单条流的单声道文件）。
     */
    private val audioPlayerController: RtpAudioPlayerController? = null
) : ViewModel() {

    private val runScope: CoroutineScope = externalScope ?: viewModelScope

    private val _state = MutableStateFlow<VoipCallsUiState>(VoipCallsUiState.Idle)
    val state: StateFlow<VoipCallsUiState> = _state.asStateFlow()

    /** 选中呼叫后的整个解码结果（含 `unsupported` 与 `mix`）；未选中时为 `null`。 */
    private val _playback = MutableStateFlow<RtpDecodeResult?>(null)
    val playback: StateFlow<RtpDecodeResult?> = _playback.asStateFlow()

    /**
     * RTP3-UI-03：双轨播放器的轨道输入；解码未完成或会话失效时为 `null`。
     *
     * 与 [playback] 是**两份用途不同的状态**：详情页只关心「解出了几条流 / 失败原因」，
     * 播放器页还要知道哪条轨道在共享轴上的哪一段。两者由同一处（[publishDualTrack]）发布，
     * 不会互相矛盾。
     */
    private val _dualTrackPlayback = MutableStateFlow<RtpDualTrackPlayback?>(null)
    val dualTrackPlayback: StateFlow<RtpDualTrackPlayback?> = _dualTrackPlayback.asStateFlow()

    private val idlePlaybackState = MutableStateFlow<RtpPlayerState>(RtpPlayerState.Idle)

    /** 播放器状态；没有注入控制器时恒为 [RtpPlayerState.Idle]（与 `RtpViewModel` 同形）。 */
    val playerPlaybackState: StateFlow<RtpPlayerState> =
        audioPlayerController?.state ?: idlePlaybackState.asStateFlow()

    private val idlePlayerPosition = MutableStateFlow(0L)

    /** 播放位置（毫秒）；没有注入控制器时恒为 `0`。 */
    val playerPositionMs: StateFlow<Long> =
        audioPlayerController?.positionMs ?: idlePlayerPosition.asStateFlow()

    private val _playerMuteState = MutableStateFlow(RtpTrackMuteState())

    /** 左/右声道静音状态；界面只读这里（见 [RtpTrackMuteState]）。 */
    val playerMuteState: StateFlow<RtpTrackMuteState> = _playerMuteState.asStateFlow()

    private var loadJob: Job? = null
    private var decodeJob: Job? = null

    /** 自增的加载请求号：结果返回时与它比较，过期结果直接丢弃。 */
    private var requestId = 0L

    /** 自增的解码请求号；会话失效或再次选呼叫后，旧结果不得覆盖新结果。 */
    private var decodeRequestId = 0L

    /** 自增的媒体请求号；每个解码批次使用独立缓存目录。 */
    private var mediaRequestId = 0L

    private var decodeSessionHandle: Long? = null
    private var decodeMediaRequestId: Long? = null

    /** 最近一次发布的扫描结果：`selectCall` 需要它的 `scanGeneration` 与流列表。 */
    private var lastScan: RtpScanResult? = null

    /** 缓存的通信分析及其会话三元组；只有成功发布 [VoipCallsUiState.Ready] 时才提交。 */
    private var cachedAnalysis: CommunicationAnalysis? = null
    private var cachedAnalysisKey: SessionKey? = null

    /** 最近一次 [load] 使用的 `limitToDisplayFilter`，用于过滤失效判定。 */
    private var lastLimitToDisplayFilter = false

    /** `(sessionHandle, sessionGeneration, analysisConfigVersion)` 三元组的记忆。 */
    private var lastSessionKey: SessionKey? = null

    /** `filterRevision` 的记忆；只在 `limitToDisplayFilter=true` 时参与比较。 */
    private var lastFilterRevision: Long = 0L

    init {
        runScope.launch {
            sessionCoordinator.state.collect { session ->
                val key = session.sessionKey()
                val previousKey = lastSessionKey
                val previousRevision = lastFilterRevision
                // 第一次收到状态时只记录：构造完就立刻空跑一次重置是没有意义的。
                lastSessionKey = key
                lastFilterRevision = session.filterRevision
                if (previousKey == null) return@collect

                val sessionChanged = previousKey != key
                val filterChanged = lastLimitToDisplayFilter && previousRevision != session.filterRevision
                if (sessionChanged || filterChanged) {
                    resetForInvalidation()
                }
            }
        }
    }

    /**
     * 加载当前会话的 VoIP 呼叫列表。
     *
     * 通信分析与 RTP 扫描在 [ioDispatcher] 上**并行**发起；随后在本 ViewModel 内完成 SIP 关联、
     * 流关联与呼叫建立阶段分析。同一会话内重复调用不会重跑通信分析（见类注释）。
     *
     * @param limitToDisplayFilter 跟随「只分析当前过滤结果」开关，默认 false
     */
    fun load(limitToDisplayFilter: Boolean = false) {
        lastLimitToDisplayFilter = limitToDisplayFilter
        val session = sessionCoordinator.state.value
        val request = ++requestId
        loadJob?.cancel()
        loadJob = null
        // UI-03：进入 VoIP 页面时上一次的播放必须已经停下（理由见 selectCall）。
        stopPlaybackForNewRequest()
        cancelPlaybackRequest()
        _playback.value = null
        lastScan = null

        if (!session.hasSession) {
            // 没有会话就打不开呼叫列表；这里不是错误（用户还没打开文件），保持 Idle。
            _state.value = VoipCallsUiState.Idle
            return
        }

        _state.value = VoipCallsUiState.Loading
        val key = session.sessionKey()
        val expectedSession = session.token

        // LAZY + start()：先让 loadJob 指向本次 Job，协程体才开始跑。否则
        // Unconfined/Main.immediate 下协程体会在 launch 返回前就执行，
        // 回调里触发的 cancel() 会看到过期的 loadJob。
        val job = runScope.launch(start = CoroutineStart.LAZY) {
            val loaded = try {
                withContext(ioDispatcher) {
                    coroutineScope {
                        // 卡片要求并行：两个原生遍历各自独立，互不等待。
                        val analysis = async { cachedOrBuildAnalysis(key) }
                        val scan = async { rtpRepository.scanRtpStreams(limitToDisplayFilter) }
                        analysis.await() to scan.await()
                    }
                }
            } catch (cancelled: CancellationException) {
                // 取消不是失败：不提交任何状态，交由 cancel()/失效规则负责。
                throw cancelled
            } catch (error: Throwable) {
                commitErrorIfCurrent(request, expectedSession, error.message ?: LOAD_FAILED_MESSAGE)
                return@launch
            }
            if (isStale(request, expectedSession)) return@launch

            val (analysis, scan) = loaded
            analysis.error?.takeIf { it.isNotBlank() }?.let { message ->
                _state.value = VoipCallsUiState.Error(message)
                return@launch
            }
            if (scan.cancelled) {
                _state.value = VoipCallsUiState.Error(SCAN_CANCELLED_MESSAGE)
                return@launch
            }
            if (scan.error.isNotEmpty()) {
                _state.value = VoipCallsUiState.Error(scan.error)
                return@launch
            }

            val ready = try {
                withContext(ioDispatcher) { buildReady(analysis, scan, limitToDisplayFilter) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                commitErrorIfCurrent(request, expectedSession, error.message ?: LOAD_FAILED_MESSAGE)
                return@launch
            }
            if (isStale(request, expectedSession)) return@launch

            cachedAnalysis = analysis
            cachedAnalysisKey = key
            lastScan = scan
            _state.value = ready
        }
        loadJob = job
        job.start()
    }

    /**
     * 选中一通呼叫并解码它的双向音频。
     *
     * 左声道固定取 `FORWARD`（主叫 → 被叫），右声道取 `REVERSE`（卡片要求）；只有一个方向时
     * 只解那一条流（不带 `mix`，因为原生层要求 `mix.left` 与 `mix.right` 不同且在 `streams` 里）；
     * 一条流都没有（或没有可用的关联流）时给出明确的播放错误，不调用原生层。
     *
     * 结果整份（含 `unsupported` 与 `mix`）发布到 [playback]，UI 据此展示每条流的失败原因。
     */
    fun selectCall(callId: String) {
        val call = (_state.value as? VoipCallsUiState.Ready)
            ?.calls
            ?.firstOrNull { it.callId == callId }
            ?: return

        // RTP3-UI-03：无论这次选呼叫最后成不成功，先把正在放的音频停住。上一批解码产物马上会被
        // deleteDecodeRequest 删掉，而 Android 会保留已打开 fd 的文件内容——不停的话，旧呼叫的
        // 音频会在新呼叫解码期间继续从被删除的文件里响。
        stopPlaybackForNewRequest()

        val scan = lastScan
        if (scan == null || !scan.isSuccess) {
            _playback.value = decodeError(PLAYER_SCAN_REQUIRED_MESSAGE)
            return
        }
        val cache = mediaCache
        if (cache == null) {
            _playback.value = decodeError(PLAYER_CACHE_UNAVAILABLE_MESSAGE)
            return
        }
        val session = sessionCoordinator.state.value
        if (!session.hasSession) {
            _playback.value = decodeError(PLAYER_NO_SESSION_MESSAGE)
            return
        }

        val forward = call.streams.firstOrNull { it.direction == RtpStreamDirection.FORWARD }?.stream
        val reverse = call.streams.firstOrNull { it.direction == RtpStreamDirection.REVERSE }?.stream
        // 方向判不出来（表 2 的 UNKNOWN）时退化为「解第一条流」，总比什么都不放要好；
        // 一条流都没有才是真的没得放。
        val left = forward ?: reverse ?: call.streams.firstOrNull()?.stream
        if (left == null) {
            _playback.value = decodeError(PLAYER_NO_STREAMS_MESSAGE)
            return
        }
        val right = if (forward != null && reverse != null && reverse.id != left.id) reverse else null
        val mix = right?.let { RtpMixRequest(leftStreamId = left.id, rightStreamId = it.id) }
        // 混音的两路必须同时出现在 streams 里（原生解析器会校验），这里正好就是这两条。
        val streamIds = if (right != null) listOf(left.id, right.id) else listOf(left.id)

        decodeRequestId += 1
        val attempt = decodeRequestId
        decodeJob?.cancel()
        decodeJob = null
        sessionCoordinator.cancelLongRunningOperations()
        deleteDecodeRequest()

        val mediaRequest = nextMediaRequestId()
        val outDir = runCatching { cache.dirFor(session.sessionHandle, mediaRequest) }.getOrElse { error ->
            _playback.value = decodeError(error.message ?: PLAYER_DECODE_FAILED_MESSAGE)
            return
        }
        decodeSessionHandle = session.sessionHandle
        decodeMediaRequestId = mediaRequest
        val expectedSession = session.token
        _playback.value = null

        val decodeRequest = RtpDecodeRequest(
            scanGeneration = scan.scanGeneration,
            streamIds = streamIds,
            timing = RtpTimingMode.JITTER,
            jitterMs = PLAYER_JITTER_MS,
            mix = mix,
            dtmf = true,
            // RTP4-KT-03：按编码路由（RTP4-KT-02）需要这两条流各自的规范 ID；
            // 混音请求里它们仍会被路由到原生一侧，所以这里只是把表填全。
            streamCodecs = buildMap {
                put(left.id, left.codec)
                right?.let { put(it.id, it.codec) }
            }
        )

        val job = runScope.launch(start = CoroutineStart.LAZY) {
            val result = try {
                withContext(ioDispatcher) {
                    rtpRepository.decodeAudio(
                        request = decodeRequest,
                        outDir = outDir,
                        onProgress = {
                            // 返回 false 即请求原生层取消：只有本次请求且会话没换才继续。
                            attempt == decodeRequestId && sessionCoordinator.isCurrent(expectedSession)
                        }
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                if (
                    attempt == decodeRequestId &&
                    sessionCoordinator.isCurrent(expectedSession)
                ) {
                    _playback.value = decodeError(error.message ?: PLAYER_DECODE_FAILED_MESSAGE)
                }
                return@launch
            }

            if (attempt != decodeRequestId || !sessionCoordinator.isCurrent(expectedSession)) {
                runCatching { cache.deleteRequest(session.sessionHandle, mediaRequest) }
                return@launch
            }
            _playback.value = result
            publishDualTrack(call, left, right, result)
        }
        decodeJob = job
        job.start()
    }

    /**
     * RTP3-UI-03：播放 / 暂停。
     *
     * 只在控制器已经有音源时切换；解码未完成时按「播放」什么都不会发生（控制器处于
     * [RtpPlayerState.Preparing] 时 `play()` 也只是登记「准备好就开始」，不会报错）。
     */
    fun playPause() {
        val controller = audioPlayerController ?: return
        if (controller.state.value == RtpPlayerState.Playing) {
            controller.pause()
        } else {
            controller.play()
        }
    }

    /** RTP3-UI-03：跳到共享时间轴上的 [positionMs]。 */
    fun seekPlayer(positionMs: Long) {
        audioPlayerController?.seekTo(positionMs)
    }

    /**
     * RTP3-UI-03：设置左右声道静音。`true` = 静音（控制器把该声道音量设 0）。
     *
     * 没有控制器时只更新状态：界面开关与状态保持一致，无音频环境（JVM 单测）也能走通。
     */
    fun setTrackMuted(left: Boolean, right: Boolean) {
        _playerMuteState.value = RtpTrackMuteState(left = left, right = right)
        audioPlayerController?.setMuted(left, right)
    }

    /**
     * RTP3-UI-03：关闭播放器（离开 VoIP 页面、返回键、或解码中取消）。
     *
     * 停放音频后取消在途解码：**已完成的**解码产物保留给详情页与导出（与
     * `RtpViewModel.closePlayer` 同一理由——导出/分享可能还在读那个 WAV），停放在删除之前发生，
     * 所以不会出现「音频继续从一个已被 unlink 的文件里放」的情况。
     */
    fun closePlayback() {
        audioPlayerController?.pause()
        val finished = _playback.value?.let { it.isSuccess && it.items.isNotEmpty() } == true
        if (!finished) {
            cancelPlaybackRequest()
        }
        _dualTrackPlayback.value = null
    }

    override fun onCleared() {
        loadJob?.cancel()
        decodeJob?.cancel()
        audioPlayerController?.release()
        super.onCleared()
    }

    // ---------------------------------------------------------------- 内部实现

    /** 会话三元组命中缓存就用缓存，否则向 [analysisSource]（或仓库）要一份新的。 */
    private suspend fun cachedOrBuildAnalysis(key: SessionKey): CommunicationAnalysis {
        cachedAnalysis?.let { if (cachedAnalysisKey == key) return it }
        return analysisSource?.invoke() ?: packetRepository.buildCommunicationAnalysis()
    }

    /**
     * 关联与呼叫建立分析（纯 Kotlin，仍在 [ioDispatcher] 上执行）。
     *
     * `timelines` 走 `SipTransactionCorrelator.correlate(...)`（卡片指定，且是一次廉价的
     * 纯 Kotlin 过程），`callIds` 取 dialog 的 `callId` —— 没有可见 SIP dialog 的呼叫无法关联。
     */
    private suspend fun buildReady(
        analysis: CommunicationAnalysis,
        scan: RtpScanResult,
        limitToDisplayFilter: Boolean
    ): VoipCallsUiState.Ready {
        val timelines = SipTransactionCorrelator.correlate(analysis.sipMessages).dialogs
        val callIds = timelines.map { it.callId }.distinct()
        val fromTo = fromToProvider?.invoke(callIds) ?: emptyMap()
        val linked = RtpCallLinker.link(
            callIds = callIds,
            fromTo = fromTo,
            timelines = timelines,
            streams = scan.streams,
            sipTruncated = analysis.sipTruncated
        )
        val setup = SipCallSetupAnalyzer.analyze(
            timelines = timelines,
            coreEvents = analysis.coreMessages,
            captureRange = captureRange(analysis, limitToDisplayFilter)
        )
        return VoipCallsUiState.Ready(
            calls = linked.calls,
            unlinked = linked.unlinkedStreams,
            sipTruncated = analysis.sipTruncated,
            warnings = linked.warnings,
            setup = setup,
            // RTP3-UI-02：详情页要按 callId 找回 dialog 的 events，这里把已经算好的原样发布。
            dialogs = timelines
        )
    }

    /**
     * 呼叫建立分析的抓包范围。
     *
     * 与 `CommunicationAnalysisTool` 的同名构造保持同一口径（`sipSourceTruncated`、
     * `scopeIsFiltered`、帧号来自会话），但**本项目拿不到** `CaptureStatistics`——那需要再跑一次原生统计。
     * 因此 `startTime` / `endTime` 退化为「可见 SIP 消息的时间跨度」：对负证据判定来说这是保守方向
     * （把抓包终点报得比真实更早，只会让「没有最终响应」这类结论更难成立）。
     */
    private fun captureRange(
        analysis: CommunicationAnalysis,
        limitToDisplayFilter: Boolean
    ): SipCallSetupCaptureRange {
        val session = sessionCoordinator.state.value
        val times = analysis.sipMessages.map { it.time }
        val hasFrames = session.frameCount > 0
        return SipCallSetupCaptureRange(
            firstFrame = 1L.takeIf { hasFrames },
            lastFrame = session.frameCount.toLong().takeIf { hasFrames },
            startTime = times.minOrNull(),
            endTime = times.maxOrNull(),
            sipSourceTruncated = analysis.sipTruncated,
            scopeIsFiltered = limitToDisplayFilter || session.appliedDisplayFilter.isNotBlank(),
            displayFilter = session.appliedDisplayFilter
        )
    }

    /** 会话语义上的失效：取消在途工作、清掉会话级结果与缓存、回到 [VoipCallsUiState.Idle]。 */
    private fun resetForInvalidation() {
        requestId += 1
        loadJob?.cancel()
        loadJob = null
        // UI-03：先停放音频，再让 cancelPlaybackRequest 删掉旧请求目录（理由见 selectCall）。
        stopPlaybackForNewRequest()
        cancelPlaybackRequest()
        sessionCoordinator.cancelLongRunningOperations()
        cachedAnalysis = null
        cachedAnalysisKey = null
        lastScan = null
        mediaRequestId = 0L
        _playback.value = null
        _state.value = VoipCallsUiState.Idle
    }

    /** 停放音频并清掉上一份双轨输入；删除旧请求目录之前必须先调用它。 */
    private fun stopPlaybackForNewRequest() {
        audioPlayerController?.pause()
        _dualTrackPlayback.value = null
    }

    /**
     * 把一次成功的解码结果整理成双轨播放器输入，并在有音源时装载音频。
     *
     * **只装载一个音源**：有 `mix` 时装 `mix.wavPath`（两路已经对齐的立体声），否则装主方向那条
     * 单声道文件。绝不把两条单声道文件分别塞给两个播放器——它们的起始时刻不同，各放各的必然漂移，
     * 共享时间轴上的播放头就没有意义了。
     */
    private fun publishDualTrack(
        call: VoipCall,
        leftStream: RtpStream,
        rightStream: RtpStream?,
        result: RtpDecodeResult
    ) {
        val mix = result.mix
        val leftItem = result.items.firstOrNull { it.streamId == leftStream.id }
        val rightItem = rightStream?.let { stream ->
            result.items.firstOrNull { it.streamId == stream.id }
        }
        // 没有 mix 时右轨为 null：两条轨道没有对齐基准，硬画第二条只会给出错误的相对时间。
        val rightSource = if (mix != null && rightStream != null && rightItem != null) {
            RtpPlayerTrackSource(item = rightItem, stream = rightStream, offsetMs = mix.rightOffsetMs)
        } else {
            null
        }
        _dualTrackPlayback.value = RtpDualTrackPlayback(
            callId = call.callId,
            left = leftItem?.let {
                RtpPlayerTrackSource(item = it, stream = leftStream, offsetMs = mix?.leftOffsetMs ?: 0L)
            },
            right = rightSource,
            mix = mix
        )

        val source = mix?.wavPath?.takeIf(String::isNotBlank)
            ?: leftItem?.wavPath?.takeIf(String::isNotBlank)
            ?: return
        // 先同步静音状态再装载：控制器装载时也会重新应用一次自己的音量，两边必须一致。
        audioPlayerController?.setMuted(_playerMuteState.value.left, _playerMuteState.value.right)
        audioPlayerController?.load(source)
    }

    /** 取消在途解码并抹掉本次请求号，让迟到结果无法提交；已发布的 [playback] 由调用方决定。 */
    private fun cancelPlaybackRequest() {
        decodeRequestId += 1
        decodeJob?.cancel()
        decodeJob = null
        deleteDecodeRequest()
    }

    private fun deleteDecodeRequest() {
        val sessionHandle = decodeSessionHandle
        val request = decodeMediaRequestId
        decodeSessionHandle = null
        decodeMediaRequestId = null
        if (sessionHandle != null && request != null) {
            mediaCache?.deleteRequest(sessionHandle, request)
        }
    }

    private fun nextMediaRequestId(): Long = ++mediaRequestId

    /** 请求号或会话已经不匹配：结果必须丢弃，绝不能提交。 */
    private fun isStale(request: Long, expectedSession: CaptureSessionToken): Boolean =
        request != requestId || !sessionCoordinator.isCurrent(expectedSession)

    private fun commitErrorIfCurrent(
        request: Long,
        expectedSession: CaptureSessionToken,
        message: String
    ) {
        if (!isStale(request, expectedSession)) {
            _state.value = VoipCallsUiState.Error(message)
        }
    }

    private fun decodeError(message: String): RtpDecodeResult = RtpDecodeResult(
        error = message,
        cancelled = false,
        items = emptyList(),
        unsupported = emptyList()
    )

    private data class SessionKey(
        val sessionHandle: Long,
        val sessionGeneration: Long,
        val analysisConfigVersion: Int
    )

    private fun CaptureSessionState.sessionKey(): SessionKey = SessionKey(
        sessionHandle = sessionHandle,
        sessionGeneration = sessionGeneration,
        analysisConfigVersion = analysisConfigVersion
    )

    private companion object {
        const val LOAD_FAILED_MESSAGE = "Unable to build the VoIP call list."
        const val SCAN_CANCELLED_MESSAGE = "RTP scan was cancelled."
        const val PLAYER_JITTER_MS = 50
        const val PLAYER_SCAN_REQUIRED_MESSAGE = "Scan RTP streams before playing audio."
        const val PLAYER_CACHE_UNAVAILABLE_MESSAGE = "RTP media cache is not configured."
        const val PLAYER_NO_SESSION_MESSAGE = "No capture is open."
        const val PLAYER_NO_STREAMS_MESSAGE = "This call has no linked RTP stream to play."
        const val PLAYER_DECODE_FAILED_MESSAGE = "Unable to render RTP audio."
    }
}
