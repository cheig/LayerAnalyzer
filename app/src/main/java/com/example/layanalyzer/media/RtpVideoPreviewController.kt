// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import android.content.Context
import android.media.AudioAttributes
import android.media.MediaPlayer
import android.view.Surface
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * RTP5-KT-03：`MediaPlayer` 的接缝，形状与 [PlayerFacade] 一一对应。
 *
 * 额外多出三样视频才有的东西：
 *  - [setSurface]：视频要渲染到 `TextureView` 的 `SurfaceTexture` 上。传 `null` 表示
 *    「放开这个 Surface」（见 [RtpVideoPreviewController.detachSurface]）。
 *  - [onSeekComplete]：`seekTo` 是异步的，「上一次拖动还没落地」是这里唯一要防的竞态，
 *    没有这个回调就只能靠猜。
 *  - [durationMs] 会被**发布**出去（[RtpVideoPreviewController.durationMs]）：音频播放器
 *    的时长来自解码结果，视频预览的时长只有播放器知道。
 *
 * 与 [PlayerFacade] 一样，接口上只出现基本类型、`String` 和 [Surface] —— 这样 JVM 单测可以
 * 用一个 fake 把整套状态机跑完，不必有设备。
 */
interface VideoPreviewPlayerFacade {
    fun setDataSource(path: String)
    fun setSurface(surface: Surface?)
    fun prepareAsync()
    fun start()
    fun pause()
    fun seekTo(ms: Long)
    fun release()

    val durationMs: Long
    val positionMs: Long
    val isPlaying: Boolean

    var onPrepared: (() -> Unit)?
    var onCompletion: (() -> Unit)?
    var onError: ((String) -> Unit)?
    var onSeekComplete: (() -> Unit)?
}

/**
 * RTP5-KT-03：应用内预览的播放状态机，[RtpAudioPlayerController] 的视频版兄弟。
 *
 * 复用音频那套状态词（[RtpPlayerState]）而不是再定义一份：对界面而言「一个媒体文件在放」
 * 就是那几个状态，两个播放器各说各话只会让宿主多写一遍 `when`。
 *
 * 它拥有 `MediaPlayer` 的生命周期：prepare / play / pause / seek / release，位置由一个
 * 50 ms 的 ticker 轮询发布。**释放**只在 [release]（宿主在 `ViewModel.onCleared` 里调）和
 * 替换数据源时发生，[detachSurface] 只暂停不释放 —— 释放掉的话，屏幕因为配置变化重建就
 * 再也放不起来了。
 *
 * **拖动（seek）与忙碌**。`MediaPlayer.seekTo` 只能在 Prepared/Started/Paused/PlaybackCompleted
 * 状态调用，而且从 API 26 起是异步的。所以：
 *  - 播放器还在 `Preparing`（`onPrepared` 没回来）时来的 seek**不调用播放器**：位置记进
 *    [pendingSeekMs]，同时立刻发布到 [positionMs]（用户拖动的位置要马上看到），
 *    `onPrepared` 里先把它应用掉再开始播。
 *  - 上一次 `seekTo` 还没等到 `onSeekComplete` 时来的 seek 也不调用播放器，而是**合并**到
 *    [pendingSeekMs]：拖动会连着来几十次，逐个下发给一个还在处理上一次调用的播放器既没意义
 *    也不安全。`onSeekComplete` 里把最后那个位置补上。
 *  两种情况都不静默丢弃：位置一直发布在 [positionMs] 上，补应用后还会从播放器回读一次。
 *
 * @param tickMillis 位置轮询间隔；单测传一个大值让 ticker 不干扰断言（与音频控制器同）。
 */
class RtpVideoPreviewController(
    private val facade: VideoPreviewPlayerFacade,
    private val scope: CoroutineScope,
    private val tickMillis: Long = 50L
) {
    private val _state = MutableStateFlow<RtpPlayerState>(RtpPlayerState.Idle)
    val state: StateFlow<RtpPlayerState> = _state.asStateFlow()

    private val _positionMs = MutableStateFlow(0L)
    val positionMs: StateFlow<Long> = _positionMs.asStateFlow()

    private val _durationMs = MutableStateFlow(0L)
    val durationMs: StateFlow<Long> = _durationMs.asStateFlow()

    private var tickerJob: Job? = null
    private var currentPath: String? = null

    /** 自增的加载代次：过期的回调（上一次的 `onPrepared`/`onCompletion`）直接丢弃。 */
    private var loadGeneration = 0L
    private var playWhenPrepared = false
    private var released = false

    /** 当前绑定的 Surface；可能比播放器先到（TextureView 的回调总是晚一步）。 */
    private var surface: Surface? = null

    /** 还没下发给播放器的目标位置；`null` 表示没有欠账。 */
    private var pendingSeekMs: Long? = null

    /** 已经下发、正在等 `onSeekComplete`。 */
    private var seekInFlight = false

    /**
     * 打开 [mp4Path]：准备好就播。同一个路径重复调用是空操作，
     * 免得重组把正在放的视频拽回开头。
     */
    fun load(mp4Path: String) {
        if (released || mp4Path == currentPath) return

        val replacingExistingSource = currentPath != null
        stopTicker()
        clearFacadeCallbacks()
        if (replacingExistingSource) {
            runCatching { facade.release() }
        }

        val generation = ++loadGeneration
        currentPath = mp4Path
        playWhenPrepared = true
        // 新数据源不该继承上一次的欠账：那些位置说的是另一个文件的时间轴。
        pendingSeekMs = null
        seekInFlight = false
        _positionMs.value = 0L
        _durationMs.value = 0L
        _state.value = RtpPlayerState.Preparing

        facade.onPrepared = { handlePrepared(generation) }
        facade.onCompletion = { handleCompletion(generation) }
        facade.onError = { message -> handleError(generation, message) }
        facade.onSeekComplete = { handleSeekComplete(generation) }

        try {
            facade.setDataSource(mp4Path)
            surface?.let { facade.setSurface(it) }
            facade.prepareAsync()
        } catch (error: Exception) {
            handleError(generation, error.message ?: LOAD_FAILED_MESSAGE)
        }
    }

    /**
     * 把 [surface]（`TextureView` 的 `SurfaceTexture` 包出来的那个）交给播放器。
     *
     * 可以早于 [load] 调用：Surface 在这里存下来，`load` 时一起下发。这**不是**多余的
     * 保险 —— `TextureView` 的 `onSurfaceTextureAvailable` 与宿主什么时候 `load` 没有
     * 先后关系，两种顺序都必须成立。
     */
    fun attachSurface(surface: Surface) {
        if (released) return
        this.surface = surface
        if (currentPath != null) {
            runCatching { facade.setSurface(surface) }
        }
    }

    /**
     * 放开当前 Surface，并在正在播放时暂停。
     *
     * 暂停是刻意的：`TextureView` 消失时框架会释放 `SurfaceTexture`（listener 返回 true），
     * 继续往一个已经释放的纹理上渲染是未定义行为，而 `MediaPlayer.setSurface(null)` 是否真
     * 的放开旧 Surface 在各 API 版本上并不一致。宁可停下来，也不要留一个还在解码的播放器
     * 指着一块已经不存在的纹理。
     */
    fun detachSurface() {
        if (released) return
        surface = null
        if (currentPath != null) {
            runCatching { facade.setSurface(null) }
        }
        if (_state.value == RtpPlayerState.Playing) {
            pause()
        }
    }

    /** 播放；`Preparing` 时记下来，`onPrepared` 之后自动开始。 */
    fun play() {
        if (released || currentPath == null) return

        when (_state.value) {
            RtpPlayerState.Preparing -> {
                playWhenPrepared = true
            }

            RtpPlayerState.Paused -> {
                playWhenPrepared = true
                startPlayback()
            }

            // 播完之后再按播放：从头来一遍。显式 seek 到 0 再 start，与音频控制器同口径，
            // 不依赖「PlaybackCompleted 状态下 start() 会回到开头」这条各版本说法不一的规则。
            RtpPlayerState.Completed -> {
                playWhenPrepared = true
                seekTo(0L)
                startPlayback()
            }

            RtpPlayerState.Playing,
            RtpPlayerState.Idle,
            is RtpPlayerState.Error -> Unit
        }
    }

    fun pause() {
        if (released) return
        playWhenPrepared = false
        val wasPlaying = _state.value == RtpPlayerState.Playing
        if (wasPlaying) {
            try {
                facade.pause()
            } catch (error: Exception) {
                handleError(loadGeneration, error.message ?: PAUSE_FAILED_MESSAGE)
                return
            }
        }
        stopTicker()
        if (wasPlaying) {
            _positionMs.value = safePosition()
            _state.value = RtpPlayerState.Paused
        }
    }

    /**
     * 拖动到 [ms]。
     *
     * 位置**立刻**发布（用户拖动的位置要马上看到），是否真的下发给播放器由「忙不忙」决定，
     * 见类注释里的两条规则。没打开数据源、以及已经失败的状态一律不动播放器。
     */
    fun seekTo(ms: Long) {
        if (released || currentPath == null) return
        if (_state.value is RtpPlayerState.Error || _state.value == RtpPlayerState.Idle) return

        val duration = safeDuration()
        val target = if (duration > 0L) ms.coerceIn(0L, duration) else ms.coerceAtLeast(0L)
        _positionMs.value = target
        if (_state.value == RtpPlayerState.Completed) {
            _state.value = RtpPlayerState.Paused
        }

        // Preparing：播放器还不是个能收 seek 的状态。
        if (_state.value == RtpPlayerState.Preparing || seekInFlight) {
            pendingSeekMs = target
            return
        }

        try {
            facade.seekTo(target)
            seekInFlight = true
        } catch (error: Exception) {
            handleError(loadGeneration, error.message ?: SEEK_FAILED_MESSAGE)
        }
    }

    /** 释放播放器。幂等；释放之后再调任何播放函数都是空操作。 */
    fun release() {
        if (released) return
        released = true
        playWhenPrepared = false
        stopTicker()
        clearFacadeCallbacks()
        runCatching { facade.release() }
        currentPath = null
        surface = null
        pendingSeekMs = null
        seekInFlight = false
        _positionMs.value = 0L
        _durationMs.value = 0L
        _state.value = RtpPlayerState.Idle
    }

    private fun handlePrepared(generation: Long) {
        if (!isCurrent(generation)) return
        _durationMs.value = safeDuration()

        // 欠着的拖动先补上，再决定要不要开始播 —— 顺序反过来的话会先闪一帧旧位置。
        val pending = pendingSeekMs
        if (pending != null) {
            pendingSeekMs = null
            try {
                facade.seekTo(pending)
                seekInFlight = true
            } catch (error: Exception) {
                handleError(generation, error.message ?: SEEK_FAILED_MESSAGE)
                return
            }
        }

        if (!playWhenPrepared) {
            _state.value = RtpPlayerState.Paused
            return
        }
        startPlayback()
    }

    private fun handleSeekComplete(generation: Long) {
        if (!isCurrent(generation)) return
        seekInFlight = false

        val pending = pendingSeekMs
        if (pending != null) {
            pendingSeekMs = null
            try {
                facade.seekTo(pending)
                seekInFlight = true
            } catch (error: Exception) {
                handleError(generation, error.message ?: SEEK_FAILED_MESSAGE)
            }
            return
        }
        // 没有欠账才回读：正在播放时 ticker 马上会覆盖它，暂停时它才是权威值。
        _positionMs.value = safePosition()
    }

    private fun handleCompletion(generation: Long) {
        if (!isCurrent(generation)) return
        stopTicker()
        playWhenPrepared = false
        _positionMs.value = safeDuration()
        _state.value = RtpPlayerState.Completed
    }

    private fun handleError(generation: Long, message: String) {
        if (!isCurrent(generation)) return
        stopTicker()
        playWhenPrepared = false
        pendingSeekMs = null
        seekInFlight = false
        _state.value = RtpPlayerState.Error(message.ifBlank { PLAYER_FAILED_MESSAGE })
        // 报错之后这一次加载就结束了：把代次推一格，迟到的 onPrepared / onSeekComplete
        // 一律丢弃，不能让它们把 Error 又改回 Paused 或 Playing。
        loadGeneration += 1
        // 同时忘掉数据源：否则「同一个路径的 load 是空操作」这条规则会让错误之后再想
        // 重试同一个文件的调用什么也做不了。
        currentPath = null
    }

    private fun startPlayback() {
        if (released) return
        if (!playWhenPrepared) {
            _state.value = RtpPlayerState.Paused
            return
        }
        try {
            facade.start()
            _state.value = RtpPlayerState.Playing
            startTicker()
        } catch (error: Exception) {
            handleError(loadGeneration, error.message ?: PLAY_FAILED_MESSAGE)
        }
    }

    private fun startTicker() {
        stopTicker()
        tickerJob = scope.launch {
            while (isActive && !released && _state.value == RtpPlayerState.Playing) {
                _positionMs.value = safePosition()
                delay(tickMillis.coerceAtLeast(1L))
            }
        }
    }

    private fun stopTicker() {
        tickerJob?.cancel()
        tickerJob = null
    }

    private fun clearFacadeCallbacks() {
        facade.onPrepared = null
        facade.onCompletion = null
        facade.onError = null
        facade.onSeekComplete = null
    }

    private fun safeDuration(): Long =
        runCatching { facade.durationMs }
            .getOrDefault(0L)
            .coerceAtLeast(0L)

    private fun safePosition(): Long =
        runCatching { facade.positionMs }
            .getOrDefault(_positionMs.value)
            .coerceAtLeast(0L)

    private fun isCurrent(generation: Long): Boolean =
        !released && generation == loadGeneration

    private companion object {
        const val LOAD_FAILED_MESSAGE = "Unable to prepare this video."
        const val PLAY_FAILED_MESSAGE = "Unable to play this video."
        const val PAUSE_FAILED_MESSAGE = "Unable to pause this video."
        const val SEEK_FAILED_MESSAGE = "Unable to seek this video."
        const val PLAYER_FAILED_MESSAGE = "Video playback failed."
    }
}

/**
 * [VideoPreviewPlayerFacade] 的 `MediaPlayer` 实现。
 *
 * 播放器**第一次用到时才建**（与 [AndroidMediaPlayerFacade] 同），并且把已经收到的 Surface
 * 在建出来的时候一并交过去：`attachSurface` 早于第一次 `setDataSource` 是完全正常的顺序。
 *
 * `setSurface(null)` 在这里被 `runCatching` 包着：新旧 API 上它是否真的放开旧 Surface 说法
 * 不一，这里不靠它保证正确性 —— 正确性由 [RtpVideoPreviewController.detachSurface] 的
 * 「先暂停」承担。
 */
class AndroidVideoPreviewPlayerFacade(context: Context) : VideoPreviewPlayerFacade {
    private val appContext = context.applicationContext
    private var mediaPlayer: MediaPlayer? = null
    private var surface: Surface? = null

    override var onPrepared: (() -> Unit)? = null
    override var onCompletion: (() -> Unit)? = null
    override var onError: ((String) -> Unit)? = null
    override var onSeekComplete: (() -> Unit)? = null

    override fun setDataSource(path: String) {
        currentPlayer().setDataSource(path)
    }

    override fun setSurface(surface: Surface?) {
        this.surface = surface
        val player = mediaPlayer ?: return
        runCatching { player.setSurface(surface) }
    }

    override fun prepareAsync() {
        currentPlayer().prepareAsync()
    }

    override fun start() {
        currentPlayer().start()
    }

    override fun pause() {
        currentPlayer().pause()
    }

    override fun seekTo(ms: Long) {
        currentPlayer().seekTo(ms.coerceIn(0L, Int.MAX_VALUE.toLong()).toInt())
    }

    override fun release() {
        val player = mediaPlayer
        mediaPlayer = null
        if (player != null) {
            runCatching { player.reset() }
            runCatching { player.release() }
        }
    }

    override val durationMs: Long
        get() = mediaPlayer?.let { player ->
            runCatching { player.duration.toLong() }.getOrDefault(0L)
        }?.coerceAtLeast(0L) ?: 0L

    override val positionMs: Long
        get() = mediaPlayer?.let { player ->
            runCatching { player.currentPosition.toLong() }.getOrDefault(0L)
        }?.coerceAtLeast(0L) ?: 0L

    override val isPlaying: Boolean
        get() = mediaPlayer?.let { player ->
            runCatching { player.isPlaying }.getOrDefault(false)
        } ?: false

    private fun currentPlayer(): MediaPlayer =
        mediaPlayer ?: MediaPlayer().also { player ->
            player.setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_MOVIE)
                    .build()
            )
            player.setOnPreparedListener { onPrepared?.invoke() }
            player.setOnCompletionListener { onCompletion?.invoke() }
            player.setOnSeekCompleteListener { onSeekComplete?.invoke() }
            player.setOnErrorListener { _, what, extra ->
                onError?.invoke("MediaPlayer error ($what, $extra)")
                true
            }
            mediaPlayer = player
            surface?.let { player.setSurface(it) }
        }
}
