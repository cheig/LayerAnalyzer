// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFocusRequest
import android.media.AudioManager
import android.media.MediaPlayer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** RTP audio playback state exposed to the player UI. */
sealed interface RtpPlayerState {
    data object Idle : RtpPlayerState
    data object Preparing : RtpPlayerState
    data object Playing : RtpPlayerState
    data object Paused : RtpPlayerState
    data object Completed : RtpPlayerState
    data class Error(val message: String) : RtpPlayerState
}

/** Small abstraction around MediaPlayer so controller behavior is JVM-testable. */
interface PlayerFacade {
    fun setDataSource(path: String)
    fun prepareAsync()
    fun start()
    fun pause()
    fun seekTo(ms: Long)
    fun release()
    fun setVolume(left: Float, right: Float)

    val durationMs: Long
    val positionMs: Long
    val isPlaying: Boolean

    var onPrepared: (() -> Unit)?
    var onCompletion: (() -> Unit)?
    var onError: ((String) -> Unit)?
}

/** Optional audio-focus integration kept separate from MediaPlayer. */
interface AudioFocusFacade {
    fun requestAudioFocus(onFocusChange: (Int) -> Unit): Boolean
    fun abandonAudioFocus()
}

/**
 * Owns playback state and the position ticker for one RTP WAV file.
 *
 * [load] prepares and starts playback by default; autoPlay = false waits for [play].
 * Re-loading the same path is a no-op so repeated UI recompositions cannot reset
 * the active stream.
 */
class RtpAudioPlayerController(
    private val facade: PlayerFacade,
    private val scope: CoroutineScope,
    private val tickMillis: Long = 50L,
    private val audioFocus: AudioFocusFacade? = null
) {
    private val _state = MutableStateFlow<RtpPlayerState>(RtpPlayerState.Idle)
    val state: StateFlow<RtpPlayerState> = _state.asStateFlow()

    private val _positionMs = MutableStateFlow(0L)
    val positionMs: StateFlow<Long> = _positionMs.asStateFlow()

    private var tickerJob: Job? = null
    private var currentPath: String? = null
    private var loadGeneration = 0L
    private var playWhenPrepared = false
    private var released = false
    private var hasAudioFocus = false
    private var ducking = false
    private var leftMuted = false
    private var rightMuted = false

    fun load(wavPath: String, autoPlay: Boolean = true) {
        if (released || wavPath == currentPath) return

        val replacingExistingSource = currentPath != null
        stopTicker()
        abandonAudioFocus()
        facade.onPrepared = null
        facade.onCompletion = null
        facade.onError = null
        if (replacingExistingSource) {
            runCatching { facade.release() }
        }

        val generation = ++loadGeneration
        currentPath = wavPath
        playWhenPrepared = autoPlay
        ducking = false
        _positionMs.value = 0L
        _state.value = RtpPlayerState.Preparing

        facade.onPrepared = { handlePrepared(generation) }
        facade.onCompletion = { handleCompletion(generation) }
        facade.onError = { message -> handleError(generation, message) }

        try {
            facade.setDataSource(wavPath)
            facade.prepareAsync()
        } catch (error: Exception) {
            handleError(generation, error.message ?: LOAD_FAILED_MESSAGE)
        }
    }

    fun play() {
        if (released) return

        when (_state.value) {
            RtpPlayerState.Preparing -> {
                playWhenPrepared = true
                requestAudioFocus()
            }

            RtpPlayerState.Paused -> {
                playWhenPrepared = true
                startPlayback()
            }

            RtpPlayerState.Completed -> {
                playWhenPrepared = true
                try {
                    facade.seekTo(0L)
                    _positionMs.value = 0L
                    startPlayback()
                } catch (error: Exception) {
                    handleError(loadGeneration, error.message ?: PLAY_FAILED_MESSAGE)
                }
            }

            RtpPlayerState.Playing,
            RtpPlayerState.Idle,
            is RtpPlayerState.Error -> Unit
        }
    }

    fun pause() {
        if (released) return
        pauseInternal(abandonFocus = true)
    }

    fun seekTo(ms: Long) {
        if (released || currentPath == null || _state.value is RtpPlayerState.Error) return

        val duration = safeDuration()
        val target = if (duration > 0L) {
            ms.coerceIn(0L, duration)
        } else {
            ms.coerceAtLeast(0L)
        }
        try {
            facade.seekTo(target)
            _positionMs.value = target
            if (_state.value == RtpPlayerState.Completed) {
                _state.value = RtpPlayerState.Paused
            }
        } catch (error: Exception) {
            handleError(loadGeneration, error.message ?: SEEK_FAILED_MESSAGE)
        }
    }

    fun release() {
        if (released) return
        released = true
        playWhenPrepared = false
        stopTicker()
        facade.onPrepared = null
        facade.onCompletion = null
        facade.onError = null
        runCatching { facade.release() }
        abandonAudioFocus()
        currentPath = null
        _positionMs.value = 0L
        _state.value = RtpPlayerState.Idle
    }

    fun setMuted(left: Boolean, right: Boolean) {
        leftMuted = left
        rightMuted = right
        applyVolume()
    }

    private fun handlePrepared(generation: Long) {
        if (!isCurrent(generation)) return
        if (!playWhenPrepared) {
            _state.value = RtpPlayerState.Paused
            return
        }
        startPlayback()
    }

    private fun startPlayback() {
        if (released) return
        requestAudioFocus()
        if (!playWhenPrepared) {
            _state.value = RtpPlayerState.Paused
            return
        }

        try {
            facade.start()
            applyVolume()
            _state.value = RtpPlayerState.Playing
            startTicker()
        } catch (error: Exception) {
            handleError(loadGeneration, error.message ?: PLAY_FAILED_MESSAGE)
        }
    }

    private fun pauseInternal(abandonFocus: Boolean) {
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
        if (abandonFocus) abandonAudioFocus()
    }

    private fun handleCompletion(generation: Long) {
        if (!isCurrent(generation)) return
        stopTicker()
        playWhenPrepared = false
        _positionMs.value = safeDuration()
        _state.value = RtpPlayerState.Completed
        abandonAudioFocus()
    }

    private fun handleError(generation: Long, message: String) {
        if (!isCurrent(generation)) return
        stopTicker()
        playWhenPrepared = false
        _state.value = RtpPlayerState.Error(message.ifBlank { PLAYER_FAILED_MESSAGE })
        abandonAudioFocus()
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

    private fun requestAudioFocus() {
        val focus = audioFocus ?: return
        if (hasAudioFocus) return
        hasAudioFocus = runCatching {
            focus.requestAudioFocus(::onAudioFocusChange)
        }.getOrDefault(false)
    }

    private fun abandonAudioFocus() {
        audioFocus?.let { focus ->
            runCatching { focus.abandonAudioFocus() }
        }
        hasAudioFocus = false
        ducking = false
    }

    private fun onAudioFocusChange(change: Int) {
        if (released) return
        when (change) {
            AudioManager.AUDIOFOCUS_GAIN -> {
                hasAudioFocus = true
                ducking = false
                applyVolume()
            }

            AudioManager.AUDIOFOCUS_LOSS,
            AudioManager.AUDIOFOCUS_LOSS_TRANSIENT -> {
                hasAudioFocus = false
                ducking = false
                pauseInternal(abandonFocus = false)
            }

            AudioManager.AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK -> {
                ducking = true
                applyVolume()
            }
        }
    }

    private fun applyVolume() {
        if (released || currentPath == null) return
        val scale = if (ducking) DUCK_VOLUME else 1f
        val left = if (leftMuted) 0f else scale
        val right = if (rightMuted) 0f else scale
        runCatching { facade.setVolume(left, right) }
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
        const val DUCK_VOLUME = 0.2f
        const val LOAD_FAILED_MESSAGE = "Unable to prepare audio."
        const val PLAY_FAILED_MESSAGE = "Unable to play audio."
        const val PAUSE_FAILED_MESSAGE = "Unable to pause audio."
        const val SEEK_FAILED_MESSAGE = "Unable to seek audio."
        const val PLAYER_FAILED_MESSAGE = "Audio playback failed."
    }
}

/** Android MediaPlayer implementation of [PlayerFacade]. */
class AndroidMediaPlayerFacade(context: Context) : PlayerFacade {
    private val appContext = context.applicationContext
    private var mediaPlayer: MediaPlayer? = null

    override var onPrepared: (() -> Unit)? = null
    override var onCompletion: (() -> Unit)? = null
    override var onError: ((String) -> Unit)? = null

    override fun setDataSource(path: String) {
        currentPlayer().setDataSource(path)
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

    override fun setVolume(left: Float, right: Float) {
        currentPlayer().setVolume(
            left.coerceIn(0f, 1f),
            right.coerceIn(0f, 1f)
        )
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
                    .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                    .build()
            )
            player.setOnPreparedListener { onPrepared?.invoke() }
            player.setOnCompletionListener { onCompletion?.invoke() }
            player.setOnErrorListener { _, what, extra ->
                onError?.invoke("MediaPlayer error ($what, $extra)")
                true
            }
            mediaPlayer = player
        }
}

/** Android audio-focus implementation using a persistent [AudioFocusRequest]. */
class AndroidAudioFocusFacade(context: Context) : AudioFocusFacade {
    private val audioManager = context.applicationContext
        .getSystemService(AudioManager::class.java)
    private var focusRequest: AudioFocusRequest? = null

    override fun requestAudioFocus(onFocusChange: (Int) -> Unit): Boolean {
        val manager = audioManager ?: return false
        val request = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                    .build()
            )
            .setOnAudioFocusChangeListener(onFocusChange)
            .build()
        focusRequest = request
        return runCatching {
            manager.requestAudioFocus(request) == AudioManager.AUDIOFOCUS_REQUEST_GRANTED
        }.getOrDefault(false)
    }

    override fun abandonAudioFocus() {
        val manager = audioManager ?: return
        val request = focusRequest ?: return
        focusRequest = null
        runCatching { manager.abandonAudioFocusRequest(request) }
    }
}
