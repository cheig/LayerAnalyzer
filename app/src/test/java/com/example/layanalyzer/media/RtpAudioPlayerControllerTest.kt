// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import android.media.AudioManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RtpAudioPlayerControllerTest {

    @Test
    fun `playback follows preparing playing paused completed`() {
        val facade = FakePlayerFacade()
        val controller = controller(facade)

        assertEquals(RtpPlayerState.Idle, controller.state.value)

        controller.load(PATH)
        assertEquals(RtpPlayerState.Preparing, controller.state.value)

        facade.prepare()
        assertEquals(RtpPlayerState.Playing, controller.state.value)

        controller.pause()
        assertEquals(RtpPlayerState.Paused, controller.state.value)

        facade.complete()
        assertEquals(RtpPlayerState.Completed, controller.state.value)

        controller.release()
    }

    @Test
    fun `loading without auto play waits for play before starting or requesting audio focus`() {
        val facade = FakePlayerFacade()
        val focus = FakeAudioFocusFacade()
        val controller = controller(facade, audioFocus = focus)

        controller.load(PATH, autoPlay = false)
        assertEquals(RtpPlayerState.Preparing, controller.state.value)

        facade.prepare()
        assertEquals(RtpPlayerState.Paused, controller.state.value)
        assertEquals(0L, controller.positionMs.value)
        assertEquals(0, facade.startCalls)
        assertEquals(0, focus.requestCalls)

        controller.play()
        assertEquals(RtpPlayerState.Playing, controller.state.value)
        assertEquals(1, facade.startCalls)
        assertEquals(1, focus.requestCalls)
        controller.release()
    }

    @Test
    fun `loading the same path is a no-op`() {
        val facade = FakePlayerFacade()
        val controller = controller(facade)

        controller.load(PATH)
        facade.prepare()
        controller.load(PATH)

        assertEquals(1, facade.dataSourceCalls)
        assertEquals(1, facade.prepareCalls)
        assertEquals(listOf(PATH), facade.dataSources)
        controller.release()
    }

    @Test
    fun `position stops changing after pause`() = runBlocking {
        val facade = FakePlayerFacade()
        val controller = controller(facade, tickMillis = 10_000L)
        controller.load(PATH)
        facade.prepare()

        facade.currentPositionMs = 120L
        controller.pause()
        assertEquals(120L, controller.positionMs.value)

        facade.currentPositionMs = 900L
        delay(20L)
        assertEquals(120L, controller.positionMs.value)
        controller.release()
    }

    @Test
    fun `release is idempotent and play after release is ignored`() {
        val facade = FakePlayerFacade()
        val controller = controller(facade)
        controller.load(PATH)
        facade.prepare()

        controller.release()
        controller.release()
        controller.play()

        assertEquals(1, facade.releaseCalls)
        assertEquals(1, facade.startCalls)
        assertEquals(RtpPlayerState.Idle, controller.state.value)
    }

    @Test
    fun `audio focus loss pauses and transient ducking changes volume`() {
        val facade = FakePlayerFacade()
        val focus = FakeAudioFocusFacade()
        val controller = controller(facade, audioFocus = focus)
        controller.load(PATH)
        facade.prepare()

        assertEquals(1, focus.requestCalls)
        assertTrue(controller.state.value == RtpPlayerState.Playing)

        focus.change(AudioManager.AUDIOFOCUS_LOSS_TRANSIENT)
        assertEquals(RtpPlayerState.Paused, controller.state.value)

        controller.play()
        focus.change(AudioManager.AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK)
        assertEquals(0.2f, facade.lastLeftVolume)
        assertEquals(0.2f, facade.lastRightVolume)

        focus.change(AudioManager.AUDIOFOCUS_GAIN)
        assertEquals(1f, facade.lastLeftVolume)
        assertEquals(1f, facade.lastRightVolume)
        controller.release()
    }

    @Test
    fun `a denied focus request does not block playback`() {
        val facade = FakePlayerFacade()
        val focus = FakeAudioFocusFacade(granted = false)
        val controller = controller(facade, audioFocus = focus)

        controller.load(PATH)
        facade.prepare()

        assertEquals(RtpPlayerState.Playing, controller.state.value)
        assertEquals(1, facade.startCalls)
        assertFalse(focus.grantedFocus)
        controller.release()
    }

    private fun controller(
        facade: FakePlayerFacade,
        tickMillis: Long = 10_000L,
        audioFocus: AudioFocusFacade? = null
    ): RtpAudioPlayerController = RtpAudioPlayerController(
        facade = facade,
        scope = CoroutineScope(Dispatchers.Unconfined),
        tickMillis = tickMillis,
        audioFocus = audioFocus
    )

    private companion object {
        const val PATH = "/tmp/rtp.wav"
    }
}

private class FakePlayerFacade : PlayerFacade {
    var dataSourceCalls = 0
    var prepareCalls = 0
    var startCalls = 0
    var releaseCalls = 0
    var currentPositionMs = 0L
    var lastLeftVolume = 1f
    var lastRightVolume = 1f

    val dataSources = mutableListOf<String>()

    override var onPrepared: (() -> Unit)? = null
    override var onCompletion: (() -> Unit)? = null
    override var onError: ((String) -> Unit)? = null

    override var durationMs: Long = 1_000L
    override val positionMs: Long
        get() = currentPositionMs
    override var isPlaying: Boolean = false
        private set

    override fun setDataSource(path: String) {
        dataSourceCalls += 1
        dataSources += path
    }

    override fun prepareAsync() {
        prepareCalls += 1
    }

    override fun start() {
        startCalls += 1
        isPlaying = true
    }

    override fun pause() {
        isPlaying = false
    }

    override fun seekTo(ms: Long) {
        currentPositionMs = ms
    }

    override fun release() {
        releaseCalls += 1
        isPlaying = false
    }

    override fun setVolume(left: Float, right: Float) {
        lastLeftVolume = left
        lastRightVolume = right
    }

    fun prepare() {
        isPlaying = false
        onPrepared?.invoke()
    }

    fun complete() {
        isPlaying = false
        onCompletion?.invoke()
    }
}

private class FakeAudioFocusFacade(
    private val granted: Boolean = true
) : AudioFocusFacade {
    var requestCalls = 0
    var grantedFocus = false
    private var listener: ((Int) -> Unit)? = null

    override fun requestAudioFocus(onFocusChange: (Int) -> Unit): Boolean {
        requestCalls += 1
        listener = onFocusChange
        grantedFocus = granted
        return granted
    }

    override fun abandonAudioFocus() {
        listener = null
        grantedFocus = false
    }

    fun change(change: Int) {
        listener?.invoke(change)
    }
}
