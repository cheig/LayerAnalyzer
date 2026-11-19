// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksSessionLimits
import java.nio.channels.Selector
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Exactly two internal loops with ONE shared session admission. No production server switch. */
internal class SocksEventLoopGroup(
    val config: SocksEventLoopConfig = SocksEventLoopConfig(),
    selectorFactory: (Int) -> Selector = { Selector.open() },
    threadFactory: (Runnable, String) -> Thread = { task, name -> Thread(task, name) },
    sessionLimits: SocksSessionLimits = SocksSessionLimits(),
    sessionNanoClock: () -> Long = System::nanoTime,
    onLoopStopping: (Int, Throwable?) -> Unit = { _, _ -> }
) : AutoCloseable {
    init {
        require((config.tcpValidationProfile == null && config.udpValidationProfile == null && config.runtimeLimits == null) || sessionLimits == SocksSessionLimits()) {
            "Validation profiles cannot be combined with legacy limit overrides"
        }
    }
    private enum class State { NEW, STARTING, RUNNING, STOPPING }
    private val state = AtomicReference(State.NEW)
    private val cursor = AtomicInteger()
    private val loops = List(LOOP_COUNT) { index ->
        SocksEventLoop("SocksNio-$index", config, { selectorFactory(index) }, threadFactory,
            onStopping = { cause -> onLoopStopping(index, cause) })
    }

    val sessionAdmission = SocksSessionAdmission(this, sessionLimits, sessionNanoClock)
    internal fun isRunning(): Boolean = state.get() == State.RUNNING

    fun loop(index: Int): SocksEventLoop = loops[index]

    /** Explicit callers retain round-robin; the listener uses admission.reserveLoadAware(). */
    fun nextLoop(): SocksEventLoop = loops[(cursor.getAndIncrement() and Int.MAX_VALUE) % LOOP_COUNT]

    fun start() {
        check(state.compareAndSet(State.NEW, State.STARTING)) { "Group already started/stopped" }
        try {
            loops.forEach {
                check(state.get() == State.STARTING) { "Group start canceled" }
                it.start()
            }
            check(loops.all { it.stats().state == SocksEventLoop.State.RUNNING }) { "Loop failed during start" }
            check(state.compareAndSet(State.STARTING, State.RUNNING)) { "Group start canceled" }
        } catch (error: Throwable) {
            requestStop() // Assembly owns the single external startup/shutdown deadline.
            throw error
        }
    }

    fun requestStop() {
        state.set(State.STOPPING)
        sessionAdmission.stop()
        loops.forEach { it.requestStop() }
    }

    /** One total deadline, not two per-loop timeouts. No waits from ANY group loop callback. */
    fun shutdown(timeoutMillis: Long = config.shutdownTimeoutMillis): Boolean {
        require(timeoutMillis in 0..60_000)
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        requestStop()
        return awaitUntil(deadline)
    }

    internal fun awaitUntil(deadline: Long): Boolean {
        if (loops.any { it.inEventLoop() }) return loops.all { it.stats().state == SocksEventLoop.State.TERMINATED }
        var done = true
        loops.forEach { if (!it.awaitUntil(deadline)) done = false }
        return done
    }

    fun stats(): List<SocksEventLoop.Stats> = loops.map { it.stats() }
    override fun close() { shutdown() }
    companion object { const val LOOP_COUNT = 2 }
}
