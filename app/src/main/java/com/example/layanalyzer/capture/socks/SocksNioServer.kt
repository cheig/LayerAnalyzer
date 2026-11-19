// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksSessionLimits
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Internal P1 assembly, deliberately absent from the production mode selector. A handler is
 * required: NIO-105 supplies the bounded incremental handshake, subsequent phases the relay.
 * Each start creates a fresh group/admission and generation. Callbacks/factories must not block.
 * Startup owns the listener until ACCEPTED; afterwards only loop 0 closes it. Every client is
 * nonblocking and reserved before handoff; provisional, unadmitted clients are never read.
 */
internal class SocksNioServer(
    private val handler: SessionHandler,
    private val config: SocksEventLoopConfig = SocksEventLoopConfig(),
    private val sessionLimits: SocksSessionLimits = SocksSessionLimits(),
    private val listenerFactory: () -> ServerSocketChannel = { ServerSocketChannel.open() },
    private val selectorFactory: (Int) -> Selector = { Selector.open() },
    private val threadFactory: (Runnable, String) -> Thread = { task, name -> Thread(task, name) },
    private val sessionNanoClock: () -> Long = System::nanoTime,
    private val handshakeTimeoutNanos: Long = SocksSessionAdmission.DEFAULT_HANDSHAKE_TIMEOUT_NANOS,
    /** Bounded nonblocking lifecycle hooks; starting precedes every accept, stopping runs once. */
    private val onRunStarting: (Long) -> Unit = {},
    private val onRunStopping: (Long) -> Unit = {},
    /** Owner counter hook after the session has released its resources and admission. */
    private val onSessionClosed: (Throwable?) -> Unit = {}
) : AutoCloseable {
    init { require(handshakeTimeoutNanos in 1..SocksSessionAdmission.DEFAULT_HANDSHAKE_TIMEOUT_NANOS) }
    interface SessionHandler {
        /** Owner-only; configure parser state/control buffers here. No blocking I/O. */
        fun onSession(session: SocksSession, registration: SocksEventLoop.Registration)
        /** Owner-only bounded I/O, with the original accepted SocketChannel in registration. */
        fun onReady(session: SocksSession, registration: SocksEventLoop.Registration, ops: Int)
    }

    enum class State { NEW, STARTING, RUNNING, STOPPING, STOPPED }
    data class Stats(
        val state: State,
        val captureGeneration: Long,
        val port: Int?,
        val listenerRegistered: Boolean,
        val acceptedClients: Long,
        val rejectedAdmissions: Long,
        val rejectedTransfers: Long,
        val admission: SocksSessionAdmission.Stats?,
        val loops: List<SocksEventLoop.Stats>,
        val failure: Throwable?
    )

    private val gate = Any()
    private var nextGeneration = 0L
    @Volatile private var current: Run? = null

    private inner class Run(val generation: Long) {
        val stopRequested = AtomicBoolean()
        val startupDone = CountDownLatch(1)
        val stopHookDone = CountDownLatch(1)
        val registered = CountDownLatch(1)
        val listenerRegistered = AtomicBoolean()
        val accepted = AtomicLong()
        val rejectedAdmissions = AtomicLong()
        val rejectedTransfers = AtomicLong()
        val failure = AtomicReference<Throwable?>()
        @Volatile var port: Int? = null
        val group = SocksEventLoopGroup(config, selectorFactory, threadFactory,
            sessionLimits, sessionNanoClock,
            onLoopStopping = { index, cause ->
                if (!stopRequested.get()) fail(cause ?: IOException("Loop $index stopped unexpectedly"))
            })

        fun fail(cause: Throwable) {
            failure.compareAndSet(null, cause)
            requestStop()
            registered.countDown() // wake failed startup independently of owner cleanup
        }

        fun requestStop() {
            val firstStop = synchronized(gate) {
                port = null
                !stopRequested.getAndSet(true)
            }
            try {
                if (firstStop) onRunStopping(generation)
            } catch (error: Throwable) {
                failure.compareAndSet(null, error)
            } finally {
                if (firstStop) stopHookDone.countDown()
                group.requestStop() // out-of-band, no thread wait
                registered.countDown()
            }
        }

        fun cleaned(): Boolean = startupDone.count == 0L && stopHookDone.count == 0L &&
            group.stats().all { it.state == SocksEventLoop.State.TERMINATED }
    }

    /**
     * Publishes a port only after OP_ACCEPT registration; the listener binds loopback only.
     * Publication and stop are serialized. As with any running listener, concurrent stop may
     * close a port immediately after publication (including before start's caller observes it).
     */
    fun start(port: Int = 0, timeoutMillis: Long = config.shutdownTimeoutMillis): Int {
        require(port in 0..65535)
        require(timeoutMillis in 1..60_000)
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        val run = synchronized(gate) {
            check(current == null || checkNotNull(current).cleaned()) { "Server already starting/running/stopping" }
            Run(++nextGeneration).also { current = it }
        }
        var channel: ServerSocketChannel? = null
        var handedOff = false
        try {
            synchronized(gate) {
                check(!run.stopRequested.get()) { "Server start canceled" }
                onRunStarting(run.generation)
            }
            run.group.start()
            check(!run.stopRequested.get()) { "Server start canceled" }
            channel = listenerFactory()
            check(channel.isOpen) { "Listener factory returned a closed channel" }
            check(!run.stopRequested.get()) { "Server start canceled" }
            channel.configureBlocking(false)
            channel.bind(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port))
            val boundPort = (channel.localAddress as InetSocketAddress).port
            val result = run.group.loop(0).transfer(channel, SelectionKey.OP_ACCEPT,
                onReady = { registration, ops ->
                    if (ops and SelectionKey.OP_ACCEPT != 0) acceptClients(run, registration)
                },
                onRegistered = {
                    run.listenerRegistered.set(true)
                    run.registered.countDown()
                },
                onClosed = { cause ->
                    run.listenerRegistered.set(false)
                    if (!run.stopRequested.get()) run.fail(cause ?: IOException("Listener closed unexpectedly"))
                    run.registered.countDown()
                })
            check(result == SocksEventLoop.Submission.ACCEPTED) { "Listener transfer rejected: $result" }
            handedOff = true
            val remaining = deadline - System.nanoTime()
            check(remaining > 0 && run.registered.await(remaining, TimeUnit.NANOSECONDS)) { "Listener registration timed out" }
            synchronized(gate) {
                check(!run.stopRequested.get() && run.listenerRegistered.get() && run.group.isRunning()) {
                    "Server start canceled or listener registration failed"
                }
                run.port = boundPort
            }
            return boundPort
        } catch (error: Throwable) {
            run.fail(error)
            throw error
        } finally {
            // Never close a channel after ACCEPTED, even while still waiting for registration.
            try { if (!handedOff) channel?.close() } finally { run.startupDone.countDown() }
            if (run.stopRequested.get()) run.group.awaitUntil(deadline)
        }
    }

    private fun acceptClients(run: Run, registration: SocksEventLoop.Registration) {
        val listener = registration.channel as ServerSocketChannel
        // Draining rejected clients clears ACCEPT readiness; no pause timer or unbounded backlog
        // loop. At most one provisional FD exists, and at most 16 accepts run in one callback.
        repeat(MAX_ACCEPTS_PER_CALLBACK) {
            if (run.stopRequested.get()) return
            val client = listener.accept() ?: return
            run.accepted.incrementAndGet()
            var reservation: SocksSessionAdmission.Reservation? = null
            var handedOff = false
            try {
                client.configureBlocking(false)
                reservation = run.group.sessionAdmission.reserveLoadAware(run.generation, handshakeTimeoutNanos)
                if (reservation == null) {
                    if (!run.stopRequested.get()) run.rejectedAdmissions.incrementAndGet()
                } else {
                    val result = reservation.transfer(client, SelectionKey.OP_READ,
                        onReady = handler::onReady, onSession = handler::onSession,
                        onClosed = onSessionClosed)
                    handedOff = result == SocksEventLoop.Submission.ACCEPTED
                    if (!handedOff) run.rejectedTransfers.incrementAndGet()
                }
            } finally {
                reservation?.close() // no-op after ACCEPTED
                if (!handedOff) client.close()
            }
        }
    }

    /** One deadline covers startup cleanup and both loops. Loop callers never wait for peers. */
    fun stop(timeoutMillis: Long = config.shutdownTimeoutMillis, expectedGeneration: Long? = null): Boolean {
        require(timeoutMillis in 0..60_000)
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        val run = synchronized(gate) {
            current?.also { if (expectedGeneration != null && it.generation != expectedGeneration) return false }
        } ?: return true
        run.requestStop()
        if ((0 until SocksEventLoopGroup.LOOP_COUNT).any { run.group.loop(it).inEventLoop() }) return run.cleaned()
        val remaining = deadline - System.nanoTime()
        if (run.startupDone.count > 0L && (remaining <= 0 || !run.startupDone.await(remaining, TimeUnit.NANOSECONDS))) return false
        val hookRemaining = deadline - System.nanoTime()
        if (run.stopHookDone.count > 0L && (hookRemaining <= 0 || !run.stopHookDone.await(hookRemaining, TimeUnit.NANOSECONDS))) return false
        return run.group.awaitUntil(deadline)
    }

    fun stats(): Stats {
        val run = current ?: return Stats(State.NEW, 0, null, false, 0, 0, 0, null, emptyList(), null)
        val state = when {
            run.cleaned() -> State.STOPPED
            run.stopRequested.get() -> State.STOPPING
            run.port != null -> State.RUNNING
            else -> State.STARTING
        }
        return Stats(state, run.generation, run.port, run.listenerRegistered.get(),
            run.accepted.get(), run.rejectedAdmissions.get(), run.rejectedTransfers.get(),
            run.group.sessionAdmission.stats(), run.group.stats(), run.failure.get())
    }

    internal fun loop(index: Int): SocksEventLoop = checkNotNull(current).group.loop(index)
    override fun close() { stop() }
    companion object { const val MAX_ACCEPTS_PER_CALLBACK = 16 }
}
