// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import java.io.IOException
import java.nio.channels.SelectableChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.ArrayDeque
import java.util.PriorityQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.LockSupport

/**
 * Single owner of its selector, keys and transferred channels. No Android or blocking stream I/O.
 *
 * Admission and stop share a short lock: ACCEPTED transfers ownership even if stop wins before
 * execution; any rejection leaves captured resources with the caller (onDiscard is NOT called).
 * Callbacks must not block and must bound their own bytes/packets. Scoped callback failure closes
 * that scope; unscoped task/timer failure stops the loop, since its affected resource is unknown.
 * No raw key/selector is exposed. A readiness snapshot is exhausted before another selection,
 * so a hot key cannot overtake the other keys in that snapshot. WRITE readiness is one-shot:
 * rearm it only while actual output remains. READ/ACCEPT/CONNECT are level-triggered.
 */
internal class SocksEventLoop(
    val name: String,
    val config: SocksEventLoopConfig = SocksEventLoopConfig(),
    private val selectorFactory: () -> Selector = { Selector.open() },
    private val threadFactory: (Runnable, String) -> Thread = { task, threadName -> Thread(task, threadName) },
    private val nanoClock: () -> Long = System::nanoTime,
    private val onStopping: (Throwable?) -> Unit = {}
) : AutoCloseable {
    enum class State { NEW, STARTING, RUNNING, STOPPING, TERMINATED }
    enum class Submission { ACCEPTED, NOT_STARTED, STOPPED, QUEUE_FULL, TIMER_FULL, CHANNEL_LIMIT, OWNER_CLOSED }

    data class Stats(
        val state: State,
        val commands: Int,
        val completions: Int,
        val timers: Int,
        val resources: Int,
        /** Includes accepted transfers not yet registered. */
        val channels: Int,
        val keys: Int,
        val readyKeys: Int,
        val turns: Long,
        val selectCalls: Long,
        val selectNowCalls: Long,
        val rejectedCommands: Long,
        val rejectedCompletions: Long,
        val rejectedTimers: Long,
        val callbackFailures: Long,
        val cleanupFailures: Long,
        val firedTimers: Long,
        val readinessCallbacks: Long,
        val emptySelectBackoffs: Long,
        val failure: Throwable?,
        val peakChannels: Int = 0,
        val peakCommands: Int = 0,
        val peakCompletions: Int = 0,
        /** Callback/work time per turn, excluding selector's intentional idle wait. */
        val maxWorkNanos: Long = 0,
        val maxTimerLatenessNanos: Long = 0
    )

    private class Command(
        val owner: Resource?,
        val action: () -> Unit,
        val discard: () -> Unit
    )
    private data class Ready(val registration: Registration, val ops: Int)
    internal data class TimerCall(val owner: Resource?, val action: () -> Unit)

    private val gate = Any()
    @Volatile private var state = State.NEW
    @Volatile private var selector: Selector? = null
    @Volatile private var thread: Thread? = null
    @Volatile private var failure: Throwable? = null
    private val terminated = CountDownLatch(1)
    private val commands = ArrayDeque<Command>()
    private val completions = ArrayDeque<Command>()
    private val channels = LinkedHashSet<SelectableChannel>() // gate; includes pending transfers
    private val resources = LinkedHashSet<Resource>() // loop thread; count published under gate
    private val ready = ArrayDeque<Ready>() // loop thread only
    // All live deadlines differ by < 2*MAX_DELAY_NANOS, including across nanoTime wrap.
    private val timers = PriorityQueue<Timer> { a, b -> (a.deadlineNanos - b.deadlineNanos).compareTo(0L) }
    private var resourceCount = 0
    @Volatile private var keyCount = 0
    @Volatile private var readyCount = 0
    private val turns = AtomicLong()
    private val selectCalls = AtomicLong()
    private val rejectedCommands = AtomicLong()
    private val rejectedCompletions = AtomicLong()
    private val rejectedTimers = AtomicLong()
    private val callbackFailures = AtomicLong()
    private val cleanupFailures = AtomicLong()
    private val firedTimers = AtomicLong()
    private val readinessCallbacks = AtomicLong()
    private val emptySelectBackoffs = AtomicLong()
    private var peakChannels = 0
    private var peakCommands = 0
    private var peakCompletions = 0
    private val maxWorkNanos = AtomicLong()
    private val maxTimerLatenessNanos = AtomicLong()

    fun inEventLoop(): Boolean = Thread.currentThread() === thread

    /** One-shot start. A failed selector/thread start terminates and closes the opened selector. */
    fun start() {
        synchronized(gate) {
            check(state == State.NEW) { "$name cannot start from $state" }
            state = State.STARTING
        }
        var opened: Selector? = null
        try {
            // Potentially slow factories never hold admission/stop gate.
            opened = selectorFactory()
            check(opened.isOpen) { "Selector factory returned a closed selector" }
            val worker = threadFactory(Runnable { runLoop() }, name)
            check(worker.state == Thread.State.NEW) { "Thread factory must return an unstarted thread" }
            synchronized(gate) {
                check(state == State.STARTING) { "Loop start canceled" }
                selector = opened
                thread = worker
                state = State.RUNNING
                worker.start()
            }
        } catch (error: Throwable) {
            failure = error
            cleanup { opened?.close() }
            synchronized(gate) {
                selector = null
                state = State.TERMINATED
            }
            terminated.countDown()
            throw error
        }
    }
    /** Scoped commands skip execution if their owner closed, and run discard on the loop instead. */
    fun submit(owner: Resource? = null, onDiscard: () -> Unit = {}, action: () -> Unit): Submission =
        enqueue(commands, config.commandCapacity, rejectedCommands, owner, onDiscard, action)

    /** Separate bounded ingress for future DNS/worker completions; same ownership rules as submit. */
    fun complete(owner: Resource? = null, onDiscard: () -> Unit = {}, action: () -> Unit): Submission =
        enqueue(completions, config.completionCapacity, rejectedCompletions, owner, onDiscard, action)

    private fun enqueue(
        queue: ArrayDeque<Command>, capacity: Int, rejections: AtomicLong,
        owner: Resource?, discard: () -> Unit, action: () -> Unit
    ): Submission = synchronized(gate) {
        checkOwner(owner)
        val rejection = admission(owner) ?: if (queue.size >= capacity) Submission.QUEUE_FULL else null
        if (rejection != null) {
            rejections.incrementAndGet()
            rejection
        } else {
            queue.addLast(Command(owner, action, discard))
            peakCommands = maxOf(peakCommands, commands.size)
            peakCompletions = maxOf(peakCompletions, completions.size)
            wakeup()
            Submission.ACCEPTED
        }
    }

    /**
     * The ONLY cross-thread channel handoff. Caller must have exclusive ownership and must stop
     * using/closing it on ACCEPTED. On rejection caller still owns it. On every accepted path
     * (including registration failure or queued shutdown), loop closes it and calls onClosed once.
     * onRegistered/onReady/onClosed execute on this loop, never on the submitting thread.
     */
    fun transfer(
        channel: SelectableChannel,
        interestOps: Int,
        onReady: (Registration, Int) -> Unit,
        onRegistered: (Registration) -> Unit = {},
        onClosed: (Throwable?) -> Unit = {}
    ): Submission = synchronized(gate) {
        check(channel !in channels) { "Channel already owned by $name" }
        val rejection = admission(null)
            ?: if (commands.size >= config.commandCapacity) Submission.QUEUE_FULL
            else if (channels.size >= config.channelCapacity) Submission.CHANNEL_LIMIT else null
        if (rejection != null) {
            rejectedCommands.incrementAndGet()
            rejection
        } else {
            channels.add(channel)
            peakChannels = maxOf(peakChannels, channels.size)
            commands.addLast(Command(null, {
                var resource: Resource? = null
                try {
                    resource = openResource(onClosed)
                    val registration = registerOwned(resource, channel, interestOps, onReady)
                    invoke(resource) { onRegistered(registration) }
                } catch (error: Throwable) {
                    releaseChannel(channel)
                    if (resource != null) resource.close(error) else cleanup { onClosed(error) }
                }
            }, {
                releaseChannel(channel)
                cleanup { onClosed(LoopStoppedException()) }
            }))
            peakCommands = maxOf(peakCommands, commands.size)
            wakeup()
            Submission.ACCEPTED
        }
    }

    /** Loop-local cleanup scope, NOT a session or admission lease. */
    fun openResource(onClosed: (Throwable?) -> Unit = {}): Resource {
        requireEventLoop()
        synchronized(gate) {
            check(state == State.RUNNING) { "Loop stopping" }
            check(resourceCount < config.resourceCapacity) { "Resource capacity exhausted" }
            return Resource(onClosed).also {
                resources.add(it)
                resourceCount++
            }
        }
    }

    inner class Resource internal constructor(private var onClosed: ((Throwable?) -> Unit)?) {
        internal val loop: SocksEventLoop get() = this@SocksEventLoop
        @Volatile var isClosed: Boolean = false
            private set
        private val registrations = LinkedHashSet<Registration>()

        /**
         * Loop-only handoff; ownership transfers after thread/owner/exclusivity preconditions.
         * From that point even invalid ops, blocking-channel or capacity failure closes channel
         * AND scope, then throws. Before those preconditions caller retains ownership.
         * Caller prepares protect/bind/nonblocking first; this method never configures/connects.
         */
        fun register(
            channel: SelectableChannel, interestOps: Int,
            onReady: (Registration, Int) -> Unit
        ): Registration {
            requireEventLoop()
            check(!isClosed) { "Resource closed; channel remains caller-owned" }
            synchronized(gate) {
                check(channel !in channels) { "Channel already owned" }
                channels.add(channel)
                peakChannels = maxOf(peakChannels, channels.size)
            }
            return try {
                registerOwned(this, channel, interestOps, onReady)
            } catch (error: Throwable) {
                releaseChannel(channel)
                close(error)
                throw error
            }
        }

        /** Idempotent loop-only close: timers, keys/channels, then the scope cleanup hook. */
        fun close(cause: Throwable? = null) {
            requireEventLoop()
            val hook = synchronized(gate) {
                if (isClosed) return
                isClosed = true
                val iterator = timers.iterator()
                while (iterator.hasNext()) {
                    val timer = iterator.next()
                    if (timer.owner === this) {
                        iterator.remove()
                        timer.clear()
                    }
                }
                resources.remove(this)
                resourceCount--
                onClosed.also { onClosed = null }
            }
            registrations.toList().forEach { it.close() }
            cleanup { hook?.invoke(cause) }
        }

        internal fun attach(registration: Registration) { registrations.add(registration) }
        internal fun detach(registration: Registration) { registrations.remove(registration) }
    }

    inner class Registration internal constructor(
        val resource: Resource,
        val channel: SelectableChannel,
        private val key: SelectionKey,
        private var handler: ((Registration, Int) -> Unit)?
    ) {
        private var closed = false
        val isOpen: Boolean get() = !closed && channel.isOpen

        /** Owner-only phase handoff; no new key/channel or secondary handler registry. */
        fun replaceHandler(onReady: (Registration, Int) -> Unit) {
            requireEventLoop()
            check(!closed && !resource.isClosed && key.isValid) { "Registration closed" }
            handler = onReady
        }

        fun interestOps(): Int {
            requireEventLoop()
            check(!closed)
            return key.interestOps()
        }

        fun interestOps(ops: Int) {
            requireEventLoop()
            try {
                check(!closed)
                key.interestOps(ops)
            } catch (error: Throwable) {
                resource.close(error)
                throw error
            }
        }

        /** Rearm WRITE only for pending output; WRITE auto-disarms before every callback. */
        fun pendingWrite(pending: Boolean) {
            val ops = interestOps()
            interestOps(if (pending) ops or SelectionKey.OP_WRITE else ops and SelectionKey.OP_WRITE.inv())
        }

        /** Closes just this channel; close resource to also release sibling channels/timers/hook. */
        fun close() {
            requireEventLoop()
            if (closed) return
            closed = true
            handler = null
            cleanup { key.attach(null) }
            cleanup { key.cancel() }
            resource.detach(this)
            releaseChannel(channel)
        }

        internal fun dispatch(ops: Int) {
            if (closed || resource.isClosed) return
            invoke(resource) {
                if (!key.isValid || !channel.isOpen) {
                    resource.close(IOException("Registered channel invalidated outside its owner"))
                } else {
                    val interested = ops and key.interestOps()
                    if (interested != 0) {
                        if (interested and SelectionKey.OP_WRITE != 0) {
                            key.interestOps(key.interestOps() and SelectionKey.OP_WRITE.inv())
                        }
                        readinessCallbacks.incrementAndGet()
                        handler?.invoke(this, interested)
                    }
                }
            }
        }
    }

    private fun registerOwned(
        resource: Resource, channel: SelectableChannel, ops: Int,
        handler: (Registration, Int) -> Unit
    ): Registration {
        requireEventLoop()
        check(!resource.isClosed && state == State.RUNNING)
        synchronized(gate) { check(channels.size <= config.channelCapacity) { "Channel capacity exhausted" } }
        require(!channel.isBlocking) { "Prepare nonblocking channel before handoff" }
        require(ops and channel.validOps().inv() == 0) { "Invalid channel interestOps" }
        val key = channel.register(checkNotNull(selector), ops)
        return Registration(resource, channel, key, handler).also {
            key.attach(it)
            resource.attach(it)
            keyCount = checkNotNull(selector).keys().size
        }
    }

    data class TimerSubmission(val result: Submission, val timer: Timer? = null)

    /** Monotonic relative deadline, 0..one day. No wall clock and no timer/worker thread. */
    fun schedule(delayNanos: Long, owner: Resource? = null, action: () -> Unit): TimerSubmission {
        require(delayNanos in 0..MAX_DELAY_NANOS)
        synchronized(gate) {
            checkOwner(owner)
            val rejection = admission(owner) ?: if (timers.size >= config.timerCapacity) Submission.TIMER_FULL else null
            if (rejection != null) {
                rejectedTimers.incrementAndGet()
                return TimerSubmission(rejection)
            }
            val timer = Timer(nanoClock() + delayNanos, owner, action)
            timers.add(timer)
            wakeup()
            return TimerSubmission(Submission.ACCEPTED, timer)
        }
    }

    inner class Timer internal constructor(
        val deadlineNanos: Long,
        internal var owner: Resource?,
        private var action: (() -> Unit)?
    ) {
        /**
         * Thread-safe immediate removal and reference clearing, independent of command saturation.
         * true means callback cannot start; false means already canceled/claimed for firing.
         * A claimed callback may still execute after cancel returns false, at most once.
         */
        fun cancel(): Boolean = synchronized(gate) {
            if (!timers.remove(this)) return false
            clear()
            wakeup()
            true
        }

        internal fun clear() { owner = null; action = null }
        internal fun claim(): TimerCall {
            val call = TimerCall(owner, checkNotNull(action))
            clear()
            return call
        }
        internal fun retainsCallback(): Boolean = synchronized(gate) { action != null || owner != null }
    }

    /** Out-of-band stop cannot be rejected by either queue. */
    fun requestStop() {
        synchronized(gate) {
            when (state) {
                State.NEW -> {
                    state = State.TERMINATED
                    terminated.countDown()
                }
                State.STARTING, State.RUNNING -> state = State.STOPPING
                State.STOPPING, State.TERMINATED -> Unit
            }
            wakeup()
        }
    }

    fun shutdown(timeoutMillis: Long = config.shutdownTimeoutMillis): Boolean {
        require(timeoutMillis in 0..60_000)
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        requestStop()
        return awaitUntil(deadline)
    }

    internal fun awaitUntil(deadlineNanos: Long): Boolean {
        if (inEventLoop()) return state == State.TERMINATED // never self-join
        if (terminated.count == 0L) return true
        val remaining = deadlineNanos - System.nanoTime()
        return remaining > 0 && terminated.await(remaining, TimeUnit.NANOSECONDS)
    }

    override fun close() { shutdown() }

    fun stats(): Stats = synchronized(gate) {
        Stats(state, commands.size, completions.size, timers.size, resourceCount, channels.size,
            keyCount, readyCount, turns.get(), selectCalls.get(), 0, rejectedCommands.get(),
            rejectedCompletions.get(), rejectedTimers.get(), callbackFailures.get(), cleanupFailures.get(),
            firedTimers.get(), readinessCallbacks.get(), emptySelectBackoffs.get(), failure,
            peakChannels, peakCommands, peakCompletions, maxWorkNanos.get(), maxTimerLatenessNanos.get())
    }

    private fun runLoop() {
        try {
            while (state == State.RUNNING) {
                if (Thread.interrupted()) {
                    requestStop()
                    break
                }
                turns.incrementAndGet()
                val workStarted = System.nanoTime()
                drain(commands, config.commandsPerTurn)
                drain(completions, config.completionsPerTurn)
                fireTimers()
                repeat(config.readinessPerTurn) {
                    if (state != State.RUNNING) return@repeat
                    val item = ready.pollFirst() ?: return@repeat
                    readyCount = ready.size
                    item.registration.dispatch(item.ops)
                }
                if (state != State.RUNNING) break
                maxWorkNanos.accumulateAndGet(System.nanoTime() - workStarted, ::maxOf)
                if (ready.isNotEmpty()) continue // bounded snapshot, other phases run every turn
                selectReady()
            }
        } catch (error: Throwable) {
            failure = error
        } finally {
            requestStop()
            // Assembly-level failure supervision; never under the loop gate or a queue slot.
            cleanup { onStopping(failure) }
            // No producers after STOPPING. Discard, never execute, remaining accepted commands.
            while (true) {
                val command = synchronized(gate) { commands.pollFirst() ?: completions.pollFirst() } ?: break
                cleanup { command.discard() }
            }
            resources.toList().forEach { it.close(LoopStoppedException()) }
            synchronized(gate) {
                timers.forEach { it.clear() }
                timers.clear()

            }
            val remainingChannels = synchronized(gate) { channels.toList() }
            remainingChannels.forEach { releaseChannel(it) }
            ready.clear()
            readyCount = 0
            cleanup { selector?.selectedKeys()?.clear() }
            cleanup { selector?.close() }
            selector = null
            keyCount = 0
            synchronized(gate) { state = State.TERMINATED }
            terminated.countDown()
        }
    }

    private fun drain(queue: ArrayDeque<Command>, limit: Int) {
        repeat(limit) {
            val command = synchronized(gate) {
                if (state == State.RUNNING) queue.pollFirst() else null
            } ?: return
            if (command.owner?.isClosed == true) cleanup { command.discard() }
            else invoke(command.owner, command.action)
        }
    }

    private fun fireTimers() {
        repeat(config.timersPerTurn) {
            val call = synchronized(gate) {
                val head = timers.peek()
                if (state != State.RUNNING || head == null || head.deadlineNanos - nanoClock() > 0) null
                else {
                    maxTimerLatenessNanos.accumulateAndGet(maxOf(0L, nanoClock() - head.deadlineNanos), ::maxOf)
                    checkNotNull(timers.poll()).claim()
                }
            } ?: return
            if (call.owner?.isClosed != true) {
                firedTimers.incrementAndGet()
                invoke(call.owner, call.action)
            }
        }
    }

    private fun selectReady() {
        val activeSelector = checkNotNull(selector)
        val timeout = synchronized(gate) {
            if (commands.isNotEmpty() || completions.isNotEmpty()) 1L
            else {
                val remaining = timers.peek()?.let { it.deadlineNanos - nanoClock() }
                if (remaining == null) config.idleSelectMillis
                else if (remaining <= 0) 1L
                else minOf(config.idleSelectMillis, 1 + (remaining - 1) / 1_000_000)
            }
        }
        val before = System.nanoTime()
        selectCalls.incrementAndGet()
        // Always positive, even for sub-ms/overdue timers or work backlog. Never selectNow/select(0).
        val count = activeSelector.select(timeout)
        keyCount = activeSelector.keys().size
        val iterator = activeSelector.selectedKeys().iterator()
        while (iterator.hasNext()) {
            val key = iterator.next()
            iterator.remove()
            val registration = key.attachment() as? Registration ?: continue
            if (key.isValid) ready.addLast(Ready(registration, key.readyOps()))
            else registration.resource.close(IOException("Selection key invalidated"))
        }
        readyCount = ready.size
        // Defend against empty early returns (including coalesced wakeups/provider quirks).
        val immediateWork = synchronized(gate) {
            commands.isNotEmpty() || completions.isNotEmpty() || timers.peek()?.let {
                it.deadlineNanos - nanoClock() <= 0
            } == true
        }
        if (count == 0 && ready.isEmpty() && !immediateWork && state == State.RUNNING &&
            System.nanoTime() - before < 1_000_000) {
            emptySelectBackoffs.incrementAndGet()
            LockSupport.parkNanos(1_000_000) // bounded 1ms, no lock held
        }
    }

    private fun invoke(owner: Resource?, action: () -> Unit) {
        try {
            action()
        } catch (error: Throwable) {
            callbackFailures.incrementAndGet()
            if (owner != null) owner.close(error)
            else {
                failure = error
                requestStop()
            }
        }
    }

    private fun cleanup(action: () -> Unit) {
        try { action() } catch (_: Throwable) { cleanupFailures.incrementAndGet() }
    }

    private fun releaseChannel(channel: SelectableChannel) {
        requireEventLoop()
        cleanup { channel.close() }
        synchronized(gate) { channels.remove(channel) }
    }

    private fun requireEventLoop() { check(inEventLoop()) { "Operation requires $name owner thread" } }
    private fun checkOwner(owner: Resource?) { require(owner == null || owner.loop === this) { "Foreign owner" } }
    private fun admission(owner: Resource?): Submission? = when {
        state == State.NEW || state == State.STARTING -> Submission.NOT_STARTED
        state != State.RUNNING -> Submission.STOPPED
        owner?.isClosed == true -> Submission.OWNER_CLOSED
        else -> null
    }
    private fun wakeup() { cleanup { selector?.wakeup() } }

    internal class LoopStoppedException : IOException("SOCKS event loop stopped")
    companion object { const val MAX_DELAY_NANOS: Long = 86_400_000_000_000 }
}
