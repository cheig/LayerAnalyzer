// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import java.io.IOException
import java.net.InetAddress
import java.util.Locale
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Process-wide bounded DNS workers. A capture owns a Scope, never an executor. Uninterruptible
 * system lookups keep occupying one of these SAME workers after stop/restart; no replacement
 * pool or worker is created. No result cache, blocking wait, or default system-network lookup.
 * The supplied lookup must use the frozen physical network and runs only on a DNS worker.
 */
internal class SocksResolver private constructor(private val limits: Limits, private val testInstance: Boolean) {
    val configuration: Limits get() = limits
    data class Limits(
        val workers: Int = 4,
        val queuedQueries: Int = 128,
        val subscribers: Int = 1024,
        val subscribersPerQuery: Int = 256
    ) {
        init {
            require(workers in 1..4 && queuedQueries in 1..128)
            require(subscribers in 1..1024 && subscribersPerQuery in 1..minOf(subscribers, 256))
        }
    }

    enum class Failure { QUEUE_FULL, SUBSCRIBER_LIMIT, SCOPE_CLOSED, INVALID_NAME, LOOKUP_FAILED, EMPTY_RESULT, TOO_MANY_ADDRESSES }
    class ResolveException(val reason: Failure, cause: Throwable? = null) : IOException("SOCKS DNS: $reason", cause)
    sealed class Result {
        data class Addresses(val addresses: List<InetAddress>) : Result()
        data class Failed(val error: ResolveException) : Result()
    }
    data class Submitted(val subscription: AutoCloseable? = null, val failure: ResolveException? = null)
    data class ScopeStats(val captureGeneration: Long, val networkGeneration: Long, val open: Boolean,
        val subscribers: Int, val inFlightQueries: Int,
        val peakSubscribers: Int = 0, val peakInFlightQueries: Int = 0)
    data class Stats(
        val workers: Int, val activeLookups: Int, val queuedQueries: Int, val inFlightQueries: Int,
        val subscribers: Int, val peakSubscribers: Int, val lookups: Long, val merged: Long,
        val rejected: Long, val failed: Long, val cancelled: Long, val abandonedResults: Long,
        val timedOut: Long, val discardedCompletions: Long, val rejectedCompletions: Long,
        val callbackFailures: Long,
        val peakActiveLookups: Int = 0, val peakQueuedQueries: Int = 0
    )

    private val gate = Any()
    private val jobs = LinkedHashMap<Key, Job>() // <= workers + queuedQueries, including abandoned running jobs
    private var subscribers = 0
    private var peakSubscribers = 0
    private var activeLookups = 0
    private var peakActiveLookups = 0
    private var peakQueuedQueries = 0
    private var lookups = 0L
    private var merged = 0L
    private var rejected = 0L
    private var failed = 0L
    private var cancelled = 0L
    private var abandonedResults = 0L
    private var timedOut = 0L
    private var discardedCompletions = 0L
    private var rejectedCompletions = 0L
    private var callbackFailures = 0L
    private val executor = ThreadPoolExecutor(limits.workers, limits.workers, 0, TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(limits.queuedQueries), { work ->
            Thread(work, "SocksDns-${threadIds.incrementAndGet()}").apply { isDaemon = true }
        })

    /** Identity is unique even when separate server objects both start with captureGeneration=1. */
    inner class Scope internal constructor(
        val captureGeneration: Long,
        val networkGeneration: Long,
        internal var lookup: ((String) -> Array<InetAddress>)?
    ) : AutoCloseable {
        internal val resolver: SocksResolver get() = this@SocksResolver
        @Volatile var isOpen: Boolean = true
            private set
        internal var peakSubscribers = 0
        internal var peakInFlightQueries = 0

        fun stats(): ScopeStats = synchronized(gate) {
            val owned = jobs.values.filter { it.key.scope === this }
            ScopeStats(captureGeneration, networkGeneration, isOpen,
                owned.sumOf { it.subscriptions.size }, owned.size, peakSubscribers, peakInFlightQueries)
        }

        /** Also the network invalidation hook. Bounded bookkeeping, no worker interrupt or join. */
        override fun close() = synchronized(gate) {
            if (!isOpen) return@synchronized
            isOpen = false
            lookup = null
            jobs.values.filter { it.key.scope === this }.toList().forEach { job ->
                job.subscriptions.toList().forEach { it.cancelLocked() }
            }
        }
    }

    fun newScope(captureGeneration: Long, networkGeneration: Long,
        lookup: (String) -> Array<InetAddress>): Scope = Scope(captureGeneration, networkGeneration, lookup)

    private data class Key(val scope: Scope, val networkGeneration: Long, val name: String)

    /** Callback must only submit to the bounded owner completion ingress; never mutate a session. */
    fun resolve(scope: Scope, host: String, callback: (Result) -> Unit): Submitted = synchronized(gate) {
        require(scope.resolver === this) { "Foreign resolver scope" }
        fun reject(reason: Failure): Submitted { rejected++; return Submitted(failure = ResolveException(reason)) }
        if (!scope.isOpen || executor.isShutdown) return@synchronized reject(Failure.SCOPE_CLOSED)
        if (host.isEmpty() || host.length > 255 || host.any { it <= ' ' || it == '\u007f' })
            return@synchronized reject(Failure.INVALID_NAME)
        val key = Key(scope, scope.networkGeneration, host.lowercase(Locale.ROOT))
        val existing = jobs[key]
        if (subscribers >= limits.subscribers || (existing?.subscriptions?.size ?: 0) >= limits.subscribersPerQuery)
            return@synchronized reject(Failure.SUBSCRIBER_LIMIT)
        val job = existing ?: Job(key)
        val subscription = Subscription(job, callback)
        job.subscriptions.add(subscription)
        subscribers++
        peakSubscribers = maxOf(peakSubscribers, subscribers)
        if (existing != null) {
            merged++
        } else {
            jobs[key] = job
            try { executor.execute(job) } catch (_: RejectedExecutionException) {
                subscription.cancelLocked(countCancellation = false)
                jobs.remove(key)
                return@synchronized reject(Failure.QUEUE_FULL)
            }
        }
        val owned = jobs.values.filter { it.key.scope === scope }
        scope.peakSubscribers = maxOf(scope.peakSubscribers, owned.sumOf { it.subscriptions.size })
        scope.peakInFlightQueries = maxOf(scope.peakInFlightQueries, owned.size)
        peakQueuedQueries = maxOf(peakQueuedQueries, executor.queue.size)
        Submitted(subscription)
    }

    private inner class Subscription(val job: Job, var callback: ((Result) -> Unit)?) : AutoCloseable {
        override fun close() = synchronized(gate) { cancelLocked() }
        fun cancelLocked(countCancellation: Boolean = true) {
            if (callback == null) return
            callback = null
            job.subscriptions.remove(this)
            subscribers--
            if (countCancellation) cancelled++
            // A running lookup stays in jobs and in the actual worker budget until it returns.
            if (job.subscriptions.isEmpty() && executor.remove(job)) jobs.remove(job.key)
        }
    }

    private inner class Job(val key: Key) : Runnable {
        val subscriptions = LinkedHashSet<Subscription>()
        override fun run() {
            val lookup = synchronized(gate) {
                if (subscriptions.isEmpty() || !key.scope.isOpen) {
                    jobs.remove(key)
                    return
                }
                activeLookups++
                peakActiveLookups = maxOf(peakActiveLookups, activeLookups)
                lookups++
                checkNotNull(key.scope.lookup)
            }
            // The only blocking operation; no selector ownership or resolver lock is held here.
            val result = try {
                val addresses = lookup(key.name)
                when {
                    addresses.isEmpty() -> Result.Failed(ResolveException(Failure.EMPTY_RESULT))
                    addresses.size > SocksNioTcpConnect.MAX_ADDRESSES -> Result.Failed(ResolveException(Failure.TOO_MANY_ADDRESSES))
                    else -> Result.Addresses(addresses.toList())
                }
            } catch (error: Throwable) {
                Result.Failed(ResolveException(Failure.LOOKUP_FAILED, error))
            }
            val callbacks = synchronized(gate) {
                activeLookups--
                jobs.remove(key)
                if (result is Result.Failed) failed++
                if (subscriptions.isEmpty()) abandonedResults++
                subscriptions.mapNotNull { subscription ->
                    subscription.callback.also { subscription.callback = null; subscribers-- }
                }.also { subscriptions.clear() }
            }
            // <=256 subscribers per query, <=1024 globally; external code never runs under gate.
            callbacks.forEach { callback ->
                try { callback(result) } catch (_: Throwable) { synchronized(gate) { callbackFailures++ } }
            }
        }
    }

    fun stats(): Stats = synchronized(gate) {
        Stats(executor.poolSize, activeLookups, executor.queue.size, jobs.size, subscribers, peakSubscribers,
            lookups, merged, rejected, failed, cancelled, abandonedResults,
            timedOut, discardedCompletions, rejectedCompletions, callbackFailures, peakActiveLookups, peakQueuedQueries)
    }
    internal fun recordTimeout() = synchronized(gate) { timedOut++ }
    internal fun recordDiscard() = synchronized(gate) { discardedCompletions++ }
    internal fun recordCompletionRejection() = synchronized(gate) { rejectedCompletions++ }

    /** Tests release their controlled lookups before shutdown; production never tears down the pool. */
    internal fun shutdownForTest(): Boolean {
        check(testInstance)
        synchronized(gate) { jobs.keys.map { it.scope }.distinct().forEach { it.close() } }
        executor.shutdown()
        return executor.awaitTermination(3, TimeUnit.SECONDS)
    }

    companion object {
        private val threadIds = AtomicLong()
        val shared: SocksResolver by lazy { SocksResolver(Limits(), false) }
        internal fun forTest(limits: Limits = Limits()): SocksResolver = SocksResolver(limits, true)
    }
}
