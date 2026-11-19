// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture

import java.util.concurrent.atomic.AtomicBoolean

/** Non-waiting admission, with an event-time high-water mark (not a sampled peak). */
internal class SocksSessionBudget(private val limit: Int) {
    init { require(limit > 0) }
    private var current = 0
    private var peak = 0

    @Synchronized
    fun tryAcquire(): Boolean {
        if (current == limit) return false
        current++
        peak = maxOf(peak, current)
        return true
    }

    /** Lease callers never use release() directly; the legacy Boolean API is unchanged. */
    @Synchronized
    fun tryAcquireLease(): Lease? = if (tryAcquire()) Lease(this) else null

    class Lease internal constructor(private val budget: SocksSessionBudget) : AutoCloseable {
        private val released = AtomicBoolean()
        val isReleased: Boolean get() = released.get()

        override fun close() {
            if (released.compareAndSet(false, true)) budget.release()
        }
    }

    @Synchronized
    fun release() {
        check(current > 0) { "SOCKS admission released twice" }
        current--
    }

    @Synchronized
    fun snapshot() = SocksBudgetStats(current, peak, limit)
}

internal data class SocksBudgetStats(val current: Int, val peak: Int, val limit: Int)
