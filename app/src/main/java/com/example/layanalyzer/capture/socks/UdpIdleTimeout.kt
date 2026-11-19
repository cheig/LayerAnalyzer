package com.example.layanalyzer.capture.socks

import java.io.IOException

/**
 * One resource-owned timer, using the same monotonic activity clock as the data plane.
 * Refreshes do not cancel/recreate timers. The periodic check and packet admission both read
 * current activity, so an old scheduled check cannot close a refreshed association and an
 * overdue datagram/completion cannot revive it. No association thread or independent registry.
 */
internal class UdpIdleTimeout private constructor(
    private val active: UdpAssociation.Active,
    private val driver: UdpDataPlane,
    private val checkIntervalNanos: Long
) : UdpDataPlane.Lifecycle {
    private val session = active.session
    private var timer: SocksEventLoop.Timer? = null
    private var closed = false

    override fun beforeIo(nowNanos: Long): Boolean {
        check(session.owner.inEventLoop())
        if (closed || session.resource.isClosed) return false
        val activity = driver.policy.activity()
        val limit = if (activity.dnsOnly) DNS_IDLE_NANOS else UDP_IDLE_NANOS
        // Subtraction, rather than absolute timestamp ordering, survives nanoTime wrap.
        if (nowNanos - activity.lastActivityNanos >= limit) {
            active.close(IdleExpiredException(limit))
            return false
        }
        return true
    }

    private fun schedule() {
        if (!driver.checkActive()) return
        check(timer == null)
        val scheduled = session.owner.schedule(checkIntervalNanos, session.resource) {
            timer = null
            // Includes runtime/scope/owner invalidation even while no channel is ready.
            schedule()
        }
        if (scheduled.result != SocksEventLoop.Submission.ACCEPTED) {
            active.close(SocksSession.SchedulingRejectedException(scheduled.result))
        } else timer = checkNotNull(scheduled.timer)
    }

    override fun close() {
        check(session.owner.inEventLoop())
        if (closed) return
        closed = true
        timer?.cancel()
        timer = null
    }

    class IdleExpiredException(val idleLimitNanos: Long) :
        IOException("SOCKS UDP idle expired after ${idleLimitNanos / 1_000_000_000L}s")

    companion object {
        const val DNS_IDLE_NANOS = 10_000_000_000L
        const val UDP_IDLE_NANOS = 60_000_000_000L
        const val CHECK_INTERVAL_NANOS = 1_000_000_000L

        /** Install cleanup before attempting a timer; even initial rejection closes everything. */
        fun attach(active: UdpAssociation.Active, driver: UdpDataPlane,
            checkIntervalNanos: Long = CHECK_INTERVAL_NANOS): UdpIdleTimeout {
            require(checkIntervalNanos in 1..CHECK_INTERVAL_NANOS)
            check(active.session.owner.inEventLoop())
            val idle = UdpIdleTimeout(active, driver, checkIntervalNanos)
            if (driver.checkActive()) {
                driver.installLifecycle(idle)
                idle.schedule()
            } else idle.close()
            return idle
        }
    }
}
