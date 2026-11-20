// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksBudgetStats
import com.example.layanalyzer.capture.SocksSessionBudget
import com.example.layanalyzer.capture.SocksSessionLimits
import java.nio.channels.SelectableChannel
import java.util.concurrent.atomic.AtomicLong

/** One instance per group/capture. Legacy limits stay at 64; internal profiles are finite. */
internal class SocksSessionAdmission internal constructor(
    private val group: SocksEventLoopGroup,
    limits: SocksSessionLimits,
    private val nanoClock: () -> Long = System::nanoTime
) {
    enum class Protocol { TCP, UDP }
    data class Stats(
        val handshakes: SocksBudgetStats,
        val tcp: SocksBudgetStats,
        val udp: SocksBudgetStats,
        val rejectedHandshakes: Long,
        val rejectedTcp: Long,
        val rejectedUdp: Long,
        /** Only caller-owned reservations; transferred sessions live ONLY in loop resources. */
        val pendingReservations: Int,
        /** Reservations + auth + admitted TCP/UDP, held until the owner actually cleans up. */
        val ownerLoads: List<Int>
    )

    private val gate = Any()
    private val handshakes = SocksSessionBudget(group.config.runtimeLimits?.authentication ?: limits.handshakes)
    private val tcp = SocksSessionBudget(group.config.runtimeLimits?.tcp ?: group.config.udpValidationProfile?.tcp ?: group.config.tcpValidationProfile?.tcp ?: limits.tcp)
    private val udp = SocksSessionBudget(group.config.runtimeLimits?.udp ?: group.config.udpValidationProfile?.udp ?: limits.udp)
    private val nextId = AtomicLong()
    private val pending = LinkedHashSet<Reservation>()
    private val ownerLoads = IntArray(SocksEventLoopGroup.LOOP_COUNT)
    private var loadCursor = 0
    private var stopped = false
    private var rejectedHandshakes = 0L
    private var rejectedTcp = 0L
    private var rejectedUdp = 0L

    /**
     * NIO-104 listener accepts at most one caller-owned channel before reserving, never reads it
     * before admission, and immediately closes it on rejection. Standalone callers may reserve
     * before accept, but must close on no channel/accept failure. The caller owns
     * this reservation and any accepted channel until transfer returns ACCEPTED. Stop revokes all
     * untransferred reservations, not caller-owned channels. A fixed owner is chosen at reservation.
     * The 15s total auth/request deadline includes transfer queuing and never resets on fragments.
     */
    fun reserve(
        captureGeneration: Long,
        owner: SocksEventLoop = group.nextLoop(),
        handshakeTimeoutNanos: Long = DEFAULT_HANDSHAKE_TIMEOUT_NANOS
    ): Reservation? = synchronized(gate) {
        reserveOwned(captureGeneration, owner, handshakeTimeoutNanos)
    }

    /** Fixed-size counters, no additional session registry. Tie breaking rotates. */
    fun reserveLoadAware(captureGeneration: Long,
        handshakeTimeoutNanos: Long = DEFAULT_HANDSHAKE_TIMEOUT_NANOS): Reservation? = synchronized(gate) {
        val index = (0 until SocksEventLoopGroup.LOOP_COUNT)
            .map { (loadCursor + it) % SocksEventLoopGroup.LOOP_COUNT }
            .minBy { ownerLoads[it] }
        loadCursor = (index + 1) % SocksEventLoopGroup.LOOP_COUNT
        reserveOwned(captureGeneration, group.loop(index), handshakeTimeoutNanos)
    }

    private fun reserveOwned(captureGeneration: Long, owner: SocksEventLoop,
        handshakeTimeoutNanos: Long): Reservation? {
        val index = (0 until SocksEventLoopGroup.LOOP_COUNT).firstOrNull { group.loop(it) === owner }
        require(index != null) { "Foreign loop" }
        require(handshakeTimeoutNanos in 1..DEFAULT_HANDSHAKE_TIMEOUT_NANOS)
        if (stopped || !group.isRunning()) return null
        // An injected clock can fail; evaluate it before owning a lease/load slot.
        val deadline = nanoClock() + handshakeTimeoutNanos
        val lease = handshakes.tryAcquireLease() ?: run {
            rejectedHandshakes++
            return null
        }
        ownerLoads[index]++
        return Reservation(captureGeneration, nextId.incrementAndGet(), owner,
            deadline, lease, index).also { pending.add(it) }
    }

    inner class Reservation internal constructor(
        val captureGeneration: Long,
        val sessionId: Long,
        val owner: SocksEventLoop,
        internal val deadlineNanos: Long,
        private val handshakeLease: SocksSessionBudget.Lease,
        private val ownerIndex: Int
    ) : AutoCloseable {
        private var loadReleased = false // gate; covers pending and transferred cleanup
        private var handedOff = false // gate
        private var closed = false // gate

        /**
         * Reuses NIO-102 transfer (no listener here). ACCEPTED owns channel + lease, even before
         * registration, and must not be touched by the caller. EVERY rejection consumes/releases
         * this reservation but leaves channel caller-owned: caller must close that channel.
         * Callbacks are owner-only; factory failure/register failure/queued stop releases the lease
         * through transfer's onClosed hook. A second handoff is a programming error, not a release.
         */
        fun transfer(
            channel: SelectableChannel,
            interestOps: Int,
            onReady: (SocksSession, SocksEventLoop.Registration, Int) -> Unit,
            onSession: (SocksSession, SocksEventLoop.Registration) -> Unit,
            onClosed: (Throwable?) -> Unit = {}
        ): SocksEventLoop.Submission = synchronized(gate) {
            check(!handedOff) { "Reservation already transferred" }
            if (closed || stopped || !group.isRunning()) {
                closeReserved()
                return SocksEventLoop.Submission.STOPPED
            }
            var session: SocksSession? = null // accessed ONLY by owner callbacks
            val result = try {
                owner.transfer(channel, interestOps,
                    onReady = { registration, ops -> onReady(checkNotNull(session), registration, ops) },
                    onRegistered = { registration ->
                        val created = SocksSession(this@SocksSessionAdmission, owner, registration.resource,
                            captureGeneration, sessionId, deadlineNanos, handshakeLease, nanoClock)
                        session = created
                        if (created.armHandshakeDeadline()) onSession(created, registration)
                    },
                    onClosed = { cause ->
                        try {
                            session?.resourceClosed(cause)
                        } finally {
                            session = null
                            handshakeLease.close() // also covers no session/factory/register failure
                            releaseLoad()
                            onClosed(cause)
                        }
                    })
            } catch (error: Throwable) {
                closeReserved()
                throw error // NIO-102 precondition failure: channel remains caller-owned
            }
            pending.remove(this)
            if (result == SocksEventLoop.Submission.ACCEPTED) handedOff = true
            else closeReserved()
            result
        }

        /** After ACCEPTED this is a no-op: only the session/loop can release the lease. */
        override fun close() = synchronized(gate) { if (!handedOff) closeReserved() }

        private fun closeReserved() {
            if (closed) return
            closed = true
            pending.remove(this)
            handshakeLease.close()
            releaseLoad()
        }

        private fun releaseLoad() = synchronized(gate) {
            if (!loadReleased) {
                loadReleased = true
                check(ownerLoads[ownerIndex] > 0)
                ownerLoads[ownerIndex]--
            }
        }
    }

    internal fun tryProtocol(protocol: Protocol): SocksSessionBudget.Lease? = synchronized(gate) {
        if (stopped || !group.isRunning()) return null
        when (protocol) {
            Protocol.TCP -> tcp.tryAcquireLease().also { if (it == null) rejectedTcp++ }
            Protocol.UDP -> udp.tryAcquireLease().also { if (it == null) rejectedUdp++ }
        }
    }

    internal fun stop() = synchronized(gate) {
        stopped = true
        pending.toList().forEach { it.close() }
    }

    fun stats(): Stats = synchronized(gate) {
        Stats(handshakes.snapshot(), tcp.snapshot(), udp.snapshot(),
            rejectedHandshakes, rejectedTcp, rejectedUdp, pending.size, ownerLoads.toList())
    }

    companion object { const val DEFAULT_HANDSHAKE_TIMEOUT_NANOS = 15_000_000_000L }
}
