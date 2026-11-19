// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksSessionBudget
import com.example.layanalyzer.capture.tls.TlsGatewayConnection
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.SelectableChannel

/**
 * Session lifecycle, not a parser/connect/relay implementation. Constructed ONLY by admission transfer
 * on the chosen loop and backed by that transfer's real NIO-102 resource. All mutable state,
 * channels, timers, buffers and session leases are owner-only. No independent session registry.
 * NIO-105 enters AUTH/REQUEST with a fixed handshake deadline; NIO-201 adds bounded connection
 * setup/reply phases. No worker may retain a channel/buffer or mutate this session.
 */
internal class SocksSession internal constructor(
    private val admission: SocksSessionAdmission,
    val owner: SocksEventLoop,
    internal val resource: SocksEventLoop.Resource,
    val captureGeneration: Long,
    val sessionId: Long,
    private val handshakeDeadlineNanos: Long,
    private var handshakeLease: SocksSessionBudget.Lease?,
    private val nanoClock: () -> Long
) {
    enum class State { ACCEPTED, AUTH, REQUEST, ADMITTED, RESOLVING, CONNECTING, GATEWAY_WRITE, GATEWAY_READY, UDP_SETUP, SOCKS_REPLY, TCP_CONNECTED, TCP_RELAY, UDP_ACTIVE, DRAINING, FAILING, CLOSING, CLOSED }
    data class Operation(
        val captureGeneration: Long,
        val sessionId: Long,
        val operationId: Long,
        val deadlineNanos: Long
    )
    data class Snapshot(
        val state: State,
        val protocol: SocksSessionAdmission.Protocol?,
        val deadlineNanos: Long?,
        val operationId: Long?,
        val buffers: Int,
        val bufferBytes: Int,
        val hasHandshakeLease: Boolean,
        val hasProtocolLease: Boolean,
        val closeCause: Throwable?,
        val operationCleanupFailures: Long,
        val udpCleanupFailures: Long
    )

    private var state = State.ACCEPTED
    private var protocol: SocksSessionAdmission.Protocol? = null
    private var protocolLease: SocksSessionBudget.Lease? = null
    private var deadlineNanos: Long? = handshakeDeadlineNanos
    private var phaseTimer: SocksEventLoop.Timer? = null
    private var phaseTimeout: (() -> Unit)? = null
    private var operationTimer: SocksEventLoop.Timer? = null
    private var operation: Operation? = null
    private var operationTimeout: (() -> Unit)? = null
    private var operationCleanup: AutoCloseable? = null
    private var operationCleanupFailures = 0L
    private var nextOperationId = 0L
    // Identity, NOT ByteBuffer.equals/hashCode (both change with buffer positions/content).
    private val buffers = ArrayList<ByteBuffer>()
    private var bufferBytes = 0
    private var tcpBuffers: SocksTcpBufferBudget.Reservation? = null
    private var gatewayFrame: TlsGatewayConnection? = null
    private var gatewayFrameBytes = 0
    private var closeCause: Throwable? = null
    private var udpCleanup: AutoCloseable? = null
    private var udpCleanupFailures = 0L

    fun snapshot(): Snapshot {
        requireOwner()
        return Snapshot(state, protocol, deadlineNanos, operation?.operationId,
            buffers.size + (tcpBuffers?.bufferCount ?: 0) + (if (gatewayFrame != null) 1 else 0),
            bufferBytes + (tcpBuffers?.bufferBytes ?: 0) + gatewayFrameBytes,
            handshakeLease != null, protocolLease != null, closeCause, operationCleanupFailures, udpCleanupFailures)
    }

    /** Same injected monotonic clock as admission/phase deadlines, for bounded I/O drivers. */
    internal fun ownerNowNanos(): Long { requireOwner(); return nanoClock() }

    internal fun armHandshakeDeadline(): Boolean {
        requireOpen()
        return armPhaseDeadline(handshakeDeadlineNanos)
    }

    /** NIO-105 fragments/phase changes never extend the admission-time total handshake deadline. */
    fun enterAuth(): Boolean {
        requireOpen()
        check(state == State.ACCEPTED)
        if (!withinPhaseDeadline()) return false
        state = State.AUTH
        return true
    }

    fun enterRequest(): Boolean {
        requireOpen()
        check(state == State.AUTH)
        if (!withinPhaseDeadline()) return false
        state = State.REQUEST
        return true
    }

    /**
     * Failure leaves REQUEST, deadline and handshake lease untouched until explicit close/failure
     * reply. Success owns protocol lease BEFORE releasing auth, and invalidates auth operations.
     * A second promotion, even to the same protocol, is rejected rather than double acquiring.
     */
    fun admitProtocol(target: SocksSessionAdmission.Protocol): Boolean {
        requireOpen()
        check(state == State.REQUEST && protocolLease == null)
        if (!withinPhaseDeadline()) return false
        val acquired = admission.tryProtocol(target) ?: return false
        protocolLease = acquired
        protocol = target
        handshakeLease?.close()
        handshakeLease = null
        state = State.ADMITTED
        phaseTimer?.cancel()
        phaseTimer = null
        phaseTimeout = null
        deadlineNanos = null // next stages must explicitly install their own operation deadline
        invalidateOperation()
        return true
    }

    /** DNS queuing and lookup consume the same establishment budget as connect. */
    fun enterResolving(deadline: Long, onTimeout: () -> Unit): Boolean {
        requireOpen()
        check(state == State.ADMITTED && protocol == SocksSessionAdmission.Protocol.TCP)
        state = State.RESOLVING
        return armPhaseDeadline(deadline, onTimeout)
    }

    /** One absolute deadline for DNS and all direct-connect attempts. */
    fun enterConnecting(deadline: Long, onTimeout: () -> Unit): Boolean {
        requireOpen()
        check((state == State.ADMITTED || state == State.RESOLVING) && protocol == SocksSessionAdmission.Protocol.TCP)
        state = State.CONNECTING
        return armPhaseDeadline(deadline, onTimeout)
    }

    /** The write and READY read share one absolute deadline, never renewed by partial progress. */
    fun enterGatewayWrite(deadline: Long, onTimeout: () -> Unit): Boolean {
        requireOpen()
        check(state == State.CONNECTING)
        if (!withinPhaseDeadline()) return false
        state = State.GATEWAY_WRITE
        return armPhaseDeadline(deadline, onTimeout)
    }

    fun enterGatewayReady(): Boolean {
        requireOpen()
        check(state == State.GATEWAY_WRITE)
        if (!withinPhaseDeadline()) return false
        state = State.GATEWAY_READY
        return true
    }

    fun enterUdpSetup(deadline: Long, onTimeout: () -> Unit): Boolean {
        requireOpen()
        check(state == State.ADMITTED && protocol == SocksSessionAdmission.Protocol.UDP)
        state = State.UDP_SETUP
        return armPhaseDeadline(deadline, onTimeout)
    }

    fun ownUdpCleanup(cleanup: AutoCloseable) {
        requireOpen()
        check(protocol == SocksSessionAdmission.Protocol.UDP && udpCleanup == null)
        udpCleanup = cleanup
    }

    fun enterUdpActive(): Boolean {
        requireOpen()
        check(state == State.SOCKS_REPLY && protocol == SocksSessionAdmission.Protocol.UDP)
        if (!withinPhaseDeadline()) return false
        state = State.UDP_ACTIVE
        phaseTimer?.cancel()
        phaseTimer = null
        phaseTimeout = null
        deadlineNanos = null
        return true
    }

    /** Successful TCP connect/READY or UDP setup precedes this independently bounded reply. */
    fun enterSocksReply(timeoutNanos: Long): Boolean {
        requireOpen()
        check(state == State.CONNECTING || state == State.GATEWAY_READY || state == State.UDP_SETUP)
        require(timeoutNanos in 1..SocksEventLoop.MAX_DELAY_NANOS)
        if (!withinPhaseDeadline()) return false
        state = State.SOCKS_REPLY
        return armPhaseDeadline(nanoClock() + timeoutNanos)
    }

    /** No relay/idle deadline is introduced by NIO-201; the next handler owns data transfer. */
    fun enterTcpConnected(): Boolean {
        requireOpen()
        check(state == State.SOCKS_REPLY && protocol == SocksSessionAdmission.Protocol.TCP)
        if (!withinPhaseDeadline()) return false
        state = State.TCP_CONNECTED
        phaseTimer?.cancel()
        phaseTimer = null
        phaseTimeout = null
        deadlineNanos = null
        return true
    }

    fun enterTcpRelay() {
        requireOpen()
        check(state == State.TCP_CONNECTED)
        state = State.TCP_RELAY
    }

    /** At least one source has sent FIN; the other direction may live indefinitely. */
    fun enterDraining() {
        requireOpen()
        check(state == State.TCP_RELAY || state == State.DRAINING)
        state = State.DRAINING
    }

    /** Reserve before connect when assembling the full pipeline; release on every scope close. */
    fun reserveTcpBuffers(budget: SocksTcpBufferBudget): SocksTcpBufferBudget.Reservation? {
        requireOpen()
        check(protocol == SocksSessionAdmission.Protocol.TCP)
        tcpBuffers?.let { check(it.budget === budget); return it }
        return budget.reserve(owner)?.also { tcpBuffers = it }
    }

    /** Auth failure is capped by auth time; connect failure gets its own bounded reply window. */
    fun enterFailing(timeoutNanos: Long): Boolean {
        requireOpen()
        require(timeoutNanos in 1..SocksEventLoop.MAX_DELAY_NANOS)
        invalidateOperation()
        val now = nanoClock()
        val remaining = when (state) {
            State.ADMITTED, State.RESOLVING, State.CONNECTING, State.GATEWAY_WRITE, State.GATEWAY_READY, State.UDP_SETUP -> null
            else -> deadlineNanos?.let { it - now }
        }
        state = State.FAILING
        return armPhaseDeadline(now + minOf(timeoutNanos, remaining ?: timeoutNanos))
    }

    /** Bounded protocol control storage only; P2/P4 global data-buffer budgets are separate. */
    fun allocateControlBuffer(capacity: Int): ByteBuffer {
        requireOpen()
        require(capacity in 1..MAX_CONTROL_BUFFER_BYTES && capacity <= MAX_CONTROL_BUFFER_BYTES - bufferBytes)
        return ByteBuffer.allocate(capacity).also {
            buffers.add(it)
            bufferBytes += capacity
        }
    }

    fun releaseControlBuffer(buffer: ByteBuffer) {
        requireOwner()
        val index = buffers.indexOfFirst { it === buffer }
        if (index < 0) return
        wipe(buffer)
        bufferBytes -= buffer.capacity()
        buffers.removeAt(index)
    }

    /** Ownership transfers only on success; caller closes a rejected description. */
    fun ownGatewayFrame(description: TlsGatewayConnection) {
        requireOpen()
        check(protocol == SocksSessionAdmission.Protocol.TCP && gatewayFrame == null)
        gatewayFrameBytes = description.frame.capacity()
        gatewayFrame = description
    }

    fun releaseGatewayFrame(description: TlsGatewayConnection) {
        requireOwner()
        if (gatewayFrame !== description) return
        gatewayFrame = null
        gatewayFrameBytes = 0
        description.close()
    }

    /** Loop-only additional channel handoff into the SAME scope (no migration to another loop). */
    fun register(
        channel: SelectableChannel,
        interestOps: Int,
        onReady: (SocksEventLoop.Registration, Int) -> Unit
    ): SocksEventLoop.Registration {
        requireOpen() // failure here leaves channel caller-owned, matching NIO-102
        return resource.register(channel, interestOps, onReady)
    }

    /** One current operation. Installing a new one invalidates the old token and timer. */
    fun beginOperation(timeoutNanos: Long, onTimeout: () -> Unit = { close(DeadlineExceededException()) }): Operation? {
        requireOpen()
        require(timeoutNanos in 1..SocksEventLoop.MAX_DELAY_NANOS)
        if (!withinPhaseDeadline()) return null
        invalidateOperation()
        val now = nanoClock()
        val delay = minOf(timeoutNanos, deadlineNanos?.let { it - now } ?: timeoutNanos)
        if (delay <= 0) {
            close(DeadlineExceededException())
            return null
        }
        check(nextOperationId < Long.MAX_VALUE) { "Operation IDs exhausted" }
        val token = Operation(captureGeneration, sessionId, ++nextOperationId, now + delay)
        operation = token
        operationTimeout = onTimeout
        val submitted = owner.schedule(delay, resource) {
            if (operation == token) expireOperation()
        }
        if (submitted.result != SocksEventLoop.Submission.ACCEPTED) {
            close(SchedulingRejectedException(submitted.result))
            return null
        }
        operationTimer = checkNotNull(submitted.timer)
        return token
    }

    /** One bounded external subscription, detached on success, timeout, replacement or scope close. */
    fun attachOperationCleanup(token: Operation, cleanup: AutoCloseable) {
        requireOwner()
        if (operation != token || resource.isClosed) { cleanOperation(cleanup); return }
        check(operationCleanup == null)
        operationCleanup = cleanup
    }

    /** Owner-only cancellation without closing the session or disturbing a newer operation. */
    fun cancelOperation(token: Operation): Boolean {
        requireOwner()
        if (operation != token) return false
        invalidateOperation()
        return true
    }

    /**
     * The only worker-result ingress. Worker owns its result until this call. discard must be
     * thread-safe/nonblocking: rejection runs it on submitting thread; stale/stop runs it on owner.
     * Accepted callbacks validate generation + session + operation AND monotonic deadline on owner.
     * Only one valid result can claim an operation; duplicates/stale results dispose exactly once.
     */
    fun complete(
        token: Operation,
        onDiscard: () -> Unit = {},
        action: (SocksSession) -> Unit
    ): SocksEventLoop.Submission {
        val result = owner.complete(resource, onDiscard) {
            if (operation != token || token.captureGeneration != captureGeneration || token.sessionId != sessionId) {
                onDiscard()
            } else if (token.deadlineNanos - nanoClock() <= 0) {
                try { onDiscard() } finally { expireOperation() }
            } else if (!withinPhaseDeadline()) {
                onDiscard()
            } else {
                invalidateOperation()
                action(this)
            }
        }
        if (result != SocksEventLoop.Submission.ACCEPTED) onDiscard()
        return result
    }

    /** Owner-only, unified idempotent close. External callers request group stop or submit to owner. */
    fun close(cause: Throwable? = null) {
        requireOwner()
        if (state == State.CLOSED) return
        state = State.CLOSING
        resource.close(cause) // resource closes keys/channels/timers THEN invokes resourceClosed
    }

    /** Invoked by NIO-102 scope close, including callback failure and group stop. */
    internal fun resourceClosed(cause: Throwable?) {
        requireOwner()
        if (state == State.CLOSED) return
        state = State.CLOSED
        closeCause = cause
        phaseTimer?.cancel()
        phaseTimer = null
        phaseTimeout = null
        invalidateOperation()
        deadlineNanos = null
        val udp = udpCleanup
        udpCleanup = null
        try { udp?.close() } catch (_: Throwable) { udpCleanupFailures++ }
        buffers.forEach(::wipe)
        buffers.clear()
        bufferBytes = 0
        gatewayFrame?.close()
        gatewayFrame = null
        gatewayFrameBytes = 0
        tcpBuffers?.close()
        tcpBuffers = null
        protocolLease?.close()
        protocolLease = null
        handshakeLease?.close()
        handshakeLease = null
    }

    private fun armPhaseDeadline(deadline: Long, onTimeout: () -> Unit = { close(DeadlineExceededException()) }): Boolean {
        phaseTimer?.cancel()
        phaseTimer = null
        phaseTimeout = onTimeout
        deadlineNanos = deadline
        val remaining = deadline - nanoClock()
        if (remaining <= 0) {
            expirePhase()
            return false
        }
        val scheduled = owner.schedule(remaining, resource) { expirePhase() }
        if (scheduled.result != SocksEventLoop.Submission.ACCEPTED) {
            close(SchedulingRejectedException(scheduled.result))
            return false
        }
        phaseTimer = checkNotNull(scheduled.timer)
        return true
    }

    private fun withinPhaseDeadline(): Boolean {
        if (deadlineNanos?.let { it - nanoClock() <= 0 } == true) {
            expirePhase()
            return false
        }
        return true
    }

    private fun expirePhase() {
        val action = phaseTimeout
        phaseTimeout = null
        phaseTimer?.cancel()
        phaseTimer = null
        action?.invoke()
    }

    private fun invalidateOperation() {
        operation = null
        operationTimeout = null
        operationTimer?.cancel()
        operationTimer = null
        val cleanup = operationCleanup
        operationCleanup = null
        cleanup?.let(::cleanOperation)
    }

    private fun cleanOperation(cleanup: AutoCloseable) {
        try { cleanup.close() } catch (_: Throwable) { operationCleanupFailures++ }
    }

    private fun expireOperation() {
        val timeout = operationTimeout
        invalidateOperation()
        timeout?.invoke()
    }

    private fun wipe(buffer: ByteBuffer) {
        val bytes = buffer.duplicate()
        bytes.clear()
        while (bytes.hasRemaining()) bytes.put(0)
        buffer.clear()
    }

    private fun requireOwner() = check(owner.inEventLoop()) { "Session requires ${owner.name} owner thread" }
    private fun requireOpen() {
        requireOwner()
        check(state != State.CLOSED && state != State.CLOSING && !resource.isClosed) { "Session closed" }
    }

    internal class DeadlineExceededException : IOException("SOCKS session deadline expired")
    internal class SchedulingRejectedException(result: SocksEventLoop.Submission) :
        IOException("SOCKS session timer rejected: $result")

    companion object { const val MAX_CONTROL_BUFFER_BYTES = 4_096 }
}
