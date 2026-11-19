package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.UdpDestinationPolicy
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.util.ArrayDeque

/**
 * Owner-only data plane. A single FIFO shares both directions and unresolved packets' budget.
 * Policy decoding/encoding creates at most one transient candidate per owner before admission;
 * only admitted arrays are retained. The queue limit excludes scratch and transient allocations.
 */
internal class UdpDataPlane(
    private val active: UdpAssociation.Active,
    private val runtime: UdpDataPlaneRuntime,
    private val scope: SocksResolver.Scope,
    rule: UdpDestinationPolicy = UdpDestinationPolicy.PRESERVE,
    private val io: ChannelIo = ChannelIo.CHANNEL,
    private val dnsTimeoutNanos: Long = SocksNioTcpResolve.DNS_TIMEOUT_NANOS
) : AutoCloseable {
    interface ChannelIo {
        fun receive(channel: DatagramChannel, scratch: ByteBuffer): InetSocketAddress? =
            channel.receive(scratch) as? InetSocketAddress
        fun send(channel: DatagramChannel, bytes: ByteBuffer, target: InetSocketAddress): Int = channel.send(bytes, target)
        companion object { val CHANNEL = object : ChannelIo {} }
    }

    /** Admission and activity refresh share one time sample, including the exact idle boundary. */
    interface Lifecycle : AutoCloseable { fun beforeIo(nowNanos: Long): Boolean }
    data class Snapshot(val queuedPackets: Int, val queuedBytes: Int, val resolving: Boolean,
        val retryPending: Boolean, val closed: Boolean, val policy: UdpPacketPolicy.Stats)

    val policy = UdpPacketPolicy(active.session, rule)
    private val session = active.session
    private val resolver = scope.resolver
    private var lease: UdpDataPlaneRuntime.Lease? = null
    private val pending = ArrayDeque<UdpPacketPolicy.Pending>()
    private var operation: SocksSession.Operation? = null
    private var retry: SocksEventLoop.Timer? = null
    private var lifecycle: Lifecycle? = null
    private var closed = false
    private var publishedTraffic = UdpDataPlaneRuntime.Traffic()

    init {
        require(dnsTimeoutNanos in 1..SocksNioTcpResolve.DNS_TIMEOUT_NANOS)
        check(session.owner.inEventLoop())
        active.ownDataPlane(this)
        if (live()) {
            lease = runtime.acquire(session.owner)
            if (lease == null) active.close() else {
                active.relay.replaceHandler { _, ops -> ready(active.relay, ops) }
                active.upstream.replaceHandler { _, ops -> ready(active.upstream, ops) }
                interests()
            }
        }
    }

    fun installLifecycle(value: Lifecycle) {
        check(session.owner.inEventLoop() && !closed && lifecycle == null)
        lifecycle = value
    }

    fun snapshot(): Snapshot {
        check(session.owner.inEventLoop())
        return Snapshot(pending.size, lease?.queuedBytes ?: 0, operation != null, retry != null, closed, policy.stats())
    }

    /** Owner-local periodic checks also retire invalid runtime/network scopes with no ready I/O. */
    fun checkActive(): Boolean {
        check(session.owner.inEventLoop())
        return live()
    }

    private fun live(nowNanos: Long = session.ownerNowNanos()): Boolean {
        if (closed || session.resource.isClosed) return false
        if (!runtime.isOpen || !scope.isOpen || scope.captureGeneration != session.captureGeneration ||
            session.owner.stats().state != SocksEventLoop.State.RUNNING) {
            active.close()
            return false
        }
        return lifecycle?.beforeIo(nowNanos) != false && !closed && !session.resource.isClosed
    }

    private fun ready(registration: SocksEventLoop.Registration, ops: Int) {
        if (!live()) return
        var work = 0
        if (ops and SelectionKey.OP_READ != 0) {
            val scratch = checkNotNull(lease).scratch
            while (work < MAX_DATAGRAMS_PER_CALLBACK && live()) {
                scratch.clear()
                val source = io.receive(registration.channel as DatagramChannel, scratch) ?: break
                work++
                // A controlled clock can cross the expiry boundary during receive, too.
                val now = session.ownerNowNanos()
                if (!live(now)) break
                val decision = if (registration === active.relay)
                    policy.fromClient(source, scratch.array(), length = scratch.position(), nowNanos = now)
                else policy.fromUpstream(source, scratch.array(), length = scratch.position(), nowNanos = now)
                if (decision is UdpPacketPolicy.Pending) {
                    if (checkNotNull(lease).reserve(decision.bytes.size)) pending.addLast(decision)
                    else policy.complete(decision, UdpPacketPolicy.Completion.QUEUE_DROPPED)
                }
                work += drain(MAX_DATAGRAMS_PER_CALLBACK - work)
            }
        }
        work += drain(MAX_DATAGRAMS_PER_CALLBACK - work)
        runtime.recordWork(work)
        interests()
        publishTraffic()
    }

    private fun drain(allowance: Int): Int {
        var work = 0
        while (live() && retry == null) {
            when (val packet = pending.peekFirst() ?: break) {
                is UdpPacketPolicy.Resolve -> {
                    if (operation == null) resolve(packet)
                    // Immediate submission failure removed the head; continue bounded work later.
                    break
                }
                is UdpPacketPolicy.Send -> {
                    if (work >= allowance) break
                    work++
                    val buffer = ByteBuffer.wrap(packet.bytes)
                    val written = try {
                        io.send(destination(packet).channel as DatagramChannel, buffer, packet.target)
                    } catch (_: IOException) {
                        finish(packet, UdpPacketPolicy.Completion.SEND_FAILED)
                        continue
                    }
                    if (!live()) break
                    when {
                        written == 0 && packet.bytes.isEmpty() -> {
                            runtime.recordEmptyAttempt()
                            finish(packet, UdpPacketPolicy.Completion.EMPTY_ATTEMPTED)
                        }
                        written == packet.bytes.size && buffer.position() == packet.bytes.size ->
                            finish(packet, UdpPacketPolicy.Completion.SENT)
                        written == 0 && buffer.position() == 0 -> { retrySend(); break }
                        else -> finish(packet, UdpPacketPolicy.Completion.SEND_FAILED)
                    }
                }
            }
        }
        return work
    }

    private fun resolve(packet: UdpPacketPolicy.Resolve) {
        val token = session.beginOperation(dnsTimeoutNanos) {
            operation = null
            resolver.recordTimeout()
            if (live() && pending.peekFirst() === packet) {
                finish(packet, UdpPacketPolicy.Completion.RESOLUTION_FAILED)
                continueQueue()
            }
        } ?: return
        operation = token
        val submitted = resolver.resolve(scope, packet.name) { result ->
            // No payload is captured by this worker callback; the FIFO owns all queued arrays.
            val accepted = session.complete(token, onDiscard = { resolver.recordDiscard() }) {
                operation = null
                if (live()) {
                    val head = pending.peekFirst() as? UdpPacketPolicy.Resolve
                    if (head != null) {
                        when (result) {
                            is SocksResolver.Result.Addresses -> {
                                val decision = policy.resolved(head, result.addresses.first())
                                pending.removeFirst()
                                if (decision is UdpPacketPolicy.Send) pending.addFirst(decision)
                                else checkNotNull(lease).release(head.bytes.size)
                            }
                            is SocksResolver.Result.Failed -> finish(head, UdpPacketPolicy.Completion.RESOLUTION_FAILED)
                        }
                        continueQueue()
                    }
                }
            }
            // Rejected ingress cannot mutate owner state. The existing operation timer frees
            // the bounded packet; stop closes it immediately. No worker retry queue is created.
            if (accepted != SocksEventLoop.Submission.ACCEPTED) resolver.recordCompletionRejection()
        }
        submitted.subscription?.let { session.attachOperationCleanup(token, it) }
        if (submitted.failure != null) {
            session.cancelOperation(token)
            operation = null
            if (live()) finish(packet, UdpPacketPolicy.Completion.RESOLUTION_FAILED)
            // Bound immediate failures to one per drain pass; use one resource-owned timer.
            retrySend()
        }
    }

    private fun continueQueue() {
        runtime.recordWork(drain(MAX_DATAGRAMS_PER_CALLBACK))
        interests()
        publishTraffic()
    }

    private fun publishTraffic() {
        val next = UdpDataPlaneRuntime.Traffic.from(policy.stats())
        runtime.recordTraffic(publishedTraffic, next)
        publishedTraffic = next
    }

    private fun retrySend() {
        if (!live() || retry != null || pending.isEmpty()) return
        val scheduled = session.owner.schedule(RETRY_NANOS, session.resource) {
            retry = null
            if (live()) {
                // Nonempty zero writes yield even if the OS repeatedly reports writability.
                // Rearm readiness after the delay; only DNS submission failures need a timer
                // continuation because an unresolved head has no channel readiness to await.
                if (pending.peekFirst() is UdpPacketPolicy.Resolve) continueQueue() else interests()
            }
        }
        if (scheduled.result != SocksEventLoop.Submission.ACCEPTED)
            active.close(SocksSession.SchedulingRejectedException(scheduled.result))
        else retry = scheduled.timer
    }

    private fun finish(packet: UdpPacketPolicy.Pending, completion: UdpPacketPolicy.Completion) {
        check(pending.removeFirst() === packet)
        checkNotNull(lease).release(packet.bytes.size)
        if (completion == UdpPacketPolicy.Completion.SEND_FAILED) runtime.recordSendFailure()
        policy.complete(packet, completion)
    }

    private fun destination(packet: UdpPacketPolicy.Send) =
        if (packet.direction == UdpPacketPolicy.Direction.UPSTREAM) active.upstream else active.relay

    private fun interests() {
        if (!live()) return
        active.relay.pendingWrite(false)
        active.upstream.pendingWrite(false)
        active.relay.interestOps(SelectionKey.OP_READ)
        active.upstream.interestOps(SelectionKey.OP_READ)
        val head = pending.peekFirst()
        if (head is UdpPacketPolicy.Send && retry == null) destination(head).pendingWrite(true)
    }

    override fun close() {
        check(session.owner.inEventLoop())
        if (closed) return
        closed = true
        publishTraffic()
        retry?.cancel()
        retry = null
        operation?.let(session::cancelOperation)
        operation = null
        pending.clear()
        lease?.close()
        lease = null
        policy.close()
        val cleanup = lifecycle
        lifecycle = null
        cleanup?.close()
    }

    companion object {
        const val MAX_DATAGRAMS_PER_CALLBACK = 32
        private const val RETRY_NANOS = 1_000_000L
    }
}
