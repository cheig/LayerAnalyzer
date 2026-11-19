package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.UdpDestinationPolicy
import com.example.layanalyzer.capture.UdpInterventionStats
import com.example.layanalyzer.capture.UdpVerdict
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Owner-local UDP protocol/policy state. No socket I/O, DNS, timers or packet retention.
 * The data-plane owner must close this alongside its bounded queues and DNS subscriptions.
 * Callers check association expiry BEFORE offering a packet; rejected packets never refresh it.
 * The injected policy is the capture's frozen, nonblocking policy, never a settings lookup.
 */
internal class UdpPacketPolicy(
    private val session: SocksSession,
    private val policy: UdpDestinationPolicy = UdpDestinationPolicy.PRESERVE
) : AutoCloseable {
    enum class Direction { UPSTREAM, CLIENT }
    enum class DropReason { INVALID, SOURCE, UNALLOWED_PEER, POLICY, TOO_LARGE, INACTIVE }
    enum class Completion { SENT, EMPTY_ATTEMPTED, QUEUE_DROPPED, SEND_FAILED, RESOLUTION_FAILED, CANCELLED }

    sealed interface Decision
    data class Dropped(val reason: DropReason) : Decision

    /**
     * One owned array, never a view of the shared receive scratch. The driver budgets bytes.size
     * (including a response's SOCKS header), retains it only in bounded queues, and completes it
     * once. This class does not keep references to pending packets.
     */
    sealed class Pending protected constructor(
        internal val owner: UdpPacketPolicy,
        val bytes: ByteArray
    ) : Decision {
        internal var finished = false
    }

    class Resolve internal constructor(owner: UdpPacketPolicy, bytes: ByteArray, val name: String, val port: Int) :
        Pending(owner, bytes)

    class Send internal constructor(
        owner: UdpPacketPolicy,
        bytes: ByteArray,
        val target: InetSocketAddress,
        val direction: Direction
    ) : Pending(owner, bytes)

    data class Activity(val lastActivityNanos: Long, val dnsOnly: Boolean)
    data class Stats(
        val intervention: UdpInterventionStats,
        val invalidDatagrams: Long,
        val sourceRejectedDatagrams: Long,
        val unallowedResponses: Long,
        val oversizedDatagrams: Long,
        val queueDroppedDatagrams: Long,
        val queueDroppedBytes: Long,
        val sendFailures: Long,
        val resolutionFailures: Long,
        val sentBytes: Long,
        val receivedBytes: Long,
        val allowedPeers: Int,
        val clientEndpoint: InetSocketAddress?,
        val closed: Boolean
    )

    private val allowedPeers = LinkedHashMap<InetSocketAddress, Long>(16, 0.75f, true)
    private var clientEndpoint: InetSocketAddress? = null
    private var lastActivityNanos = session.ownerNowNanos()
    private var dnsOnly = true
    private var closed = false
    private var blockedDatagrams = 0L
    private var blockedBytes = 0L
    private var invalidDatagrams = 0L
    private var sourceRejectedDatagrams = 0L
    private var unallowedResponses = 0L
    private var oversizedDatagrams = 0L
    private var queueDroppedDatagrams = 0L
    private var queueDroppedBytes = 0L
    private var sendFailures = 0L
    private var resolutionFailures = 0L
    private var sentBytes = 0L
    private var receivedBytes = 0L

    init { check(session.snapshot().state == SocksSession.State.UDP_ACTIVE) }

    fun activity(): Activity { requireOwner(); return Activity(lastActivityNanos, dnsOnly) }

    fun stats(): Stats {
        requireOwner()
        return Stats(UdpInterventionStats(blockedDatagrams, blockedBytes), invalidDatagrams,
            sourceRejectedDatagrams, unallowedResponses, oversizedDatagrams, queueDroppedDatagrams,
            queueDroppedBytes, sendFailures, resolutionFailures, sentBytes, receivedBytes,
            allowedPeers.size, clientEndpoint, closed)
    }

    /**
     * Validates the source and frame before locking the client. decodeUdpRequest makes exactly one
     * payload copy; callers may conservatively reserve the incoming wire length before this call,
     * then charge the returned Pending.bytes.size. No array/closure retains the receive scratch.
     */
    fun fromClient(source: InetSocketAddress, bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset,
        nowNanos: Long = session.ownerNowNanos()): Decision {
        requireOwner()
        if (!live()) return Dropped(DropReason.INACTIVE)
        if (source.isUnresolved || !source.address.isLoopbackAddress || source.port == 0 ||
            clientEndpoint?.let { it != source } == true) return drop(DropReason.SOURCE)
        if (!validSlice(bytes, offset, length)) return drop(DropReason.INVALID)
        if (length > MAX_RECEIVE_BYTES) return drop(DropReason.TOO_LARGE)
        val request = SocksProtocol.decodeUdpRequest(bytes, offset, length) ?: return drop(DropReason.INVALID)
        // Destination zero cannot be sent by either DatagramSocket or DatagramChannel.
        if (request.port == 0) return drop(DropReason.INVALID)
        val maxPayload = (request.destination as? SocksDestination.Ip)?.address?.let(::maxPayloadBytes)
            ?: MAX_IPV6_PAYLOAD_BYTES
        if (request.payload.size > maxPayload) return drop(DropReason.TOO_LARGE)
        clientEndpoint = source
        lastActivityNanos = nowNanos
        if (request.port != DNS_PORT) dnsOnly = false
        return when (val destination = request.destination) {
            is SocksDestination.Ip -> forward(request.payload, destination.address, request.port)
            is SocksDestination.Domain -> Resolve(this, request.payload, destination.name, request.port)
        }
    }

    /** DNS driver validates capture/session/operation generation first. Resolving never renews idle. */
    fun resolved(packet: Resolve, address: InetAddress): Decision {
        requireOwner()
        check(packet.owner === this)
        if (!live() || packet.finished) return Dropped(DropReason.INACTIVE)
        packet.finished = true
        return forward(packet.bytes, address, packet.port)
    }

    private fun forward(bytes: ByteArray, address: InetAddress, port: Int): Decision {
        if (bytes.size > maxPayloadBytes(address)) return drop(DropReason.TOO_LARGE)
        if (policy.decide(address, port) == UdpVerdict.BlockSelectedUdp443) {
            blockedDatagrams++
            blockedBytes += bytes.size
            return Dropped(DropReason.POLICY)
        }
        return Send(this, bytes, InetSocketAddress(address, port), Direction.UPSTREAM)
    }

    /**
     * Responses require a confirmed send (or one explicitly counted empty-datagram attempt)
     * to this exact address AND port. See EMPTY_ATTEMPTED's NIO ambiguity in complete().
     * Their encoded size can be reserved before allocation with responseWireBytes().
     */
    fun fromUpstream(source: InetSocketAddress, bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset,
        nowNanos: Long = session.ownerNowNanos()): Decision {
        requireOwner()
        if (!live()) return Dropped(DropReason.INACTIVE)
        if (!validSlice(bytes, offset, length)) return drop(DropReason.INVALID)
        if (source.isUnresolved || source.port == 0) return drop(DropReason.UNALLOWED_PEER)
        if (length > MAX_RECEIVE_BYTES || responseWireBytes(source.address, length) > MAX_IPV4_PAYLOAD_BYTES) {
            return drop(DropReason.TOO_LARGE)
        }
        val now = nowNanos
        val seen = allowedPeers[source] ?: return drop(DropReason.UNALLOWED_PEER)
        if (now - seen > PEER_TTL_NANOS) {
            allowedPeers.remove(source)
            return drop(DropReason.UNALLOWED_PEER)
        }
        allowedPeers[source] = now
        lastActivityNanos = now
        receivedBytes += length
        val client = checkNotNull(clientEndpoint)
        return Send(this, SocksProtocol.encodeUdpResponse(source.address, source.port, bytes, offset, length),
            client, Direction.CLIENT)
    }

    /**
     * SENT means the driver proved the whole datagram was sent. EMPTY_ATTEMPTED separately admits
     * responses after one empty-datagram attempt: public NIO cannot distinguish success from
     * would-block for send() == 0. The driver counts that ambiguity and never retries the packet.
     * Confirmed upstream sends and empty attempts admit peers; drops/failures cannot admit replies.
     * Duplicate or late completion is harmless, and no completion refreshes association idle.
     */
    fun complete(packet: Pending, completion: Completion): Boolean {
        requireOwner()
        check(packet.owner === this)
        if (!live() || packet.finished) return false
        require(completion != Completion.SENT || packet is Send)
        require(completion != Completion.EMPTY_ATTEMPTED || packet is Send && packet.bytes.isEmpty())
        require(completion != Completion.SEND_FAILED || packet is Send)
        require(completion != Completion.RESOLUTION_FAILED || packet is Resolve)
        packet.finished = true
        when (completion) {
            Completion.SENT, Completion.EMPTY_ATTEMPTED -> if ((packet as Send).direction == Direction.UPSTREAM) {
                sentBytes += packet.bytes.size
                allowPeer(packet.target, session.ownerNowNanos())
            }
            Completion.QUEUE_DROPPED -> { queueDroppedDatagrams++; queueDroppedBytes += packet.bytes.size }
            Completion.SEND_FAILED -> sendFailures++
            Completion.RESOLUTION_FAILED -> resolutionFailures++
            Completion.CANCELLED -> Unit
        }
        return true
    }

    private fun allowPeer(peer: InetSocketAddress, now: Long) {
        allowedPeers[peer] = now
        val iterator = allowedPeers.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (allowedPeers.size <= MAX_ALLOWED_PEERS && now - entry.value <= PEER_TTL_NANOS) break
            iterator.remove()
        }
    }

    private fun drop(reason: DropReason): Dropped {
        when (reason) {
            DropReason.INVALID -> invalidDatagrams++
            DropReason.SOURCE -> sourceRejectedDatagrams++
            DropReason.UNALLOWED_PEER -> unallowedResponses++
            DropReason.TOO_LARGE -> oversizedDatagrams++
            else -> Unit
        }
        return Dropped(reason)
    }

    override fun close() {
        requireOwner()
        closed = true
        allowedPeers.clear()
        clientEndpoint = null
    }

    private fun live() = !closed && !session.resource.isClosed
    private fun requireOwner() { check(session.owner.inEventLoop()) }

    companion object {
        const val MAX_RECEIVE_BYTES = 65_535
        const val MAX_IPV4_PAYLOAD_BYTES = 65_507
        const val MAX_IPV6_PAYLOAD_BYTES = 65_527
        const val MAX_ALLOWED_PEERS = 512
        const val PEER_TTL_NANOS = 120_000_000_000L
        private const val DNS_PORT = 53

        fun maxPayloadBytes(address: InetAddress): Int =
            if (address.address.size == 4) MAX_IPV4_PAYLOAD_BYTES else MAX_IPV6_PAYLOAD_BYTES

        fun responseWireBytes(address: InetAddress, payloadBytes: Int): Int {
            require(payloadBytes in 0..MAX_RECEIVE_BYTES)
            return 6 + address.address.size + payloadBytes
        }

        private fun validSlice(bytes: ByteArray, offset: Int, length: Int) =
            offset >= 0 && length >= 0 && offset <= bytes.size && length <= bytes.size - offset
    }
}
