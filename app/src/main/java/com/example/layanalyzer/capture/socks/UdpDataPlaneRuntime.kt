package com.example.layanalyzer.capture.socks

import java.nio.ByteBuffer

/** One capture's bounded packet accounting and at most one receive scratch per event loop. */
internal class UdpDataPlaneRuntime(val limits: Limits = Limits()) : AutoCloseable {
    data class Limits(
        val packetsPerAssociation: Int = 8,
        val bytesPerAssociation: Int = 128 * 1024,
        val globalBytes: Int = 8 * 1024 * 1024
    ) {
        init {
            require(packetsPerAssociation in 1..8)
            require(bytesPerAssociation in 1..128 * 1024)
            require(globalBytes in 1..8 * 1024 * 1024)
        }
    }

    data class Snapshot(val open: Boolean, val associations: Int, val scratchBuffers: Int,
        val scratchBytes: Int, val queuedPackets: Int, val queuedBytes: Int,
        val peakQueuedPackets: Int, val peakQueuedBytes: Int, val queueDroppedPackets: Long,
        val queueDroppedBytes: Long, val sendFailures: Long, val ambiguousEmptySends: Long,
        val maxDatagramsPerCallback: Int, val traffic: Traffic)

    /** Cumulative per run, including closed associations; never retains policies or endpoints. */
    data class Traffic(val sentBytes: Long = 0, val receivedBytes: Long = 0,
        val blockedDatagrams: Long = 0, val blockedBytes: Long = 0,
        val invalidDatagrams: Long = 0, val sourceRejectedDatagrams: Long = 0,
        val unallowedResponses: Long = 0, val oversizedDatagrams: Long = 0,
        val resolutionFailures: Long = 0) {
        companion object {
            fun from(stats: UdpPacketPolicy.Stats) = Traffic(stats.sentBytes, stats.receivedBytes,
                stats.intervention.blockedDatagrams, stats.intervention.blockedBytes,
                stats.invalidDatagrams, stats.sourceRejectedDatagrams, stats.unallowedResponses,
                stats.oversizedDatagrams, stats.resolutionFailures)
        }
    }

    private class Scratch(val buffer: ByteBuffer = ByteBuffer.allocate(UdpPacketPolicy.MAX_RECEIVE_BYTES),
        var references: Int = 0)
    private val gate = Any()
    private val scratch = LinkedHashMap<SocksEventLoop, Scratch>()
    @Volatile var isOpen = true
        private set
    private var associations = 0
    private var packets = 0
    private var bytes = 0
    private var peakPackets = 0
    private var peakBytes = 0
    private var droppedPackets = 0L
    private var droppedBytes = 0L
    private var sendFailures = 0L
    private var emptySends = 0L
    private var maxWork = 0
    private var traffic = Traffic()

    fun snapshot(): Snapshot = synchronized(gate) {
        Snapshot(isOpen, associations, scratch.size, scratch.size * UdpPacketPolicy.MAX_RECEIVE_BYTES,
            packets, bytes, peakPackets, peakBytes, droppedPackets, droppedBytes, sendFailures,
            emptySends, maxWork, traffic)
    }

    fun acquire(owner: SocksEventLoop): Lease? = synchronized(gate) {
        check(owner.inEventLoop())
        if (!isOpen) return@synchronized null
        val shared = scratch[owner] ?: run {
            check(scratch.size < SocksEventLoopGroup.LOOP_COUNT)
            Scratch().also { scratch[owner] = it }
        }
        shared.references++
        associations++
        Lease(owner, shared.buffer)
    }

    inner class Lease internal constructor(private val owner: SocksEventLoop, val scratch: ByteBuffer) : AutoCloseable {
        var queuedPackets = 0
            private set
        var queuedBytes = 0
            private set
        private var closed = false

        fun reserve(size: Int): Boolean = synchronized(gate) {
            check(owner.inEventLoop() && !closed)
            require(size >= 0)
            if (!isOpen || queuedPackets == limits.packetsPerAssociation ||
                size > limits.bytesPerAssociation - queuedBytes || size > limits.globalBytes - bytes) {
                droppedPackets++
                droppedBytes += size
                false
            } else {
                queuedPackets++
                queuedBytes += size
                packets++
                bytes += size
                peakPackets = maxOf(peakPackets, packets)
                peakBytes = maxOf(peakBytes, bytes)
                true
            }
        }

        fun release(size: Int) = synchronized(gate) {
            check(owner.inEventLoop() && !closed && queuedPackets > 0 && size in 0..queuedBytes)
            queuedPackets--
            queuedBytes -= size
            packets--
            bytes -= size
        }

        override fun close() = synchronized(gate) {
            check(owner.inEventLoop())
            if (closed) return@synchronized
            closed = true
            packets -= queuedPackets
            bytes -= queuedBytes
            queuedPackets = 0
            queuedBytes = 0
            associations--
            val shared = checkNotNull(this@UdpDataPlaneRuntime.scratch[owner])
            if (--shared.references == 0) {
                shared.buffer.clear()
                shared.buffer.array().fill(0)
                this@UdpDataPlaneRuntime.scratch.remove(owner)
            }
        }
    }

    internal fun recordSendFailure() = synchronized(gate) { sendFailures++ }
    internal fun recordEmptyAttempt() = synchronized(gate) { emptySends++ }
    internal fun recordWork(work: Int) = synchronized(gate) { maxWork = maxOf(maxWork, work) }

    /** Called by owners after bounded callbacks and during cleanup. Readers need no owner hop. */
    internal fun recordTraffic(previous: Traffic, next: Traffic) = synchronized(gate) {
        traffic = Traffic(
            traffic.sentBytes + next.sentBytes - previous.sentBytes,
            traffic.receivedBytes + next.receivedBytes - previous.receivedBytes,
            traffic.blockedDatagrams + next.blockedDatagrams - previous.blockedDatagrams,
            traffic.blockedBytes + next.blockedBytes - previous.blockedBytes,
            traffic.invalidDatagrams + next.invalidDatagrams - previous.invalidDatagrams,
            traffic.sourceRejectedDatagrams + next.sourceRejectedDatagrams - previous.sourceRejectedDatagrams,
            traffic.unallowedResponses + next.unallowedResponses - previous.unallowedResponses,
            traffic.oversizedDatagrams + next.oversizedDatagrams - previous.oversizedDatagrams,
            traffic.resolutionFailures + next.resolutionFailures - previous.resolutionFailures)
    }

    /** Run stop hook: mark only. Assembly next stops owners; their last lease releases scratch. */
    override fun close() { synchronized(gate) { isOpen = false } }
}
