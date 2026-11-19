package com.example.layanalyzer.capture.socks

import java.io.EOFException
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey

/** Owner-only UDP setup/control lifecycle. The successor supplies datagram handling and idle policy. */
internal class UdpAssociation(
    private val prepareUdp: (DatagramSocket) -> Unit,
    private val onActive: (Active) -> Unit,
    private val setupTimeoutNanos: Long = SETUP_TIMEOUT_NANOS,
    private val replyTimeoutNanos: Long = REPLY_TIMEOUT_NANOS,
    private val io: ChannelIo = ChannelIo.CHANNEL
) {
    init {
        require(setupTimeoutNanos in 1..SETUP_TIMEOUT_NANOS)
        require(replyTimeoutNanos in 1..REPLY_TIMEOUT_NANOS)
    }

    /** Factories and prepareUdp must not connect, send, resolve names, or block waiting for workers. */
    interface ChannelIo {
        fun open(): DatagramChannel = DatagramChannel.open()
        fun bind(channel: DatagramChannel, address: InetSocketAddress) { channel.socket().bind(address) }

        companion object { val CHANNEL = object : ChannelIo {} }
    }

    class Active internal constructor(
        val session: SocksSession,
        val relay: SocksEventLoop.Registration,
        val upstream: SocksEventLoop.Registration
    ) {
        private var dataPlane: AutoCloseable? = null

        /** One owner-local successor owns policy, queued packets and resolver subscriptions. */
        fun ownDataPlane(cleanup: AutoCloseable) {
            check(session.owner.inEventLoop())
            check(!session.resource.isClosed && dataPlane == null)
            dataPlane = cleanup
        }

        fun close(cause: Throwable? = null) { session.close(cause) }

        internal fun dispose() {
            val cleanup = dataPlane
            dataPlane = null
            cleanup?.close()
        }
    }

    fun start(client: SocksNioHandshake.AdmittedRequest) {
        val session = client.session
        check(session.owner.inEventLoop())
        check(client.request.command == SocksProtocol.COMMAND_UDP_ASSOCIATE)
        check(session.snapshot().state == SocksSession.State.ADMITTED)
        Context(client).start()
    }

    private inner class Context(val client: SocksNioHandshake.AdmittedRequest) {
        val session = client.session
        val deadline = session.ownerNowNanos() + setupTimeoutNanos
        var relay: SocksEventLoop.Registration? = null
        var upstream: SocksEventLoop.Registration? = null
        var active: Active? = null
        var output: ByteBuffer? = null
        var control: ByteBuffer? = null
        var retry: SocksEventLoop.Timer? = null
        var failure: Throwable? = null

        fun start() {
            session.ownUdpCleanup(AutoCloseable { dispose() })
            client.interestOps(SelectionKey.OP_READ)
            client.onReady { _, ops -> ready(ops) }
            control = session.allocateControlBuffer(CONTROL_READ_BYTES)
            if (!session.enterUdpSetup(deadline) { fail(SocksSession.DeadlineExceededException()) }) return
            readControl()
            if (!withinSetup()) return
            try {
                relay = open(false) ?: return
                upstream = open(true) ?: return
                if (!withinSetup()) return
                val bound = (checkNotNull(relay).channel as DatagramChannel).localAddress as InetSocketAddress
                check(bound.address.isLoopbackAddress && bound.port != 0)
                if (!session.enterSocksReply(replyTimeoutNanos)) return
                queue(SocksProtocol.encodeReply(SocksProtocol.REPLY_SUCCEEDED, bound.address, bound.port))
            } catch (error: Exception) {
                if (live()) fail(error)
            }
        }

        fun open(outbound: Boolean): SocksEventLoop.Registration? {
            var unowned: DatagramChannel? = null
            try {
                val channel = io.open().also { unowned = it }
                check(channel.isOpen && !channel.isConnected && channel.localAddress == null)
                if (!withinSetup()) return null
                if (outbound) prepareUdp(channel.socket())
                check(channel.isOpen && !channel.isConnected)
                if (!withinSetup()) return null
                channel.configureBlocking(false)
                // Each association owns both receive endpoints exclusively. UDP
                // address reuse can assign the same ephemeral endpoint to live
                // associations and deliver one flow's reply to another flow.
                channel.socket().reuseAddress = false
                if (channel.localAddress == null) {
                    io.bind(channel, if (outbound) InetSocketAddress(0) else InetSocketAddress(LOOPBACK, 0))
                }
                if (!withinSetup()) return null
                val registered = session.register(channel, 0) { _, _ -> error("UDP data handler not installed") }
                unowned = null
                return registered
            } finally {
                unowned?.close()
            }
        }

        fun live(): Boolean {
            if (session.resource.isClosed) return false
            if (session.owner.stats().state != SocksEventLoop.State.RUNNING) {
                session.close()
                return false
            }
            return true
        }

        fun withinSetup(): Boolean {
            if (!live()) return false
            if (deadline - session.ownerNowNanos() <= 0) {
                fail(SocksSession.DeadlineExceededException())
                return false
            }
            return true
        }

        fun ready(ops: Int) {
            if (!live()) return
            if (session.snapshot().deadlineNanos?.let { it - session.ownerNowNanos() <= 0 } == true) {
                session.close(failure ?: SocksSession.DeadlineExceededException())
                return
            }
            if (ops and SelectionKey.OP_READ != 0) readControl()
            if (live() && ops and SelectionKey.OP_WRITE != 0) writeReply()
        }

        fun readControl() {
            val buffer = checkNotNull(control)
            buffer.clear()
            if (client.readClient(buffer) < 0) session.close(EOFException("UDP control closed"))
        }

        fun fail(cause: Throwable) {
            if (!live()) return
            retry?.cancel()
            retry = null
            relay?.close()
            upstream?.close()
            relay = null
            upstream = null
            failure = cause
            if (!session.enterFailing(replyTimeoutNanos)) return
            queue(SocksProtocol.encodeReply(SocksProtocol.REPLY_GENERAL_FAILURE))
        }

        fun queue(bytes: ByteArray) {
            check(output == null)
            output = session.allocateControlBuffer(MAX_REPLY_BYTES).also { it.put(bytes); it.flip() }
            client.interestOps(SelectionKey.OP_READ or SelectionKey.OP_WRITE)
        }

        fun writeReply() {
            val buffer = checkNotNull(output)
            val written = try { client.writeClient(buffer) } catch (error: IOException) {
                session.close(error)
                return
            }
            if (!live()) return
            if (buffer.hasRemaining()) {
                if (written == 0) {
                    client.pendingWrite(false)
                    check(retry == null)
                    val scheduled = session.owner.schedule(RETRY_NANOS, session.resource) {
                        retry = null
                        if (live()) client.pendingWrite(true)
                    }
                    if (scheduled.result != SocksEventLoop.Submission.ACCEPTED) {
                        session.close(SocksSession.SchedulingRejectedException(scheduled.result))
                    } else retry = scheduled.timer
                } else client.pendingWrite(true)
                return
            }
            client.interestOps(SelectionKey.OP_READ)
            session.releaseControlBuffer(buffer)
            output = null
            if (failure != null) { session.close(failure); return }
            if (!session.enterUdpActive()) return
            val established = Active(session, checkNotNull(relay), checkNotNull(upstream))
            active = established
            onActive(established)
        }

        fun dispose() {
            retry?.cancel()
            retry = null
            output = null
            control = null
            relay = null
            upstream = null
            val established = active
            active = null
            established?.dispose()
        }
    }

    companion object {
        const val SETUP_TIMEOUT_NANOS = 1_000_000_000L
        const val REPLY_TIMEOUT_NANOS = 1_000_000_000L
        const val CONTROL_READ_BYTES = 1024
        const val MAX_REPLY_BYTES = 22
        private const val RETRY_NANOS = 1_000_000L
        private val LOOPBACK = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    }
}
