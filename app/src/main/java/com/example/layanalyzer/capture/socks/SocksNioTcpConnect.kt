// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksDestination
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel

/**
 * Internal direct TCP setup after NIO-105. Call ONLY after routing has selected direct TCP;
 * this is not a TLS fallback or a selectable production server. No DNS or application relay.
 * prepareTcp must protect, then bind the socket to the captured network, throwing on failure
 * (the same contract as DirectSocks5Server). It must not connect, resolve, or wait for workers.
 * All callbacks run on the session owner. onConnected must install the next readiness handler
 * and consume client data through AdmittedRequest, including its retained handshake suffix.
 */
internal class SocksNioTcpConnect(
    private val prepareTcp: (Socket) -> Unit,
    private val onConnected: (Connected) -> Unit,
    private val connectTimeoutNanos: Long = CONNECT_TIMEOUT_NANOS,
    private val replyTimeoutNanos: Long = REPLY_TIMEOUT_NANOS,
    private val io: ConnectIo = ConnectIo.CHANNEL
) {
    init {
        require(connectTimeoutNanos in 1..CONNECT_TIMEOUT_NANOS)
        require(replyTimeoutNanos in 1..REPLY_TIMEOUT_NANOS)
    }

    /** All implementations must be nonblocking; injection only controls OS outcomes in tests. */
    interface ConnectIo {
        fun open(): SocketChannel = SocketChannel.open()
        fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean = channel.connect(address)
        fun finishConnect(channel: SocketChannel): Boolean = channel.finishConnect()

        companion object { val CHANNEL = object : ConnectIo {} }
    }

    data class Connected(
        val client: SocksNioHandshake.AdmittedRequest,
        val upstream: SocksEventLoop.Registration
    )

    /** Literal-only entry; use SocksNioTcpResolve for the bounded DNS + connect pipeline. */
    fun connect(client: SocksNioHandshake.AdmittedRequest) {
        val address = (client.request.destination as? SocksDestination.Ip)?.address
        connectResolved(client, address?.let(::listOf).orEmpty(),
            client.session.ownerNowNanos() + connectTimeoutNanos)
    }

    /**
     * NIO-204 ingress: caller validates resolution generation/operation on owner first. Preserve
     * the pre-resolution absolute deadline; neither retries nor this call restart that clock.
     * At most 64 resolved candidates, one attempt per callback. Empty/oversized results fail.
     */
    fun connectResolved(
        client: SocksNioHandshake.AdmittedRequest,
        addresses: List<InetAddress>,
        establishmentDeadlineNanos: Long
    ) {
        val session = client.session
        check(session.owner.inEventLoop()) { "Connect requires session owner" }
        check(client.request.command == SocksProtocol.COMMAND_CONNECT)
        check(session.snapshot().state in listOf(SocksSession.State.ADMITTED, SocksSession.State.RESOLVING))
        val now = session.ownerNowNanos()
        val deadline = now + minOf(connectTimeoutNanos, establishmentDeadlineNanos - now)
        val candidates = if (addresses.size in 1..MAX_ADDRESSES) addresses.toList() else emptyList()
        Context(client, candidates, deadline).start()
    }

    /** DNS/admission failure uses the same bounded control writer as connection failures. */
    fun fail(client: SocksNioHandshake.AdmittedRequest, cause: Throwable,
        replyCode: Int = SocksProtocol.REPLY_GENERAL_FAILURE) {
        require(replyCode in 1..8)
        check(client.session.owner.inEventLoop())
        check(client.session.snapshot().state in listOf(SocksSession.State.ADMITTED, SocksSession.State.RESOLVING))
        Context(client, emptyList(), client.session.ownerNowNanos()).apply {
            installReplyHandler()
            fail(cause, replyCode)
        }
    }

    private inner class Context(
        val client: SocksNioHandshake.AdmittedRequest,
        val addresses: List<InetAddress>,
        val deadline: Long
    ) {
        val session = client.session
        var nextAddress = 0
        var upstream: SocksEventLoop.Registration? = null
        var retry: SocksEventLoop.Timer? = null
        var output: ByteBuffer? = null
        var failure: Throwable? = null

        fun start() {
            installReplyHandler()
            if (!session.enterConnecting(deadline) { fail(SocksSession.DeadlineExceededException()) }) return
            if (addresses.isEmpty()) {
                fail(IOException("SOCKS direct connect requires 1..$MAX_ADDRESSES resolved addresses"))
                return
            }
            attempt()
        }

        fun installReplyHandler() {
            client.interestOps(0) // Keep all pipelined application data untouched until handoff.
            client.onReady { _, ops -> if (ops and SelectionKey.OP_WRITE != 0) writeReply() }
        }

        fun live(): Boolean {
            if (session.resource.isClosed) return false
            if (session.owner.stats().state != SocksEventLoop.State.RUNNING) {
                session.close()
                return false
            }
            return true
        }

        fun withinConnectDeadline(): Boolean {
            if (!live()) return false
            if (deadline - session.ownerNowNanos() <= 0) {
                fail(SocksSession.DeadlineExceededException())
                return false
            }
            return true
        }

        fun attempt() {
            if (!withinConnectDeadline()) return
            var unowned: SocketChannel? = null
            try {
                val channel = io.open().also { unowned = it }
                check(channel.isOpen && !channel.isConnected && !channel.isConnectionPending)
                // Native channel first; its adapter is protected/bound BEFORE any possible SYN.
                prepareTcp(channel.socket())
                check(channel.isOpen && !channel.isConnected && !channel.isConnectionPending)
                if (!withinConnectDeadline()) return
                channel.configureBlocking(false)
                upstream = session.register(channel, 0) { _, ops ->
                    if (ops and SelectionKey.OP_CONNECT != 0) finishConnect()
                }
                unowned = null // The session scope now owns this channel, even on connect failure.
            } catch (error: Exception) {
                // Preparation failures never try another address or bypass protection.
                if (live()) fail(error)
                return
            } finally {
                unowned?.close()
            }
            if (!withinConnectDeadline()) return
            val registration = checkNotNull(upstream)
            val connected = try {
                io.connect(registration.channel as SocketChannel,
                    InetSocketAddress(addresses[nextAddress++], client.request.port))
            } catch (error: IOException) {
                attemptFailed(error)
                return
            } catch (error: SecurityException) {
                fail(error)
                return
            }
            if (connected) connected() else registration.interestOps(SelectionKey.OP_CONNECT)
        }

        fun finishConnect() {
            if (!withinConnectDeadline()) return
            val registration = checkNotNull(upstream)
            val connected = try {
                io.finishConnect(registration.channel as SocketChannel)
            } catch (error: IOException) {
                attemptFailed(error)
                return
            } catch (error: SecurityException) {
                fail(error)
                return
            }
            if (connected) connected() else {
                // Some providers can report readiness without progress. Never spin on that key.
                registration.interestOps(0)
                later { registration.interestOps(SelectionKey.OP_CONNECT) }
            }
        }

        fun attemptFailed(error: IOException) {
            upstream?.close()
            upstream = null
            if (!withinConnectDeadline()) return
            if (nextAddress < addresses.size) later { attempt() } else fail(error)
        }

        fun connected() {
            if (!withinConnectDeadline()) return
            val registration = checkNotNull(upstream)
            registration.interestOps(0)
            val bound = try {
                registration.channel.let { (it as SocketChannel).localAddress as InetSocketAddress }
            } catch (error: IOException) {
                fail(error)
                return
            }
            if (!session.enterSocksReply(replyTimeoutNanos)) return
            queue(SocksProtocol.encodeReply(SocksProtocol.REPLY_SUCCEEDED, bound.address, bound.port))
        }

        fun fail(error: Throwable, replyCode: Int = SocksProtocol.REPLY_GENERAL_FAILURE) {
            if (!live()) return
            retry?.cancel()
            retry = null
            upstream?.close()
            upstream = null
            failure = error
            if (!session.enterFailing(replyTimeoutNanos)) return
            // Preserve the blocking direct path's general-failure wire mapping.
            queue(SocksProtocol.encodeReply(replyCode))
        }

        fun queue(bytes: ByteArray) {
            check(output == null)
            output = session.allocateControlBuffer(MAX_REPLY_BYTES).also { it.put(bytes); it.flip() }
            client.interestOps(SelectionKey.OP_WRITE)
        }

        fun writeReply() {
            if (!live()) return
            if (checkNotNull(session.snapshot().deadlineNanos) - session.ownerNowNanos() <= 0) {
                session.close(failure ?: SocksSession.DeadlineExceededException())
                return
            }
            val buffer = checkNotNull(output)
            val written = try { client.writeClient(buffer) } catch (error: IOException) {
                session.close(error)
                return
            }
            if (buffer.hasRemaining()) {
                if (written == 0) later { client.pendingWrite(true) } else client.pendingWrite(true)
                return
            }
            client.interestOps(0)
            session.releaseControlBuffer(buffer)
            output = null
            if (failure != null) { session.close(failure); return }
            if (!session.enterTcpConnected()) return
            val registration = checkNotNull(upstream)
            // Clear setup closures; both keys stay idle until the required next handler arms them.
            client.onReady { _, _ -> error("TCP client relay handler not installed") }
            registration.replaceHandler { _, _ -> error("TCP upstream relay handler not installed") }
            onConnected(Connected(client, registration))
        }

        fun later(action: () -> Unit) {
            check(retry == null)
            val scheduled = session.owner.schedule(RETRY_NANOS, session.resource) {
                retry = null
                if (live()) action()
            }
            if (scheduled.result != SocksEventLoop.Submission.ACCEPTED) {
                session.close(SocksSession.SchedulingRejectedException(scheduled.result))
            } else retry = scheduled.timer
        }
    }

    companion object {
        const val CONNECT_TIMEOUT_NANOS = 15_000_000_000L
        const val REPLY_TIMEOUT_NANOS = 1_000_000_000L
        const val MAX_ADDRESSES = 64
        const val MAX_REPLY_BYTES = 22 // IPv6 bound address + SOCKS header + port.
        private const val RETRY_NANOS = 1_000_000L
    }
}
