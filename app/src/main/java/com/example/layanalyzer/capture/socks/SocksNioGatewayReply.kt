package com.example.layanalyzer.capture.socks

import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel

/**
 * READY is only an upstream verdict. Both read interests stay disabled until every SOCKS
 * success byte has been accepted by the original client channel. This is a local write-drain
 * guarantee, not a remote acknowledgement. The reply has a fresh, non-renewable one-second
 * deadline; its buffer and zero-write retry belong to the same session resource.
 * Handoff preserves the unique client prefix reader and the original upstream registration,
 * including unread bytes following READY. Neither direction uses streams or another channel.
 */
internal class SocksNioGatewayReply(
    private val onConnected: (SocksNioTcpConnect.Connected) -> Unit,
    private val replyTimeoutNanos: Long = SocksNioTcpConnect.REPLY_TIMEOUT_NANOS
) {
    init { require(replyTimeoutNanos in 1..SocksNioTcpConnect.REPLY_TIMEOUT_NANOS) }

    fun ready(connection: SocksNioGatewayConnect.Ready) {
        val session = connection.client.session
        check(session.owner.inEventLoop())
        check(session.snapshot().state == SocksSession.State.GATEWAY_READY)
        Context(connection).start()
    }

    private inner class Context(val connection: SocksNioGatewayConnect.Ready) {
        val client = connection.client
        val session = client.session
        var output: ByteBuffer? = null
        var retry: SocksEventLoop.Timer? = null

        fun start() {
            if (!session.enterSocksReply(replyTimeoutNanos)) return
            connection.upstream.interestOps(0)
            client.interestOps(0)
            try {
                val bound = (connection.upstream.channel as SocketChannel).localAddress as InetSocketAddress
                val bytes = SocksProtocol.encodeReply(SocksProtocol.REPLY_SUCCEEDED, bound.address, bound.port)
                output = session.allocateControlBuffer(SocksNioTcpConnect.MAX_REPLY_BYTES).also {
                    it.put(bytes); it.flip()
                }
                client.onReady { _, ops -> if (ops and SelectionKey.OP_WRITE != 0) write() }
                client.pendingWrite(true)
            } catch (error: Exception) {
                session.close(error)
            }
        }

        fun write() {
            if (!live() || retry != null) return
            if (checkNotNull(session.snapshot().deadlineNanos) - session.ownerNowNanos() <= 0) {
                session.close(SocksSession.DeadlineExceededException())
                return
            }
            val buffer = checkNotNull(output)
            val count = try { client.writeClient(buffer) } catch (error: IOException) {
                session.close(error)
                return
            }
            if (!live()) return
            if (buffer.hasRemaining()) {
                if (count == 0) {
                    client.interestOps(0)
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
            client.interestOps(0)
            session.releaseControlBuffer(buffer)
            output = null
            if (!session.enterTcpConnected()) return
            client.onReady { _, _ -> error("Gateway relay handler not installed") }
            onConnected(SocksNioTcpConnect.Connected(client, connection.upstream))
        }

        fun live(): Boolean {
            if (session.resource.isClosed) return false
            if (session.owner.stats().state != SocksEventLoop.State.RUNNING) {
                session.close()
                return false
            }
            return true
        }
    }

    companion object { private const val RETRY_NANOS = 1_000_000L }
}
