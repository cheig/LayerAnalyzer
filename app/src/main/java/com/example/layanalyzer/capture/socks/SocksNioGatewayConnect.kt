package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.tls.SocksNioTlsGateway
import com.example.layanalyzer.capture.tls.TlsGatewayChannel
import com.example.layanalyzer.capture.tls.TlsGatewayConnection
import java.io.EOFException
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLongArray
import org.json.JSONObject
import org.json.JSONTokener

/**
 * Owner-only LAT1 setup, AFTER routing has selected GATEWAY and bounded DNS has resolved a literal.
 * No direct fallback, DNS, blocking streams or workers. The caller MUST freeze the establishment
 * deadline before DNS submission (including queue time), then pass the same absolute value here.
 * Default total: DNS <=10s + hop <=1s + frame/READY <=11s = 22s, followed by <=1s failure reply.
 * Custom READY budgets up to 30s still cannot extend the explicitly supplied total (max 41s).
 * Ready is a handoff, NOT SOCKS success: the next owner handler must write/drain success first.
 */
internal class SocksNioGatewayConnect(
    private val gateway: SocksNioTlsGateway,
    private val onReady: (Ready) -> Unit,
    private val onFailure: (Failure) -> Unit = {},
    private val replyTimeoutNanos: Long = SocksNioTcpConnect.REPLY_TIMEOUT_NANOS,
    private val io: GatewayIo = GatewayIo.CHANNEL
) {
    init { require(replyTimeoutNanos in 1..SocksNioTcpConnect.REPLY_TIMEOUT_NANOS) }

    /** Injection only controls nonblocking OS outcomes; channels still come from the description. */
    interface GatewayIo {
        fun connect(channel: SocketChannel, endpoint: InetSocketAddress): Boolean = channel.connect(endpoint)
        fun finishConnect(channel: SocketChannel): Boolean = channel.finishConnect()
        fun write(channel: SocketChannel, source: ByteBuffer): Int = channel.write(source)
        fun read(channel: SocketChannel, target: ByteBuffer): Int = channel.read(target)
        companion object { val CHANNEL = object : GatewayIo {} }
    }

    data class Ready(val client: SocksNioHandshake.AdmittedRequest, val upstream: SocksEventLoop.Registration)
    enum class Stage { RESOLVING, DESCRIPTION, HOP_CONNECT, LAT1_WRITE, READY_READ }
    enum class Reason { IO, TIMEOUT, MALFORMED, REFUSED }
    class Failure(val stage: Stage, val reason: Reason, val replyCode: Int,
        cause: Throwable? = null) : IOException("TLS gateway $stage failed: $reason", cause)
    data class Stats(val attempts: Long, val ready: Long, val failures: Map<Stage, Long>,
        val timeouts: Long, val refusals: Long)

    private val attempts = AtomicLong()
    private val ready = AtomicLong()
    private val failures = AtomicLongArray(Stage.entries.size)
    private val timeouts = AtomicLong()
    private val refusals = AtomicLong()

    fun stats() = Stats(attempts.get(), ready.get(), Stage.entries.associateWith { failures.get(it.ordinal) },
        timeouts.get(), refusals.get())

    fun connectResolved(client: SocksNioHandshake.AdmittedRequest, address: InetAddress,
        establishmentDeadlineNanos: Long) {
        requireIngress(client)
        val now = client.session.ownerNowNanos()
        val deadline = now + minOf(MAX_ESTABLISHMENT_TIMEOUT_NANOS, establishmentDeadlineNanos - now)
        attempts.incrementAndGet()
        Context(client, deadline).start(address)
    }

    /** DNS, route/run-unavailable or metadata failure: finite failure reply, never a direct retry. */
    fun fail(client: SocksNioHandshake.AdmittedRequest, cause: Throwable,
        stage: Stage = Stage.RESOLVING) {
        requireIngress(client)
        Context(client, client.session.ownerNowNanos()).apply {
            this.stage = stage
            installClientHandler()
            fail(cause, if (cause is SocksSession.DeadlineExceededException) Reason.TIMEOUT else Reason.IO)
        }
    }

    private fun requireIngress(client: SocksNioHandshake.AdmittedRequest) {
        check(client.session.owner.inEventLoop()) { "Gateway requires session owner" }
        check(client.request.command == SocksProtocol.COMMAND_CONNECT)
        check(client.session.snapshot().state in listOf(SocksSession.State.ADMITTED, SocksSession.State.RESOLVING))
    }

    private inner class Context(val client: SocksNioHandshake.AdmittedRequest, val totalDeadline: Long) {
        val session = client.session
        var stage = Stage.DESCRIPTION
        var phaseDeadline = totalDeadline
        var description: TlsGatewayConnection? = null
        var upstream: SocksEventLoop.Registration? = null
        var input: ByteBuffer? = null
        var readingHeader = true
        var output: ByteBuffer? = null
        var failure: Failure? = null
        var retry: SocksEventLoop.Timer? = null
        var handedOff = false

        fun installClientHandler() {
            client.interestOps(0)
            client.onReady { _, ops -> if (ops and SelectionKey.OP_WRITE != 0) writeFailure() }
        }

        fun start(address: InetAddress) {
            installClientHandler()
            if (!withinDeadline()) return
            var unownedDescription: TlsGatewayConnection? = null
            var unownedChannel: SocketChannel? = null
            try {
                val metadata = gateway.describe(address, client.request.port).also { unownedDescription = it }
                session.ownGatewayFrame(metadata)
                description = metadata
                unownedDescription = null
                stage = Stage.HOP_CONNECT
                phaseDeadline = minDeadline(metadata.connectTimeoutNanos)
                if (!session.enterConnecting(phaseDeadline, ::timeout)) return
                val channel = metadata.openChannel().also { unownedChannel = it }
                if (!withinDeadline()) return
                upstream = session.register(channel, 0) { _, ops -> dispatch(ops) }
                unownedChannel = null
                if (!withinDeadline()) return
                if (io.connect(channel, metadata.endpoint)) connected()
                else checkNotNull(upstream).interestOps(SelectionKey.OP_CONNECT)
            } catch (error: Exception) {
                fail(error)
            } finally {
                unownedDescription?.close()
                unownedChannel?.close()
            }
        }

        fun minDeadline(budget: Long): Long {
            val now = session.ownerNowNanos()
            return now + minOf(budget, totalDeadline - now)
        }

        fun live(): Boolean {
            if (session.resource.isClosed) return false
            if (session.owner.stats().state != SocksEventLoop.State.RUNNING) {
                session.close()
                return false
            }
            return true
        }

        fun withinDeadline(): Boolean {
            if (!live() || failure != null || handedOff) return false
            if (phaseDeadline - session.ownerNowNanos() <= 0) { timeout(); return false }
            return true
        }

        fun timeout() = fail(SocksSession.DeadlineExceededException(), Reason.TIMEOUT)

        fun dispatch(ops: Int) {
            if (!withinDeadline()) return
            try {
                when (stage) {
                    Stage.HOP_CONNECT -> if (ops and SelectionKey.OP_CONNECT != 0) {
                        if (io.finishConnect(channel())) connected()
                        else later { checkNotNull(upstream).interestOps(SelectionKey.OP_CONNECT) }
                    }
                    Stage.LAT1_WRITE -> if (ops and SelectionKey.OP_WRITE != 0) writeFrame()
                    Stage.READY_READ -> if (ops and SelectionKey.OP_READ != 0) readReady()
                    else -> error("Unexpected gateway readiness stage")
                }
            } catch (error: Exception) {
                if (handedOff) session.close(error) else fail(error)
            }
        }

        fun channel() = checkNotNull(upstream).channel as SocketChannel

        fun connected() {
            if (!withinDeadline()) return
            val metadata = checkNotNull(description)
            checkNotNull(upstream).interestOps(0)
            phaseDeadline = minDeadline(metadata.readyTimeoutNanos)
            if (!session.enterGatewayWrite(phaseDeadline, ::timeout)) return
            stage = Stage.LAT1_WRITE
            checkNotNull(upstream).pendingWrite(true)
        }

        fun writeFrame() {
            val metadata = checkNotNull(description)
            val frame = metadata.frame
            val count = io.write(channel(), frame)
            if (!withinDeadline()) return
            if (frame.hasRemaining()) {
                if (count == 0) later { checkNotNull(upstream).pendingWrite(true) }
                else checkNotNull(upstream).pendingWrite(true)
                return
            }
            releaseFrame()
            if (!session.enterGatewayReady()) return
            stage = Stage.READY_READ
            input = session.allocateControlBuffer(8)
            checkNotNull(upstream).interestOps(SelectionKey.OP_READ)
        }

        fun readReady() {
            val buffer = checkNotNull(input)
            val count = io.read(channel(), buffer)
            if (!withinDeadline()) return
            if (count < 0) { fail(EOFException("Gateway READY ended early")); return }
            if (buffer.hasRemaining()) {
                if (count == 0) later { checkNotNull(upstream).interestOps(SelectionKey.OP_READ) }
                return
            }
            buffer.flip()
            if (readingHeader) {
                val magic = buffer.int
                val length = buffer.int
                releaseInput()
                if (magic != TlsGatewayChannel.FRAME_MAGIC_INT || length !in 1..TlsGatewayChannel.MAX_REPLY_BYTES) {
                    fail(IOException("Invalid gateway READY framing"), Reason.MALFORMED)
                    return
                }
                readingHeader = false
                input = session.allocateControlBuffer(length)
                return
            }
            val verdict = try { parseReply(buffer) } catch (error: Exception) {
                fail(error, Reason.MALFORMED)
                return
            }
            releaseInput()
            if (verdict != null) {
                fail(null, Reason.REFUSED, SocksProtocol.replyForGatewayRefusal(verdict))
                return
            }
            if (!withinDeadline()) return
            val registration = checkNotNull(upstream)
            registration.interestOps(0)
            registration.replaceHandler { _, _ -> error("Gateway successor handler not installed") }
            client.onReady { _, _ -> error("Gateway client successor handler not installed") }
            handedOff = true
            ready.incrementAndGet()
            onReady(Ready(client, registration))
        }

        fun fail(cause: Throwable?, reason: Reason = Reason.IO,
            replyCode: Int = SocksProtocol.REPLY_GENERAL_FAILURE) {
            if (failure != null) return
            val error = Failure(stage, reason, replyCode, cause)
            failure = error
            failures.incrementAndGet(stage.ordinal)
            if (reason == Reason.TIMEOUT) timeouts.incrementAndGet()
            if (reason == Reason.REFUSED) refusals.incrementAndGet()
            try { onFailure(error) } catch (observerError: Exception) {
                session.close(observerError)
                return
            }
            if (!live()) return
            retry?.cancel()
            retry = null
            upstream?.close()
            upstream = null
            releaseFrame()
            releaseInput()
            if (!session.enterFailing(replyTimeoutNanos)) return
            output = session.allocateControlBuffer(10).also {
                it.put(SocksProtocol.encodeReply(replyCode)); it.flip()
            }
            client.interestOps(SelectionKey.OP_WRITE)
        }

        fun writeFailure() {
            if (!live()) return
            if (checkNotNull(session.snapshot().deadlineNanos) - session.ownerNowNanos() <= 0) {
                session.close(failure)
                return
            }
            val buffer = checkNotNull(output)
            val count = try { client.writeClient(buffer) } catch (error: IOException) {
                session.close(error)
                return
            }
            if (buffer.hasRemaining()) {
                if (count == 0) later { client.pendingWrite(true) } else client.pendingWrite(true)
            } else {
                session.releaseControlBuffer(buffer)
                output = null
                session.close(failure)
            }
        }

        fun releaseFrame() {
            description?.let(session::releaseGatewayFrame)
            description = null
        }

        fun releaseInput() {
            input?.let(session::releaseControlBuffer)
            input = null
        }

        fun later(action: () -> Unit) {
            check(retry == null)
            upstream?.interestOps(0)
            if (failure != null) client.interestOps(0)
            val scheduled = session.owner.schedule(RETRY_NANOS, session.resource) {
                retry = null
                if (live()) action()
            }
            if (scheduled.result != SocksEventLoop.Submission.ACCEPTED) {
                session.close(SocksSession.SchedulingRejectedException(scheduled.result))
            } else retry = scheduled.timer
        }
    }

    /** null means success; failure text is never logged or used as an unbounded stats key. */
    private fun parseReply(bytes: ByteBuffer): String? {
        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        val tokens = JSONTokener(decoder.decode(bytes).toString())
        val reply = tokens.nextValue() as? JSONObject ?: throw IOException("Gateway reply is not an object")
        if (tokens.nextClean() != '\u0000' || reply.opt("version") != TlsGatewayChannel.PROTOCOL_VERSION ||
            reply.opt("success") !is Boolean) throw IOException("Gateway reply has no usable verdict")
        if (reply.getBoolean("success")) {
            if (!reply.isNull("errorCode")) throw IOException("Gateway reply contradicts itself")
            return null
        }
        val code = reply.opt("errorCode") as? String
        if (code.isNullOrEmpty()) throw IOException("Gateway refusal carries no code")
        return code
    }

    companion object {
        const val ESTABLISHMENT_TIMEOUT_NANOS = 22_000_000_000L
        const val MAX_ESTABLISHMENT_TIMEOUT_NANOS = 41_000_000_000L
        private const val RETRY_NANOS = 1_000_000L
    }
}
