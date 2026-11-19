// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksRequest
import java.io.EOFException
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel

/**
 * Internal P1 handler: nonblocking RFC1929 + request only, with no DNS/connect/relay/worker.
 * Every context lives in its registration handler; session owns and wipes both control buffers.
 * The admission-time 15s deadline covers every fragment and control write, never resets on I/O.
 * Successful requests transfer only after auth output drains; downstream MUST establish its own
 * operation deadline and produce success only after connect/READY/UDP setup (P2/P3/P4).
 */
internal class SocksNioHandshake(
    private val credentials: () -> SocksCredentials?,
    private val onAdmitted: (AdmittedRequest) -> Unit,
    private val io: ClientIo = ClientIo.CHANNEL,
    /** Fixed counter callback, invoked once at the verdict even if the failure reply cannot drain. */
    private val onAuthenticationRejected: () -> Unit = {}
) : SocksNioServer.SessionHandler {
    /** Nonblocking seam for deterministic short/zero-I/O tests; no stream adapter is supported. */
    interface ClientIo {
        fun read(channel: SocketChannel, target: ByteBuffer): Int
        fun write(channel: SocketChannel, source: ByteBuffer): Int
        fun shutdownOutput(channel: SocketChannel) { channel.shutdownOutput() }

        companion object {
            val CHANNEL = object : ClientIo {
                override fun read(channel: SocketChannel, target: ByteBuffer) = channel.read(target)
                override fun write(channel: SocketChannel, source: ByteBuffer) = channel.write(source)
            }
        }
    }

    /**
     * Unique owner-thread ingress for future relay. readClient consumes the retained suffix first,
     * once, then the original channel (large later payload remains unread in the socket). The raw
     * channel/buffer are deliberately not exposed here; successors must use this ingress rather
     * than independently reading the registration's channel and skipping the retained suffix.
     * No automatic read occurs after handoff. Install bounded readiness and interestOps explicitly.
     * A callback may retain this handle, but all methods require an open session and its loop.
     */
    class AdmittedRequest internal constructor(
        val session: SocksSession,
        val request: SocksRequest,
        private val registration: SocksEventLoop.Registration,
        private var prefix: ByteBuffer?,
        private val io: ClientIo
    ) {
        val bufferedClientBytes: Int get() { requireOpen(); return prefix?.remaining() ?: 0 }

        fun readClient(target: ByteBuffer): Int {
            requireOpen()
            if (!target.hasRemaining()) return 0
            val retained = prefix
            if (retained != null) {
                val count = minOf(retained.remaining(), target.remaining())
                val oldLimit = retained.limit()
                retained.limit(retained.position() + count)
                target.put(retained)
                retained.limit(oldLimit)
                if (!retained.hasRemaining()) {
                    session.releaseControlBuffer(retained)
                    prefix = null
                }
                return count
            }
            return io.read(registration.channel as SocketChannel, target)
        }

        fun writeClient(source: ByteBuffer): Int { requireOpen(); return io.write(registration.channel as SocketChannel, source) }
        /** Preserve the unique read handle while allowing an owner-driven TCP half-close. */
        fun shutdownOutput() { requireOpen(); io.shutdownOutput(registration.channel as SocketChannel) }
        fun interestOps(ops: Int) { requireOpen(); registration.interestOps(ops) }
        fun pendingWrite(pending: Boolean) { requireOpen(); registration.pendingWrite(pending) }
        fun onReady(action: (AdmittedRequest, Int) -> Unit) {
            requireOpen()
            registration.replaceHandler { _, ops -> action(this, ops) }
        }

        private fun requireOpen() {
            check(session.owner.inEventLoop()) { "Client requires session owner thread" }
            check(!session.resource.isClosed && registration.isOpen) { "Client session closed" }
        }
    }

    override fun onSession(session: SocksSession, registration: SocksEventLoop.Registration) {
        if (!session.enterAuth()) return
        val context = Context(session, registration)
        registration.replaceHandler { _, ops -> context.ready(ops) }
    }

    override fun onReady(session: SocksSession, registration: SocksEventLoop.Registration, ops: Int) {
        error("Handshake context must be installed before readiness")
    }

    private enum class Phase { GREETING, METHOD_WRITE, AUTH, AUTH_WRITE, REQUEST, FAILING, HANDED_OFF }

    private inner class Context(val session: SocksSession, val registration: SocksEventLoop.Registration) {
        val channel = registration.channel as SocketChannel
        val input = session.allocateControlBuffer(INPUT_BYTES)
        val output = session.allocateControlBuffer(OUTPUT_BYTES).also { it.limit(0) }
        var phase = Phase.GREETING
        var afterWrite = Phase.AUTH

        fun ready(ops: Int) {
            // Readiness can precede timer dispatch. Do not authenticate an expired fragment.
            if (session.snapshot().deadlineNanos?.let { it - session.ownerNowNanos() <= 0 } == true) {
                session.close(SocksSession.DeadlineExceededException())
                return
            }
            if (ops and SelectionKey.OP_WRITE != 0 && output.hasRemaining()) {
                val written = io.write(channel, output) // One bounded nonblocking syscall.
                if (output.hasRemaining()) {
                    if (written == 0) {
                        // A provider may report writable yet write zero. Yield via one scoped
                        // timer rather than repeatedly selecting the same unproductive key.
                        registration.pendingWrite(false)
                        val retry = session.owner.schedule(ZERO_WRITE_RETRY_NANOS, session.resource) {
                            registration.pendingWrite(output.hasRemaining())
                        }
                        if (retry.result != SocksEventLoop.Submission.ACCEPTED) {
                            session.close(SocksSession.SchedulingRejectedException(retry.result))
                        }
                    } else registration.pendingWrite(true)
                    return
                }
                output.clear(); output.limit(0)
                if (phase == Phase.FAILING) { session.close(); return }
                phase = afterWrite
                if (phase == Phase.REQUEST && !session.enterRequest()) return
                drive()
            }
            if (!registration.isOpen || phase == Phase.HANDED_OFF || phase == Phase.FAILING || output.hasRemaining()) return
            if (ops and SelectionKey.OP_READ != 0) {
                check(input.hasRemaining()) { "Control frame exceeds fixed input storage" }
                val count = io.read(channel, input) // At most 1024 bytes; surplus stays in kernel.
                if (count < 0) { session.close(EOFException()); return }
                if (count > 0) drive()
            }
        }

        fun drive() {
            input.flip()
            try {
                when (phase) {
                    Phase.GREETING -> {
                        val greeting = SocksIncrementalProtocol.greeting(input) ?: return
                        val method = greeting.method ?: run {
                            onAuthenticationRejected()
                            session.close()
                            return
                        }
                        if (method == SocksProtocol.AUTH_NO_ACCEPTABLE) {
                            onAuthenticationRejected()
                            fail(SocksProtocol.encodeMethodSelection(method))
                        } else queue(SocksProtocol.encodeMethodSelection(method), Phase.METHOD_WRITE, Phase.AUTH)
                    }
                    Phase.AUTH -> {
                        val auth = SocksIncrementalProtocol.authentication(input, credentials) ?: return
                        if (!auth.accepted) {
                            onAuthenticationRejected()
                            fail(SocksProtocol.encodeAuthenticationReply(false))
                        } else queue(SocksProtocol.encodeAuthenticationReply(true), Phase.AUTH_WRITE, Phase.REQUEST)
                    }
                    Phase.REQUEST -> {
                        val request = SocksIncrementalProtocol.request(input) ?: return
                        val protocol = when (request.command) {
                            SocksProtocol.COMMAND_CONNECT -> SocksSessionAdmission.Protocol.TCP
                            SocksProtocol.COMMAND_UDP_ASSOCIATE -> SocksSessionAdmission.Protocol.UDP
                            else -> {
                                fail(SocksProtocol.encodeReply(SocksProtocol.REPLY_COMMAND_NOT_SUPPORTED))
                                return
                            }
                        }
                        if (!session.admitProtocol(protocol)) {
                            if (!session.resource.isClosed) fail(SocksProtocol.encodeReply(SocksProtocol.REPLY_GENERAL_FAILURE))
                            return
                        }
                        phase = Phase.HANDED_OFF
                        registration.interestOps(0)
                        session.releaseControlBuffer(output)
                        val retained = if (input.hasRemaining()) input else null
                        if (retained == null) {
                            session.releaseControlBuffer(input)
                        }
                        val admitted = AdmittedRequest(session, request, registration, retained, io)
                        // Detach parser before callback; later phases own the key and must arm reads.
                        registration.replaceHandler { _, _ -> error("Downstream readiness handler not installed") }
                        onAdmitted(admitted)
                    }
                    else -> Unit
                }
            } catch (error: IOException) {
                session.close(error) // Old malformed request / EOF wire behavior is silent close.
            } finally {
                if (phase != Phase.HANDED_OFF && !session.resource.isClosed) {
                    input.compact()
                    // Wipe consumed credentials in the vacated tail, including short EOF paths.
                    val tail = input.duplicate()
                    while (tail.hasRemaining()) tail.put(0)
                    if (!output.hasRemaining()) registration.interestOps(SelectionKey.OP_READ)
                }
            }
        }

        fun queue(bytes: ByteArray, writing: Phase, next: Phase) {
            check(!output.hasRemaining())
            output.clear(); output.put(bytes); output.flip()
            phase = writing; afterWrite = next
            registration.interestOps(SelectionKey.OP_WRITE)
        }

        fun fail(bytes: ByteArray) {
            if (!session.enterFailing(FAILURE_WRITE_NANOS)) return
            queue(bytes, Phase.FAILING, Phase.FAILING)
        }
    }

    companion object {
        const val INPUT_BYTES = 1024
        const val OUTPUT_BYTES = 16
        const val FAILURE_WRITE_NANOS = 1_000_000_000L
        const val ZERO_WRITE_RETRY_NANOS = 1_000_000L
    }
}
