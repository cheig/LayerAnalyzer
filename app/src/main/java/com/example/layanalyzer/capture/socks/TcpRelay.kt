// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel

/**
 * Internal direct/gateway TCP relay. One instance/budget is shared by a server's fixed event loops;
 * each connection's mutable context is confined to its session owner. No tasks or relay threads.
 * Each source EOF drains its queue before closing only the destination output. The opposite
 * direction stays live without a relay idle/half-close timeout; both FINs finish the session.
 */
internal class TcpRelay(
    val budget: SocksTcpBufferBudget = SocksTcpBufferBudget(),
    private val io: UpstreamIo = UpstreamIo.CHANNEL,
    /** Bounded, nonblocking counter sink. Counts bytes actually written, including pre-read data. */
    private val onForwarded: (upload: Boolean, bytes: Int) -> Unit = { _, _ -> }
) {
    interface UpstreamIo {
        fun read(channel: SocketChannel, target: ByteBuffer): Int = channel.read(target)
        fun write(channel: SocketChannel, source: ByteBuffer): Int = channel.write(source)
        fun shutdownOutput(channel: SocketChannel) { channel.shutdownOutput() }
        companion object { val CHANNEL = object : UpstreamIo {} }
    }

    /** Call at admission, before connector.connect. False leaves failure-reply policy to caller. */
    fun reserve(session: SocksSession): Boolean = session.reserveTcpBuffers(budget) != null

    /** onConnected ingress: direct connect or gateway READY has drained SOCKS success completely. */
    fun start(connection: SocksNioTcpConnect.Connected): Handle? {
        val session = connection.client.session
        val storage = session.reserveTcpBuffers(budget) ?: run {
            session.close(BufferBudgetExceededException())
            return null
        }
        session.enterTcpRelay()
        return Handle(connection, storage).also { it.start() }
    }

    data class DirectionSnapshot(val queuedBytes: Int, val readPaused: Boolean, val readBytes: Long,
        val writtenBytes: Long, val zeroReads: Long, val zeroWrites: Long,
        val sourceEof: Boolean, val outputShutdown: Boolean)
    data class Snapshot(val clientToUpstream: DirectionSnapshot, val upstreamToClient: DirectionSnapshot,
        val callbacks: Long, val maxBytesPerCallback: Int)

    inner class Handle internal constructor(
        private val connection: SocksNioTcpConnect.Connected,
        private val storage: SocksTcpBufferBudget.Reservation
    ) {
        private val client = connection.client
        private val session = client.session
        private val upstream = connection.upstream
        private val channel = upstream.channel as SocketChannel
        private val upload = Direction(0, client::readClient, { io.write(channel, it) }, { io.shutdownOutput(channel) })
        private val download = Direction(1, { io.read(channel, it) }, client::writeClient, client::shutdownOutput)
        private var callbacks = 0L
        private var maxBytesPerCallback = 0

        fun snapshot(): Snapshot {
            check(session.owner.inEventLoop())
            return Snapshot(upload.snapshot(), download.snapshot(), callbacks, maxBytesPerCallback)
        }

        internal fun start() {
            client.onReady { _, ops -> ready(upload, download, ops) }
            upstream.replaceHandler { _, ops -> ready(download, upload, ops) }
            // A retained handshake suffix has no socket readiness; consume it explicitly once.
            // It is <= 1024 bytes, and the next read is always driven by socket readiness.
            if (client.bufferedClientBytes > 0) upload.read()
            refreshInterests()
        }

        private fun live() = !session.resource.isClosed

        private fun ready(incoming: Direction, outgoing: Direction, ops: Int) {
            if (!live()) return
            var bytes = 0
            // At most one write + one read, each <=16KiB. A session has two keys: <=64KiB
            // per selector snapshot. EventLoop exhausts that snapshot before selecting again.
            if (ops and SelectionKey.OP_WRITE != 0) bytes += outgoing.write()
            if (live() && ops and SelectionKey.OP_READ != 0) bytes += incoming.read()
            callbacks++
            maxBytesPerCallback = maxOf(maxBytesPerCallback, bytes)
            if (live()) refreshInterests()
        }

        private fun refreshInterests() {
            if (!live()) return
            client.interestOps(upload.readInterest() or download.writeInterest())
            upstream.interestOps(download.readInterest() or upload.writeInterest())
        }

        private inner class Direction(
            val index: Int,
            val readFrom: (ByteBuffer) -> Int,
            val writeTo: (ByteBuffer) -> Int,
            val shutdownOutput: () -> Unit
        ) {
            private var paused = false
            private var sourceEof = false
            private var outputShutdown = false
            private var readRetry: SocksEventLoop.Timer? = null
            private var writeRetry: SocksEventLoop.Timer? = null
            private var readBytes = 0L
            private var writtenBytes = 0L
            private var zeroReads = 0L
            private var zeroWrites = 0L
            private val queued: Int get() = storage.existing(index)?.position() ?: 0

            fun snapshot() = DirectionSnapshot(queued, paused, readBytes, writtenBytes, zeroReads, zeroWrites,
                sourceEof, outputShutdown)
            fun readInterest() = if (!sourceEof && !paused && readRetry == null) SelectionKey.OP_READ else 0
            fun writeInterest() = if (queued > 0 && writeRetry == null) SelectionKey.OP_WRITE else 0

            fun read(): Int {
                if (sourceEof || paused || readRetry != null) return 0
                val buffer = storage.buffer(index) // write mode; position is pending byte count
                val count = readFrom(buffer)
                if (count < 0) { eof(); return 0 }
                if (count == 0) {
                    zeroReads++
                    retry(read = true)
                } else {
                    readBytes += count
                    if (!buffer.hasRemaining()) paused = true // high water = capacity
                }
                return count
            }

            fun write(): Int {
                if (queued == 0 || writeRetry != null) return 0
                val buffer = checkNotNull(storage.existing(index))
                buffer.flip()
                val count = try { writeTo(buffer) } finally { buffer.compact() }
                if (count == 0) {
                    zeroWrites++
                    retry(read = false)
                } else {
                    writtenBytes += count
                    onForwarded(index == 0, count)
                    if (paused && queued <= budget.directionBytes / 2) paused = false
                    finishOutputIfDrained()
                }
                return count
            }

            private fun eof() {
                sourceEof = true
                session.enterDraining()
                finishOutputIfDrained()
            }

            private fun finishOutputIfDrained() {
                if (!sourceEof || outputShutdown || queued != 0 || !live()) return
                // An exception (including RST) propagates to the event-loop scope's one close
                // path; never swallow it or attempt a second shutdown/write on this direction.
                shutdownOutput()
                outputShutdown = true
                if (live() && upload.outputShutdown && download.outputShutdown) session.close()
            }

            private fun retry(read: Boolean) {
                val result = session.owner.schedule(ZERO_IO_RETRY_NANOS, session.resource) {
                    if (read) readRetry = null else writeRetry = null
                    refreshInterests()
                }
                if (result.result != SocksEventLoop.Submission.ACCEPTED) {
                    session.close(SocksSession.SchedulingRejectedException(result.result))
                } else if (read) readRetry = result.timer else writeRetry = result.timer
            }
        }
    }

    internal class BufferBudgetExceededException : IOException("TCP relay buffer reservation exhausted")
    companion object { const val ZERO_IO_RETRY_NANOS = 1_000_000L }
}
