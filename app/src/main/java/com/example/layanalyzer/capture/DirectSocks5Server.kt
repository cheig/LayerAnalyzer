// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import android.util.Log
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.util.LinkedHashMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * A loopback-only SOCKS5 server used as the direct upstream for HEV tun2socks.
 * All sockets which leave the device are supplied by the caller and must be
 * protected with VpnService.protect before they are connected or used.
 */
internal class DirectSocks5Server(
    private val prepareTcp: (Socket) -> Unit,
    private val prepareUdp: (DatagramSocket) -> Unit,
    private val resolveHost: (String) -> Array<InetAddress>
) : Closeable {
    private val running = AtomicBoolean(false)
    private val upstreamFailureLogged = AtomicBoolean(false)
    private val capacityFailureLogged = AtomicBoolean(false)
    private val tcpSentBytes = AtomicLong(0)
    private val tcpReceivedBytes = AtomicLong(0)
    private val udpSentBytes = AtomicLong(0)
    private val udpReceivedBytes = AtomicLong(0)
    private val clientSlots = Semaphore(MAX_CLIENT_SESSIONS, true)
    private val connectionExecutor: ExecutorService = Executors.newFixedThreadPool(MAX_CLIENT_SESSIONS) { runnable ->
        Thread(runnable, "LayerAnalyzer-SOCKS5").apply { isDaemon = true }
    }
    private val relayExecutor: ExecutorService = Executors.newFixedThreadPool(MAX_RELAY_WORKERS) { runnable ->
        Thread(runnable, "LayerAnalyzer-SOCKS5-Relay").apply { isDaemon = true }
    }
    private val activeSockets = ConcurrentHashMap.newKeySet<Socket>()
    private val associations = ConcurrentHashMap.newKeySet<UdpAssociation>()

    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var acceptThread: Thread? = null

    val port: Int
        get() = serverSocket?.localPort ?: throw IllegalStateException("SOCKS5 server is not running.")

    fun stats(): UpstreamStats = UpstreamStats(
        sentBytes = tcpSentBytes.get() + udpSentBytes.get(),
        receivedBytes = tcpReceivedBytes.get() + udpReceivedBytes.get()
    )

    fun start(): Int {
        check(running.compareAndSet(false, true)) { "SOCKS5 server is already running." }

        return try {
            val listener = ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(LOOPBACK_ADDRESS, 0))
            }
            serverSocket = listener
            acceptThread = thread(
                start = true,
                isDaemon = true,
                name = "LayerAnalyzer-SOCKS5-Accept"
            ) {
                acceptLoop(listener)
            }
            listener.localPort
        } catch (error: IOException) {
            running.set(false)
            closeQuietly(serverSocket)
            serverSocket = null
            connectionExecutor.shutdownNow()
            relayExecutor.shutdownNow()
            throw error
        }
    }

    private fun acceptLoop(listener: ServerSocket) {
        while (running.get()) {
            val client = try {
                listener.accept()
            } catch (error: SocketException) {
                if (running.get()) continue
                break
            } catch (error: IOException) {
                if (running.get()) continue
                break
            }

            if (!running.get()) {
                closeQuietly(client)
                break
            }
            if (!clientSlots.tryAcquire()) {
                if (capacityFailureLogged.compareAndSet(false, true)) {
                    Log.w(LOG_TAG, "SOCKS5 reached its $MAX_CLIENT_SESSIONS-session limit.")
                }
                closeQuietly(client)
                continue
            }
            activeSockets += client
            if (!running.get()) {
                activeSockets.remove(client)
                closeQuietly(client)
                clientSlots.release()
                break
            }
            try {
                connectionExecutor.execute {
                    try {
                        handleClient(client)
                    } finally {
                        clientSlots.release()
                    }
                }
            } catch (_: RejectedExecutionException) {
                activeSockets.remove(client)
                closeQuietly(client)
                clientSlots.release()
            }
        }
    }

    private fun handleClient(client: Socket) {
        try {
            client.tcpNoDelay = true
            client.soTimeout = HANDSHAKE_TIMEOUT_MILLIS
            val input = BufferedInputStream(client.getInputStream())
            val output = BufferedOutputStream(client.getOutputStream())
            if (!negotiate(input, output)) return

            val request = readRequest(input)
            client.soTimeout = 0
            when (request.command) {
                COMMAND_CONNECT -> handleConnect(client, input, output, request)
                COMMAND_UDP_ASSOCIATE -> handleUdpAssociate(input, output)
                else -> writeReply(output, REPLY_COMMAND_NOT_SUPPORTED)
            }
        } catch (_: EOFException) {
            // The tunnel can close a control socket while the service is stopping.
        } catch (_: IOException) {
            // The SOCKS peer treats a closed control socket as a failed request.
        } finally {
            activeSockets.remove(client)
            closeQuietly(client)
        }
    }

    private fun negotiate(input: InputStream, output: OutputStream): Boolean {
        if (input.readRequiredByte() != SOCKS_VERSION) return false
        val methodCount = input.readRequiredByte()
        val methods = input.readRequiredBytes(methodCount)
        if (methods.none { (it.toInt() and 0xff) == AUTH_NO_AUTH }) {
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), AUTH_NO_ACCEPTABLE.toByte()))
            output.flush()
            return false
        }

        output.write(byteArrayOf(SOCKS_VERSION.toByte(), AUTH_NO_AUTH.toByte()))
        output.flush()
        return true
    }

    private fun readRequest(input: InputStream): SocksRequest {
        if (input.readRequiredByte() != SOCKS_VERSION) throw IOException("Unsupported SOCKS version.")
        val command = input.readRequiredByte()
        input.readRequiredByte() // Reserved byte.
        val addressType = input.readRequiredByte()
        val destination = when (addressType) {
            ADDRESS_TYPE_IPV4 -> SocksDestination.Ip(
                InetAddress.getByAddress(input.readRequiredBytes(4))
            )
            ADDRESS_TYPE_IPV6 -> SocksDestination.Ip(
                InetAddress.getByAddress(input.readRequiredBytes(16))
            )
            ADDRESS_TYPE_DOMAIN -> {
                val length = input.readRequiredByte()
                if (length == 0) throw IOException("Empty SOCKS domain name.")
                SocksDestination.Domain(
                    input.readRequiredBytes(length).toString(StandardCharsets.US_ASCII)
                )
            }
            else -> throw IOException("Unsupported SOCKS address type.")
        }
        val port = (input.readRequiredByte() shl 8) or input.readRequiredByte()
        return SocksRequest(command, destination, port)
    }

    private fun handleConnect(
        client: Socket,
        input: InputStream,
        output: OutputStream,
        request: SocksRequest
    ) {
        val remote = try {
            connectTo(request.destination, request.port)
        } catch (error: IOException) {
            logUpstreamFailure("TCP", error)
            writeReply(output, REPLY_GENERAL_FAILURE)
            return
        }

        activeSockets += remote
        try {
            writeReply(output, REPLY_SUCCEEDED, remote.localAddress, remote.localPort)
            relayTcp(client, input, remote)
        } finally {
            activeSockets.remove(remote)
            closeQuietly(remote)
        }
    }

    private fun connectTo(destination: SocksDestination, port: Int): Socket {
        val addresses = when (destination) {
            is SocksDestination.Ip -> arrayOf(destination.address)
            is SocksDestination.Domain -> resolveHost(destination.name)
        }
        if (addresses.isEmpty()) throw IOException("SOCKS destination did not resolve.")

        var lastError: IOException? = null
        for (address in addresses) {
            val socket = Socket()
            activeSockets += socket
            var connected = false
            try {
                if (!running.get()) throw IOException("SOCKS5 server is stopping.")
                socket.tcpNoDelay = true
                prepareTcp(socket)
                socket.connect(InetSocketAddress(address, port), CONNECT_TIMEOUT_MILLIS)
                connected = true
                return socket
            } catch (error: IOException) {
                lastError = error
            } finally {
                if (!connected) {
                    activeSockets.remove(socket)
                    closeQuietly(socket)
                }
            }
        }
        throw lastError ?: IOException("Unable to connect SOCKS destination.")
    }

    private fun relayTcp(client: Socket, clientInput: InputStream, remote: Socket) {
        val reverseRelayFinished = CountDownLatch(1)
        try {
            relayExecutor.execute {
                try {
                    copyWithHalfClose(
                        input = remote.getInputStream(),
                        output = client.getOutputStream(),
                        onBytesCopied = { tcpReceivedBytes.addAndGet(it.toLong()) },
                        closeOutput = { runCatching { client.shutdownOutput() } }
                    )
                } finally {
                    reverseRelayFinished.countDown()
                }
            }
            // The connection worker already owns this session, so use it for
            // the forward half instead of consuming a third thread per TCP flow.
            copyWithHalfClose(
                input = clientInput,
                output = remote.getOutputStream(),
                onBytesCopied = { tcpSentBytes.addAndGet(it.toLong()) },
                closeOutput = { runCatching { remote.shutdownOutput() } }
            )
            reverseRelayFinished.await()
        } catch (_: RejectedExecutionException) {
            // Server shutdown can reject a relay task. Closing both ends wakes
            // any task that was already accepted.
            closeQuietly(client)
            closeQuietly(remote)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            closeQuietly(client)
            closeQuietly(remote)
        }
    }

    private fun copyWithHalfClose(
        input: InputStream,
        output: OutputStream,
        onBytesCopied: (Int) -> Unit,
        closeOutput: () -> Unit
    ) {
        try {
            val buffer = ByteArray(TCP_COPY_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                output.write(buffer, 0, count)
                output.flush()
                onBytesCopied(count)
            }
        } catch (_: IOException) {
            // Socket closure is expected during shutdown and connection teardown.
        } finally {
            closeOutput()
        }
    }

    private fun handleUdpAssociate(input: InputStream, output: OutputStream) {
        val association = try {
            UdpAssociation().also { it.start() }
        } catch (error: IOException) {
            logUpstreamFailure("UDP", error)
            writeReply(output, REPLY_GENERAL_FAILURE)
            return
        }

        associations += association
        try {
            writeReply(output, REPLY_SUCCEEDED, LOOPBACK_ADDRESS, association.port)
            while (running.get() && input.read() >= 0) {
                // RFC 1928 keeps this TCP control channel open for the association.
            }
        } finally {
            associations.remove(association)
            association.close()
        }
    }

    private fun writeReply(
        output: OutputStream,
        reply: Int,
        address: InetAddress = LOOPBACK_ADDRESS,
        port: Int = 0
    ) {
        val rawAddress = address.address
        val addressType = when (rawAddress.size) {
            4 -> ADDRESS_TYPE_IPV4
            16 -> ADDRESS_TYPE_IPV6
            else -> throw IOException("Unsupported bound address.")
        }
        output.write(SOCKS_VERSION)
        output.write(reply)
        output.write(0)
        output.write(addressType)
        output.write(rawAddress)
        output.write((port ushr 8) and 0xff)
        output.write(port and 0xff)
        output.flush()
    }

    override fun close() {
        if (!running.getAndSet(false)) return

        closeQuietly(serverSocket)
        serverSocket = null
        connectionExecutor.shutdownNow()

        val thread = acceptThread
        if (thread != null && thread !== Thread.currentThread()) {
            joinThread(thread, ACCEPT_THREAD_JOIN_MILLIS)
        }
        acceptThread = null
        activeSockets.toList().forEach { closeQuietly(it) }
        associations.toList().forEach { it.close() }
        relayExecutor.shutdownNow()
        awaitTermination(connectionExecutor)
        awaitTermination(relayExecutor)
    }

    private sealed class SocksDestination {
        data class Ip(val address: InetAddress) : SocksDestination()
        data class Domain(val name: String) : SocksDestination()
    }

    private data class SocksRequest(
        val command: Int,
        val destination: SocksDestination,
        val port: Int
    )

    private data class Peer(val address: InetAddress, val port: Int)

    private inner class UdpAssociation : Closeable {
        private val associationRunning = AtomicBoolean(false)
        private val closeStarted = AtomicBoolean(false)
        private val closeFinished = CountDownLatch(1)
        private val relaySocket = DatagramSocket(null)
        private val upstreamSocket = try {
            DatagramSocket(null)
        } catch (error: Throwable) {
            relaySocket.close()
            throw error
        }
        private val allowedPeers = LinkedHashMap<Peer, Long>(16, 0.75f, true)
        private val allowedPeersLock = Any()

        @Volatile
        private var clientEndpoint: InetSocketAddress? = null

        @Volatile
        private var relayThread: Thread? = null

        @Volatile
        private var upstreamThread: Thread? = null

        val port: Int
            get() = relaySocket.localPort

        fun start() {
            try {
                prepareUdp(upstreamSocket)

                relaySocket.reuseAddress = true
                relaySocket.bind(InetSocketAddress(LOOPBACK_ADDRESS, 0))
                upstreamSocket.reuseAddress = true
                upstreamSocket.bind(InetSocketAddress(0))
                associationRunning.set(true)

                relayThread = thread(
                    start = true,
                    isDaemon = true,
                    name = "LayerAnalyzer-SOCKS5-UDP-Relay"
                ) {
                    relayLoop()
                }
                upstreamThread = thread(
                    start = true,
                    isDaemon = true,
                    name = "LayerAnalyzer-SOCKS5-UDP-Upstream"
                ) {
                    upstreamLoop()
                }
            } catch (error: Throwable) {
                close()
                throw error
            }
        }

        private fun relayLoop() {
            val buffer = ByteArray(MAX_UDP_PACKET_SIZE)
            while (running.get() && associationRunning.get()) {
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    relaySocket.receive(packet)
                } catch (_: SocketException) {
                    break
                } catch (_: IOException) {
                    if (associationRunning.get()) continue
                    break
                }

                val source = InetSocketAddress(packet.address, packet.port)
                if (!source.address.isLoopbackAddress) continue
                val currentClient = clientEndpoint
                if (currentClient != null && currentClient != source) continue
                clientEndpoint = source

                val request = parseUdpRequest(packet) ?: continue
                val target = resolveUdpDestination(request.destination, request.port) ?: continue
                allowPeer(Peer(target.address, target.port))
                try {
                    upstreamSocket.send(
                        DatagramPacket(request.payload, request.payload.size, target.address, target.port)
                    )
                    udpSentBytes.addAndGet(request.payload.size.toLong())
                } catch (error: IOException) {
                    logUpstreamFailure("UDP send", error)
                    // The association stays alive for later datagrams and network recovery.
                }
            }
        }

        private fun upstreamLoop() {
            val buffer = ByteArray(MAX_UDP_PACKET_SIZE)
            while (running.get() && associationRunning.get()) {
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    upstreamSocket.receive(packet)
                } catch (_: SocketException) {
                    break
                } catch (_: IOException) {
                    if (associationRunning.get()) continue
                    break
                }

                val source = Peer(packet.address, packet.port)
                if (!isPeerAllowed(source)) continue
                udpReceivedBytes.addAndGet(packet.length.toLong())
                val client = clientEndpoint ?: continue
                val response = buildUdpResponse(packet)
                try {
                    relaySocket.send(
                        DatagramPacket(response, response.size, client.address, client.port)
                    )
                } catch (error: IOException) {
                    logUpstreamFailure("UDP response", error)
                    // The control connection will close the association when its peer is gone.
                }
            }
        }

        private fun parseUdpRequest(packet: DatagramPacket): UdpRequest? {
            val bytes = packet.data
            val end = packet.offset + packet.length
            var index = packet.offset
            if (end - index < 4 || bytes[index] != 0.toByte() || bytes[index + 1] != 0.toByte()) {
                return null
            }
            if ((bytes[index + 2].toInt() and 0xff) != 0) return null
            val addressType = bytes[index + 3].toInt() and 0xff
            index += 4

            val destination = when (addressType) {
                ADDRESS_TYPE_IPV4 -> {
                    if (end - index < 6) return null
                    val address = InetAddress.getByAddress(bytes.copyOfRange(index, index + 4))
                    index += 4
                    SocksDestination.Ip(address)
                }
                ADDRESS_TYPE_IPV6 -> {
                    if (end - index < 18) return null
                    val address = InetAddress.getByAddress(bytes.copyOfRange(index, index + 16))
                    index += 16
                    SocksDestination.Ip(address)
                }
                ADDRESS_TYPE_DOMAIN -> {
                    if (end - index < 1) return null
                    val length = bytes[index].toInt() and 0xff
                    index += 1
                    if (length == 0 || end - index < length + 2) return null
                    val name = bytes.copyOfRange(index, index + length).toString(StandardCharsets.US_ASCII)
                    index += length
                    SocksDestination.Domain(name)
                }
                else -> return null
            }

            if (end - index < 2) return null
            val port = ((bytes[index].toInt() and 0xff) shl 8) or (bytes[index + 1].toInt() and 0xff)
            index += 2
            return UdpRequest(destination, port, bytes.copyOfRange(index, end))
        }

        private fun resolveUdpDestination(destination: SocksDestination, port: Int): InetSocketAddress? {
            val address = when (destination) {
                is SocksDestination.Ip -> destination.address
                is SocksDestination.Domain -> runCatching { resolveHost(destination.name).firstOrNull() }.getOrNull()
            } ?: return null
            return InetSocketAddress(address, port)
        }

        private fun buildUdpResponse(packet: DatagramPacket): ByteArray {
            val rawAddress = packet.address.address
            val addressType = if (rawAddress.size == 4) ADDRESS_TYPE_IPV4 else ADDRESS_TYPE_IPV6
            val prefixLength = 4 + rawAddress.size + 2
            val result = ByteArray(prefixLength + packet.length)
            result[0] = 0
            result[1] = 0
            result[2] = 0
            result[3] = addressType.toByte()
            rawAddress.copyInto(result, destinationOffset = 4)
            val portOffset = 4 + rawAddress.size
            result[portOffset] = (packet.port ushr 8).toByte()
            result[portOffset + 1] = packet.port.toByte()
            System.arraycopy(packet.data, packet.offset, result, prefixLength, packet.length)
            return result
        }

        private fun allowPeer(peer: Peer) {
            val now = System.nanoTime()
            synchronized(allowedPeersLock) {
                allowedPeers[peer] = now
                val iterator = allowedPeers.entries.iterator()
                while (iterator.hasNext()) {
                    val entry = iterator.next()
                    if (
                        allowedPeers.size <= MAX_ALLOWED_UDP_PEERS &&
                        now - entry.value <= ALLOWED_UDP_PEER_TTL_NANOS
                    ) {
                        break
                    }
                    iterator.remove()
                }
            }
        }

        private fun isPeerAllowed(peer: Peer): Boolean {
            val now = System.nanoTime()
            synchronized(allowedPeersLock) {
                val lastSeen = allowedPeers[peer] ?: return false
                if (now - lastSeen > ALLOWED_UDP_PEER_TTL_NANOS) {
                    allowedPeers.remove(peer)
                    return false
                }
                allowedPeers[peer] = now
                return true
            }
        }

        override fun close() {
            if (!closeStarted.compareAndSet(false, true)) {
                awaitCloseFinished()
                return
            }

            try {
                associationRunning.set(false)
                closeQuietly(relaySocket)
                closeQuietly(upstreamSocket)
                synchronized(allowedPeersLock) {
                    allowedPeers.clear()
                }
                joinThread(relayThread, UDP_THREAD_JOIN_MILLIS)
                joinThread(upstreamThread, UDP_THREAD_JOIN_MILLIS)
                relayThread = null
                upstreamThread = null
            } finally {
                closeFinished.countDown()
            }
        }

        private fun awaitCloseFinished() {
            var interrupted = false
            while (true) {
                try {
                    closeFinished.await()
                    break
                } catch (_: InterruptedException) {
                    interrupted = true
                }
            }
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    private data class UdpRequest(
        val destination: SocksDestination,
        val port: Int,
        val payload: ByteArray
    )

    data class UpstreamStats(
        val sentBytes: Long,
        val receivedBytes: Long
    )

    private fun InputStream.readRequiredByte(): Int {
        val value = read()
        if (value < 0) throw EOFException()
        return value
    }

    private fun InputStream.readRequiredBytes(length: Int): ByteArray {
        val bytes = ByteArray(length)
        var offset = 0
        while (offset < bytes.size) {
            val count = read(bytes, offset, bytes.size - offset)
            if (count < 0) throw EOFException()
            offset += count
        }
        return bytes
    }

    private fun closeQuietly(closeable: Closeable?) {
        runCatching { closeable?.close() }
    }

    private fun closeQuietly(socket: DatagramSocket?) {
        runCatching { socket?.close() }
    }

    private fun awaitTermination(executor: ExecutorService) {
        try {
            executor.awaitTermination(EXECUTOR_SHUTDOWN_MILLIS, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun logUpstreamFailure(stage: String, error: IOException) {
        if (running.get() && upstreamFailureLogged.compareAndSet(false, true)) {
            Log.w(LOG_TAG, "$stage upstream forwarding failed.", error)
        }
    }

    private fun joinThread(thread: Thread?, timeoutMillis: Long) {
        if (thread == null || thread === Thread.currentThread()) return
        try {
            thread.join(timeoutMillis)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private companion object {
        const val LOG_TAG = "LayAnalyzer-Capture"
        const val SOCKS_VERSION = 5
        const val AUTH_NO_AUTH = 0
        const val AUTH_NO_ACCEPTABLE = 0xff
        const val COMMAND_CONNECT = 1
        const val COMMAND_UDP_ASSOCIATE = 3
        const val ADDRESS_TYPE_IPV4 = 1
        const val ADDRESS_TYPE_DOMAIN = 3
        const val ADDRESS_TYPE_IPV6 = 4
        const val REPLY_SUCCEEDED = 0
        const val REPLY_GENERAL_FAILURE = 1
        const val REPLY_COMMAND_NOT_SUPPORTED = 7
        const val HANDSHAKE_TIMEOUT_MILLIS = 15_000
        const val CONNECT_TIMEOUT_MILLIS = 15_000
        const val TCP_COPY_BUFFER_SIZE = 16 * 1024
        const val MAX_UDP_PACKET_SIZE = 65_535
        const val MAX_ALLOWED_UDP_PEERS = 512
        const val ALLOWED_UDP_PEER_TTL_NANOS = 120_000_000_000L
        const val ACCEPT_THREAD_JOIN_MILLIS = 500L
        const val UDP_THREAD_JOIN_MILLIS = 500L
        const val EXECUTOR_SHUTDOWN_MILLIS = 1_000L
        const val MAX_CLIENT_SESSIONS = 64
        const val MAX_RELAY_WORKERS = MAX_CLIENT_SESSIONS

        val LOOPBACK_ADDRESS: InetAddress = InetAddress.getByName("127.0.0.1")
    }
}
