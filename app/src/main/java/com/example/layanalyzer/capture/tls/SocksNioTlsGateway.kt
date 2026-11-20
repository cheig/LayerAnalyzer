package com.example.layanalyzer.capture.tls

import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel

/**
 * NIO route/metadata boundary. Unlike the legacy blocking gateway, this interface cannot return
 * a Socket or imply READY. Callers must retain a GATEWAY decision through every setup failure;
 * UNAVAILABLE is a refusal, never permission to bypass the gateway. All methods are bounded and
 * perform no DNS, connect, stream I/O, worker wait, or selector registration.
 */
internal interface SocksNioTlsGateway : Closeable {
    enum class Route { DIRECT, GATEWAY, UNAVAILABLE }

    fun route(destinationPort: Int): Route

    /** The address has already been resolved by this capture's bounded resolver. */
    @Throws(IOException::class)
    fun describe(destinationAddress: InetAddress, destinationPort: Int): TlsGatewayConnection
}

/**
 * One owner-only, one-shot connection description. It owns the credential-bearing LAT1 frame,
 * not a connected socket. Close it on successful frame drain AND on every cancellation/failure;
 * any previously obtained frame view is wiped as well. Closing the run prevents new opens, but
 * the session owner remains responsible for closing an existing description and channel.
 *
 * [openChannel] transfers an unconnected channel to its caller on success. The caller must
 * immediately hand it to the session resource (or close it if registration fails), then drive
 * connect/OP_CONNECT, frame writes and READY on that same owner. Closing this description never
 * closes a channel already handed over. No ordinary Socket factory is accepted by this API.
 */
internal class TlsGatewayConnection internal constructor(
    val endpoint: InetSocketAddress,
    frameBytes: ByteArray,
    val connectTimeoutNanos: Long,
    val readyTimeoutNanos: Long,
    private val prepareHopSocket: (Socket) -> Unit,
    private val isRunOpen: () -> Boolean,
    private val channelFactory: () -> SocketChannel = { SocketChannel.open() }
) : Closeable {
    private val bytes = frameBytes
    private val output = ByteBuffer.wrap(bytes).asReadOnlyBuffer()
    private var opened = false
    private var closed = false

    init {
        require(!endpoint.isUnresolved && endpoint.address.isLoopbackAddress)
        require(endpoint.port in 1..65535)
        require(bytes.size in 9..(8 + TlsGatewayChannel.MAX_HEADER_BYTES))
        require(connectTimeoutNanos in 1..TlsGatewayChannel.CONNECT_TIMEOUT_MILLIS * 1_000_000L)
        require(readyTimeoutNanos in 1..TlsGatewayChannel.MAX_READY_TIMEOUT_MILLIS * 1_000_000L)
    }

    /** Same bounded buffer on each access: the driver advances its position for partial writes. */
    val frame: ByteBuffer
        get() {
            check(!closed) { "Gateway description is closed." }
            return output
        }

    fun openChannel(): SocketChannel {
        check(!opened && !closed) { "Gateway description has already been consumed." }
        opened = true
        var channel: SocketChannel? = null
        try {
            if (!isRunOpen()) throw IOException("TLS gateway channel is closed.")
            channel = channelFactory()
            check(channel.isOpen && !channel.isConnected && !channel.isConnectionPending) {
                "Gateway factory must create an open, unconnected channel."
            }
            val socket = channel.socket()
            socket.tcpNoDelay = true
            prepareHopSocket(socket)
            if (!isRunOpen()) throw IOException("TLS gateway channel is closed.")
            check(channel.isOpen && !channel.isConnected && !channel.isConnectionPending && !socket.isBound) {
                "Gateway preparation must only protect an unconnected, unbound channel."
            }
            channel.configureBlocking(false)
            return channel
        } catch (error: Throwable) {
            runCatching { channel?.close() }
            close()
            throw error
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        bytes.fill(0)
    }

    override fun toString(): String = "TlsGatewayConnection(endpoint=$endpoint, frame=<redacted>)"
}
