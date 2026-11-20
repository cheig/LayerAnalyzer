// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONObject

/**
 * The production byte channel from the VPN's SOCKS hop to the Go gateway
 * (TLS-215, design §5.2).
 *
 * One instance belongs to one engine run: it holds the run's port, its token and
 * the frozen policy the run was started with, so a capture's connections can
 * only be dispatched to the engine that actually owns them. The token never
 * leaves this object in readable form — it goes into the frame, is never logged
 * or serialized anywhere else, and is wiped by [close] together with the port
 * that needs it.
 *
 * [describe] returns metadata only. The owning NIO event loop writes LAT1 and waits for
 * READY before replying SOCKS success and relaying the retained application bytes.
 *
 * The frame is C05's `LAT1` protocol: four ASCII bytes, a big-endian uint32 body
 * length, then one UTF-8 JSON object with exactly the seven fields the gateway
 * validates — `version, captureId, connectionId, networkGeneration,
 * destinationAddress, destinationPort, token`. The address is a literal the SOCKS
 * server has already resolved and is never a name: the engine dials the
 * destination it was given and never re-resolves an asserted SNI in its place.
 */
internal class TlsGatewayChannel(
    private val gatewayPort: Int,
    token: ByteArray,
    private val captureId: String,
    private val networkGeneration: Long,
    private val policy: TlsRoutingPolicy,
    /**
     * Prepares the loopback hop before it is connected — in production this is
     * `VpnService.protect`, which must happen synchronously before `connect()`
     * for the same reason an upstream socket needs it (§5.3).
     */
    private val prepareHopSocket: (Socket) -> Unit,
    private val readyTimeoutMillis: Int = DEFAULT_READY_TIMEOUT_MILLIS,
    connectionIds: () -> String = defaultConnectionIds(),
    private val channelFactory: () -> SocketChannel = { SocketChannel.open() }
) : SocksNioTlsGateway {
    private val tokenBytes = token.copyOf()
    private val nextConnectionId = connectionIds
    private val closed = AtomicBoolean(false)

    init {
        require(gatewayPort in 1..65535) { "Gateway port is out of range." }
        require(networkGeneration >= 0) { "Network generation must not be negative." }
        require(validEngineId(captureId)) { "Capture id is not a valid engine id." }
        require(readyTimeoutMillis in 1..MAX_READY_TIMEOUT_MILLIS) { "Gateway ready budget is out of range." }
        // C05: the token is the base64url text of 32 random bytes, without
        // padding. The text travels because the gateway compares the decoded
        // bytes; a buffer of another shape is a configuration error, not a token.
        require(tokenBytes.size == TOKEN_LENGTH && tokenBytes.all { it.toInt().toChar() in TOKEN_ALPHABET }) {
            "Gateway token must be $TOKEN_LENGTH base64url characters."
        }
    }

    /** A closed run refuses routing; it can never silently bypass the gateway. */
    override fun route(destinationPort: Int): SocksNioTlsGateway.Route = when {
        closed.get() -> SocksNioTlsGateway.Route.UNAVAILABLE
        policy.prefilterVpnTraffic(destinationPort) == TlsRoutingPrefilter.Candidate -> SocksNioTlsGateway.Route.GATEWAY
        else -> SocksNioTlsGateway.Route.DIRECT
    }

    override fun describe(destinationAddress: InetAddress, destinationPort: Int): TlsGatewayConnection {
        if (closed.get()) throw IOException("TLS gateway channel is closed.")
        if (destinationPort !in 1..65535) throw IOException("Destination port is out of range.")
        if (route(destinationPort) != SocksNioTlsGateway.Route.GATEWAY) {
            throw IOException("Destination is not a gateway candidate.")
        }
        val address = destinationAddress.hostAddress ?: throw IOException("Gateway destination has no address.")
        requireLiteralAddress(address)
        val body = frameBody(address, destinationPort)
        var frame: ByteArray? = null
        try {
            frame = ByteBuffer.allocate(8 + body.size).putInt(FRAME_MAGIC_INT).putInt(body.size).put(body).array()
            if (closed.get()) throw IOException("TLS gateway channel is closed.")
            return TlsGatewayConnection(InetSocketAddress(LOOPBACK_ADDRESS, gatewayPort), frame,
                CONNECT_TIMEOUT_MILLIS * 1_000_000L, readyTimeoutMillis * 1_000_000L,
                prepareHopSocket, { !closed.get() }, channelFactory)
        } catch (error: Throwable) {
            frame?.fill(0)
            throw error
        } finally {
            body.fill(0)
        }
    }

    /** Wipes the run token and prevents new connection descriptions. */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        tokenBytes.fill(0)
    }

    /** Test seam: proves [close] wiped the run's token instead of only ignoring it. */
    internal fun carriesTokenMaterial(): Boolean = tokenBytes.any { it != 0.toByte() }

    /** The token must never appear in a rendering of this object. */
    override fun toString(): String = "TlsGatewayChannel(port=$gatewayPort, token=<redacted>)"

    private fun frameBody(destinationAddress: String, destinationPort: Int): ByteArray {
        val connectionId = nextConnectionId()
        if (!validEngineId(connectionId)) throw IOException("Generated connection id is not a valid engine id.")
        val json = JSONObject()
            .put("version", PROTOCOL_VERSION)
            .put("captureId", captureId)
            .put("connectionId", connectionId)
            .put("networkGeneration", networkGeneration)
            .put("destinationAddress", destinationAddress)
            .put("destinationPort", destinationPort)
            .put("token", String(tokenBytes, StandardCharsets.US_ASCII))
            .toString()
        val body = json.toByteArray(StandardCharsets.UTF_8)
        // The gateway refuses a header above its own bound; refusing to send one
        // is the same statement made locally, and it happens before any socket
        // exists.
        if (body.size > MAX_HEADER_BYTES || closed.get()) {
            body.fill(0)
            throw IOException("Gateway metadata is unavailable or exceeds the protocol limit.")
        }
        return body
    }

    private fun requireLiteralAddress(address: String) {
        val usable = address.isNotEmpty() && address.length <= MAX_ADDRESS_LENGTH &&
            address.none { it == '%' } && address.all { it in ADDRESS_ALPHABET }
        if (!usable) throw IOException("Gateway destination is not a literal address.")
    }

    internal companion object {
        const val PROTOCOL_VERSION = 1
        const val FRAME_MAGIC = "LAT1"
        const val FRAME_MAGIC_INT = 0x4c415431

        /** C05's header bound; the gateway rejects anything above it. */
        const val MAX_HEADER_BYTES = 4096

        /** C05's reply bound. */
        const val MAX_REPLY_BYTES = 1024

        /** C05: 32 random bytes as base64url without padding. */
        const val TOKEN_LENGTH = 43

        /**
         * C10's gateway budget: one second for authentication, and the upstream
         * TCP connection behind READY has its own ten seconds. This deadline
         * covers both, and is cleared as soon as the reply arrives so the
         * connection itself is never cut short by it.
         */
        const val DEFAULT_READY_TIMEOUT_MILLIS = 11_000
        const val MAX_READY_TIMEOUT_MILLIS = 30_000
        const val CONNECT_TIMEOUT_MILLIS = 1_000
        const val MAX_ADDRESS_LENGTH = 45

        const val TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        const val ADDRESS_ALPHABET = "0123456789abcdefABCDEF.:"

        /** The gateway listens on IPv4 loopback only (TLS-202); nothing else is dialed. */
        val LOOPBACK_ADDRESS: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    }
}

/**
 * One run's connection identifiers: `c<prefix>-<counter>`.
 *
 * The prefix is random per channel so that two runs inside one capture cannot
 * mint the same id — the event store keys a connection by this value and the
 * capture's secret asset accumulates every run's records, so a collision would
 * merge two connections rather than merely misnumber them. The counter keeps the
 * prefix's connection order readable.
 */
private fun defaultConnectionIds(): () -> String {
    val random = SecureRandom()
    val prefix = buildString(CONNECTION_PREFIX_LENGTH) {
        repeat(CONNECTION_PREFIX_LENGTH) { append(ID_ALPHABET[random.nextInt(ID_ALPHABET.length)]) }
    }
    val counter = AtomicLong(0)
    return { "c$prefix-${counter.incrementAndGet()}" }
}

private const val CONNECTION_PREFIX_LENGTH = 6
private const val ID_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"

/**
 * `engine.ValidID`: an ASCII letter or digit, then letters, digits, dash or
 * underscore, at most 128 of them. The gateway validates the same rule, so an
 * unusable id is refused here rather than on the wire.
 */
internal fun validEngineId(value: String): Boolean {
    if (value.isEmpty() || value.length > 128) return false
    return value.withIndex().all { (index, character) ->
        character in 'a'..'z' || character in 'A'..'Z' || character in '0'..'9' ||
            (index > 0 && (character == '-' || character == '_'))
    }
}
