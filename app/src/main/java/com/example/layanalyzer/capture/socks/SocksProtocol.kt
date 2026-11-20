// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksUdpRequest
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetAddress
import java.nio.charset.StandardCharsets

/** A complete request plus its wire length; bytes after it belong to application data. */
internal data class DecodedSocksRequest(val request: SocksRequest, val bytesConsumed: Int)

/**
 * SOCKS5/RFC 1929 wire operations only: no sockets, streams, DNS, policy or session budgets.
 * IPs are constructed from raw octets with getByAddress, never by parsing address strings.
 * Request decoding requires a complete frame (short input throws EOFException). This is not
 * the NIO incremental parser; that parser can reuse these operations once a frame is ready.
 */
internal object SocksProtocol {
    const val SOCKS_VERSION = 5
    const val AUTH_USERNAME_PASSWORD = 2
    const val AUTH_NO_ACCEPTABLE = 0xff
    const val AUTH_VERSION = 1
    const val AUTH_STATUS_SUCCESS = 0
    const val AUTH_STATUS_FAILURE = 1
    const val COMMAND_CONNECT = 1
    const val COMMAND_UDP_ASSOCIATE = 3
    const val ADDRESS_TYPE_IPV4 = 1
    const val ADDRESS_TYPE_DOMAIN = 3
    const val ADDRESS_TYPE_IPV6 = 4
    const val REPLY_SUCCEEDED = 0
    const val REPLY_GENERAL_FAILURE = 1
    const val REPLY_NETWORK_UNREACHABLE = 3
    const val REPLY_HOST_UNREACHABLE = 4
    const val REPLY_COMMAND_NOT_SUPPORTED = 7

    private val defaultBoundAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    /** null preserves the old silent close on a non-SOCKS5 greeting. Method 0 is never selected. */
    fun selectAuthenticationMethod(version: Int, methods: ByteArray): Int? = when {
        version != SOCKS_VERSION -> null
        methods.any { (it.toInt() and 0xff) == AUTH_USERNAME_PASSWORD } -> AUTH_USERNAME_PASSWORD
        else -> AUTH_NO_ACCEPTABLE
    }

    fun encodeMethodSelection(method: Int): ByteArray = byteArrayOf(SOCKS_VERSION.toByte(), method.toByte())

    /** Caller owns the candidate buffers and must wipe them after the verdict. */
    fun authenticationAccepted(
        version: Int,
        username: ByteArray,
        password: ByteArray,
        credentials: SocksCredentials?
    ): Boolean = version == AUTH_VERSION && credentials?.matches(username, password) == true

    fun encodeAuthenticationReply(accepted: Boolean): ByteArray = byteArrayOf(
        AUTH_VERSION.toByte(),
        (if (accepted) AUTH_STATUS_SUCCESS else AUTH_STATUS_FAILURE).toByte()
    )

    fun decodeRequest(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): DecodedSocksRequest {
        val cursor = Cursor(bytes, offset, length)
        requireVersion(cursor.readByte())
        val command = cursor.readByte()
        cursor.readByte() // Reserved: the blocking server historically tolerates any value.
        val destination = cursor.readDestination(cursor.readByte())
        val port = cursor.readPort()
        return DecodedSocksRequest(SocksRequest(command, destination, port), cursor.position - offset)
    }

    fun encodeRequest(request: SocksRequest): ByteArray = ByteArrayOutputStream().apply {
        write(SOCKS_VERSION)
        write(request.command)
        write(0)
        writeDestination(request.destination)
        writePort(request.port)
    }.toByteArray()

    /** Every malformed/short datagram is dropped; only FRAG=0 and RSV=0 are supported. */
    fun decodeUdpRequest(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): SocksUdpRequest? {
        val cursor = Cursor(bytes, offset, length)
        return try {
            if (cursor.readByte() != 0 || cursor.readByte() != 0 || cursor.readByte() != 0) return null
            val destination = cursor.readDestination(cursor.readByte())
            val port = cursor.readPort()
            SocksUdpRequest(destination, port, cursor.readBytes(cursor.remaining))
        } catch (_: IOException) {
            null
        }
    }

    /** IPv4/IPv6/domain codec, also reusable for request fixtures and future queued datagrams. */
    fun encodeUdpRequest(request: SocksUdpRequest): ByteArray = ByteArrayOutputStream().apply {
        write(byteArrayOf(0, 0, 0))
        writeDestination(request.destination)
        writePort(request.port)
        write(request.payload)
    }.toByteArray()

    fun encodeUdpResponse(
        address: InetAddress,
        port: Int,
        payload: ByteArray,
        offset: Int = 0,
        length: Int = payload.size - offset
    ): ByteArray {
        requireSlice(payload, offset, length)
        val rawAddress = address.address
        val addressType = when (rawAddress.size) {
            4 -> ADDRESS_TYPE_IPV4
            16 -> ADDRESS_TYPE_IPV6
            else -> throw IOException("Unsupported bound address.")
        }
        // Keep the old single output allocation for potentially large upstream datagrams.
        val prefixLength = 4 + rawAddress.size + 2
        val result = ByteArray(prefixLength + length)
        result[3] = addressType.toByte() // RSV and FRAG are already zero.
        rawAddress.copyInto(result, destinationOffset = 4)
        val portOffset = 4 + rawAddress.size
        result[portOffset] = (port ushr 8).toByte()
        result[portOffset + 1] = port.toByte()
        payload.copyInto(result, destinationOffset = prefixLength, startIndex = offset, endIndex = offset + length)
        return result
    }

    /** Default failures retain the existing bound endpoint 127.0.0.1:0, not 0.0.0.0:0. */
    fun encodeReply(reply: Int, address: InetAddress = defaultBoundAddress, port: Int = 0): ByteArray =
        ByteArrayOutputStream().apply {
            write(SOCKS_VERSION)
            write(reply)
            write(0)
            writeDestination(SocksDestination.Ip(address))
            writePort(port)
        }.toByteArray()

    fun replyForGatewayRefusal(code: String): Int = when (code) {
        "NETWORK_CHANGED" -> REPLY_NETWORK_UNREACHABLE
        "IO_ERROR" -> REPLY_HOST_UNREACHABLE
        else -> REPLY_GENERAL_FAILURE
    }

    fun requireVersion(version: Int) {
        if (version != SOCKS_VERSION) throw IOException("Unsupported SOCKS version.")
    }

    /** Fixed wire sizes only. The caller separately reads the one-octet domain length. */
    fun ipAddressLength(addressType: Int): Int = when (addressType) {
        ADDRESS_TYPE_IPV4 -> 4
        ADDRESS_TYPE_IPV6 -> 16
        else -> throw IOException("Unsupported SOCKS address type.")
    }

    fun requireDomainLength(length: Int) {
        if (length == 0) throw IOException("Empty SOCKS domain name.")
    }

    private fun ByteArrayOutputStream.writeDestination(destination: SocksDestination) {
        when (destination) {
            is SocksDestination.Ip -> {
                val rawAddress = destination.address.address
                write(when (rawAddress.size) {
                    4 -> ADDRESS_TYPE_IPV4
                    16 -> ADDRESS_TYPE_IPV6
                    else -> throw IOException("Unsupported bound address.")
                })
                write(rawAddress)
            }
            is SocksDestination.Domain -> {
                val name = destination.name.toByteArray(StandardCharsets.US_ASCII)
                require(name.size in 1..255) { "SOCKS domain must fit one nonzero length octet." }
                write(ADDRESS_TYPE_DOMAIN)
                write(name.size)
                write(name)
            }
        }
    }

    private fun ByteArrayOutputStream.writePort(port: Int) {
        write((port ushr 8) and 0xff)
        write(port and 0xff)
    }

    private fun requireSlice(bytes: ByteArray, offset: Int, length: Int) {
        require(offset >= 0 && length >= 0 && offset <= bytes.size && length <= bytes.size - offset) {
            "Invalid SOCKS wire slice."
        }
    }

    private class Cursor(private val bytes: ByteArray, offset: Int, length: Int) {
        init {
            requireSlice(bytes, offset, length)
        }

        private val end = offset + length
        var position: Int = offset
            private set
        val remaining: Int get() = end - position

        fun readByte(): Int {
            if (remaining < 1) throw EOFException()
            return bytes[position++].toInt() and 0xff
        }

        fun readBytes(length: Int): ByteArray {
            if (remaining < length) throw EOFException()
            return bytes.copyOfRange(position, position + length).also { position += length }
        }

        fun readPort(): Int = (readByte() shl 8) or readByte()

        fun readDestination(addressType: Int): SocksDestination = when (addressType) {
            ADDRESS_TYPE_DOMAIN -> {
                val length = readByte()
                requireDomainLength(length)
                SocksDestination.Domain(readBytes(length).toString(StandardCharsets.US_ASCII))
            }
            else -> SocksDestination.Ip(InetAddress.getByAddress(readBytes(ipAddressLength(addressType))))
        }
    }
}
