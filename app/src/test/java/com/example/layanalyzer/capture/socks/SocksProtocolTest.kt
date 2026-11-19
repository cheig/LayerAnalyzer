// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksUdpRequest
import java.io.EOFException
import java.io.IOException
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SocksProtocolTest {
    private val ipv4 = SocksDestination.Ip(InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 1)))
    private val ipv6Bytes = byteArrayOf(0x20, 1, 0x0d, 0xb8.toByte()) + ByteArray(11) + byteArrayOf(1)
    private val ipv6 = SocksDestination.Ip(InetAddress.getByAddress(ipv6Bytes))
    // Deliberately not a resolvable address. The protocol must leave the exact name alone.
    private val domain = SocksDestination.Domain("Do-Not-Resolve.example.invalid")
    private val payload = byteArrayOf(0, 1, 2, 0xff.toByte())

    @Test
    fun requestCodecMatchesIpv4Ipv6AndDomainWireBytes() {
        val destinations = listOf(
            ipv4 to (byteArrayOf(1) + ipv4.address.address),
            ipv6 to (byteArrayOf(4) + ipv6Bytes),
            domain to (byteArrayOf(3, domain.name.length.toByte()) + ascii(domain.name))
        )
        for ((destination, addressWire) in destinations) {
            for (port in listOf(0, 443, 65535)) {
                for (command in listOf(1, 3, 2, 0xff)) {
                    val expected = byteArrayOf(5, command.toByte(), 0) + addressWire + portBytes(port)
                    val request = SocksRequest(command, destination, port)
                    assertArrayEquals(expected, SocksProtocol.encodeRequest(request))
                    val decoded = SocksProtocol.decodeRequest(expected)
                    assertEquals(request, decoded.request)
                    assertEquals(expected.size, decoded.bytesConsumed)
                }
            }
        }
    }

    @Test
    fun decodingOneRequestReportsItsLengthWithoutConsumingPipelinedPayload() {
        val request = SocksRequest(1, domain, 443)
        val frame = SocksProtocol.encodeRequest(request)
        val bytes = byteArrayOf(99, 98) + frame + payload + byteArrayOf(97)
        val decoded = SocksProtocol.decodeRequest(bytes, 2, frame.size + payload.size)
        assertEquals(request, decoded.request)
        assertEquals(frame.size, decoded.bytesConsumed)
        assertArrayEquals(payload, bytes.copyOfRange(2 + decoded.bytesConsumed, bytes.size - 1))
    }

    @Test
    fun theExistingReservedByteToleranceAndUnknownCommandSurviveDecoding() {
        val wire = byteArrayOf(5, 0x7f, 0x55, 1) + ipv4.address.address + portBytes(65535)
        assertEquals(SocksRequest(0x7f, ipv4, 65535), SocksProtocol.decodeRequest(wire).request)
    }

    @Test
    fun everyTruncatedRequestHeaderAddressOrPortThrowsEof() {
        for (destination in listOf(ipv4, ipv6, domain, SocksDestination.Domain("x".repeat(255)))) {
            val frame = SocksProtocol.encodeRequest(SocksRequest(1, destination, 65535))
            for (length in 0 until frame.size) {
                assertThrows("$destination length=$length", EOFException::class.java) {
                    SocksProtocol.decodeRequest(frame, length = length)
                }
            }
        }
    }

    @Test
    fun invalidVersionAddressTypeAndEmptyDomainKeepTheirIoErrors() {
        val cases = listOf(
            byteArrayOf(4) to "Unsupported SOCKS version.",
            byteArrayOf(5, 1, 0, 2) to "Unsupported SOCKS address type.",
            byteArrayOf(5, 1, 0, 3, 0) to "Empty SOCKS domain name."
        )
        for ((frame, message) in cases) {
            assertEquals(message, assertThrows(IOException::class.java) {
                SocksProtocol.decodeRequest(frame)
            }.message)
        }
    }

    @Test
    fun aDomainUsesExactlyOneUnsignedLengthOctetAndAsciiDecoding() {
        val name = "a".repeat(255)
        val request = SocksRequest(3, SocksDestination.Domain(name), 0)
        val encoded = SocksProtocol.encodeRequest(request)
        assertEquals(0xff, encoded[4].toInt() and 0xff)
        assertEquals(request, SocksProtocol.decodeRequest(encoded).request)
        val raw = byteArrayOf(5, 1, 0, 3, 1, 0xff.toByte(), 0, 53)
        assertEquals(
            SocksDestination.Domain(byteArrayOf(0xff.toByte()).toString(StandardCharsets.US_ASCII)),
            SocksProtocol.decodeRequest(raw).request.destination
        )
        for (invalid in listOf("", "x".repeat(256))) {
            assertThrows(IllegalArgumentException::class.java) {
                SocksProtocol.encodeRequest(SocksRequest(1, SocksDestination.Domain(invalid), 80))
            }
        }
    }

    @Test
    fun methodSelectionAlwaysRequiresRfc1929AndRejectsOtherVersionsSilently() {
        assertEquals(2, SocksProtocol.selectAuthenticationMethod(5, byteArrayOf(0, 1, 2, 0xff.toByte())))
        assertEquals(0xff, SocksProtocol.selectAuthenticationMethod(5, byteArrayOf(0)))
        assertEquals(0xff, SocksProtocol.selectAuthenticationMethod(5, byteArrayOf()))
        assertNull(SocksProtocol.selectAuthenticationMethod(4, byteArrayOf(2)))
        assertArrayEquals(byteArrayOf(5, 2), SocksProtocol.encodeMethodSelection(2))
        assertArrayEquals(byteArrayOf(5, 0xff.toByte()), SocksProtocol.encodeMethodSelection(0xff))
    }

    @Test
    fun authenticationVerdictsAndReplyBytesRequireBothLiveCredentials() {
        val credentials = SocksCredentials.of("Username1", "Password2")
        val username = ascii(credentials.username)
        val password = ascii(credentials.password)
        assertTrue(SocksProtocol.authenticationAccepted(1, username, password, credentials))
        assertFalse(SocksProtocol.authenticationAccepted(2, username, password, credentials))
        assertFalse(SocksProtocol.authenticationAccepted(1, byteArrayOf(), password, credentials))
        assertFalse(SocksProtocol.authenticationAccepted(1, username, byteArrayOf(), credentials))
        assertFalse(SocksProtocol.authenticationAccepted(1, ascii("Username2"), password, credentials))
        assertFalse(SocksProtocol.authenticationAccepted(1, username, ascii("Password1"), credentials))
        assertFalse(SocksProtocol.authenticationAccepted(1, username, password, null))
        credentials.discard()
        assertFalse(SocksProtocol.authenticationAccepted(1, username, password, credentials))
        assertArrayEquals(byteArrayOf(1, 0), SocksProtocol.encodeAuthenticationReply(true))
        assertArrayEquals(byteArrayOf(1, 1), SocksProtocol.encodeAuthenticationReply(false))
    }

    @Test
    fun repliesMatchTheOldLoopbackDefaultAndIpv6BoundEndpoint() {
        for (reply in listOf(0, 1, 3, 4, 7)) {
            assertArrayEquals(
                byteArrayOf(5, reply.toByte(), 0, 1, 127, 0, 0, 1, 0, 0),
                SocksProtocol.encodeReply(reply)
            )
        }
        assertArrayEquals(
            byteArrayOf(5, 0, 0, 4) + ipv6Bytes + portBytes(65535),
            SocksProtocol.encodeReply(0, ipv6.address, 65535)
        )
    }

    @Test
    fun gatewayRefusalsKeepTheFixedErrorMappingWithoutChangingDispatch() {
        assertEquals(3, SocksProtocol.replyForGatewayRefusal("NETWORK_CHANGED"))
        assertEquals(4, SocksProtocol.replyForGatewayRefusal("IO_ERROR"))
        for (code in listOf("CAPACITY", "CONTEXT_MISMATCH", "NOT_READY", "", "future-code")) {
            assertEquals(1, SocksProtocol.replyForGatewayRefusal(code))
        }
    }

    @Test
    fun udpCodecMatchesIpv4Ipv6AndDomainFramingIncludingZeroAndMaxPorts() {
        for (destination in listOf(ipv4, ipv6, domain, SocksDestination.Domain("x".repeat(255)))) {
            for (port in listOf(0, 53, 65535)) {
                val request = SocksUdpRequest(destination, port, payload)
                val tcp = SocksProtocol.encodeRequest(SocksRequest(1, destination, port))
                val expected = byteArrayOf(0, 0, 0) + tcp.copyOfRange(3, tcp.size) + payload
                assertArrayEquals(expected, SocksProtocol.encodeUdpRequest(request))
                val decoded = SocksProtocol.decodeUdpRequest(expected)!!
                assertEquals(destination, decoded.destination)
                assertEquals(port, decoded.port)
                assertArrayEquals(payload, decoded.payload)
            }
        }
    }

    @Test
    fun udpUsesOnlyItsDeclaredSliceAndCopiesThePayload() {
        val frame = SocksProtocol.encodeUdpRequest(SocksUdpRequest(domain, 443, payload))
        val storage = byteArrayOf(99, 98) + frame + byteArrayOf(97)
        val decoded = SocksProtocol.decodeUdpRequest(storage, 2, frame.size)!!
        assertEquals(domain, decoded.destination)
        assertEquals(443, decoded.port)
        storage.fill(0)
        assertArrayEquals(payload, decoded.payload)
    }

    @Test
    fun udpDropsEveryShortHeaderAndAllowsAnEmptyPayload() {
        for (destination in listOf(ipv4, ipv6, domain, SocksDestination.Domain("x".repeat(255)))) {
            val header = SocksProtocol.encodeUdpRequest(SocksUdpRequest(destination, 53, byteArrayOf()))
            for (length in 0 until header.size) {
                assertNull("$destination length=$length", SocksProtocol.decodeUdpRequest(header, length = length))
            }
            val decoded = SocksProtocol.decodeUdpRequest(header)!!
            assertEquals(destination, decoded.destination)
            assertArrayEquals(byteArrayOf(), decoded.payload)
        }
    }

    @Test
    fun udpDropsEveryNonzeroFragReservedByteUnknownAddressTypeAndEmptyDomain() {
        val frame = SocksProtocol.encodeUdpRequest(SocksUdpRequest(ipv4, 53, payload))
        for (position in 0..2) {
            for (value in 1..255) {
                assertNull(SocksProtocol.decodeUdpRequest(frame.copyOf().also { it[position] = value.toByte() }))
            }
        }
        assertNull(SocksProtocol.decodeUdpRequest(frame.copyOf().also { it[3] = 2 }))
        assertNull(SocksProtocol.decodeUdpRequest(byteArrayOf(0, 0, 0, 3, 0, 0, 53)))
    }

    @Test
    fun udpResponseUsesOnlyThePacketPayloadSliceAndTheLiteralSourceAddress() {
        for ((destination, raw) in listOf(ipv4 to ipv4.address.address, ipv6 to ipv6Bytes)) {
            val expected = byteArrayOf(0, 0, 0, (if (raw.size == 4) 1 else 4).toByte()) +
                raw + portBytes(65535) + payload
            val storage = byteArrayOf(99) + payload + byteArrayOf(98)
            assertArrayEquals(expected, SocksProtocol.encodeUdpResponse(destination.address, 65535, storage, 1, payload.size))
        }
    }

    @Test
    fun codecDoesNotAddAnArtificialSmallDatagramLimit() {
        // Existing receive buffers are 65,535 bytes; actual sendability remains the socket's job.
        val maximumFramePayload = ByteArray(65_535 - 10) { it.toByte() }
        val frame = SocksProtocol.encodeUdpRequest(SocksUdpRequest(ipv4, 53, maximumFramePayload))
        assertEquals(65_535, frame.size)
        assertArrayEquals(maximumFramePayload, SocksProtocol.decodeUdpRequest(frame)!!.payload)
        assertEquals(65_535, SocksProtocol.encodeUdpResponse(ipv4.address, 53, maximumFramePayload).size)
    }

    @Test
    fun ipv4MappedIpv6DecodingPreservesTheOriginalInetAddressNormalization() {
        val mapped = ByteArray(10) + byteArrayOf(0xff.toByte(), 0xff.toByte()) + ipv4.address.address
        val frame = byteArrayOf(5, 1, 0, 4) + mapped + portBytes(80)
        assertEquals(ipv4, SocksProtocol.decodeRequest(frame).request.destination)
        assertEquals(ipv4, SocksProtocol.decodeUdpRequest(byteArrayOf(0, 0, 0) + frame.copyOfRange(3, frame.size))!!.destination)
    }

    @Test
    fun invalidCallerSlicesFailWithoutReadingOutsideTheBuffer() {
        val bytes = ByteArray(10)
        for ((offset, length) in listOf(-1 to 1, 0 to -1, 11 to 0, 2 to 9, 1 to Int.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { SocksProtocol.decodeRequest(bytes, offset, length) }
            assertThrows(IllegalArgumentException::class.java) { SocksProtocol.decodeUdpRequest(bytes, offset, length) }
            assertThrows(IllegalArgumentException::class.java) {
                SocksProtocol.encodeUdpResponse(ipv4.address, 53, bytes, offset, length)
            }
        }
    }

    private fun ascii(value: String): ByteArray = value.toByteArray(StandardCharsets.US_ASCII)
    private fun portBytes(port: Int): ByteArray = byteArrayOf((port ushr 8).toByte(), port.toByte())
}
