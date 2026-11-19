// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Real NIO server integration: parsing must not move resolution/dispatch into the codec. */
class SocksProtocolServerTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val payload = byteArrayOf(11, 12, 13, 14)
    private val ipv6 = InetAddress.getByAddress(ByteArray(15) + byteArrayOf(1))
    private val domain = SocksDestination.Domain("Unresolved.example.invalid")

    @Test
    fun realServerReusesTheCodecForAllAddressTypesAndKeepsPipelinedDirectPayload() {
        val destinations = listOf(SocksDestination.Ip(loopback), SocksDestination.Ip(ipv6), domain)
        for (destination in destinations) {
            val worker = Executors.newSingleThreadExecutor()
            try {
                ServerSocket(0, 1, (destination as? SocksDestination.Ip)?.address ?: loopback).use { origin ->
                    origin.soTimeout = TIMEOUT_MILLIS
                    val delivered = worker.submit<ByteArray> {
                        origin.accept().use { peer ->
                            peer.soTimeout = TIMEOUT_MILLIS
                            val received = ByteArray(payload.size)
                            DataInputStream(peer.getInputStream()).readFully(received)
                            peer.getOutputStream().write(received.reversedArray())
                            received
                        }
                    }
                    val resolved = CopyOnWriteArrayList<String>()
                    DirectSocks5Server({}, {}, { name -> resolved += name; arrayOf(loopback) }).use { socks ->
                        val port = socks.start()
                        Socket(loopback, port).use { client ->
                            client.soTimeout = TIMEOUT_MILLIS
                            val output = DataOutputStream(client.getOutputStream())
                            val input = DataInputStream(client.getInputStream())
                            // All protocol frames plus application bytes in one client write.
                            output.write(authFrames(socks.credentials) +
                                SocksProtocol.encodeRequest(SocksRequest(1, destination, origin.localPort)) + payload)
                            output.flush()
                            assertAuthenticated(input)
                            val reply = readReply(input)
                            assertEquals(0, reply.command)
                            assertEquals(SocksDestination.Ip(origin.inetAddress), reply.destination)
                            assertTrue(reply.port > 0)
                            val echoed = ByteArray(payload.size)
                            input.readFully(echoed)
                            assertArrayEquals(payload.reversedArray(), echoed)
                        }
                    }
                    assertArrayEquals(payload, delivered.get(TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS))
                    assertEquals(if (destination is SocksDestination.Domain) listOf(destination.name.lowercase(java.util.Locale.ROOT)) else emptyList<String>(), resolved.toList())
                }
            } finally {
                worker.shutdownNow()
            }
        }
    }

    @Test
    fun domainResolutionUsesTheBoundedResolverAndNormalizesItsDnsKey() {
        val worker = Executors.newSingleThreadExecutor()
        try {
            ServerSocket(0, 1, loopback).use { origin ->
                origin.soTimeout = TIMEOUT_MILLIS
                val accepted = worker.submit {
                    origin.accept().use { peer ->
                        peer.soTimeout = TIMEOUT_MILLIS
                        assertEquals(11, peer.getInputStream().read())
                    }
                }
                val resolved = CopyOnWriteArrayList<String>()
                val prepared = CopyOnWriteArrayList<Socket>()
                DirectSocks5Server(
                    prepareTcp = { prepared += it },
                    prepareUdp = {},
                    resolveHost = { name -> resolved += name; arrayOf(loopback) },
                    ).use { socks ->
                    Socket(loopback, socks.start()).use { client ->
                        client.soTimeout = TIMEOUT_MILLIS
                        val output = DataOutputStream(client.getOutputStream())
                        val input = DataInputStream(client.getInputStream())
                        output.write(authFrames(socks.credentials) +
                            SocksProtocol.encodeRequest(SocksRequest(1, domain, origin.localPort)) + byteArrayOf(11))
                        output.flush()
                        assertAuthenticated(input)
                        assertEquals(0, readReply(input).command)
                        // Keep the relay alive until the pipelined byte reaches the origin.
                        accepted.get(TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)
                    }
                }
                assertEquals(listOf(domain.name.lowercase(java.util.Locale.ROOT)), resolved.toList())
                assertEquals(1, prepared.size)
            }
        } finally {
            worker.shutdownNow()
        }
    }

    @Test
    fun unsupportedCommandsStillReplySevenBeforeDnsDialOrSessionAdmission() {
        server().use { socks ->
            val port = socks.start()
            Socket(loopback, port).use { client ->
                client.soTimeout = TIMEOUT_MILLIS
                val output = DataOutputStream(client.getOutputStream())
                val input = DataInputStream(client.getInputStream())
                output.write(authFrames(socks.credentials) + SocksProtocol.encodeRequest(SocksRequest(2, domain, 443)))
                output.flush()
                assertAuthenticated(input)
                assertEquals(SocksRequest(7, SocksDestination.Ip(loopback), 0), readReply(input))
                assertEquals(-1, input.read())
                assertEquals(0, socks.sessionStats().tcp.current)
                assertEquals(0, socks.sessionStats().udp.current)
            }
        }
    }

    @Test
    fun malformedRequestsStillCloseWithoutInventingAnAddressTypeFailureReply() {
        for (frame in listOf(byteArrayOf(4), byteArrayOf(5, 1, 0, 2), byteArrayOf(5, 1, 0, 3, 0))) {
            server().use { socks ->
                Socket(loopback, socks.start()).use { client ->
                    client.soTimeout = TIMEOUT_MILLIS
                    val output = DataOutputStream(client.getOutputStream())
                    val input = DataInputStream(client.getInputStream())
                    output.write(authFrames(socks.credentials) + frame)
                    output.flush()
                    assertAuthenticated(input)
                    assertEquals(-1, input.read())
                }
            }
        }
    }

    private fun server(): DirectSocks5Server = DirectSocks5Server(
        prepareTcp = { error("unexpected direct socket preparation") },
        prepareUdp = { error("unexpected UDP preparation") },
        resolveHost = { error("unexpected DNS resolution") },
        )

    private fun authFrames(credentials: SocksCredentials): ByteArray {
        val username = credentials.username.toByteArray(StandardCharsets.US_ASCII)
        val password = credentials.password.toByteArray(StandardCharsets.US_ASCII)
        return byteArrayOf(5, 2, 0, 2, 1, username.size.toByte()) +
            username + byteArrayOf(password.size.toByte()) + password
    }

    private fun assertAuthenticated(input: DataInputStream) {
        val reply = ByteArray(4)
        input.readFully(reply)
        assertArrayEquals(byteArrayOf(5, 2, 1, 0), reply)
    }

    private fun readReply(input: DataInputStream): SocksRequest {
        val bytes = java.io.ByteArrayOutputStream()
        repeat(4) { bytes.write(input.readUnsignedByte()) }
        val addressType = bytes.toByteArray()[3].toInt() and 0xff
        repeat((if (addressType == 1) 4 else 16) + 2) { bytes.write(input.readUnsignedByte()) }
        return SocksProtocol.decodeRequest(bytes.toByteArray()).request
    }

    private companion object {
        const val TIMEOUT_MILLIS = 5_000
    }
}
