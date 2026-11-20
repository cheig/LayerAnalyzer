// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * TLS-214: the loopback SOCKS5 hop authenticates every session with its own
 * RFC 1929 username/password pair, and the same pair is the only credential the
 * HEV document carries.
 *
 * These cases drive the real [DirectSocks5Server] over real loopback sockets
 * with real upstream channels, so the greeting, the sub-negotiation, the
 * CONNECT and the UDP relay framing are all produced and parsed by production
 * code. Nothing here claims a TUN capture, a device or a decrypted payload;
 * `LiveCaptureForwardingTest` owns the HEV side.
 *
 * The suite deliberately never makes the server log an upstream failure:
 * `android.util.Log` is a not-mocked stub on the JVM, so a rejected client is
 * asserted through its wire reply and through the socket preparation counters.
 */
class SocksAuthenticationTest {
    private val loopback: InetAddress = InetAddress.getByName("127.0.0.1")
    private val payload = ByteArray(64) { (it * 7 + 1).toByte() }

    private fun server(
        credentials: SocksCredentials? = null,
        prepareUdp: (DatagramSocket) -> Unit = {},
        prepareTcp: (Socket) -> Unit = {}
    ): DirectSocks5Server = DirectSocks5Server(
        prepareTcp = prepareTcp,
        prepareUdp = prepareUdp,
        resolveHost = { arrayOf(InetAddress.getByName(it)) },
        generateCredentials = credentials?.let { fixed -> { fixed } } ?: { SocksCredentials.generate() }
    )

    @Test
    fun `tcp connect is reachable with the session credentials`() {
        val worker = Executors.newSingleThreadExecutor()
        try {
            ServerSocket(0, 1, loopback).use { origin ->
                val delivered = worker.submit<ByteArray> {
                    origin.accept().use { peer ->
                        val received = ByteArray(payload.size)
                        DataInputStream(peer.getInputStream()).readFully(received)
                        peer.getOutputStream().write(received.reversedArray())
                        received
                    }
                }

                server().use { socks ->
                    val port = socks.start()
                    Socket(loopback, port).use { client ->
                        client.soTimeout = TIMEOUT_MILLIS
                        val output = DataOutputStream(client.getOutputStream())
                        val input = DataInputStream(client.getInputStream())

                        assertEquals(METHOD_USERNAME_PASSWORD, greet(output, input, intArrayOf(0, 2)))
                        assertEquals(AUTH_SUCCESS, authenticate(output, input, socks.credentials))

                        output.write(connectRequest(origin.localPort))
                        output.flush()
                        assertEquals(REPLY_SUCCEEDED, readReply(input).reply)

                        output.write(payload)
                        output.flush()
                        val echoed = ByteArray(payload.size)
                        input.readFully(echoed)
                        assertArrayEquals(payload.reversedArray(), echoed)
                    }
                }

                assertArrayEquals(payload, delivered.get(TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS))
            }
        } finally {
            worker.shutdownNow()
        }
    }

    @Test
    fun `udp associate relays datagrams with the session credentials`() {
        val worker = Executors.newSingleThreadExecutor()
        try {
            DatagramSocket(InetSocketAddress(loopback, 0)).use { origin ->
                val delivered = worker.submit<ByteArray> {
                    val buffer = ByteArray(MAX_DATAGRAM)
                    val request = DatagramPacket(buffer, buffer.size)
                    origin.soTimeout = TIMEOUT_MILLIS
                    origin.receive(request)
                    val datagram = buffer.copyOfRange(request.offset, request.offset + request.length)
                    origin.send(
                        DatagramPacket(
                            datagram.reversedArray(),
                            datagram.size,
                            request.address,
                            request.port
                        )
                    )
                    datagram
                }

                server().use { socks ->
                    val port = socks.start()
                    Socket(loopback, port).use { control ->
                        control.soTimeout = TIMEOUT_MILLIS
                        val output = DataOutputStream(control.getOutputStream())
                        val input = DataInputStream(control.getInputStream())

                        assertEquals(METHOD_USERNAME_PASSWORD, greet(output, input, intArrayOf(METHOD_USERNAME_PASSWORD)))
                        assertEquals(AUTH_SUCCESS, authenticate(output, input, socks.credentials))

                        output.write(udpAssociateRequest())
                        output.flush()
                        val association = readReply(input)
                        assertEquals(REPLY_SUCCEEDED, association.reply)

                        DatagramSocket().use { client ->
                            client.soTimeout = TIMEOUT_MILLIS
                            val framed = datagramHeader(origin.localPort) + payload
                            client.send(
                                DatagramPacket(
                                    framed,
                                    framed.size,
                                    InetSocketAddress(loopback, association.port)
                                )
                            )
                            val buffer = ByteArray(MAX_DATAGRAM)
                            val response = DatagramPacket(buffer, buffer.size)
                            client.receive(response)
                            assertArrayEquals(
                                payload.reversedArray(),
                                buffer.copyOfRange(UDP_HEADER_IPV4, response.length)
                            )
                        }
                    }
                }

                assertArrayEquals(payload, delivered.get(TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS))
            }
        } finally {
            worker.shutdownNow()
        }
    }

    @Test
    fun `a greeting without the username password method is refused before any request`() {
        val udpPreparations = AtomicInteger()
        server(prepareUdp = { udpPreparations.incrementAndGet() }).use { socks ->
            val port = socks.start()
            for (methods in listOf(intArrayOf(0), intArrayOf(), intArrayOf(0, 1))) {
                Socket(loopback, port).use { client ->
                    client.soTimeout = TIMEOUT_MILLIS
                    val output = DataOutputStream(client.getOutputStream())
                    val input = DataInputStream(client.getInputStream())

                    // The UDP ASSOCIATE request is pipelined behind the greeting:
                    // an unauthenticated session must never have it parsed, so no
                    // association may be created from the bytes already on the wire.
                    output.write(greeting(methods) + udpAssociateRequest())
                    output.flush()

                    assertEquals(5, input.readUnsignedByte())
                    assertEquals(AUTH_NO_ACCEPTABLE, input.readUnsignedByte())
                }
            }
            assertEquals("no UDP association may follow a refused greeting", 0, udpPreparations.get())
        }
    }

    @Test
    fun `wrong credentials are refused before any upstream connection`() {
        val attempts = AtomicInteger()
        val udpPreparations = AtomicInteger()
        val credentials = SocksCredentials.of("CorrectedUsername", "CorrectedPasswordValue")
        server(
            credentials = credentials,
            prepareUdp = { udpPreparations.incrementAndGet() },
            prepareTcp = { _ ->
                attempts.incrementAndGet()
            }
        ).use { socks ->
            val port = socks.start()
            val wrongPairs = listOf(
                "RejectedUsername" to credentials.password,
                credentials.username to "RejectedPasswordValue",
                credentials.username + "1" to credentials.password,
                credentials.username.dropLast(1) to credentials.password
            )
            for ((username, password) in wrongPairs) {
                Socket(loopback, port).use { client ->
                    client.soTimeout = TIMEOUT_MILLIS
                    val output = DataOutputStream(client.getOutputStream())
                    val input = DataInputStream(client.getInputStream())

                    assertEquals(METHOD_USERNAME_PASSWORD, greet(output, input, intArrayOf(0, 2)))
                    assertEquals(
                        "rejected pair $username/$password must fail the sub-negotiation",
                        AUTH_FAILURE,
                        authenticate(output, input, username, password)
                    )
                    assertEquals("a refused connection must be closed", -1, input.read())
                }
            }

            assertEquals("a refused peer must not reach the upstream connect", 0, attempts.get())
            assertEquals("a refused peer must not open a UDP association", 0, udpPreparations.get())
        }
    }

    @Test
    fun `malformed authentication is refused with a failure reply`() {
        server().use { socks ->
            val port = socks.start()
            // A version other than RFC 1929's 1.
            assertSubNegotiationRefused(port) { output ->
                output.writeByte(2)
                output.writeByte(3)
                output.write("abc".toByteArray(StandardCharsets.US_ASCII))
                output.writeByte(3)
                output.write("abc".toByteArray(StandardCharsets.US_ASCII))
            }
            // A zero-length username, which RFC 1929 does not allow.
            assertSubNegotiationRefused(port) { output ->
                output.writeByte(1)
                output.writeByte(0)
                output.writeByte(3)
                output.write("abc".toByteArray(StandardCharsets.US_ASCII))
            }
            // A zero-length password.
            assertSubNegotiationRefused(port) { output ->
                output.writeByte(1)
                output.writeByte(3)
                output.write("abc".toByteArray(StandardCharsets.US_ASCII))
                output.writeByte(0)
            }
        }
    }

    @Test
    fun `a truncated authentication request is closed without a reply`() {
        server().use { socks ->
            val port = socks.start()
            Socket(loopback, port).use { client ->
                client.soTimeout = TIMEOUT_MILLIS
                val output = DataOutputStream(client.getOutputStream())
                val input = DataInputStream(client.getInputStream())

                assertEquals(METHOD_USERNAME_PASSWORD, greet(output, input, intArrayOf(METHOD_USERNAME_PASSWORD)))
                output.writeByte(1)
                output.writeByte(32) // Promises 32 username bytes, delivers five.
                output.write("short".toByteArray(StandardCharsets.US_ASCII))
                output.flush()
                client.shutdownOutput()

                assertEquals("a half-request must not be answered", -1, input.read())
            }
        }
    }

    @Test
    fun `stopping a session discards its credentials and the next session replaces them`() {
        val first = SocksCredentials.of("FirstSessionUser", "FirstSessionPasswordValue")
        val firstServer = server(credentials = first)
        firstServer.start()
        assertTrue(first.matches(ascii(first.username), ascii(first.password)))
        firstServer.close()
        assertFalse(
            "a stopped session's pair must not match anything",
            first.matches(ascii(first.username), ascii(first.password))
        )
        assertThrows(IllegalStateException::class.java) { firstServer.credentials }

        val second = SocksCredentials.of("SecondSessionUsr", "SecondSessionPasswordValue")
        server(credentials = second).use { secondServer ->
            val port = secondServer.start()
            Socket(loopback, port).use { client ->
                client.soTimeout = TIMEOUT_MILLIS
                val output = DataOutputStream(client.getOutputStream())
                val input = DataInputStream(client.getInputStream())

                assertEquals(METHOD_USERNAME_PASSWORD, greet(output, input, intArrayOf(METHOD_USERNAME_PASSWORD)))
                assertEquals(
                    "the previous session's pair must not survive a restart",
                    AUTH_FAILURE,
                    authenticate(output, input, first.username, first.password)
                )
            }
            Socket(loopback, port).use { client ->
                client.soTimeout = TIMEOUT_MILLIS
                val output = DataOutputStream(client.getOutputStream())
                val input = DataInputStream(client.getInputStream())

                assertEquals(METHOD_USERNAME_PASSWORD, greet(output, input, intArrayOf(METHOD_USERNAME_PASSWORD)))
                assertEquals(AUTH_SUCCESS, authenticate(output, input, second.username, second.password))
            }
        }
    }

    @Test
    fun `generated credentials stay inside the YAML-safe alphabet`() {
        val seen = mutableSetOf<String>()
        repeat(GENERATED_SAMPLES) {
            val credentials = SocksCredentials.generate()
            assertEquals(SocksCredentials.USERNAME_LENGTH, credentials.username.length)
            assertEquals(SocksCredentials.PASSWORD_LENGTH, credentials.password.length)
            for (value in listOf(credentials.username, credentials.password)) {
                assertTrue(
                    "'$value' must only contain characters YAML never has to quote",
                    value.all { it in '0'..'9' || it in 'A'..'Z' || it in 'a'..'z' }
                )
            }
            assertNotEquals(credentials.username, credentials.password)
            assertTrue(seen.add(credentials.username + credentials.password))
        }
        // 255 characters still fit RFC 1929's single length octet and HEV's copy.
        val longest = SocksCredentials.of("a".repeat(255), "b")
        assertEquals(255, longest.username.length)
    }

    @Test
    fun `credentials reject values that would break the HEV document`() {
        val unsafe = listOf(
            "",
            "has space",
            "quo'te",
            "double\"quote",
            "colon:here",
            "hash#here",
            "new\nline",
            "标点",
            "-leading-dash"
        )
        for (value in unsafe) {
            assertThrows(IllegalArgumentException::class.java) {
                SocksCredentials.of(value, "ValidPasswordValue")
            }
            assertThrows(IllegalArgumentException::class.java) {
                SocksCredentials.of("ValidUsername", value)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            SocksCredentials.of("a".repeat(256), "ValidPasswordValue")
        }
    }

    @Test
    fun `credentials never render their own secret`() {
        val credentials = SocksCredentials.of("RenderingUsername", "RenderingSecretValue")
        val rendered = credentials.toString()
        assertFalse("the username must not be rendered", rendered.contains(credentials.username))
        assertFalse("the password must not be rendered", rendered.contains(credentials.password))
    }

    @Test
    fun `the HEV document carries both halves of the session credentials`() {
        val credentials = SocksCredentials.of("HevUsernameValue1", "HevPasswordValue1")
        val config = LiveCaptureVpnService.buildTun2SocksConfig(
            socksServerPort = SOCKS_PORT,
            credentials = credentials
        )

        assertTrue(
            "the credentials must be set together inside the socks5 block",
            config.contains(
                """
                socks5:
                  address: '127.0.0.1'
                  port: $SOCKS_PORT
                  udp: 'udp'
                  username: '${credentials.username}'
                  password: '${credentials.password}'
                """.trimIndent()
            )
        )
        assertEquals("exactly one username key", 1, config.lines().count { it.trimStart().startsWith("username:") })
        assertEquals("exactly one password key", 1, config.lines().count { it.trimStart().startsWith("password:") })
    }

    private fun assertSubNegotiationRefused(port: Int, body: (DataOutputStream) -> Unit) {
        Socket(loopback, port).use { client ->
            client.soTimeout = TIMEOUT_MILLIS
            val output = DataOutputStream(client.getOutputStream())
            val input = DataInputStream(client.getInputStream())

            assertEquals(METHOD_USERNAME_PASSWORD, greet(output, input, intArrayOf(METHOD_USERNAME_PASSWORD)))
            body(output)
            output.flush()

            assertEquals(1, input.readUnsignedByte())
            assertEquals(AUTH_FAILURE, input.readUnsignedByte())
            assertEquals("a refused connection must be closed", -1, input.read())
        }
    }

    private fun greet(output: DataOutputStream, input: DataInputStream, methods: IntArray): Int {
        output.write(greeting(methods))
        output.flush()
        assertEquals(5, input.readUnsignedByte())
        return input.readUnsignedByte()
    }

    private fun authenticate(
        output: DataOutputStream,
        input: DataInputStream,
        credentials: SocksCredentials
    ): Int = authenticate(output, input, credentials.username, credentials.password)

    private fun authenticate(
        output: DataOutputStream,
        input: DataInputStream,
        username: String,
        password: String
    ): Int {
        val user = ascii(username)
        val secret = ascii(password)
        output.writeByte(1)
        output.writeByte(user.size)
        output.write(user)
        output.writeByte(secret.size)
        output.write(secret)
        output.flush()
        assertEquals(1, input.readUnsignedByte())
        return input.readUnsignedByte()
    }

    private fun readReply(input: DataInputStream): SocksReply {
        assertEquals(5, input.readUnsignedByte())
        val reply = input.readUnsignedByte()
        input.readUnsignedByte() // Reserved.
        val address = when (val addressType = input.readUnsignedByte()) {
            ADDRESS_TYPE_IPV4 -> InetAddress.getByAddress(ByteArray(4).also(input::readFully))
            ADDRESS_TYPE_IPV6 -> InetAddress.getByAddress(ByteArray(16).also(input::readFully))
            else -> throw AssertionError("Unexpected reply address type $addressType")
        }
        val port = (input.readUnsignedByte() shl 8) or input.readUnsignedByte()
        return SocksReply(reply, address, port)
    }

    private fun greeting(methods: IntArray): ByteArray =
        byteArrayOf(5, methods.size.toByte()) + methods.map { it.toByte() }.toByteArray()

    private fun connectRequest(port: Int): ByteArray = byteArrayOf(5, 1, 0, 1) +
        loopback.address +
        byteArrayOf((port ushr 8).toByte(), port.toByte())

    private fun udpAssociateRequest(): ByteArray = byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)

    private fun datagramHeader(port: Int): ByteArray = byteArrayOf(0, 0, 0, 1) +
        loopback.address +
        byteArrayOf((port ushr 8).toByte(), port.toByte())

    private fun ascii(value: String): ByteArray = value.toByteArray(StandardCharsets.US_ASCII)

    private data class SocksReply(val reply: Int, val address: InetAddress, val port: Int)

    private companion object {
        const val TIMEOUT_MILLIS = 5_000
        const val MAX_DATAGRAM = 2_048
        const val UDP_HEADER_IPV4 = 10
        const val SOCKS_PORT = 41_234
        const val AUTH_SUCCESS = 0
        const val AUTH_FAILURE = 1
        const val AUTH_NO_ACCEPTABLE = 0xff
        const val METHOD_USERNAME_PASSWORD = 2
        const val REPLY_SUCCEEDED = 0
        const val ADDRESS_TYPE_IPV4 = 1
        const val ADDRESS_TYPE_IPV6 = 4
        const val GENERATED_SAMPLES = 64
    }
}
