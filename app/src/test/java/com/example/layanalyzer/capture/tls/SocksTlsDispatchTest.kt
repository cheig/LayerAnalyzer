// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.socks.SocksNioTcpConnect
import com.example.layanalyzer.capture.socks.SocksNioTcpProfile
import com.example.layanalyzer.capture.socks.SocksNioTcpServer
import com.example.layanalyzer.capture.socks.SocksResolver
import com.example.layanalyzer.capture.socks.SocksProtocol
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsHostScope
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.nio.channels.SocketChannel
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * TLS-215: a TCP CONNECT either goes to the TLS gateway or keeps the direct
 * path, and that choice touches nothing else — not UDP, not the RFC 1929
 * credentials, not the bytes the tunnel pipelined behind its request.
 *
 * The gateway here is a recording loopback server that speaks C05's exact
 * protocol: `LAT1`, the big-endian body length, the seven-field metadata and the
 * `{version, success, errorCode}` reply. It is strict on purpose, so a channel
 * that framed or fielded its metadata differently fails here instead of in a
 * device log. A JVM test cannot run the Go engine, so the two halves are pinned
 * by the shared fixture in
 * `native_build/verification/tls/gateway-frame/frames.json`: this suite asserts
 * that the production channel writes exactly those frames, and
 * `internal/gateway/frames_fixture_test.go` feeds the same bytes to the real Go
 * reader. `TlsGatewayForwardingTest` is where the real engine is driven.
 *
 * Nothing here claims a device, a TUN capture or a decrypted payload.
 */
class SocksTlsDispatchTest {
    private val loopback: InetAddress = InetAddress.getByName("127.0.0.1")
    private val payload = ByteArray(64) { (it * 5 + 3).toByte() }

    /**
     * A fresh RFC 1929 pair per server: stopping a session discards its
     * credentials, so a pair shared across servers would stop matching after the
     * first `use` block closed.
     */
    private fun freshCredentials(): SocksCredentials = SocksCredentials.of(USERNAME, PASSWORD)

    // ---------------------------------------------------------------- dispatch

    @Test
    fun `a candidate port is carried by the gateway instead of the direct dialer`() {
        val direct = AtomicInteger()
        gateway(token = TOKEN).use { gateway ->
            server(gateway.channel(policy(CANDIDATE_PORT)), prepareTcp = { _ ->
                direct.incrementAndGet()
                Unit
            }).use { socks ->
                socks.start().let { port ->
                    Socket(loopback, port).use { client ->
                        client.soTimeout = TIMEOUT_MILLIS
                        val output = DataOutputStream(client.getOutputStream())
                        val input = DataInputStream(client.getInputStream())
                        authenticate(output, input, socks.credentials)
                        output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT))
                        output.flush()
                        assertEquals(REPLY_SUCCEEDED, readReply(input).reply)

                        output.write(payload)
                        output.flush()
                        val echoed = ByteArray(payload.size)
                        input.readFully(echoed)
                        assertArrayEquals(payload.reversedArray(), echoed)
                    }
                }
            }

            assertEquals("the direct dialer must not be used for a claimed connection", 0, direct.get())
            assertTrue("the gateway stub must not have seen a protocol violation", gateway.protocolFailures.isEmpty())
            assertEquals("exactly one frame for one connection", 1, gateway.frames.size)
            assertEquals("the hop is prepared exactly once", 1, gateway.preparations.get())
            assertTrue("the hop is prepared before it is connected", gateway.preparedUnconnected)
            val frame = JSONObject(String(gateway.frames.single(), StandardCharsets.UTF_8))
            assertEquals(CAPTURE_ID, frame.getString("captureId"))
            assertEquals(NETWORK_GENERATION, frame.getLong("networkGeneration"))
            assertEquals(DESTINATION, frame.getString("destinationAddress"))
            assertEquals(DESTINATION_PORT, frame.getInt("destinationPort"))
            assertEquals(TOKEN, frame.getString("token"))
            assertTrue("a new connection must get an id", validEngineId(frame.getString("connectionId")))
        }
    }

    @Test
    fun `a non candidate port keeps the direct path and the gateway sees nothing`() {
        val direct = AtomicInteger()
        echoOrigin().use { origin ->
            gateway(token = TOKEN).use { gateway ->
                server(gateway.channel(policy(CANDIDATE_PORT)), prepareTcp = { _ ->
                    direct.incrementAndGet()
                    Unit
                }).use { socks ->
                    socks.start().let { port ->
                        Socket(loopback, port).use { client ->
                            client.soTimeout = TIMEOUT_MILLIS
                            val output = DataOutputStream(client.getOutputStream())
                            val input = DataInputStream(client.getInputStream())
                            authenticate(output, input, socks.credentials)
                            output.write(connectRequest(destinationFor("127.0.0.1"), origin.port))
                            output.flush()
                            assertEquals(REPLY_SUCCEEDED, readReply(input).reply)
                            output.write(payload)
                            output.flush()
                            val echoed = ByteArray(payload.size)
                            input.readFully(echoed)
                            assertArrayEquals(payload.reversedArray(), echoed)
                        }
                    }
                }

                assertEquals("a non candidate port is dialed directly", 1, direct.get())
                assertEquals("the gateway must not see a non candidate connection", 0, gateway.frames.size)
            }
        }
    }

    @Test
    fun `a disabled policy keeps every port on the direct path`() {
        val disabled = TlsRoutingPolicy.freeze(
            TlsCaptureSettings(enabled = false, candidatePorts = setOf(CANDIDATE_PORT))
        )
        echoOrigin().use { origin ->
            gateway(token = TOKEN).use { gateway ->
                val channel = gateway.channel(disabled)
                assertFalse("a disabled policy admits nothing", (channel.route(CANDIDATE_PORT) == SocksNioTlsGateway.Route.GATEWAY))
                server(channel, prepareTcp = { _ -> Unit }).use { socks ->
                    socks.start().let { port ->
                        Socket(loopback, port).use { client ->
                            client.soTimeout = TIMEOUT_MILLIS
                            val output = DataOutputStream(client.getOutputStream())
                            val input = DataInputStream(client.getInputStream())
                            authenticate(output, input, socks.credentials)
                            output.write(connectRequest(destinationFor("127.0.0.1"), origin.port))
                            output.flush()
                            assertEquals(REPLY_SUCCEEDED, readReply(input).reply)
                            output.write(payload)
                            output.flush()
                            val echoed = ByteArray(payload.size)
                            input.readFully(echoed)
                            assertArrayEquals(payload.reversedArray(), echoed)
                        }
                    }
                }
                assertEquals(0, gateway.frames.size)
            }
        }
    }

    @Test
    fun `selected application traffic reaches the gateway without per flow attribution`() {
        val scoped = TlsRoutingPolicy.freeze(
            TlsCaptureSettings(
                enabled = true,
                candidatePorts = setOf(CANDIDATE_PORT),
                hostScope = TlsHostScope.SelectedApplicationsCandidates
            ),
            allowedApplications = listOf("com.example.first", "com.example.other")
        )
        val direct = AtomicInteger()
        gateway(token = TOKEN).use { gateway ->
            val channel = gateway.channel(scoped)
            assertTrue((channel.route(CANDIDATE_PORT) == SocksNioTlsGateway.Route.GATEWAY))
            assertFalse((channel.route(NON_CANDIDATE_PORT) == SocksNioTlsGateway.Route.GATEWAY))
            // The general policy still refuses unknown app identity: only the
            // authenticated VPN path has already enforced scope membership.
            assertEquals(TlsRoutingPrefilter.ApplicationNotSelected, scoped.prefilter(CANDIDATE_PORT, null))
            server(channel, prepareTcp = { _ ->
                direct.incrementAndGet()
                Unit
            }).use { socks ->
                Socket(loopback, socks.start()).use { client ->
                    client.soTimeout = TIMEOUT_MILLIS
                    val output = DataOutputStream(client.getOutputStream())
                    val input = DataInputStream(client.getInputStream())
                    authenticate(output, input, socks.credentials)
                    output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT))
                    output.flush()
                    assertEquals(REPLY_SUCCEEDED, readReply(input).reply)
                    output.write(payload)
                    output.flush()
                    val echoed = ByteArray(payload.size)
                    input.readFully(echoed)
                    assertArrayEquals(payload.reversedArray(), echoed)
                }
            }
            assertEquals(0, direct.get())
            assertEquals(1, gateway.frames.size)
            assertTrue(gateway.protocolFailures.isEmpty())
        }
    }

    // --------------------------------------------------------------- the frame

    @Test
    fun `the frame the channel writes is the shared cross language fixture`() {
        for (entry in fixtureFrames()) {
            val id = entry.getString("id")
            val destination = entry.getString("destinationAddress")
            val destinationPort = entry.getInt("destinationPort")
            gateway(token = entry.getString("token")).use { gateway ->
                val channel = TlsGatewayChannel(
                    gatewayPort = gateway.port,
                    token = entry.getString("token").toByteArray(StandardCharsets.US_ASCII),
                    captureId = entry.getString("captureId"),
                    networkGeneration = entry.getLong("networkGeneration"),
                    policy = policy(destinationPort),
                    prepareHopSocket = {},
                    readyTimeoutMillis = TIMEOUT_MILLIS,
                    connectionIds = { entry.getString("connectionId") }
                )
                server(channel).use { socks ->
                    exchange(socks.start(), socks.credentials, destination, destinationPort)
                }

                assertEquals("$id: exactly one frame", 1, gateway.frames.size)
                val body = gateway.frames.single()
                assertSameJson(
                    "$id: the body must carry exactly the fixture's fields and values",
                    JSONObject(entry.getString("body")),
                    JSONObject(String(body, StandardCharsets.UTF_8))
                )
                assertEquals(
                    "$id: the body must be exactly the fixture's bytes",
                    entry.getString("body").toByteArray(StandardCharsets.UTF_8).size,
                    body.size
                )
                val framed = gateway.framedFrames.single()
                assertEquals(
                    "$id: the frame must start with LAT1",
                    "LAT1",
                    String(framed, 0, 4, StandardCharsets.US_ASCII)
                )
                assertEquals("$id: the declared length must be the body length", body.size, declaredLength(framed))
                assertEquals("$id: the frame is exactly the header and the body", body.size + 8, framed.size)
            }
        }
    }

    @Test
    fun `connection ids are unique per claim and are valid engine ids`() {
        gateway(token = TOKEN).use { gateway ->
            server(gateway.channel(policy(CANDIDATE_PORT))).use { socks ->
                val port = socks.start()
                repeat(4) {
                    Socket(loopback, port).use { client ->
                        client.soTimeout = TIMEOUT_MILLIS
                        val output = DataOutputStream(client.getOutputStream())
                        val input = DataInputStream(client.getInputStream())
                        authenticate(output, input, socks.credentials)
                        output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT))
                        output.flush()
                        assertEquals(REPLY_SUCCEEDED, readReply(input).reply)
                    }
                }
                val ids = gateway.frames.map { JSONObject(String(it, StandardCharsets.UTF_8)).getString("connectionId") }
                assertEquals(4, ids.size)
                ids.forEach { assertTrue("engine ids: $it", validEngineId(it)) }
                assertEquals("every claim gets its own id", 4, ids.distinct().size)
            }
        }
    }

    // ------------------------------------------------------------- read ahead

    @Test
    fun `bytes pipelined behind the request are never forwarded before READY`() {
        gateway(token = TOKEN, earlyWindowMillis = PIPELINE_WINDOW_MILLIS).use { gateway ->
            server(gateway.channel(policy(CANDIDATE_PORT))).use { socks ->
                socks.start().let { port ->
                    Socket(loopback, port).use { client ->
                        client.soTimeout = TIMEOUT_MILLIS
                        val output = DataOutputStream(client.getOutputStream())
                        val input = DataInputStream(client.getInputStream())
                        authenticate(output, input, socks.credentials)
                        // One write: the CONNECT request plus the application
                        // bytes the tunnel pipelined behind it.
                        output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT) + payload)
                        output.flush()

                        assertEquals(REPLY_SUCCEEDED, readReply(input).reply)
                        val echoed = ByteArray(payload.size)
                        input.readFully(echoed)
                        assertArrayEquals(
                            "the pipelined bytes must be relayed unchanged",
                            payload.reversedArray(),
                            echoed
                        )
                    }
                }
            }

            assertEquals("the gateway must not receive payload before READY", 0, gateway.earlyBytes.get())
            assertEquals("and it must still receive the whole payload", payload.size, gateway.payloadBytes.get())
        }
    }

    @Test
    fun `a client that sends nothing after the request still receives success`() {
        // The other order: the tunnel waits for SOCKS success before sending
        // application data, so the hop must not wait for that data.
        gateway(token = TOKEN).use { gateway ->
            server(gateway.channel(policy(CANDIDATE_PORT))).use { socks ->
                socks.start().let { port ->
                    Socket(loopback, port).use { client ->
                        client.soTimeout = TIMEOUT_MILLIS
                        val output = DataOutputStream(client.getOutputStream())
                        val input = DataInputStream(client.getInputStream())
                        authenticate(output, input, socks.credentials)
                        output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT))
                        output.flush()
                        assertEquals(REPLY_SUCCEEDED, readReply(input).reply)

                        // Only now does the tunnel send its ClientHello stand-in.
                        output.write(payload)
                        output.flush()
                        val echoed = ByteArray(payload.size)
                        input.readFully(echoed)
                        assertArrayEquals(payload.reversedArray(), echoed)
                    }
                }
            }
        }
    }

    // --------------------------------------------------------------- refusals

    @Test
    fun `a gateway refusal becomes a definite SOCKS reply`() {
        val expected = listOf(
            "NETWORK_CHANGED" to REPLY_NETWORK_UNREACHABLE,
            "IO_ERROR" to REPLY_HOST_UNREACHABLE,
            "PROTECT_FAILED" to REPLY_GENERAL_FAILURE,
            "INVALID_ARGUMENT" to REPLY_GENERAL_FAILURE,
            "CAPACITY_EXCEEDED" to REPLY_GENERAL_FAILURE,
            "CAPTURE_CONTEXT_MISSING" to REPLY_GENERAL_FAILURE,
            "STALE_GENERATION" to REPLY_GENERAL_FAILURE,
            "UNSUPPORTED" to REPLY_GENERAL_FAILURE,
            "CANCELLED" to REPLY_GENERAL_FAILURE
        )
        for ((code, reply) in expected) {
            val direct = AtomicInteger()
            gateway(token = TOKEN, refusal = code).use { gateway ->
                server(gateway.channel(policy(CANDIDATE_PORT)), prepareTcp = { _ ->
                    direct.incrementAndGet()
                    Unit
                }).use { socks ->
                    socks.start().let { port ->
                        Socket(loopback, port).use { client ->
                            client.soTimeout = TIMEOUT_MILLIS
                            val output = DataOutputStream(client.getOutputStream())
                            val input = DataInputStream(client.getInputStream())
                            authenticate(output, input, socks.credentials)
                            output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT))
                            output.flush()

                            assertEquals("$code must be answered, not ignored", reply, readReply(input).reply)
                            assertEquals("a refused connection must be closed", -1, input.read())
                        }
                    }
                }
                assertEquals("$code must not fall back to the direct dialer", 0, direct.get())
                assertEquals("$code must relay nothing", 0, gateway.payloadBytes.get())
            }
        }
    }

    @Test
    fun `a gateway that never answers fails the connection instead of hanging`() {
        val direct = AtomicInteger()
        gateway(token = TOKEN, silent = true, earlyWindowMillis = 0).use { gateway ->
            server(
                gateway.channel(policy(CANDIDATE_PORT), readyTimeoutMillis = SHORT_READY_TIMEOUT),
                prepareTcp = { _ ->
                    direct.incrementAndGet()
                    Unit
                }
            ).use { socks ->
                socks.start().let { port ->
                    Socket(loopback, port).use { client ->
                        client.soTimeout = TIMEOUT_MILLIS
                        val output = DataOutputStream(client.getOutputStream())
                        val input = DataInputStream(client.getInputStream())
                        authenticate(output, input, socks.credentials)
                        output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT))
                        output.flush()

                        assertEquals(REPLY_GENERAL_FAILURE, readReply(input).reply)
                        assertEquals("the connection must be closed, not left half open", -1, input.read())
                        assertEquals(1L, socks.sessionStats().failureEvents["gateway_ready_read_timeout"])
                    }
                }
            }
            assertTrue("the hop must be closed when the request fails", gateway.hopClosed.await(2, TimeUnit.SECONDS))
            assertEquals(0, direct.get())
        }
    }

    @Test
    fun `a gateway that is not listening fails the connection rather than dialing directly`() {
        val dead = ServerSocket(0, 1, loopback).also { it.close() }.localPort
        val direct = AtomicInteger()
        val channel = TlsGatewayChannel(
            gatewayPort = dead,
            token = TOKEN.toByteArray(StandardCharsets.US_ASCII),
            captureId = CAPTURE_ID,
            networkGeneration = NETWORK_GENERATION,
            policy = policy(CANDIDATE_PORT),
            prepareHopSocket = {},
            readyTimeoutMillis = SHORT_READY_TIMEOUT
        )
        server(channel, prepareTcp = { _ ->
            direct.incrementAndGet()
            Socket()
        }).use { socks ->
            socks.start().let { port ->
                Socket(loopback, port).use { client ->
                    client.soTimeout = TIMEOUT_MILLIS
                    val output = DataOutputStream(client.getOutputStream())
                    val input = DataInputStream(client.getInputStream())
                    authenticate(output, input, socks.credentials)
                    output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT))
                    output.flush()

                    assertEquals(REPLY_GENERAL_FAILURE, readReply(input).reply)
                    assertEquals("no half open session may remain", -1, input.read())
                }
            }
        }
        assertEquals("an unusable gateway must not silently bypass interception", 0, direct.get())
    }

    @Test
    fun `a malformed gateway reply is a general failure`() {
        val malformed = listOf(
            "not json at all" to "the reply is not JSON",
            """{"version":2,"success":true,"errorCode":null}""" to "a reply from another version",
            """{"version":1,"success":true,"errorCode":"IO_ERROR"}""" to "a success carrying a refusal",
            """{"version":1,"success":false}""" to "a refusal carrying no code",
            """{"version":1}""" to "a reply with no verdict"
        )
        for ((reply, why) in malformed) {
            gateway(token = TOKEN, rawReply = reply).use { gateway ->
                server(gateway.channel(policy(CANDIDATE_PORT))).use { socks ->
                    socks.start().let { port ->
                        Socket(loopback, port).use { client ->
                            client.soTimeout = TIMEOUT_MILLIS
                            val output = DataOutputStream(client.getOutputStream())
                            val input = DataInputStream(client.getInputStream())
                            authenticate(output, input, socks.credentials)
                            output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT))
                            output.flush()
                            assertEquals(why, REPLY_GENERAL_FAILURE, readReply(input).reply)
                            assertEquals(why, -1, input.read())
                        }
                    }
                }
                assertEquals(why, 0, gateway.payloadBytes.get())
            }
        }
    }

    // -------------------------------------------------------------- teardown

    @Test
    fun `closing the server closes the local hop and the client`() {
        val gateway = gateway(token = TOKEN)
        val socks = server(gateway.channel(policy(CANDIDATE_PORT)))
        try {
            val port = socks.start()
            Socket(loopback, port).use { client ->
                client.soTimeout = TIMEOUT_MILLIS
                val output = DataOutputStream(client.getOutputStream())
                val input = DataInputStream(client.getInputStream())
                authenticate(output, input, socks.credentials)
                output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT))
                output.flush()
                assertEquals(REPLY_SUCCEEDED, readReply(input).reply)
                output.write(payload)
                output.flush()
                val echoed = ByteArray(payload.size)
                input.readFully(echoed)
                assertArrayEquals(payload.reversedArray(), echoed)

                // The client stays open and quiet, so the only thing that can end
                // the hop is the SOCKS server closing it.
                socks.close()
                assertTrue("the hop must be closed", gateway.hopClosed.await(2, TimeUnit.SECONDS))
                assertEquals("the client must be closed too", -1, input.read())
            }
        } finally {
            runCatching { socks.close() }
            gateway.close()
        }
    }

    @Test
    fun `a closed channel admits nothing and stops carrying its token`() {
        gateway(token = TOKEN).use { gateway ->
            val channel = gateway.channel(policy(CANDIDATE_PORT))
            assertTrue((channel.route(CANDIDATE_PORT) == SocksNioTlsGateway.Route.GATEWAY))
            assertTrue("the run's token is held while it runs", channel.carriesTokenMaterial())
            assertFalse("the token must never be rendered", channel.toString().contains(TOKEN))

            channel.close()
            assertFalse("a closed channel admits nothing", (channel.route(CANDIDATE_PORT) == SocksNioTlsGateway.Route.GATEWAY))
            assertFalse("the token is wiped when the run ends", channel.carriesTokenMaterial())
            assertThrows(IOException::class.java) { channel.describe(InetAddress.getByName(DESTINATION), DESTINATION_PORT) }
            channel.close() // Idempotent.

            server(channel, prepareTcp = { _ -> Unit }).use { socks ->
                socks.start().let { port ->
                    Socket(loopback, port).use { client ->
                        client.soTimeout = TIMEOUT_MILLIS
                        val output = DataOutputStream(client.getOutputStream())
                        val input = DataInputStream(client.getInputStream())
                        authenticate(output, input, socks.credentials)
                        output.write(connectRequest(destinationFor(DESTINATION), DESTINATION_PORT))
                        output.flush()
                        assertEquals("a stopped run refuses new forwarding", REPLY_GENERAL_FAILURE, readReply(input).reply)
                    }
                }
            }
            assertEquals(0, gateway.frames.size)
        }
    }

    @Test
    fun `the UDP path is unchanged while the gateway is installed`() {
        gateway(token = TOKEN).use { gateway ->
            server(gateway.channel(policy(CANDIDATE_PORT))).use { socks ->
                socks.start().let { port ->
                    Socket(loopback, port).use { control ->
                        control.soTimeout = TIMEOUT_MILLIS
                        val output = DataOutputStream(control.getOutputStream())
                        val input = DataInputStream(control.getInputStream())
                        authenticate(output, input, socks.credentials)
                        output.write(udpAssociateRequest())
                        output.flush()
                        assertEquals(REPLY_SUCCEEDED, readReply(input).reply)
                    }
                }
            }
            assertEquals("UDP must not be dispatched to the gateway", 0, gateway.frames.size)
        }
    }

    @Test
    fun `both NIO entry points preserve every candidate refusal without DNS or direct fallback`() {
        val codes = listOf("NETWORK_CHANGED", "IO_ERROR", "PROTECT_FAILED", "INVALID_ARGUMENT",
            "CAPACITY_EXCEEDED", "CAPTURE_CONTEXT_MISSING", "STALE_GENERATION", "UNSUPPORTED",
            "CANCELLED", "NOT_READY", "UPSTREAM_CERT_INVALID", "DOWNSTREAM_TLS_REJECTED",
            "SECRETS_INCOMPLETE", "FUTURE_CODE")
        for (mode in EntryPoint.entries) for (code in codes) {
            gateway(token = TOKEN, refusal = code, earlyWindowMillis = 20).use { gateway ->
                DispatchFixture(mode, gateway.channel(policy(CANDIDATE_PORT))).use { fixture ->
                    fixture.request().use { client ->
                        val expected = when (code) {
                            "NETWORK_CHANGED" -> REPLY_NETWORK_UNREACHABLE
                            "IO_ERROR" -> REPLY_HOST_UNREACHABLE
                            else -> REPLY_GENERAL_FAILURE
                        }
                        assertRejected(client, expected)
                    }
                    assertTrue(gateway.hopClosed.await(2, TimeUnit.SECONDS))
                    fixture.assertNoDirect()
                    assertEquals(1, gateway.frames.size)
                    assertEquals(0, gateway.earlyBytes.get())
                    assertEquals(0, gateway.payloadBytes.get())
                    assertTrue(gateway.protocolFailures.toString(), gateway.protocolFailures.isEmpty())
                }
            }
        }
    }

    @Test
    fun `both NIO entry points reject failed hop protection before any LAT1 or direct dial`() {
        for (mode in EntryPoint.entries) gateway(token = TOKEN).use { gateway ->
            val channels = CopyOnWriteArrayList<SocketChannel>()
            val channel = gateway.channel(policy(CANDIDATE_PORT), prepare = { throw IOException("protect") },
                factory = { SocketChannel.open().also(channels::add) })
            DispatchFixture(mode, channel).use { fixture ->
                fixture.request().use { assertRejected(it) }
                fixture.assertNoDirect()
                assertEquals(1, gateway.preparations.get())
                assertTrue(gateway.preparedUnconnected)
                assertEquals(1, channels.size)
                assertTrue(channels.none { it.isOpen })
                assertTrue(gateway.frames.isEmpty())
            }
        }
    }

    @Test
    fun `both NIO entry points reject an unavailable listener without direct fallback`() {
        for (mode in EntryPoint.entries) gateway(token = TOKEN).use { gateway ->
            val channel = gateway.channel(policy(CANDIDATE_PORT), SHORT_READY_TIMEOUT)
            gateway.close()
            DispatchFixture(mode, channel).use { fixture ->
                fixture.request().use { assertRejected(it) }
                fixture.assertNoDirect()
                assertEquals(1, gateway.preparations.get())
                assertTrue(gateway.frames.isEmpty())
            }
        }
    }

    @Test
    fun `both NIO entry points reject malformed silent or closed READY without pipelined upload`() {
        for (mode in EntryPoint.entries) for (failure in 0..2) {
            gateway(token = TOKEN, rawReply = if (failure == 0) """{"version":2,"success":true}""" else null,
                silent = failure == 1, closeAfterMetadata = failure == 2, earlyWindowMillis = 20).use { gateway ->
                DispatchFixture(mode, gateway.channel(policy(CANDIDATE_PORT), SHORT_READY_TIMEOUT)).use { fixture ->
                    fixture.request().use { assertRejected(it) }
                    assertTrue(gateway.hopClosed.await(2, TimeUnit.SECONDS))
                    fixture.assertNoDirect()
                    assertEquals(1, gateway.frames.size)
                    assertEquals(0, gateway.earlyBytes.get())
                    assertEquals(0, gateway.payloadBytes.get())
                    assertTrue(gateway.protocolFailures.toString(), gateway.protocolFailures.isEmpty())
                }
            }
        }
    }

    @Test
    fun `both NIO entry points keep non candidates direct without opening the gateway`() {
        for (mode in EntryPoint.entries) echoOrigin().use { origin ->
            gateway(token = TOKEN).use { gateway ->
                DispatchFixture(mode, gateway.channel(policy(CANDIDATE_PORT)), directPort = origin.port).use { fixture ->
                    fixture.request(NON_CANDIDATE_PORT).use { client ->
                        assertEquals(REPLY_SUCCEEDED, readReply(DataInputStream(client.getInputStream())).reply)
                        val echoed = ByteArray(payload.size)
                        DataInputStream(client.getInputStream()).readFully(echoed)
                        assertArrayEquals(payload.reversedArray(), echoed)
                    }
                    assertEquals(0, fixture.dns.get())
                    assertEquals(1, fixture.directOpens.get())
                    assertEquals(1, fixture.directPreparations.get())
                    assertEquals(0, gateway.preparations.get())
                    assertTrue(gateway.frames.isEmpty())
                }
            }
        }
    }

    @Test
    fun `NIO rejects inconsistent routes before DNS metadata or direct factories`() {
        for ((port, route) in listOf(CANDIDATE_PORT to SocksNioTcpServer.Route.DIRECT,
            NON_CANDIDATE_PORT to SocksNioTcpServer.Route.TLS_GATEWAY)) {
            gateway(token = TOKEN).use { gateway ->
                DispatchFixture(EntryPoint.INTERNAL, gateway.channel(policy(CANDIDATE_PORT)), routeOverride = route).use { fixture ->
                    fixture.request(port, domain = "must-not-resolve.test").use { assertRejected(it) }
                    fixture.assertNoDirect()
                    assertEquals(0, gateway.preparations.get())
                    assertTrue(gateway.frames.isEmpty())
                }
            }
        }
    }

    @Test
    fun `closed run is unavailable through both NIO entry points`() {
        for (mode in EntryPoint.entries) echoOrigin().use { origin ->
            gateway(token = TOKEN).use { gateway ->
                val channel = gateway.channel(policy(CANDIDATE_PORT))
                channel.close()
                assertFalse((channel.route(CANDIDATE_PORT) == SocksNioTlsGateway.Route.GATEWAY))
                assertEquals(SocksNioTlsGateway.Route.UNAVAILABLE, channel.route(CANDIDATE_PORT))
                DispatchFixture(mode, channel, directPort = origin.port).use { fixture ->
                    fixture.request().use { client ->
                        assertRejected(client)
                        fixture.assertNoDirect()
                    }
                    assertFalse(channel.carriesTokenMaterial())
                    assertTrue(gateway.frames.isEmpty())
                    assertEquals(0, gateway.preparations.get())
                }
            }
        }
    }

    @Test
    fun `both NIO entry points stop the old hop and keep fresh gateway traffic isolated`() {
        for (mode in EntryPoint.entries) gateway(token = TOKEN).use { oldGateway ->
            val oldChannel = oldGateway.channel(policy(CANDIDATE_PORT))
            DispatchFixture(mode, oldChannel).use { old ->
                old.request().use { client ->
                    assertEquals(REPLY_SUCCEEDED, readReply(DataInputStream(client.getInputStream())).reply)
                    val echoed = ByteArray(payload.size)
                    DataInputStream(client.getInputStream()).readFully(echoed)
                    old.close()
                    assertEquals(-1, client.getInputStream().read())
                    assertTrue(oldGateway.hopClosed.await(2, TimeUnit.SECONDS))
                    assertFalse(oldChannel.carriesTokenMaterial())
                    gateway(token = TOKEN).use { freshGateway ->
                        DispatchFixture(mode, freshGateway.channel(policy(CANDIDATE_PORT))).use { fresh ->
                            fresh.request().use { next ->
                                assertEquals(REPLY_SUCCEEDED, readReply(DataInputStream(next.getInputStream())).reply)
                                DataInputStream(next.getInputStream()).readFully(echoed)
                                assertArrayEquals(payload.reversedArray(), echoed)
                            }
                            fresh.assertNoDirect()
                            assertEquals(1, freshGateway.frames.size)
                        }
                    }
                    old.assertNoDirect()
                    assertEquals(1, oldGateway.frames.size)
                    assertEquals(payload.size, oldGateway.payloadBytes.get())
                }
            }
        }
    }

    private fun assertRejected(client: Socket, expected: Int = REPLY_GENERAL_FAILURE) {
        val input = DataInputStream(client.getInputStream())
        assertEquals(expected, readReply(input).reply)
        assertEquals(-1, input.read())
    }

    private enum class EntryPoint { PRODUCTION, INTERNAL }

    private inner class DispatchFixture(
        mode: EntryPoint,
        private val channel: TlsGatewayChannel,
        private val directPort: Int? = null,
        routeOverride: SocksNioTcpServer.Route? = null
    ) : Closeable {
        val dns = AtomicInteger()
        val directOpens = AtomicInteger()
        val directPreparations = AtomicInteger()
        private val credentials = freshCredentials()
        private val resolver = if (mode == EntryPoint.INTERNAL) SocksResolver.forTest() else null
        private val closed = AtomicBoolean()
        private val facade = if (mode == EntryPoint.PRODUCTION) DirectSocks5Server(
            prepareTcp = { directOpens.incrementAndGet(); directPreparations.incrementAndGet() },
            prepareUdp = {}, resolveHost = { dns.incrementAndGet(); arrayOf(loopback) },
            generateCredentials = { credentials }, tlsGateway = channel
        ) else null
        private val nio = resolver?.let { SocksNioTcpServer(SocksNioTcpProfile.TCP_64, it,
            connectIo = object : SocksNioTcpConnect.ConnectIo {
                override fun open() = SocketChannel.open().also { directOpens.incrementAndGet() }
                override fun connect(channel: SocketChannel, address: InetSocketAddress): Boolean =
                    channel.connect(InetSocketAddress(loopback, checkNotNull(directPort)))
            }) }
        private val port = facade?.start() ?: checkNotNull(nio).start(SocksNioTcpServer.StartRequest(
            credentials, NETWORK_GENERATION, { dns.incrementAndGet(); arrayOf(loopback) },
            { directPreparations.incrementAndGet() },
            { routeOverride ?: if (it.port == CANDIDATE_PORT) SocksNioTcpServer.Route.TLS_GATEWAY else SocksNioTcpServer.Route.DIRECT },
            channel))

        fun request(destinationPort: Int = CANDIDATE_PORT, domain: String? = null): Socket = Socket(loopback, port).also { client ->
            client.soTimeout = TIMEOUT_MILLIS
            val output = DataOutputStream(client.getOutputStream())
            authenticate(output, DataInputStream(client.getInputStream()), credentials)
            val direct = destinationPort == NON_CANDIDATE_PORT && directPort != null
            val destination = domain?.let { SocksDestination.Domain(it) }
                ?: SocksDestination.Ip(if (direct) loopback else InetAddress.getByName(DESTINATION))
            output.write(SocksProtocol.encodeRequest(SocksRequest(1, destination,
                if (direct) checkNotNull(directPort) else destinationPort)) + payload)
            output.flush()
        }

        fun assertNoDirect() {
            assertEquals(0, dns.get())
            assertEquals(0, directOpens.get())
            assertEquals(0, directPreparations.get())
        }

        override fun close() {
            if (!closed.compareAndSet(false, true)) return
            try {
                facade?.close()
                nio?.let { server ->
                    assertTrue(server.stop())
                    val stats = server.stats()
                    assertEquals(0, stats.server.admission!!.tcp.current)
                    assertEquals(0, stats.server.admission.udp.current)
                    assertEquals(0, stats.server.admission.handshakes.current)
                    assertEquals(0, stats.buffers!!.allocatedBytes)
                    stats.server.loops.forEach {
                        assertEquals(0, it.channels)
                        assertEquals(0, it.resources)
                        assertEquals(0, it.keys)
                        assertEquals(0, it.timers)
                    }
                }
            } finally {
                channel.close()
                resolver?.let { assertTrue(it.shutdownForTest()) }
            }
        }
    }

    // -------------------------------------------------------------- fixtures

    /** The candidate screen one run was started with: one port, explicit hosts. */
    private fun policy(port: Int): TlsRoutingPolicy =
        TlsRoutingPolicy.freeze(TlsCaptureSettings(enabled = true, candidatePorts = setOf(port)))

    private fun RecordingGateway.channel(
        policy: TlsRoutingPolicy,
        readyTimeoutMillis: Int = TIMEOUT_MILLIS,
        prepare: (Socket) -> Unit = {},
        factory: () -> SocketChannel = { SocketChannel.open() }
    ): TlsGatewayChannel = TlsGatewayChannel(
        gatewayPort = port,
        token = tokenBytes(),
        captureId = CAPTURE_ID,
        networkGeneration = NETWORK_GENERATION,
        policy = policy,
        prepareHopSocket = { socket ->
            preparations.incrementAndGet()
            preparedUnconnected = preparedUnconnected && !socket.isConnected
            prepare(socket)
        },
        readyTimeoutMillis = readyTimeoutMillis,
        channelFactory = factory
    )

    private fun gateway(
        token: String,
        refusal: String? = null,
        rawReply: String? = null,
        silent: Boolean = false,
        earlyWindowMillis: Long = 0,
        closeAfterMetadata: Boolean = false
    ) = RecordingGateway(token, refusal, rawReply, silent, earlyWindowMillis, closeAfterMetadata)

    private fun server(
        gateway: SocksNioTlsGateway?,
        prepareTcp: (Socket) -> Unit = {}
    ): DirectSocks5Server = DirectSocks5Server(
        prepareTcp = prepareTcp,
        prepareUdp = {},
        resolveHost = { arrayOf(InetAddress.getByName(it)) },
        generateCredentials = { freshCredentials() },
        tlsGateway = gateway
    )

    /** One authenticated CONNECT plus the payload, answered by the stub's echo. */
    private fun exchange(
        socksPort: Int,
        credentials: SocksCredentials,
        destination: String,
        destinationPort: Int
    ) {
        Socket(loopback, socksPort).use { client ->
            client.soTimeout = TIMEOUT_MILLIS
            val output = DataOutputStream(client.getOutputStream())
            val input = DataInputStream(client.getInputStream())
            authenticate(output, input, credentials)
            output.write(connectRequest(destinationFor(destination), destinationPort))
            output.flush()
            assertEquals(REPLY_SUCCEEDED, readReply(input).reply)
            output.write(payload)
            output.flush()
            val echoed = ByteArray(payload.size)
            input.readFully(echoed)
            assertArrayEquals(payload.reversedArray(), echoed)
        }
    }

    /** A one-connection origin that echoes what it receives, reversed. */
    private fun echoOrigin(): EchoOrigin = EchoOrigin(payload.size)

    private fun authenticate(output: DataOutputStream, input: DataInputStream, credentials: SocksCredentials) {
        output.write(byteArrayOf(5, 1, METHOD_USERNAME_PASSWORD.toByte()))
        output.flush()
        assertEquals(5, input.readUnsignedByte())
        assertEquals("the server must select username/password", METHOD_USERNAME_PASSWORD, input.readUnsignedByte())
        val user = credentials.username.toByteArray(StandardCharsets.US_ASCII)
        val secret = credentials.password.toByteArray(StandardCharsets.US_ASCII)
        output.writeByte(1)
        output.writeByte(user.size)
        output.write(user)
        output.writeByte(secret.size)
        output.write(secret)
        output.flush()
        assertEquals(1, input.readUnsignedByte())
        assertEquals(0, input.readUnsignedByte())
    }

    private fun readReply(input: DataInputStream): SocksReply {
        assertEquals(5, input.readUnsignedByte())
        val reply = input.readUnsignedByte()
        input.readUnsignedByte()
        val address = when (val addressType = input.readUnsignedByte()) {
            ADDRESS_TYPE_IPV4 -> InetAddress.getByAddress(ByteArray(4).also(input::readFully))
            ADDRESS_TYPE_IPV6 -> InetAddress.getByAddress(ByteArray(16).also(input::readFully))
            else -> throw AssertionError("Unexpected reply address type $addressType")
        }
        val port = (input.readUnsignedByte() shl 8) or input.readUnsignedByte()
        return SocksReply(reply, address, port)
    }

    private fun connectRequest(destination: ByteArray, port: Int): ByteArray =
        byteArrayOf(5, 1, 0, destinationType(destination)) + destination +
            byteArrayOf((port ushr 8).toByte(), port.toByte())

    private fun udpAssociateRequest(): ByteArray = byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)

    private fun destinationFor(address: String): ByteArray = InetAddress.getByName(address).address

    private fun destinationType(address: ByteArray): Byte = when (address.size) {
        4 -> ADDRESS_TYPE_IPV4.toByte()
        16 -> ADDRESS_TYPE_IPV6.toByte()
        else -> throw AssertionError("Unexpected address length ${address.size}")
    }

    /** Field-by-field JSON equality, so key iteration order can never matter. */
    private fun assertSameJson(why: String, expected: JSONObject, actual: JSONObject) {
        assertEquals("$why: keys", expected.keySet().sorted(), actual.keySet().sorted())
        expected.keySet().forEach { key ->
            assertEquals("$why: $key", expected.get(key).toString(), actual.get(key).toString())
        }
    }

    /** The accepted frames of the shared cross-language fixture, in file order. */
    private fun fixtureFrames(): List<JSONObject> {
        val relative = "native_build/verification/tls/gateway-frame/frames.json"
        var directory: File? = File(".").absoluteFile
        while (directory != null) {
            val candidate = File(directory, relative)
            if (candidate.isFile) {
                val frames = JSONObject(candidate.readText()).getJSONArray("frames")
                val accepted = (0 until frames.length()).map { frames.getJSONObject(it) }
                    .filter { it.getBoolean("accept") }
                check(accepted.isNotEmpty()) { "the fixture carries no accepted frame" }
                return accepted
            }
            directory = directory.parentFile
        }
        error("shared gateway frame fixture not found: $relative")
    }

    private data class SocksReply(val reply: Int, val address: InetAddress, val port: Int)

    /** A loopback origin: one connection, answered with the same bytes reversed. */
    private class EchoOrigin(private val expectedBytes: Int) : Closeable {
        private val listener = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))

        val port: Int get() = listener.localPort

        private val worker = thread(start = true, isDaemon = true, name = "EchoOrigin") {
            runCatching {
                listener.accept().use { peer ->
                    val received = ByteArray(expectedBytes)
                    DataInputStream(peer.getInputStream()).readFully(received)
                    peer.getOutputStream().write(received.reversedArray())
                    peer.getOutputStream().flush()
                    // Hold the connection until the relay is done with it.
                    peer.getInputStream().read()
                }
            }
        }

        override fun close() {
            runCatching { listener.close() }
            worker.interrupt()
        }
    }

    /**
     * A loopback gateway that speaks C05's protocol.
     *
     * It records every frame, reports a frame it cannot parse instead of
     * succeeding quietly, notes whether payload arrives before it answered READY,
     * and — after a READY — echoes what it receives, reversed, standing in for
     * the origin the engine would relay to.
     */
    private class RecordingGateway(
        private val token: String,
        private val refusal: String? = null,
        private val rawReply: String? = null,
        private val silent: Boolean = false,
        private val earlyWindowMillis: Long = 0,
        private val closeAfterMetadata: Boolean = false
    ) : Closeable {
        val frames = CopyOnWriteArrayList<ByteArray>()
        val framedFrames = CopyOnWriteArrayList<ByteArray>()
        val protocolFailures = CopyOnWriteArrayList<String>()
        val earlyBytes = AtomicInteger()
        val payloadBytes = AtomicInteger()
        val preparations = AtomicInteger()
        val hopClosed = CountDownLatch(1)

        @Volatile
        var preparedUnconnected = true

        private val listener = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
        private val workers = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "GatewayStub").apply { isDaemon = true }
        }
        private val running = AtomicBoolean(true)
        private val hops = ConcurrentHashMap.newKeySet<Socket>()

        val port: Int get() = listener.localPort
        fun tokenBytes(): ByteArray = token.toByteArray(StandardCharsets.US_ASCII)

        init {
            workers.execute { acceptLoop() }
        }

        private fun acceptLoop() {
            while (running.get()) {
                val hop = try {
                    listener.accept()
                } catch (_: Exception) {
                    return
                }
                hops.add(hop)
                if (!running.get()) {
                    hop.close()
                    hops.remove(hop)
                    return
                }
                runCatching { workers.execute {
                    try {
                        runCatching { serve(hop) }.onFailure { protocolFailures += it.message ?: it.toString() }
                    } finally {
                        runCatching { hop.close() }
                        hops.remove(hop)
                        hopClosed.countDown()
                    }
                } }.onFailure {
                    runCatching { hop.close() }
                    hops.remove(hop)
                }
            }
        }

        private fun serve(hop: Socket) {
            val input = DataInputStream(hop.getInputStream())
            val output = DataOutputStream(hop.getOutputStream())
            val prefix = ByteArray(8)
            input.readFully(prefix)
            check(String(prefix, 0, 4, StandardCharsets.US_ASCII) == "LAT1") { "the frame does not start with LAT1" }
            val length = declaredLength(prefix)
            check(length in 1..MAX_HEADER_BYTES) { "header length $length is outside 1..$MAX_HEADER_BYTES" }
            val body = ByteArray(length)
            input.readFully(body)
            val metadata = JSONObject(String(body, StandardCharsets.UTF_8))
            check(metadata.keySet() == setOf("version", "captureId", "connectionId", "networkGeneration",
                "destinationAddress", "destinationPort", "token")) { "metadata must contain exactly seven fields" }
            check(metadata.get("version") is Number && metadata.getInt("version") == 1)
            check(metadata.get("captureId") is String && validEngineId(metadata.getString("captureId")))
            check(metadata.get("connectionId") is String && validEngineId(metadata.getString("connectionId")))
            check(metadata.get("networkGeneration") is Number && metadata.getLong("networkGeneration") >= 0)
            check(metadata.get("destinationPort") is Number && metadata.getInt("destinationPort") in 1..65535)
            check(metadata.get("token") is String && metadata.getString("token") == token)
            val address = metadata.get("destinationAddress") as? String ?: error("destination must be a literal")
            check(if (':' in address) address.matches(Regex("[0-9a-fA-F:]+")) &&
                InetAddress.getByName(address).address.size == 16 else address.split('.').let { octets ->
                octets.size == 4 && octets.all { it.matches(Regex("[0-9]{1,3}")) && it.toInt() in 0..255 }
            }) { "destination must be a literal" }
            framedFrames += prefix + body
            frames += body

            // The window in which a server that forwarded pipelined payload too
            // early would show it: nothing may arrive before READY.
            if (earlyWindowMillis > 0) {
                hop.soTimeout = earlyWindowMillis.toInt()
                try {
                    if (input.read() >= 0) earlyBytes.incrementAndGet()
                } catch (_: SocketTimeoutException) {
                    // The expected outcome.
                }
            }
            hop.soTimeout = 0

            if (closeAfterMetadata) return
            if (silent) {
                drain(input)
                return
            }
            val reply = rawReply ?: if (refusal == null) {
                """{"version":1,"success":true,"errorCode":null}"""
            } else {
                """{"version":1,"success":false,"errorCode":"$refusal"}"""
            }
            val bytes = reply.toByteArray(StandardCharsets.UTF_8)
            output.writeBytes("LAT1")
            output.writeInt(bytes.size)
            output.write(bytes)
            output.flush()
            if (refusal != null || rawReply != null) {
                drain(input)
                return
            }
            echo(input, output)
        }

        /** Echoes until the peer closes; counts what arrived. */
        private fun echo(input: DataInputStream, output: DataOutputStream) {
            val buffer = ByteArray(4096)
            while (true) {
                val count = read(input, buffer)
                if (count < 0) {
                    hopClosed.countDown()
                    return
                }
                if (count == 0) continue
                payloadBytes.addAndGet(count)
                output.write(buffer.copyOf(count).reversedArray())
                output.flush()
            }
        }

        /** Counts whatever arrives until the peer closes. */
        private fun drain(input: DataInputStream) {
            val buffer = ByteArray(4096)
            while (true) {
                val count = read(input, buffer)
                if (count < 0) {
                    hopClosed.countDown()
                    return
                }
                if (count > 0) payloadBytes.addAndGet(count)
            }
        }

        private fun read(input: DataInputStream, buffer: ByteArray): Int = try {
            input.read(buffer)
        } catch (_: Exception) {
            -1
        }

        override fun close() {
            if (!running.getAndSet(false)) return
            runCatching { listener.close() }
            hops.forEach { runCatching { it.close() } }
            workers.shutdownNow()
            workers.awaitTermination(CLOSE_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
        }
    }
}

private const val TIMEOUT_MILLIS = 5_000
private const val SHORT_READY_TIMEOUT = 400
private const val PIPELINE_WINDOW_MILLIS = 400L
private const val CLOSE_TIMEOUT_MILLIS = 1_000L
private const val MAX_HEADER_BYTES = 4096
private const val CAPTURE_ID = "capture-215"
private const val NETWORK_GENERATION = 2L
private const val CANDIDATE_PORT = 443
private const val NON_CANDIDATE_PORT = 8_080
private const val DESTINATION = "198.51.100.7"
private const val DESTINATION_PORT = 443
private const val USERNAME = "DispatchUsername"
private const val PASSWORD = "DispatchPasswordValue"
private const val METHOD_USERNAME_PASSWORD = 2
private const val REPLY_SUCCEEDED = 0
private const val REPLY_GENERAL_FAILURE = 1
private const val REPLY_NETWORK_UNREACHABLE = 3
private const val REPLY_HOST_UNREACHABLE = 4
private const val ADDRESS_TYPE_IPV4 = 1
private const val ADDRESS_TYPE_IPV6 = 4
private const val TOKEN = "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU"

private fun declaredLength(framed: ByteArray): Int =
    ((framed[4].toInt() and 0xff) shl 24) or ((framed[5].toInt() and 0xff) shl 16) or
        ((framed[6].toInt() and 0xff) shl 8) or (framed[7].toInt() and 0xff)
