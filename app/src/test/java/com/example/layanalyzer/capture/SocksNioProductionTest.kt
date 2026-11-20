// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture

import com.example.layanalyzer.capture.socks.SocksNioServer
import com.example.layanalyzer.capture.socks.SocksProtocol
import com.example.layanalyzer.capture.tls.SocksNioTlsGateway
import com.example.layanalyzer.capture.tls.TlsGatewayChannel
import com.example.layanalyzer.capture.tls.TlsRoutingPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.DataInputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Real production facade, OS channels and wire protocols; no replacement relay/handshake. */
class SocksNioProductionTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val auth = byteArrayOf(5, 1, 2, 1, 1, 117, 1, 112)

    @Test fun defaultUsesNioWithExpandedCapacity() {
        DirectSocks5Server({}, {}, { arrayOf(loopback) }).use {
            assertEquals("NIO", it.nioStats().mode)
            assertEquals(1024, it.runtimeLimits.tcp)
            assertEquals(256, it.runtimeLimits.udp)
            assertEquals(128, it.runtimeLimits.authentication)
            assertEquals(8, it.runtimeLimits.tlsHandshakes)
            it.start()
            assertEquals(2, it.nioStats().eventLoopThreadsAlive)
        }
    }

    @Test fun nativeChannelsPreservePipelinedPayloadHalfCloseAndCumulativeBytes() {
        endpoint().use { target -> server(prepareTcp = {
            assertNotNull(it.channel)
            assertFalse(it.isConnected)
            assertFalse(it.isBound)
            assertTrue(Thread.currentThread().name.startsWith("SocksNio-"))
        }).use { socks ->
            socks.start(71)
            assertEquals(71L, socks.nioStats().runResolver!!.networkGeneration)
            assertEquals("NIO", socks.nioStats().mode)
            val payload = ByteArray(73_913) { (it * 19).toByte() }
            connect(socks, target.localPort, payload = payload).use { client -> target.accept().use { peer ->
                peer.soTimeout = 3000
                assertSuccess(client)
                client.shutdownOutput()
                assertArrayEquals(payload, read(peer, payload.size))
                assertEquals(-1, peer.getInputStream().read())
                val response = byteArrayOf(9, 8, 7, 6)
                peer.getOutputStream().write(response)
                peer.shutdownOutput()
                assertArrayEquals(response, read(client, response.size))
                assertEquals(-1, client.getInputStream().read())
                await { socks.sessionStats().tcp.current == 0 }
                assertEquals(payload.size.toLong(), socks.stats().sentBytes)
                assertEquals(4L, socks.stats().receivedBytes)
                assertEquals(2, socks.nioStats().eventLoopThreadsAlive)
                assertFixedOwners(socks)
            } }
            socks.close()
            assertClean(socks)
            assertEquals(payload.size.toLong(), socks.stats().sentBytes)
        } }
    }

    @Test fun pendingAuthenticationDnsAndReadyDoNotBlockDirectTcpOrUdp() {
        val dnsStarted = CountDownLatch(1)
        val releaseDns = CountDownLatch(1)
        val dnsThread = arrayOfNulls<String>(1)
        endpoint().use { gatewayListener -> endpoint().use { target -> udpEndpoint().use { udpTarget ->
            val gateway = gateway(gatewayListener.localPort)
            server(gateway, lookup = {
                dnsThread[0] = Thread.currentThread().name
                dnsStarted.countDown()
                releaseDns.await(5, TimeUnit.SECONDS)
                arrayOf(loopback)
            }).use { socks ->
                try {
                    socks.start(88)
                    raw(socks).use { slowAuth ->
                        slowAuth.getOutputStream().write(byteArrayOf(5))
                        connect(socks, target.localPort, SocksDestination.Domain("held.example")).use { dns ->
                            assertTrue(dnsStarted.await(3, TimeUnit.SECONDS))
                            assertTrue(dnsThread[0]!!.startsWith("SocksDns-"))
                            connect(socks, 443, payload = byteArrayOf(22, 3, 3)).use { tls -> gatewayListener.accept().use { hop ->
                                hop.soTimeout = 3000
                                val frame = readFrame(hop)
                                assertEquals(7L, frame.getLong("networkGeneration"))
                                assertEquals("127.0.0.1", frame.getString("destinationAddress"))
                                noData(tls)
                                noData(hop) // client payload is retained until READY and success drain
                                connect(socks, target.localPort).use { plain -> target.accept().use { peer ->
                                    peer.soTimeout = 3000
                                    assertSuccess(plain)
                                    exchange(plain, peer, byteArrayOf(1, 2, 3, 4, 5))
                                    udpLink(socks).use { link -> udpExchange(link, udpTarget, byteArrayOf(7, 8)) }
                                } }
                                ready(hop)
                                assertSuccess(tls)
                                assertArrayEquals(byteArrayOf(22, 3, 3), read(hop, 3))
                                exchange(tls, hop, byteArrayOf(55, 56))
                                assertEquals(2, socks.nioStats().eventLoopThreadsAlive)
                                assertFixedOwners(socks)
                            } }
                            releaseDns.countDown()
                            target.accept().use { peer -> assertSuccess(dns); peer.soTimeout = 3000 }
                        }
                    }
                } finally { releaseDns.countDown() }
            }
        } } }
    }

    @Test fun unavailableGatewayAndReadyRefusalNeverConnectDirectly() {
        endpoint().use { listener ->
            val directPrepares = AtomicInteger()
            val tlsGateway = gateway(listener.localPort)
            server(tlsGateway, prepareTcp = { directPrepares.incrementAndGet() }).use { socks ->
                socks.start()
                connect(socks, 443).use { client -> listener.accept().use { hop ->
                    hop.soTimeout = 3000
                    readFrame(hop)
                    ready(hop, success = false)
                    assertEquals(SocksProtocol.REPLY_GENERAL_FAILURE, reply(client)[1].toInt())
                } }
                await { socks.nioStats().gateway!!.refusals == 1L }
                tlsGateway.close()
                connect(socks, 443).use { client ->
                    assertEquals(SocksProtocol.REPLY_GENERAL_FAILURE, reply(client)[1].toInt())
                }
                assertEquals(0, directPrepares.get())
                assertEquals(0L, socks.nioStats().gatewayRelays)
            }
        }
    }

    @Test fun udpInterventionAndByteTotalsStayCompatibleAfterStop() {
        udpEndpoint().use { target -> server(policy = UdpDestinationPolicy { _, port ->
            if (port == 443) UdpVerdict.BlockSelectedUdp443 else UdpVerdict.Forward
        }, prepareUdp = {
            assertNotNull(it.channel)
            assertFalse(it.isBound)
            assertTrue(Thread.currentThread().name.startsWith("SocksNio-"))
        }).use { socks ->
            socks.start()
            udpLink(socks).use { link ->
                udpExchange(link, target, byteArrayOf(2, 3, 4, 5))
                link.send(443, byteArrayOf(1, 2, 3))
                await { socks.udpInterventionStats().blockedDatagrams == 1L }
                assertEquals(3L, socks.udpInterventionStats().blockedBytes)
                assertEquals(4L, socks.stats().sentBytes)
                assertEquals(4L, socks.stats().receivedBytes)
            }
            socks.close()
            assertClean(socks)
            assertEquals(1L, socks.udpInterventionStats().blockedDatagrams)
            assertEquals(4L, socks.stats().sentBytes)
        } }
    }

    @Test fun authenticationCapacityRejectsAndRecoversWithoutWorkerThreads() {
        server().use { socks ->
            socks.start()
            val clients = mutableListOf<Socket>()
            try {
                repeat(64) { index ->
                    clients.add(raw(socks))
                    // Capacity test: wait for acceptance so the OS listener backlog is not the limit.
                    await { socks.sessionStats().handshakes.current == index + 1 }
                }
                raw(socks).use { assertEquals(-1, it.getInputStream().read()) }
                await { socks.sessionStats().rejectedHandshakes == 1L }
                assertEquals(64, socks.sessionStats().handshakes.peak)
                assertFixedOwners(socks)
            } finally { clients.forEach(Socket::close) }
            await { socks.sessionStats().handshakes.current == 0 }
            raw(socks).use {
                it.getOutputStream().write(auth)
                assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
            }
            socks.close()
            assertClean(socks)
            assertEquals(1L, socks.sessionStats().rejectedHandshakes)
        }
    }

    @Test fun stopTimeoutIsVisibleAndDoesNotWipeInputsStillOwnedByLoop() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val creds = SocksCredentials.of("u", "p")
        val socks = server(credentials = { creds }, prepareTcp = {
            entered.countDown()
            release.await(5, TimeUnit.SECONDS) // deliberately broken platform callback
        })
        try {
            socks.start()
            connect(socks, 12345).use {
                assertTrue(entered.await(3, TimeUnit.SECONDS))
                assertThrows(IOException::class.java) { socks.close() }
                assertEquals(SocksNioServer.State.STOPPING, socks.nioStats().server.state)
                val report = CaptureCompletenessReport.append(JSONObject().put("complete", true), socks.runtimeLimits,
                    socks.sessionStats(), socks.nioStats(), null, true)
                assertTrue(report.getJSONObject("nio").getBoolean("cleanupIncomplete"))
                assertEquals("INCOMPLETE", CaptureReportIntegrity.read(report).cleanup)
                assertTrue(report.getBoolean("complete"))
                assertTrue(creds.matches(byteArrayOf(117), byteArrayOf(112)))
                assertEquals(1, socks.sessionStats().tcp.current)
                assertThrows(IllegalStateException::class.java) { socks.start() }
                release.countDown()
            }
            socks.close()
            assertClean(socks)
            assertFalse(creds.matches(byteArrayOf(117), byteArrayOf(112)))
        } finally { release.countDown(); socks.close() }
    }

    @Test fun udpIdleExpiryIsRetainedInFacadeFinalSnapshot() {
        server().use { socks ->
            socks.start()
            udpLink(socks).use { link ->
                link.control.soTimeout = 13_000
                assertEquals(-1, link.control.getInputStream().read())
            }
            await { socks.sessionStats().expiredUdp == 1L }
            socks.close()
            assertClean(socks)
            assertEquals(1L, socks.sessionStats().expiredUdp)
            assertEquals(1L, socks.sessionStats().failureEvents["udp_idle"])
        }
    }

    @Test fun freshRunsFreezeNetworkGenerationAndCredentialsAfterCompleteStop() {
        server().use { socks ->
            val sampling = AtomicBoolean(true)
            val sampler = thread(name = "Nio501-stats") {
                while (sampling.get()) { socks.nioStats(); Thread.yield() }
            }
            try { repeat(20) { index ->
                socks.start(index.toLong())
                val creds = socks.credentials
                assertEquals(index.toLong(), socks.nioStats().runResolver!!.networkGeneration)
                raw(socks).use {
                    it.getOutputStream().write(auth)
                    assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
                }
                socks.close()
                assertClean(socks)
                assertFalse(creds.matches(byteArrayOf(117), byteArrayOf(112)))
                assertThrows(IllegalStateException::class.java) { socks.credentials }
            } } finally { sampling.set(false); sampler.join(3000); assertFalse(sampler.isAlive) }
        }
    }

    private fun server(gateway: SocksNioTlsGateway? = null,
        lookup: (String) -> Array<InetAddress> = { error("literal entered DNS") },
        prepareTcp: (Socket) -> Unit = {}, prepareUdp: (DatagramSocket) -> Unit = {},
        policy: UdpDestinationPolicy = UdpDestinationPolicy.PRESERVE,
        credentials: () -> SocksCredentials = { SocksCredentials.of("u", "p") }) = DirectSocks5Server(
            prepareTcp, prepareUdp, lookup, generateCredentials = credentials, tlsGateway = gateway,
            udpPolicy = policy, runtimeLimits = com.example.layanalyzer.capture.socks.SocksRuntimeLimits(64, 64, 64))
    private fun gateway(port: Int) = TlsGatewayChannel(port,
        "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU".toByteArray(), "capture-501", 7,
        TlsRoutingPolicy.freeze(TlsCaptureSettings(enabled = true, candidatePorts = setOf(443))), {})
    private fun raw(socks: DirectSocks5Server) = Socket().apply {
        soTimeout = 3000
        connect(InetSocketAddress(loopback, socks.port))
    }
    private fun connect(socks: DirectSocks5Server, port: Int,
        destination: SocksDestination = SocksDestination.Ip(loopback), payload: ByteArray = byteArrayOf(),
        command: Int = SocksProtocol.COMMAND_CONNECT): Socket = raw(socks).also {
            it.getOutputStream().write(auth + SocksProtocol.encodeRequest(SocksRequest(command, destination, port)) + payload)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0), read(it, 4))
        }
    private fun endpoint() = ServerSocket(0, 64, loopback).apply { soTimeout = 3000 }
    private fun udpEndpoint() = DatagramSocket(0, loopback).apply { soTimeout = 3000 }
    private fun read(socket: Socket, size: Int) = ByteArray(size).also { DataInputStream(socket.getInputStream()).readFully(it) }
    private fun reply(socket: Socket): ByteArray {
        val header = read(socket, 4)
        return header + read(socket, if (header[3].toInt() == 1) 6 else 18)
    }
    private fun assertSuccess(socket: Socket) { assertEquals(0, reply(socket)[1].toInt()) }
    private fun exchange(client: Socket, peer: Socket, bytes: ByteArray) {
        client.getOutputStream().write(bytes)
        assertArrayEquals(bytes, read(peer, bytes.size))
        peer.getOutputStream().write(bytes.reversedArray())
        assertArrayEquals(bytes.reversedArray(), read(client, bytes.size))
    }
    private fun readFrame(hop: Socket): JSONObject {
        assertArrayEquals("LAT1".toByteArray(), read(hop, 4))
        return JSONObject(String(read(hop, ByteBuffer.wrap(read(hop, 4)).int)))
    }
    private fun ready(hop: Socket, success: Boolean = true) {
        val body = JSONObject().put("version", 1).put("success", success)
            .put("errorCode", if (success) JSONObject.NULL else "GATEWAY_CAPACITY").toString().toByteArray()
        hop.getOutputStream().write("LAT1".toByteArray() + ByteBuffer.allocate(4).putInt(body.size).array() + body)
    }
    private fun noData(socket: Socket) {
        socket.soTimeout = 80
        try { assertThrows(SocketTimeoutException::class.java) { socket.getInputStream().read() } }
        finally { socket.soTimeout = 3000 }
    }
    private inner class Link(val control: Socket, private val relay: InetSocketAddress) : AutoCloseable {
        val client = udpEndpoint()
        fun send(port: Int, bytes: ByteArray) {
            val wire = SocksProtocol.encodeUdpRequest(SocksUdpRequest(SocksDestination.Ip(loopback), port, bytes))
            client.send(DatagramPacket(wire, wire.size, relay))
        }
        override fun close() { client.close(); control.close() }
    }
    private fun udpLink(socks: DirectSocks5Server): Link {
        val control = connect(socks, 0, command = SocksProtocol.COMMAND_UDP_ASSOCIATE)
        val response = reply(control)
        assertEquals(0, response[1].toInt())
        return Link(control, InetSocketAddress(InetAddress.getByAddress(response.copyOfRange(4, 8)),
            ((response[8].toInt() and 255) shl 8) or (response[9].toInt() and 255)))
    }
    private fun udpExchange(link: Link, target: DatagramSocket, bytes: ByteArray) {
        link.send(target.localPort, bytes)
        val packet = DatagramPacket(ByteArray(65535), 65535).also(target::receive)
        assertArrayEquals(bytes, packet.data.copyOf(packet.length))
        target.send(DatagramPacket(packet.data, packet.length, packet.socketAddress))
        val response = DatagramPacket(ByteArray(65535), 65535).also(link.client::receive)
        assertArrayEquals(bytes, SocksProtocol.decodeUdpRequest(response.data, length = response.length)!!.payload)
    }
    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) { assertTrue("condition deadline", System.nanoTime() < deadline); Thread.sleep(2) }
    }
    private fun assertFixedOwners(server: DirectSocks5Server) {
        val expected = if (server.sessionStats().running) 2 else 0
        await { server.nioStats().eventLoopThreadsAlive == expected }
        assertFalse(Thread.getAllStackTraces().keys.any {
            it.isAlive && it.name.startsWith("LayerAnalyzer-SOCKS5")
        })
    }

    private fun assertClean(socks: DirectSocks5Server) {
        val stats = socks.nioStats()
        assertEquals(SocksNioServer.State.STOPPED, stats.server.state)
        assertFalse(socks.sessionStats().running)
        assertEquals(0, socks.sessionStats().handshakes.current)
        assertEquals(0, socks.sessionStats().tcp.current)
        assertEquals(0, socks.sessionStats().udp.current)
        assertEquals(0, stats.buffers!!.allocatedBytes)
        assertEquals(0, stats.buffers.reservedBytes)
        assertEquals(0, stats.udp!!.scratchBytes)
        assertEquals(0, stats.udp.queuedBytes)
        stats.server.loops.forEach { assertEquals(0, it.channels); assertEquals(0, it.resources); assertEquals(0, it.timers) }
        assertFixedOwners(socks)
    }
}
