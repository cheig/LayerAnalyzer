// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import com.example.layanalyzer.capture.tls.SocksNioTlsGateway
import com.example.layanalyzer.capture.tls.TlsGatewayChannel
import com.example.layanalyzer.capture.tls.TlsRoutingPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.DataOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Real RFC 1929/1928 sockets: long UDP controls must not starve TCP or admission. */
class SocksSessionCapacityTest {
    private val loopback = InetAddress.getByName("127.0.0.1")

    private fun server(gateway: SocksNioTlsGateway? = null) = DirectSocks5Server(
        prepareTcp = {}, prepareUdp = {},
        resolveHost = { arrayOf(InetAddress.getByName(it)) }, tlsGateway = gateway,
        runtimeLimits = com.example.layanalyzer.capture.socks.SocksRuntimeLimits(64, 64, 64)
    )

    @Test
    fun `64 live UDP associations leave direct TCP TLS gateway and authentication available`() {
        EchoOrigin().use { origin -> EchoOrigin(gateway = true).use { hop ->
            val gateway = TlsGatewayChannel(hop.port, "A".repeat(43).toByteArray(), "capacity", 1,
                TlsRoutingPolicy.freeze(TlsCaptureSettings(enabled = true, candidatePorts = setOf(443))), {})
            server(gateway = gateway).use { socks ->
                socks.start()
                val udp = ArrayList<Client>()
                try {
                    repeat(64) { udp += client(socks, command = 3).also { assertEquals(0, it.reply) } }
                    assertEquals(SocksBudgetStats(64, 64, 64), socks.sessionStats().udp)
                    client(socks, command = 3).use { assertEquals(1, it.reply) }
                    client(socks, port = origin.port).use { tcp ->
                        assertEquals(0, tcp.reply)
                        assertEcho(tcp, 42)
                    }
                    client(socks, port = 443).use { tls ->
                        assertEquals(0, tls.reply)
                        assertEcho(tls, 43)
                    }
                    assertEquals(1, hop.gatewayConnections.get())
                    assertEquals(1L, socks.sessionStats().rejectedUdp)
                    assertEquals(0L, socks.sessionStats().rejectedTcp)
                    assertEquals(0L, socks.sessionStats().rejectedHandshakes)
                } finally {
                    udp.forEach { it.close() }
                }
            }
        } }
    }

    @Test
    fun `TCP saturation leaves UDP available and closed TCP slots are reusable`() {
        EchoOrigin().use { origin -> server().use { socks ->
            socks.start()
            val clients = ArrayList<Client>()
            try {
                repeat(64) { clients += client(socks, port = origin.port).also { assertEquals(0, it.reply) } }
                client(socks, port = origin.port).use { assertEquals(1, it.reply) }
                client(socks, command = 3).use { udp ->
                    assertEquals(0, udp.reply)
                    udpEcho(udp)
                }
                clients.forEachIndexed { index, tcp -> assertEcho(tcp, index) }
                clients.removeAt(clients.lastIndex).close()
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                while (socks.sessionStats().tcp.current != 63 && System.nanoTime() < deadline) Thread.sleep(5)
                assertEquals(63, socks.sessionStats().tcp.current)
                client(socks, port = origin.port).use { assertEcho(it, 56) }
                assertEquals(1L, socks.sessionStats().rejectedTcp)
                assertEquals(0L, socks.sessionStats().rejectedUdp)
            } finally { clients.forEach { it.close() } }
        } }
    }

    // The production 10-second idle expiry is covered by SocksNioProductionTest;
    // UdpIdleTimeoutTest drives the 10/60-second activity boundaries with a monotonic clock.

    @Test
    fun `stopping server closes UDP controls and direct TCP sessions`() {
        EchoOrigin().use { origin ->
            val socks = server()
            socks.start()
            try {
                client(socks, command = 3).use { udp ->
                    client(socks, port = origin.port).use { tcp ->
                        assertEcho(tcp, 7)
                        socks.close()
                        assertEquals(0, socks.sessionStats().handshakes.current)
                        assertEquals(SocksBudgetStats(0, 1, 64), socks.sessionStats().tcp)
                        assertEquals(SocksBudgetStats(0, 1, 64), socks.sessionStats().udp)
                        assertEquals(-1, udp.input.read())
                        assertEquals(-1, tcp.input.read())
                    }
                }
            } finally {
                socks.close()
            }
        }
    }

    @Test
    fun `stop releases queued authentication admissions and preserves their event peak`() {
        val socks = server()
        val clients = ArrayList<Socket>()
        try {
            socks.start()
            repeat(40) { clients += Socket(loopback, socks.port) }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (socks.sessionStats().handshakes.current != 40 && System.nanoTime() < deadline) {
                Thread.sleep(5)
            }
            assertEquals(SocksBudgetStats(40, 40, 64), socks.sessionStats().handshakes)
            socks.close()
            socks.close()
            assertEquals(SocksBudgetStats(0, 40, 64), socks.sessionStats().handshakes)
            assertEquals(false, socks.sessionStats().running)
            assertEquals(0, socks.sessionStats().tcp.peak)
        } finally {
            clients.forEach { it.close() }
            socks.close()
        }
    }

    @Test
    fun `authentication failures are counted even between resource samples`() {
        server().use { socks ->
            socks.start()
            repeat(3) {
                Socket(loopback, socks.port).use { client ->
                    client.soTimeout = 5000
                    client.getOutputStream().write(byteArrayOf(5, 1, 0))
                    assertEquals(5, client.getInputStream().read())
                    assertEquals(255, client.getInputStream().read())
                    assertEquals(-1, client.getInputStream().read())
                }
            }
            socks.close()
            assertEquals(3L, socks.nioStats().failureEvents["authentication_rejected"])
            assertEquals(3L, socks.sessionStats().failureEvents["authentication_rejected"])
            assertTrue(socks.sessionStats().handshakes.peak >= 1)
            assertEquals(0, socks.sessionStats().tcp.peak)
        }
    }

    private fun client(socks: DirectSocks5Server, command: Int = 1, port: Int = 0): Client {
        val socket = Socket(loopback, socks.port)
        try {
            socket.soTimeout = 5_000
            val input = DataInputStream(socket.getInputStream())
            val output = socket.getOutputStream()
            output.write(byteArrayOf(5, 1, 2))
            assertEquals(5, input.readUnsignedByte())
            assertEquals(2, input.readUnsignedByte())
            val user = socks.credentials.username.toByteArray(Charsets.US_ASCII)
            val password = socks.credentials.password.toByteArray(Charsets.US_ASCII)
            output.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(password.size.toByte()) + password)
            assertEquals(1, input.readUnsignedByte())
            assertEquals(0, input.readUnsignedByte())
            output.write(byteArrayOf(5, command.toByte(), 0, 1) + loopback.address +
                byteArrayOf((port ushr 8).toByte(), port.toByte()))
            assertEquals(5, input.readUnsignedByte())
            val reply = input.readUnsignedByte()
            input.readUnsignedByte()
            val addressType = input.readUnsignedByte()
            input.readFully(ByteArray(if (addressType == 1) 4 else 16))
            val boundPort = input.readUnsignedShort()
            return Client(socket, input, reply, boundPort)
        } catch (error: Throwable) {
            socket.close()
            throw error
        }
    }

    private fun assertEcho(client: Client, value: Int) {
        assertEquals(0, client.reply)
        client.socket.getOutputStream().write(value)
        assertEquals(value, client.input.readUnsignedByte())
    }

    private fun udpEcho(client: Client, rounds: Int = 1, pauseMillis: Long = 0) {
        DatagramSocket(InetSocketAddress(loopback, 0)).use { origin ->
            DatagramSocket().use { sender ->
                origin.soTimeout = 5_000
                sender.soTimeout = 5_000
                val framed = byteArrayOf(0, 0, 0, 1) + loopback.address +
                    byteArrayOf((origin.localPort ushr 8).toByte(), origin.localPort.toByte(), 99)
                repeat(rounds) {
                    sender.send(DatagramPacket(framed, framed.size, loopback, client.boundPort))
                    val received = DatagramPacket(ByteArray(32), 32)
                    origin.receive(received)
                    assertEquals(99, received.data[received.offset].toInt())
                    origin.send(DatagramPacket(byteArrayOf(100), 1, received.socketAddress))
                    sender.receive(received)
                    assertEquals(100, received.data[received.offset + received.length - 1].toInt())
                    if (pauseMillis > 0) Thread.sleep(pauseMillis)
                }
            }
        }
    }

    private class Client(
        val socket: Socket,
        val input: DataInputStream,
        val reply: Int,
        val boundPort: Int
    ) : Closeable {
        override fun close() = socket.close()
    }

    private inner class EchoOrigin(private val gateway: Boolean = false) : Closeable {
        val gatewayConnections = AtomicInteger()
        private val server = ServerSocket(0, 64, loopback)
        private val peers = CopyOnWriteArrayList<Socket>()
        private val workers = Executors.newCachedThreadPool()
        val port: Int get() = server.localPort

        init {
            workers.execute {
                while (!server.isClosed) {
                    val peer = try { server.accept() } catch (_: java.io.IOException) { break }
                    peers += peer
                    workers.execute {
                        peer.use {
                            try {
                                if (gateway) {
                                    val input = DataInputStream(it.getInputStream())
                                    check(input.readInt() == 0x4c415431)
                                    val length = input.readInt()
                                    check(length in 1..8192)
                                    input.readFully(ByteArray(length))
                                    gatewayConnections.incrementAndGet()
                                    val ready = """{"version":1,"success":true}""".toByteArray()
                                    DataOutputStream(it.getOutputStream()).apply {
                                        writeInt(0x4c415431); writeInt(ready.size); write(ready); flush()
                                    }
                                }
                                it.getInputStream().copyTo(it.getOutputStream())
                            } catch (_: java.io.IOException) { }
                        }
                    }
                }
            }
        }

        override fun close() {
            server.close()
            peers.forEach { it.close() }
            workers.shutdownNow()
            assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS))
        }
    }
}
