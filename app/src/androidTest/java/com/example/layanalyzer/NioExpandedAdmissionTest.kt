// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.SocksUdpRequest
import com.example.layanalyzer.capture.socks.SocksProtocol
import com.example.layanalyzer.capture.socks.SocksRuntimeLimits
import java.io.DataInputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Full configured admission, including UDP control-close recovery. This is not a TUN soak. */
@RunWith(AndroidJUnit4::class)
class NioExpandedAdmissionTest {
    @Test fun configuredTcpAndUdpSaturateIndependentlyAndRecover() {
        val args = InstrumentationRegistry.getArguments()
        val runId = args.getString("nio601RunId")
        assumeTrue("Opt-in controlled capacity fixture", runId != null)
        require(requireNotNull(runId).matches(Regex("[a-f0-9]{32}")))
        NativeTestSupport.awaitApplicationEngine()
        val context = ApplicationProvider.getApplicationContext<Context>()
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val network = requireNotNull(connectivity.activeNetwork)
        assertFalse(connectivity.getNetworkCapabilities(network)!!.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
        val host = InetAddress.getByName(requireNotNull(args.getString("hostGateway")))
        val tcpPort = requireNotNull(args.getString("hostTcpPort")).toInt()
        val udpPort = requireNotNull(args.getString("hostUdpPort")).toInt()
        val limits = SocksRuntimeLimits(BuildConfig.SOCKS_TCP_LIMIT,
            BuildConfig.SOCKS_UDP_LIMIT, BuildConfig.SOCKS_AUTH_LIMIT)
        assertEquals(1024, limits.tcp)
        assertEquals(256, limits.udp)
        assertEquals(128, limits.authentication)
        assertEquals(8, limits.tlsHandshakes)
        val out = File(context.getExternalFilesDir(null), "nio-601/$runId").apply { mkdirs() }
        val server = DirectSocks5Server(
            prepareTcp = { network.bindSocket(it); it.tcpNoDelay = true },
            prepareUdp = { network.bindSocket(it) },
            resolveHost = { network.getAllByName(it) },
            generateCredentials = { SocksCredentials.of("u", "p") }, runtimeLimits = limits)
        val sampler = ProcessResourceSampler(File(out, "expanded-admission.jsonl"), runId,
            sessions = { server.sessionStats() })
        val clients = mutableListOf<Socket>()
        val associations = mutableListOf<UdpLink>()
        fun await(what: String, condition: () -> Boolean) {
            val deadline = SystemClock.elapsedRealtime() + 5000
            while (!condition()) {
                assertTrue(what, SystemClock.elapsedRealtime() < deadline)
                SystemClock.sleep(5)
            }
        }
        fun request(command: Int, port: Int): Pair<Socket, ByteArray> {
            val peer = Socket()
            try {
                peer.soTimeout = 5000
                peer.tcpNoDelay = true
                peer.connect(InetSocketAddress("127.0.0.1", server.port), 5000)
                peer.getOutputStream().write(byteArrayOf(5, 1, 2, 1, 1, 117, 1, 112) +
                    SocksProtocol.encodeRequest(SocksRequest(command, SocksDestination.Ip(host), port)))
                val input = DataInputStream(peer.getInputStream())
                assertEquals(0x0502, input.readUnsignedShort())
                assertEquals(0x0100, input.readUnsignedShort())
                val header = ByteArray(4).also(input::readFully)
                val tail = ByteArray(if (header[3].toInt() == 1) 6 else 18).also(input::readFully)
                return peer to (header + tail)
            } catch (error: Throwable) { peer.close(); throw error }
        }
        fun tcp(): Socket {
            val (peer, reply) = request(SocksProtocol.COMMAND_CONNECT, tcpPort)
            try { assertEquals(0, reply[1].toInt()); return peer }
            catch (error: Throwable) { peer.close(); throw error }
        }
        fun echo(peer: Socket) {
            val payload = byteArrayOf(9, 8, 7, 6)
            peer.getOutputStream().write(payload)
            assertArrayEquals(payload, ByteArray(payload.size).also { DataInputStream(peer.getInputStream()).readFully(it) })
        }
        fun udp(): UdpLink {
            val (peer, reply) = request(SocksProtocol.COMMAND_UDP_ASSOCIATE, 0)
            try {
                assertEquals(0, reply[1].toInt())
                val relay = InetSocketAddress(InetAddress.getByAddress(reply.copyOfRange(4, 8)),
                    ((reply[8].toInt() and 255) shl 8) or (reply[9].toInt() and 255))
                return UdpLink(peer, relay)
            } catch (error: Throwable) { peer.close(); throw error }
        }
        fun echo(link: UdpLink) {
            val body = byteArrayOf(3, 4, 5, 6)
            val wire = SocksProtocol.encodeUdpRequest(SocksUdpRequest(SocksDestination.Ip(host), udpPort, body))
            link.socket.send(DatagramPacket(wire, wire.size, link.relay))
            val reply = DatagramPacket(ByteArray(1024), 1024)
            link.socket.receive(reply)
            assertArrayEquals(body, requireNotNull(SocksProtocol.decodeUdpRequest(reply.data, length = reply.length)).payload)
        }
        try {
            sampler.sample("before")
            server.start()
            repeat(limits.tcp) { clients += tcp().also(::echo) }
            await("all TCP admitted") { server.sessionStats().tcp.current == limits.tcp }
            request(SocksProtocol.COMMAND_CONNECT, tcpPort).let { (peer, reply) ->
                peer.use { assertEquals(SocksProtocol.REPLY_GENERAL_FAILURE, reply[1].toInt()) }
            }
            await("TCP excess counted once") { server.sessionStats().rejectedTcp == 1L }
            repeat(limits.udp) { associations += udp().also(::echo) }
            await("UDP independent of full TCP") { server.sessionStats().udp.current == limits.udp }
            request(SocksProtocol.COMMAND_UDP_ASSOCIATE, 0).let { (peer, reply) ->
                peer.use { assertEquals(SocksProtocol.REPLY_GENERAL_FAILURE, reply[1].toInt()) }
            }
            await("UDP excess counted once") { server.sessionStats().rejectedUdp == 1L }
            val full = sampler.sample("both_populations_full")
            assertEquals(2, server.nioStats().eventLoopThreadsAlive)
            assertEquals(limits.tcpBufferBytes, server.nioStats().bufferCapacityBytes)
            clients.forEach(::echo)
            associations.forEach(::echo)
            clients.removeAt(0).close()
            associations.removeAt(0).close()
            await("both protocol slots released") {
                server.sessionStats().tcp.current == limits.tcp - 1 &&
                    server.sessionStats().udp.current == limits.udp - 1
            }
            clients += tcp().also(::echo)
            associations += udp().also(::echo)
            await("both populations recovered") {
                server.sessionStats().tcp.current == limits.tcp && server.sessionStats().udp.current == limits.udp
            }
            assertEquals(0L, server.sessionStats().rejectedHandshakes)
            assertEquals(1L, server.sessionStats().rejectedTcp)
            assertEquals(1L, server.sessionStats().rejectedUdp)
            val start = SystemClock.elapsedRealtime()
            server.close()
            val stopMs = SystemClock.elapsedRealtime() - start
            assertTrue("stop <= 5s", stopMs <= 5000)
            assertEquals(0, server.sessionStats().tcp.current)
            assertEquals(0, server.sessionStats().udp.current)
            assertEquals(0, server.sessionStats().handshakes.current)
            assertEquals(0, server.nioStats().buffers!!.reservedBytes)
            assertEquals(0, server.nioStats().udp!!.scratchBytes)
            clients.forEach { it.close() }; associations.forEach { it.close() }
            val stopped = sampler.sample("stopped")
            File(out, "expanded-admission-result.json").writeText(JSONObject().put("status", "PASS")
                .put("runtime", limits.encode()).put("scope", "production facade, physical LAN, no TUN or TLS")
                .put("tcpExcessRefused", 1).put("udpExcessRefused", 1).put("bothRecovered", true)
                .put("stopMs", stopMs).put("full", full).put("stopped", stopped).toString(2))
        } finally {
            server.close()
            clients.forEach { runCatching { it.close() } }
            associations.forEach { runCatching { it.close() } }
            sampler.close()
        }
    }

    private class UdpLink(val control: Socket, val relay: InetSocketAddress) : AutoCloseable {
        val socket = DatagramSocket().apply { soTimeout = 5000 }
        override fun close() { socket.close(); control.close() }
    }
}
