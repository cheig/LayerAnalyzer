// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.BuildConfig
import com.example.layanalyzer.capture.DirectSocks5Server
import java.io.File
import java.net.InetAddress
import java.net.Socket
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class SocksRuntimeLimitsTest {
    @Test fun sharedVectorsFreezeProductionAdmissionAndInfrastructure() {
        val file = listOf(File("docs/fixtures/socks-nio/runtime-capacity-v2.json"),
            File("../docs/fixtures/socks-nio/runtime-capacity-v2.json")).first { it.isFile }
        val vectors = JSONObject(file.readText()).getJSONArray("vectors")
        assertEquals(31, vectors.length())
        for (index in 0 until vectors.length()) {
            val row = vectors.getJSONObject(index)
            val value = row.getJSONObject("effective")
            val limits = SocksRuntimeLimits(value.getInt("tcp"), value.getInt("udp"), value.getInt("authentication"), value.getInt("tlsHandshakes"))
            assertEquals(value.toMap(), limits.encode().toMap())
            val config = limits.eventLoopConfig()
            assertEquals(limits, config.runtimeLimits)
            assertEquals(limits.authentication + limits.tcp + limits.udp + 1, config.resourceCapacity)
            assertEquals(limits.authentication + 2 * limits.tcp + 3 * limits.udp + 1, config.channelCapacity)
            assertThrows(IllegalArgumentException::class.java) { config.copy(channelCapacity = config.channelCapacity + 1) }
            assertThrows(IllegalArgumentException::class.java) { config.copy(resourceCapacity = config.resourceCapacity + 1) }
            assertThrows(IllegalArgumentException::class.java) { config.copy(timerCapacity = config.timerCapacity + 1) }
            DirectSocks5Server({}, {}, { arrayOf(InetAddress.getLoopbackAddress()) },
                   runtimeLimits = limits).use { server ->
                server.start(7)
                val stats = server.nioStats()
                assertEquals(limits, stats.effectiveRuntime)
                assertEquals(limits.authentication, stats.server.admission!!.handshakes.limit)
                assertEquals(limits.tcp, stats.server.admission!!.tcp.limit)
                assertEquals(limits.udp, stats.server.admission!!.udp.limit)
                assertEquals(limits.tcpBufferBytes, stats.bufferCapacityBytes)
                assertEquals(2, stats.eventLoopThreadsAlive)
                server.close()
                assertEquals(0, server.sessionStats().tcp.current)
                assertEquals(0, server.sessionStats().udp.current)
                assertEquals(0, server.sessionStats().handshakes.current)
            }
        }
    }
    @Test fun authentication128SaturatesAndRecoversWithoutConsumingTcpOrUdp() {
        val limits = SocksRuntimeLimits(128, 128, 128)
        DirectSocks5Server({}, {}, { arrayOf(InetAddress.getLoopbackAddress()) },
               runtimeLimits = limits).use { server ->
            val port = server.start(7)
            val peers = mutableListOf<Socket>()
            fun await(condition: () -> Boolean) {
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
                while (!condition()) { check(System.nanoTime() < deadline); Thread.sleep(1) }
            }
            fun pending() = Socket().apply { connect(InetSocketAddress("127.0.0.1", port), 3000); soTimeout = 3000 }
            try {
                repeat(128) { count -> peers += pending(); await { server.sessionStats().handshakes.current == count + 1 } }
                pending().use { assertEquals(-1, it.getInputStream().read()) }
                await { server.sessionStats().rejectedHandshakes == 1L }
                assertEquals(0, server.sessionStats().tcp.current)
                assertEquals(0, server.sessionStats().udp.current)
                repeat(32) { peers.removeAt(0).close() }
                await { server.sessionStats().handshakes.current == 96 }
                repeat(32) { count -> peers += pending(); await { server.sessionStats().handshakes.current == 97 + count } }
                assertEquals(128, server.sessionStats().handshakes.peak)
                assertEquals(2, server.nioStats().eventLoopThreadsAlive)
            } finally { peers.forEach { it.close() } }
            server.close()
            assertEquals(0, server.sessionStats().handshakes.current)
        }
    }

    @Test fun invalidLimitsNeverSilentlyClamp() {
        assertThrows(IllegalArgumentException::class.java) { SocksRuntimeLimits(tcp = 65) }
        assertThrows(IllegalArgumentException::class.java) { SocksRuntimeLimits(udp = 512) }
        assertThrows(IllegalArgumentException::class.java) { SocksRuntimeLimits(authentication = 129) }
        assertThrows(IllegalArgumentException::class.java) { SocksRuntimeLimits(tlsHandshakes = 9) }
    }

    @Test fun expandedDefaultsDoNotClaimCompletedDeviceAcceptance() {
        val limits = SocksRuntimeLimits()
        assertEquals(1024, limits.tcp)
        assertEquals(256, limits.udp)
        assertEquals(128, limits.authentication)
        assertEquals(8, limits.tlsHandshakes)
        assertEquals(32 * 1024 * 1024, limits.tcpBufferBytes)
        assertFalse(limits.deviceAccepted)
        assertTrue(SocksRuntimeLimits(64, 64, 64).deviceAccepted)
        assertEquals("NIO", limits.encode().getString("mode"))
    }

    @Test fun frozenBuildConfigurationUsesExpandedDefaultsOrAnExplicitFiniteTier() {
        val frozen = SocksRuntimeLimits(BuildConfig.SOCKS_TCP_LIMIT,
            BuildConfig.SOCKS_UDP_LIMIT, BuildConfig.SOCKS_AUTH_LIMIT)
        assertEquals(8, frozen.tlsHandshakes)
        assertEquals("NIO", frozen.encode().getString("mode"))
        assertEquals(frozen.tcp * 2 * 16 * 1024, frozen.tcpBufferBytes)
    }
}
