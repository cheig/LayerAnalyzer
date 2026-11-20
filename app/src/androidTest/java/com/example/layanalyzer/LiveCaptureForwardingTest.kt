// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket

@RunWith(AndroidJUnit4::class)
class LiveCaptureForwardingTest {
    // The emulator reaches the host fixture through its loopback alias; a real
    // device has to reach a controlled LAN host instead, so let the runner pass
    // hostGateway/hostHttpPort while keeping the emulator default untouched.
    private val hostGateway = arguments.getString("hostGateway") ?: HOST_GATEWAY
    private val hostHttpPort =
        arguments.getString("hostHttpPort")?.toIntOrNull() ?: HOST_HTTP_PORT
    // A controlled UDP echo fixture (native_build/verification/tls/udp_echo_fixture.py).
    // The emulator reaches the host alias by default; a real device passes hostUdpPort.
    private val hostUdpPort =
        arguments.getString("hostUdpPort")?.toIntOrNull() ?: HOST_UDP_PORT
    private val connectivity = ApplicationProvider.getApplicationContext<Context>()
        .getSystemService(ConnectivityManager::class.java)
    private val arguments get() = InstrumentationRegistry.getArguments()

    @Test
    fun forwardsTcpAndCapturesBothDirections() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        assumeTrue("Host HTTP fixture is not running", hostFixtureAvailable())

        // Match the UI's new-capture setup. A persisted failure from an earlier
        // run must not satisfy the wait below before this service request starts.
        LiveCaptureStore.clearError()

        val startIntent = Intent(context, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
        }
        ContextCompat.startForegroundService(context, startIntent)

        try {
            waitUntil("capture did not start") {
                val state = LiveCaptureStore.state.value
                state.isCapturing || state.error != null
            }
            val started = LiveCaptureStore.state.value
            assertTrue(started.error ?: "capture failed to start", started.isCapturing)
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            waitUntil("VPN did not become the active transport") {
                connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }

            repeat(HTTP_REQUESTS) { iteration -> performHttpRequest(iteration) }
        } finally {
            context.startService(
                Intent(context, LiveCaptureVpnService::class.java)
                    .setAction(LiveCaptureVpnService.ACTION_STOP)
            )
        }

        waitUntil("capture did not stop") { !LiveCaptureStore.state.value.isCapturing }
        val stopped = LiveCaptureStore.state.value
        assertTrue(stopped.error ?: "capture ended with an error", stopped.error == null)
        assertTrue("too few packets were captured: ${stopped.packetCount}", stopped.packetCount > HTTP_REQUESTS * 2)
        val output = File(requireNotNull(stopped.outputPath))
        assertTrue("capture file is missing", output.length() > 24)

        val directions = readIpv4Directions(output.readBytes())
        assertTrue(
            "outbound request was not captured; addresses=$directions",
            directions.any { it.second == hostGateway }
        )
        assertTrue(
            "inbound response was not captured; addresses=$directions",
            directions.any { it.first == hostGateway }
        )
    }

    /**
     * TLS-214's remaining device gate: a UDP datagram must survive
     * TUN -> HEV -> authenticated SOCKS and come back, and both directions must be
     * captured. The echo round trip *is* the fixture-reachability check, so a
     * missing or unreachable UDP fixture fails here instead of skipping (a skip is
     * not a pass): a down fixture can never be reported as green.
     */
    @Test
    fun forwardsUdpAndCapturesBothDirections() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)

        LiveCaptureStore.clearError()

        val startIntent = Intent(context, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
        }
        ContextCompat.startForegroundService(context, startIntent)

        try {
            waitUntil("capture did not start") {
                val state = LiveCaptureStore.state.value
                state.isCapturing || state.error != null
            }
            val started = LiveCaptureStore.state.value
            assertTrue(started.error ?: "capture failed to start", started.isCapturing)
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            waitUntil("VPN did not become the active transport") {
                connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }

            assertTrue(
                "the UDP echo fixture at $hostGateway:$hostUdpPort must return the datagram " +
                    "through TUN -> HEV -> authenticated SOCKS",
                udpEchoRoundTrip()
            )
        } finally {
            context.startService(
                Intent(context, LiveCaptureVpnService::class.java)
                    .setAction(LiveCaptureVpnService.ACTION_STOP)
            )
        }

        waitUntil("capture did not stop") { !LiveCaptureStore.state.value.isCapturing }
        val stopped = LiveCaptureStore.state.value
        assertTrue(stopped.error ?: "capture ended with an error", stopped.error == null)
        val output = File(requireNotNull(stopped.outputPath))
        assertTrue("capture file is missing", output.length() > 24)

        val flows = readUdpFlows(output.readBytes())
        assertTrue(
            "the outbound UDP datagram to the fixture was not captured; " +
                "captured=${stopped.packetCount} udp=$flows ipv4=${describeIpv4(output.readBytes())}",
            flows.any { it.dst == hostGateway && it.dstPort == hostUdpPort }
        )
        assertTrue(
            "the inbound UDP echo from the fixture was not captured; " +
                "captured=${stopped.packetCount} udp=$flows ipv4=${describeIpv4(output.readBytes())}",
            flows.any { it.src == hostGateway && it.srcPort == hostUdpPort }
        )
    }

    /** Reproduces the shared-slot failure with 64 UDP flows on the real TUN path. */
    @Test
    fun udpBurstLeavesTcpAvailable() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        LiveCaptureStore.clearError()
        ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
            putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
        })
        val sockets = ArrayList<DatagramSocket>()
        try {
            waitUntil("capture did not start") { LiveCaptureStore.state.value.isCapturing }
            waitUntil("VPN did not become active") {
                connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
            val vpn = requireNotNull(connectivity.activeNetwork)
            val target = InetSocketAddress(hostGateway, hostUdpPort)
            val started = SystemClock.elapsedRealtime()
            repeat(64) { index ->
                val socket = DatagramSocket().also { sockets += it }
                vpn.bindSocket(socket)
                socket.soTimeout = 3_000
                val payload = "socks-udp-capacity-$index".toByteArray(Charsets.US_ASCII)
                socket.send(DatagramPacket(payload, payload.size, target))
                val reply = DatagramPacket(ByteArray(256), 256)
                socket.receive(reply)
                assertTrue(payload.contentEquals(reply.data.copyOfRange(reply.offset, reply.offset + reply.length)))
            }
            assertTrue("fixture too slow to fill 64 UDP slots before idle expiry",
                SystemClock.elapsedRealtime() - started < 45_000)
            repeat(3) { performHttpRequest(it, throughVpn = true) }
        } finally {
            sockets.forEach { it.close() }
            context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
        }
        waitUntil("capture did not stop") { !LiveCaptureStore.state.value.isCapturing }
        val stopped = LiveCaptureStore.state.value
        assertTrue(stopped.error ?: "capture failed", stopped.error == null)
        val output = File(requireNotNull(stopped.outputPath))
        val reportFile = File(output.parentFile, "${output.name}.report.json")
        waitUntil("capture report was not finalized") { reportFile.exists() }
        val report = JSONObject(reportFile.readText())
        val sessions = report.getJSONObject("socks")
        assertEquals(0L, sessions.getLong("rejectedTcpSessions"))
        assertEquals(0L, sessions.getLong("rejectedUdpSessions"))
        val flows = readUdpFlows(output.readBytes())
        assertTrue(flows.count { it.dst == hostGateway && it.dstPort == hostUdpPort } >= 64)
        assertTrue(flows.count { it.src == hostGateway && it.srcPort == hostUdpPort } >= 64)
        assertTrue(readIpv4Directions(output.readBytes()).any { it.first == hostGateway })
    }

    /**
     * Sends one datagram and waits for the verbatim echo. The first datagram can
     * race the SOCKS UDP association setup, so a bounded retry keeps the gate
     * deterministic without weakening it: the test still fails unless a real echo
     * comes back.
     */
    private fun udpEchoRoundTrip(): Boolean {
        DatagramSocket().use { socket ->
            socket.soTimeout = UDP_REPLY_TIMEOUT_MILLIS
            // Route the probe through the active VPN explicitly. A socket created
            // right after establishment can otherwise latch onto the physical
            // network and bypass the TUN; the echo would still return over the
            // direct path, so the round trip alone cannot detect it. Binding to the
            // VPN network guarantees the datagram actually traverses TUN -> HEV.
            val vpn = requireNotNull(connectivity.activeNetwork) {
                "the VPN must be the active network before the UDP probe"
            }
            assertTrue(
                "the VPN must be the active transport before the UDP probe",
                connectivity.getNetworkCapabilities(vpn)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            )
            vpn.bindSocket(socket)
            val target = InetSocketAddress(hostGateway, hostUdpPort)
            val payload = "layanalyzer-udp-${SystemClock.elapsedRealtime()}".toByteArray(Charsets.US_ASCII)
            repeat(UDP_ATTEMPTS) {
                socket.send(DatagramPacket(payload, payload.size, target))
                val reply = ByteArray(UDP_REPLY_BUFFER_BYTES)
                val packet = DatagramPacket(reply, reply.size)
                if (runCatching { socket.receive(packet) }.isSuccess &&
                    reply.copyOf(packet.length).contentEquals(payload)
                ) {
                    return true
                }
            }
            return false
        }
    }

    private fun waitUntil(message: String, timeoutMillis: Long = 20_000, predicate: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (!predicate() && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(100)
        }
        assertTrue(message, predicate())
    }

    private fun hostFixtureAvailable(): Boolean = runCatching {
        Socket().use { it.connect(InetSocketAddress(hostGateway, hostHttpPort), 1_000) }
    }.isSuccess

    private fun performHttpRequest(iteration: Int, throughVpn: Boolean = false) {
        Socket().use { socket ->
            if (throughVpn) requireNotNull(connectivity.activeNetwork).bindSocket(socket)
            socket.connect(InetSocketAddress(hostGateway, hostHttpPort), 10_000)
            socket.soTimeout = 10_000
            socket.getOutputStream().write(
                "HEAD / HTTP/1.0\r\nHost: $hostGateway\r\nConnection: close\r\n\r\n"
                    .toByteArray()
            )
            val reader = socket.getInputStream().bufferedReader(Charsets.US_ASCII)
            val statusLine = reader.readLine()
            assertTrue(
                "Request $iteration did not receive an HTTP status line: $statusLine",
                statusLine?.startsWith(HTTP_RESPONSE_PREFIX) == true
            )
            while (true) {
                val header = reader.readLine() ?: break
                if (header.isEmpty()) break
            }
        }
    }

    private fun readIpv4Directions(pcap: ByteArray): List<Pair<String, String>> {
        require(pcap.size >= 24 && readLeInt(pcap, 0) == 0xa1b2c3d4.toInt())
        val result = mutableListOf<Pair<String, String>>()
        var offset = 24
        while (offset + 16 <= pcap.size) {
            val length = readLeInt(pcap, offset + 8)
            val packetOffset = offset + 16
            if (length < 0 || packetOffset + length > pcap.size) break
            if (length >= 20 && (pcap[packetOffset].toInt() ushr 4 and 0x0f) == 4) {
                result += ipv4(pcap, packetOffset + 12) to ipv4(pcap, packetOffset + 16)
            }
            offset = packetOffset + length
        }
        return result
    }

    private fun ipv4(bytes: ByteArray, offset: Int): String =
        (offset until offset + 4).joinToString(".") { (bytes[it].toInt() and 0xff).toString() }

    private fun readLeInt(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)

    private data class UdpFlow(val src: String, val srcPort: Int, val dst: String, val dstPort: Int)

    private fun readUdpFlows(pcap: ByteArray): List<UdpFlow> {
        require(pcap.size >= 24 && readLeInt(pcap, 0) == 0xa1b2c3d4.toInt())
        val result = mutableListOf<UdpFlow>()
        var offset = 24
        while (offset + 16 <= pcap.size) {
            val length = readLeInt(pcap, offset + 8)
            val packetOffset = offset + 16
            if (length < 0 || packetOffset + length > pcap.size) break
            if (length >= 20 && (pcap[packetOffset].toInt() ushr 4 and 0x0f) == 4) {
                val ipHeaderLength = (pcap[packetOffset].toInt() and 0x0f) * 4
                val protocol = pcap[packetOffset + 9].toInt() and 0xff
                if (protocol == 17 && ipHeaderLength >= 20 && ipHeaderLength + 8 <= length) {
                    val udpOffset = packetOffset + ipHeaderLength
                    result += UdpFlow(
                        ipv4(pcap, packetOffset + 12),
                        readBeShort(pcap, udpOffset),
                        ipv4(pcap, packetOffset + 16),
                        readBeShort(pcap, udpOffset + 2)
                    )
                }
            }
            offset = packetOffset + length
        }
        return result
    }

    private fun readBeShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun describeIpv4(pcap: ByteArray): String {
        val entries = mutableListOf<String>()
        var offset = 24
        while (offset + 16 <= pcap.size) {
            val length = readLeInt(pcap, offset + 8)
            val packetOffset = offset + 16
            if (length < 0 || packetOffset + length > pcap.size) break
            entries += if (length >= 20 && (pcap[packetOffset].toInt() ushr 4 and 0x0f) == 4) {
                val proto = pcap[packetOffset + 9].toInt() and 0xff
                "${ipv4(pcap, packetOffset + 12)}>${ipv4(pcap, packetOffset + 16)}/$proto"
            } else {
                "ver${pcap[packetOffset].toInt() ushr 4}/len$length"
            }
            offset = packetOffset + length
        }
        return "bytes=${pcap.size} records=${entries.size} ${entries.take(80)}"
    }

    private companion object {
        // Emulator defaults; override with -Pandroid.testInstrumentationRunnerArguments.<name>.
        const val HOST_GATEWAY = "10.0.2.2"
        const val HOST_HTTP_PORT = 18_080
        const val HOST_UDP_PORT = 18_081
        const val HTTP_REQUESTS = 50
        const val HTTP_RESPONSE_PREFIX = "HTTP/"
        const val UDP_ATTEMPTS = 5
        const val UDP_REPLY_TIMEOUT_MILLIS = 3_000
        const val UDP_REPLY_BUFFER_BYTES = 1_024
    }
}
