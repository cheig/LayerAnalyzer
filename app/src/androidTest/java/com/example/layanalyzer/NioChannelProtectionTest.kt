package com.example.layanalyzer

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel

/** P0 platform proof only: no production NIO forwarding, mock VPN, or native probe. */
@RunWith(AndroidJUnit4::class)
class NioChannelProtectionTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val vpnService = VpnService() // protect is the UID-scoped Android native API.
    private val trace = JSONArray()
    private val protectedTcpPorts = mutableSetOf<Int>()
    private val protectedUdpPorts = mutableSetOf<Int>()

    @Test
    fun channelAdaptersProtectAndBindBeforeNonblockingIoUnderVpn() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("Opt-in fixture: run verify_nio_channels.py", args.getString("nioRunId") != null)
        val runId = requireNotNull(args.getString("nioRunId")).also { require(it.matches(Regex("[a-f0-9]{32}"))) }
        val host = requireNotNull(args.getString("hostGateway"))
        val address = InetAddress.getByName(host)
        require(address.address.size == 4 && address.isSiteLocalAddress && !address.isLoopbackAddress)
        val tcpTarget = InetSocketAddress(address, requireNotNull(args.getString("hostTcpPort")).toInt())
        val udpTarget = InetSocketAddress(address, requireNotNull(args.getString("hostUdpPort")).toInt())
        val directory = File(context.filesDir, "socks-nio-protection/$runId").apply { mkdirs() }
        val result = JSONObject().put("runId", runId).put("api", Build.VERSION.SDK_INT)
            .put("abi", Build.SUPPORTED_ABIS[0]).put("trace", trace).put("complete", false)
        assertEquals("This run's user-approved platform scope is API 36", 36, Build.VERSION.SDK_INT)
        assertFalse("Do not replace a user capture", LiveCaptureStore.state.value.isCapturing)
        assertNull("Grant debug app VPN consent first; missing consent is a failure", VpnService.prepare(context))
        assertFalse("Do not replace another VPN", activeVpn() != null)
        val physical = physicalNetwork()
        var started = false
        try {
            LiveCaptureStore.clearError()
            ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
                putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
                putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
                putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
            })
            started = true
            waitUntil("VPN startup") { LiveCaptureStore.state.value.isCapturing || LiveCaptureStore.state.value.error != null }
            assertTrue(LiveCaptureStore.state.value.error, LiveCaptureStore.state.value.isCapturing)
            waitUntil("VPN transport") { activeVpn() != null }
            val vpn = requireNotNull(activeVpn())

            // Explicit VPN binding proves the positive controls really enter TUN.
            val controlTcp = tcpEcho(tcpTarget, "control-tcp", vpn, protect = false)
            val controlUdp = udpEcho(udpTarget, "control-udp", vpn, protect = false)
            waitUntil("positive controls captured") { LiveCaptureStore.state.value.packetCount > 0 }

            // Warm platform adapters/Selector before FD comparison. Protect-only LAN
            // controls also prove protect independently of physical bind bypass.
            protectedTcpPorts += tcpEcho(tcpTarget, "protect-only-tcp", null)
            protectedUdpPorts += udpEcho(udpTarget, "protect-only-udp", null)
            protectedTcpPorts += tcpEcho(tcpTarget, "warm-tcp", physical)
            protectedUdpPorts += udpEcho(udpTarget, "warm-udp", physical)
            loopbackEcho()
            preparationFailures()
            val before = settledFdCount()
            repeat(20) { index ->
                protectedTcpPorts += tcpEcho(tcpTarget, "direct-tcp-$index", physical)
                protectedUdpPorts += udpEcho(udpTarget, "direct-udp-$index", physical)
                loopbackEcho()
                preparationFailures()
            }
            val after = settledFdCount()
            result.put("fdBefore", before).put("fdAfter", after).put("iterations", 20)
                .put("protectedTcpRoundTrips", 22).put("protectedUdpRoundTrips", 22)
                .put("loopbackRoundTrips", 21).put("failureRounds", 21)
            assertTrue("Repeated channels/selectors leaked descriptors: $before -> $after", after <= before)

            stopVpn()
            started = false
            val stopped = LiveCaptureStore.state.value
            assertNull(stopped.error)
            val pcap = File(requireNotNull(stopped.outputPath))
            val report = File(pcap.parentFile, "${pcap.name}.report.json")
            waitUntil("final capture report") { report.isFile }
            val captureReport = JSONObject(report.readText())
            assertTrue("Incomplete capture cannot prove bypass", captureReport.getBoolean("complete"))
            assertEquals(0L, captureReport.getLong("droppedPackets"))
            assertEquals(0L, captureReport.getLong("ioErrors"))
            assertEquals(captureReport.getLong("offeredPackets"), captureReport.getLong("writtenPackets"))
            val socks = captureReport.getJSONObject("socks")
            for (name in listOf("handshakes", "tcp", "udp")) {
                assertEquals(0, socks.getJSONObject(name).getInt("current"))
                assertEquals("Only positive controls may use SOCKS", 1, socks.getJSONObject(name).getInt("peak"))
            }
            pcap.copyTo(File(directory, "capture.pcap"))
            report.copyTo(File(directory, "capture.report.json"))
            val observed = capturedSourcePorts(pcap.readBytes(), address.address, tcpTarget.port, udpTarget.port)
            assertTrue("TCP positive-control SYN absent", controlTcp in observed.first)
            assertTrue("UDP positive-control absent", controlUdp in observed.second)
            assertTrue("Protected TCP entered TUN", (observed.first intersect protectedTcpPorts).isEmpty())
            assertTrue("Protected UDP entered TUN", (observed.second intersect protectedUdpPorts).isEmpty())
            assertEquals("Unexpected target TCP flow", setOf(controlTcp), observed.first)
            assertEquals("Unexpected target UDP flow", setOf(controlUdp), observed.second)
            result.put("capturedTargetTcpFlows", observed.first.size).put("capturedTargetUdpFlows", observed.second.size)
                .put("protectedFlowsInTun", 0).put("capturePackets", stopped.packetCount).put("complete", true)
        } finally {
            try {
                if (started) stopVpn()
                result.put("vpnStopped", !LiveCaptureStore.state.value.isCapturing && activeVpn() == null)
            } finally {
                File(directory, "result.json").writeText(result.toString(2))
            }
        }
    }

    private fun tcpEcho(target: InetSocketAddress, label: String, network: Network?, protect: Boolean = true): Int {
        val channel = SocketChannel.open()
        val selector = Selector.open()
        var key: SelectionKey? = null
        try {
            val stages = JSONArray().put("created")
            val socket = channel.socket()
            assertSame(channel, socket.channel)
            assertTrue(channel.isBlocking)
            assertFalse(socket.isConnected)
            assertFalse(channel.isConnectionPending)
            if (protect) { assertTrue("TCP protect rejected", vpnService.protect(socket)); stages.put("protected") }
            if (network != null) { network.bindSocket(socket); stages.put("bound") }
            assertFalse("Preparation must not connect", socket.isConnected)
            channel.configureBlocking(false)
            stages.put("nonblocking")
            key = channel.register(selector, 0)
            val deadline = SystemClock.elapsedRealtime() + 10_000
            stages.put("connect")
            if (!channel.connect(target)) {
                while (!channel.finishConnect()) ready(selector, key, SelectionKey.OP_CONNECT, deadline)
            }
            val payload = "nio004-$label".toByteArray(Charsets.US_ASCII)
            transfer(channel, selector, key, payload, deadline)
            stages.put("echo")
            trace.put(JSONObject().put("path", label).put("stages", stages))
            return socket.localPort
        } finally {
            key?.cancel()
            channel.close()
            selector.close()
            assertFalse(channel.isOpen)
            assertTrue(channel.socket().isClosed)
            assertFalse(selector.isOpen)
            if (key != null) assertFalse(key.isValid)
        }
    }

    private fun udpEcho(target: InetSocketAddress, label: String, network: Network?, protect: Boolean = true): Int {
        val channel = DatagramChannel.open()
        val selector = Selector.open()
        var key: SelectionKey? = null
        try {
            val stages = JSONArray().put("created")
            val socket = channel.socket()
            assertSame(channel, socket.channel)
            assertTrue(channel.isBlocking)
            assertFalse(socket.isConnected)
            if (protect) { assertTrue("UDP protect rejected", vpnService.protect(socket)); stages.put("protected") }
            if (network != null) { network.bindSocket(socket); stages.put("bound") }
            assertFalse(socket.isConnected)
            channel.configureBlocking(false)
            stages.put("nonblocking")
            key = channel.register(selector, 0)
            val deadline = SystemClock.elapsedRealtime() + 10_000
            val payload = "nio004-$label".toByteArray(Charsets.US_ASCII)
            val outgoing = ByteBuffer.wrap(payload)
            stages.put("send")
            while (channel.send(outgoing, target) == 0) ready(selector, key, SelectionKey.OP_WRITE, deadline)
            assertFalse("Datagrams must remain whole", outgoing.hasRemaining())
            val incoming = ByteBuffer.allocate(128)
            var from = channel.receive(incoming)
            while (from == null) {
                ready(selector, key, SelectionKey.OP_READ, deadline)
                from = channel.receive(incoming)
            }
            assertEquals(target, from)
            assertArrayEquals(payload, incoming.array().copyOf(incoming.position()))
            stages.put("echo")
            trace.put(JSONObject().put("path", label).put("stages", stages))
            return socket.localPort
        } finally {
            key?.cancel()
            channel.close()
            selector.close()
            assertFalse(channel.isOpen)
            assertTrue(channel.socket().isClosed)
            assertFalse(selector.isOpen)
            if (key != null) assertFalse(key.isValid)
        }
    }

    /** Models the gateway hop only, without changing LAT1 or using a fake gateway. */
    private fun loopbackEcho() {
        Selector.open().use { selector ->
            ServerSocketChannel.open().use { listener ->
                listener.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
                listener.configureBlocking(false)
                val listenerKey = listener.register(selector, SelectionKey.OP_ACCEPT)
                SocketChannel.open().use { client ->
                    assertTrue(client.isBlocking)
                    assertFalse(client.socket().isConnected)
                    assertTrue(vpnService.protect(client.socket()))
                    // Deliberately no Network.bindSocket on a loopback gateway hop.
                    client.configureBlocking(false)
                    val key = client.register(selector, 0)
                    val deadline = SystemClock.elapsedRealtime() + 10_000
                    if (!client.connect(listener.localAddress)) {
                        while (!client.finishConnect()) ready(selector, key, SelectionKey.OP_CONNECT, deadline)
                    }
                    var accepted = listener.accept()
                    while (accepted == null) {
                        ready(selector, listenerKey, SelectionKey.OP_ACCEPT, deadline)
                        accepted = listener.accept()
                    }
                    accepted.use { peer ->
                        assertNotNull(peer.socket().channel)
                        peer.configureBlocking(false)
                        val peerKey = peer.register(selector, 0)
                        val payload = "nio004-loopback".toByteArray(Charsets.US_ASCII)
                        writeAll(client, selector, key, ByteBuffer.wrap(payload), deadline)
                        val buffer = ByteBuffer.allocate(payload.size)
                        readAll(peer, selector, peerKey, buffer, deadline)
                        buffer.flip()
                        writeAll(peer, selector, peerKey, buffer, deadline)
                        buffer.clear()
                        readAll(client, selector, key, buffer, deadline)
                        assertArrayEquals(payload, buffer.array())
                        peerKey.cancel()
                    }
                    key.cancel()
                    listenerKey.cancel()
                }
            }
        }
        trace.put(JSONObject().put("path", "loopback").put("stages",
            JSONArray(listOf("created", "protected", "nonblocking", "connect", "accept-channel", "echo", "closed"))))
    }

    private fun preparationFailures() {
        // Real Android adapter failures: a closed descriptor cannot be protected
        // or bound. Socket overloads can throw or return false depending on API.
        val network = physicalNetwork()
        val tcp = SocketChannel.open()
        val tcpSocket = tcp.socket()
        tcp.close()
        assertFalse(runCatching { vpnService.protect(tcpSocket) }.getOrDefault(false))
        assertTrue("bind closed TCP must fail", runCatching { network.bindSocket(tcpSocket) }.isFailure)
        val udp = DatagramChannel.open()
        val udpSocket = udp.socket()
        udp.close()
        assertFalse(runCatching { vpnService.protect(udpSocket) }.getOrDefault(false))
        assertTrue("bind closed UDP must fail", runCatching { network.bindSocket(udpSocket) }.isFailure)

        // This proves actual closed-adapter rejection only. A live socket protect
        // refusal and the future production fail-closed gate belong to P1/P2.
        trace.put(JSONObject().put("path", "preparation-failures").put("closedAdapterProtectAndBindRejected", true)
            .put("channelsClosed", !tcp.isOpen && !udp.isOpen))
    }

    private fun transfer(channel: SocketChannel, selector: Selector, key: SelectionKey, payload: ByteArray, deadline: Long) {
        writeAll(channel, selector, key, ByteBuffer.wrap(payload), deadline)
        val reply = ByteBuffer.allocate(payload.size)
        readAll(channel, selector, key, reply, deadline)
        assertArrayEquals(payload, reply.array())
    }

    private fun writeAll(channel: SocketChannel, selector: Selector, key: SelectionKey, bytes: ByteBuffer, deadline: Long) {
        while (bytes.hasRemaining()) {
            checkDeadline(deadline)
            if (channel.write(bytes) == 0) ready(selector, key, SelectionKey.OP_WRITE, deadline)
        }
        key.interestOps(0)
    }

    private fun readAll(channel: SocketChannel, selector: Selector, key: SelectionKey, bytes: ByteBuffer, deadline: Long) {
        while (bytes.hasRemaining()) {
            checkDeadline(deadline)
            val count = channel.read(bytes)
            assertTrue("Unexpected EOF", count >= 0)
            if (count == 0) ready(selector, key, SelectionKey.OP_READ, deadline)
        }
        key.interestOps(0)
    }

    private fun ready(selector: Selector, key: SelectionKey, operation: Int, deadline: Long) {
        checkDeadline(deadline)
        key.interestOps(operation)
        selector.select(minOf(250L, deadline - SystemClock.elapsedRealtime()).coerceAtLeast(1))
        selector.selectedKeys().clear()
    }

    private fun checkDeadline(deadline: Long) = assertTrue("NIO fixture deadline exceeded", SystemClock.elapsedRealtime() < deadline)

    @Suppress("DEPRECATION")
    private fun physicalNetwork(): Network = connectivity.allNetworks.firstOrNull {
        connectivity.getNetworkCapabilities(it)?.let { caps ->
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        } == true
    } ?: error("Controlled Wi-Fi physical network required")

    private fun activeVpn(): Network? = connectivity.activeNetwork?.takeIf {
        connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    private fun stopVpn() {
        context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
        waitUntil("VPN stop") { !LiveCaptureStore.state.value.isCapturing && activeVpn() == null }
    }

    private fun waitUntil(message: String, condition: () -> Boolean) {
        val end = SystemClock.elapsedRealtime() + 20_000
        while (!condition() && SystemClock.elapsedRealtime() < end) SystemClock.sleep(100)
        assertTrue(message, condition())
    }

    private fun settledFdCount(): Int = (1..5).minOf {
        SystemClock.sleep(100)
        requireNotNull(File("/proc/self/fd").list()).size
    }

    /** DLT_RAW IPv4 PCAP, count distinct outbound target flows, tolerating retransmits. */
    private fun capturedSourcePorts(pcap: ByteArray, target: ByteArray, tcpPort: Int, udpPort: Int): Pair<Set<Int>, Set<Int>> {
        fun u16(offset: Int) = ((pcap[offset].toInt() and 255) shl 8) or (pcap[offset + 1].toInt() and 255)
        fun le32(offset: Int) = (0..3).fold(0) { n, i -> n or ((pcap[offset + i].toInt() and 255) shl (8 * i)) }
        assertTrue(pcap.size >= 24)
        assertEquals(0xa1b2c3d4.toInt(), le32(0))
        assertEquals(101, le32(20))
        val tcp = mutableSetOf<Int>()
        val udp = mutableSetOf<Int>()
        var offset = 24
        while (offset + 16 <= pcap.size) {
            val size = le32(offset + 8)
            val packet = offset + 16
            require(size >= 0 && size <= pcap.size - packet)
            if (size >= 20 && (pcap[packet].toInt() ushr 4 and 15) == 4 &&
                pcap.copyOfRange(packet + 16, packet + 20).contentEquals(target)) {
                val ipHeader = (pcap[packet].toInt() and 15) * 4
                require(ipHeader >= 20 && ipHeader <= size)
                val transport = packet + ipHeader
                when (pcap[packet + 9].toInt() and 255) {
                    6 -> if (size >= ipHeader + 20 && u16(transport + 2) == tcpPort &&
                        (pcap[transport + 13].toInt() and 0x12) == 2) tcp += u16(transport)
                    17 -> if (size >= ipHeader + 8 && u16(transport + 2) == udpPort) udp += u16(transport)
                }
            }
            offset = packet + size
        }
        assertEquals("Truncated PCAP tail", pcap.size, offset)
        return tcp to udp
    }
}
