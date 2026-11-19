// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import java.io.DataInputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** NIO-601 accepted-tier evidence through the production TUN/HEV/NIO/PCAP path.
 * Host owns the echo origins. Only this test UID enters the VPN. Short windows are
 * explicit smoke runs and never satisfy the 5/30 minute acceptance thresholds.
 */
@RunWith(AndroidJUnit4::class)
class NioVpnAcceptanceTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val args = InstrumentationRegistry.getArguments()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private lateinit var directory: File
    private lateinit var runId: String
    private lateinit var tcpTarget: InetSocketAddress
    private lateinit var udpTarget: InetSocketAddress
    private val udpAttempts = AtomicLong()
    private val udpTimeouts = AtomicLong()
    private val udpLateReplies = AtomicLong()

    @Before fun ready() {
        assumeTrue("Opt-in: run_nio_acceptance.py", args.getString("nio601RunId") != null)
        runId = requireNotNull(args.getString("nio601RunId"))
        require(runId.matches(Regex("[a-f0-9]{32}")))
        assertFalse(BuildConfig.TLS_PROBE_ENABLED)
        assertTrue(BuildConfig.SOCKS_TCP_LIMIT in setOf(64, 128, 256, 512, 1024))
        assertTrue(BuildConfig.SOCKS_UDP_LIMIT in setOf(64, 128, 256))
        assertNull("VPN consent is required", VpnService.prepare(context))
        assertFalse("An existing capture must not be replaced", LiveCaptureStore.state.value.isCapturing)
        // The host runner keeps the app visible. Its ADB launch also avoids the
        // synchronous ActivityScenario launch that stalled on the fixture device.
        await("host foreground preparation") { File(context.getExternalFilesDir(null), "nio-601/$runId/ready").exists() }
        NativeTestSupport.awaitApplicationEngine()
        val host = requireNotNull(args.getString("hostGateway"))
        tcpTarget = InetSocketAddress(host, requireNotNull(args.getString("hostTcpPort")).toInt())
        udpTarget = InetSocketAddress(host, requireNotNull(args.getString("hostUdpPort")).toInt())
        directory = File(context.getExternalFilesDir(null), "nio-601/$runId").apply { mkdirs() }
    }

    @Test fun tcp64ThroughTunForFiveMinutes() = hold("tcp", 64, 0, tierSeconds())
    @Test fun udp64ThroughTunForFiveMinutes() = hold("udp", 0, 64, tierSeconds())
    @Test fun udp64PhysicalNetworkControl() = hold("udp-control", 0, 64, 30, throughVpn = false)
    @Test fun mixed64Tcp64UdpThroughTunForThirtyMinutes() =
        hold("mixed", 64, 64, args.getString("nio601MixedSeconds")?.toLong() ?: 1800)

    @Test fun configuredTcpCapacityThroughTunForFiveMinutes() =
        hold("target-tcp", BuildConfig.SOCKS_TCP_LIMIT, 0, tierSeconds())

    @Test fun configuredUdpCapacityThroughTunForFiveMinutes() =
        hold("target-udp", 0, BuildConfig.SOCKS_UDP_LIMIT, tierSeconds())

    @Test fun configuredMixedCapacityThroughTunForThirtyMinutes() =
        hold("target-mixed", BuildConfig.SOCKS_TCP_LIMIT, BuildConfig.SOCKS_UDP_LIMIT,
            args.getString("nio601MixedSeconds")?.toLong() ?: 1800)

    @Test fun twentyVpnRestartsStopWithLiveConnections() {
        val stops = mutableListOf<Long>()
        val samples = mutableListOf<JSONObject>()
        val sampler = ProcessResourceSampler(File(directory, "restart.jsonl"), runId)
        try {
            repeat(22) { index ->
                val clients = mutableListOf<Socket>()
                try {
                    val vpn = startVpn()
                    repeat(4) { clients += connect(vpn) }
                    clients.forEachIndexed { id, peer -> echo(peer, payload(id, index.toLong())) }
                    // Still-established sessions are owned and closed by service shutdown.
                    stops += stopVpn()
                } finally {
                    clients.forEach { runCatching { it.close() } }
                    ensureStopped()
                }
                SystemClock.sleep(1000)
                val row = sampler.sample(if (index < 2) "warmup" else "after_cycle_${index - 1}")
                if (index >= 2) samples += row
            }
            val first = samples.take(5).map { it.getJSONObject("process").getLong("pssKiB") }.average()
            val last = samples.takeLast(5).map { it.getJSONObject("process").getLong("pssKiB") }.average()
            val baseline = samples.first().getJSONObject("process")
            val final = samples.last().getJSONObject("process")
            assertTrue("FDs drifted", final.getInt("fds") <= baseline.getInt("fds") + 8)
            assertTrue("Threads drifted", final.getInt("threads") <= baseline.getInt("threads") + 8)
            assertTrue("PSS requires investigation: early=$first late=$last KiB", last <= first + 24 * 1024)
            writeResult("restart", JSONObject().put("cycles", 20).put("maxStopMs", stops.maxOrNull())
                .put("earlyPssKiB", first).put("latePssKiB", last).put("baseline", baseline).put("final", final))
        } finally {
            ensureStopped()
            sampler.close()
        }
    }

    @Test fun twentyUdpStartupStopsReleaseNativeAndNio() {
        val stops = mutableListOf<Long>()
        val baseline = com.example.layanalyzer.capture.Tun2SocksBridge.getLwipCleanupStats()[0]
        repeat(20) { cycle ->
            val sockets = mutableListOf<DatagramSocket>()
            try {
                val vpn = startVpn()
                // Keep all clients open and leave most UDP associations in startup
                // instead of waiting for the whole population to settle first.
                repeat(64) { flow ->
                    val socket = DatagramSocket(null).also { sockets += it }
                    vpn.bindSocket(socket)
                    socket.bind(InetSocketAddress(localIpv4(vpn), 0))
                    socket.soTimeout = 5000
                    val bytes = payload(flow, cycle.toLong())
                    socket.send(DatagramPacket(bytes, bytes.size, udpTarget))
                }
                val reply = DatagramPacket(ByteArray(512), 512)
                sockets.first().receive(reply)
                assertArrayEquals("one real UDP round trip must precede stop", payload(0, cycle.toLong()),
                    reply.data.copyOfRange(reply.offset, reply.offset + reply.length))
                stops += stopVpn()
                val cleanup = com.example.layanalyzer.capture.Tun2SocksBridge.getLwipCleanupStats()
                assertEquals(baseline + cycle + 1, cleanup[0])
                assertEquals("native TCP PCB cleanup", 0L, cleanup[2])
                assertEquals("native UDP PCB cleanup", 0L, cleanup[3])
            } finally {
                sockets.forEach { runCatching { it.close() } }
                ensureStopped()
            }
        }
        writeResult("udp-startup-stop", JSONObject().put("cycles", 20)
            .put("udpCandidatesPerCycle", 64).put("maxStopMs", stops.maxOrNull()))
    }

    private fun hold(label: String, tcpCount: Int, udpCount: Int, seconds: Long, throughVpn: Boolean = true) {
        require(seconds in 1..7200)
        val running = AtomicBoolean(true)
        val failure = AtomicReference<Throwable>()
        val rtts = AtomicLong()
        val churns = AtomicLong()
        val tcp = mutableListOf<Socket>()
        val udp = mutableListOf<DatagramSocket>()
        val workers = mutableListOf<Thread>()
        val sampler = ProcessResourceSampler(File(directory, "$label.jsonl"), runId)
        try {
            sampler.sample("before")
            val vpn = if (throughVpn) startVpn() else requireNotNull(connectivity.activeNetwork).also {
                assertFalse(connectivity.getNetworkCapabilities(it)!!.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
            }
            repeat(tcpCount) { id -> tcp += connect(vpn).also { echo(it, payload(id, -1)) } }
            repeat(udpCount) { id ->
                udp += DatagramSocket(null).also {
                    vpn.bindSocket(it)
                    it.bind(InetSocketAddress(localIpv4(vpn), 0))
                    it.soTimeout = 2000
                    it.connect(udpTarget)
                    echo(it, payload(id, -1))
                }
            }
            if (throughVpn) await("established capacity") {
                snapshot().tcp.current == tcpCount && snapshot().udp.current == udpCount
            }
            sampler.sample("established")
            val start = SystemClock.elapsedRealtime()
            val deadline = start + seconds * 1000
            var previousSample = start
            // Eight fixed drivers. Expanded tiers use a five-second round so the 30-minute
            // soak stays below the explicit 1 GiB capture limit instead of failing on storage.
            // Every connection still transfers before the hold and on every round.
            val roundPeriodMillis = if (tcpCount + udpCount > 512) 5000L else 1000L
            for (isUdp in listOf(false, true)) {
                val count = if (isUdp) udpCount else tcpCount
                if (count == 0) continue
                repeat(4) { driver ->
                    workers += thread(name = "nio601-${if (isUdp) "udp" else "tcp"}-$driver", isDaemon = true) {
                        try {
                            var sequence = 0L
                            while (running.get() && SystemClock.elapsedRealtime() < deadline) {
                                val roundStart = SystemClock.elapsedRealtime()
                                for (id in driver until count step 4) {
                                    if (!running.get()) break
                                    val body = payload(id, sequence)
                                    if (isUdp) echo(udp[id], body) else echo(tcp[id], body)
                                    rtts.incrementAndGet()
                                }
                                if (!isUdp && driver == 0 && label.endsWith("mixed") && sequence > 0 && sequence % 10 == 0L) {
                                    tcp[0].close()
                                    await("one TCP capacity slot released") { snapshot().tcp.current < tcpCount }
                                    tcp[0] = connect(vpn)
                                    echo(tcp[0], payload(0, sequence))
                                    await("churn restored full TCP capacity") { snapshot().tcp.current == tcpCount }
                                    churns.incrementAndGet()
                                }
                                sequence++
                                val pause = roundPeriodMillis - (SystemClock.elapsedRealtime() - roundStart)
                                if (pause > 0) Thread.sleep(pause)
                            }
                        } catch (error: Throwable) {
                            if (running.get()) failure.compareAndSet(null, error)
                        }
                    }
                }
            }
            while (SystemClock.elapsedRealtime() < deadline) {
                SystemClock.sleep(minOf(5000, deadline - SystemClock.elapsedRealtime()).coerceAtLeast(1))
                failure.get()?.let { throw it }
                if (throughVpn) {
                    assertTrue("capture stopped during load", LiveCaptureStore.state.value.isCapturing)
                    val stats = snapshot()
                    assertEquals("all UDP associations alive", udpCount, stats.udp.current)
                    assertTrue("TCP population", stats.tcp.current in (tcpCount - if (label.endsWith("mixed")) 1 else 0)..tcpCount)
                    assertEquals(0L, stats.rejectedHandshakes)
                    assertEquals(0L, stats.rejectedTcp)
                    assertEquals(0L, stats.rejectedUdp)
                }
                sampler.sample("held")
                val sampled = SystemClock.elapsedRealtime()
                assertTrue("Sampling gap indicates a paused or stalled load", sampled - previousSample < 15000)
                previousSample = sampled
            }
            val elapsed = SystemClock.elapsedRealtime() - start
            running.set(false)
            // Stop before closing clients: exercise active-forwarding teardown.
            val stopMs = if (throughVpn) stopVpn() else 0L
            tcp.forEach { runCatching { it.close() } }
            udp.forEach { runCatching { it.close() } }
            workers.forEach { it.join(10000) }
            assertTrue("drivers must terminate", workers.none { it.isAlive })
            failure.get()?.let { throw it }
            assertTrue("every connection must transfer", rtts.get() >= tcpCount + udpCount)
            if (label.endsWith("mixed") && seconds >= 30) assertTrue("continuous churn missing", churns.get() > 0)
            sampler.sample("after_stop")
            writeResult(label, JSONObject().put("tcp", tcpCount).put("udp", udpCount)
                .put("elapsedMs", elapsed).put("stopMs", stopMs).put("rtts", rtts.get())
                .put("verifiedBytes", rtts.get() * 2 * 512).put("tcpReplacements", churns.get())
                .put("throughVpn", throughVpn).put("roundPeriodMillis", roundPeriodMillis)
                .put("udpAttempts", udpAttempts.get()).put("udpTimeouts", udpTimeouts.get())
                .put("udpLateReplies", udpLateReplies.get())
                .put("durationGatePassed", elapsed >= (if (label.endsWith("mixed")) 1800 else 300) * 1000L))
        } finally {
            running.set(false)
            tcp.forEach { runCatching { it.close() } }
            udp.forEach { runCatching { it.close() } }
            workers.forEach { it.interrupt(); it.join(10000) }
            ensureStopped()
            sampler.close()
        }
    }

    private fun tierSeconds() = args.getString("nio601TierSeconds")?.toLong() ?: 300L

    private fun startVpn(): Network {
        // Android publishes removal of the previous VPN asynchronously after
        // close(TUN). Binding a new socket to that stale Network can reset it or
        // bypass the new SOCKS population even though the service is Running.
        await("previous VPN network withdrawn") { activeVpn() == null }
        LiveCaptureStore.clearError()
        ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
            putExtra(LiveCaptureVpnService.EXTRA_MAX_DURATION_MINUTES, 125)
            putExtra(LiveCaptureVpnService.EXTRA_MAX_SIZE_MEGABYTES, 1024)
            putExtra(LiveCaptureVpnService.EXTRA_SEGMENT_SIZE_MEGABYTES, 64)
            putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
        })
        await("VPN start") {
            LiveCaptureStore.state.value.error?.let { error(it) }
            LiveCaptureStore.state.value.isCapturing && activeVpn() != null
        }
        val vpn = requireNotNull(activeVpn())
        // Connectivity may publish the VPN before its UID routes/pumps are usable.
        // Only this disposable readiness exchange may retry; workload bytes and
        // population assertions below retain their original strict checks.
        await("new VPN forwards readiness probe through NIO") {
            runCatching {
                connect(vpn).use { echo(it, payload(-1, -1)) }
                true
            }.getOrDefault(false)
        }
        await("readiness probe released TCP admission") { snapshot().tcp.current == 0 }
        return vpn
    }

    private fun stopVpn(): Long {
        val capture = File(requireNotNull(LiveCaptureStore.state.value.outputPath))
        val start = SystemClock.elapsedRealtime()
        context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
        await("VPN stopped") { !LiveCaptureStore.state.value.isCapturing && !snapshot().running }
        val elapsed = SystemClock.elapsedRealtime() - start
        assertTrue("stop exceeded five seconds: $elapsed", elapsed <= 5000)
        assertNull(LiveCaptureStore.state.value.error)
        val report = File(capture.parentFile, "${capture.name}.report.json")
        var finalReport: JSONObject? = null
        await("complete final report") {
            finalReport = runCatching { JSONObject(report.readText()) }.getOrNull()
            finalReport != null
        }
        val json = requireNotNull(finalReport)
        assertEquals("COMPLETE", json.getJSONObject("integrity").getJSONObject("cleanup").getString("status"))
        assertEquals("COMPLETE", json.getJSONObject("integrity").getJSONObject("packetEvidence").getString("status"))
        assertEquals("NIO", json.getJSONObject("socksRuntime").getString("mode"))
        assertEquals(0, snapshot().tcp.current)
        assertEquals(0, snapshot().udp.current)
        assertEquals(0, snapshot().handshakes.current)
        File(directory, "${capture.name}.report.json").writeText(json.toString(2))
        await("stopped VPN network withdrawn") { activeVpn() == null }
        return elapsed
    }

    private fun ensureStopped() {
        val output = LiveCaptureStore.state.value.outputPath?.let { File(it) }
        if (LiveCaptureStore.state.value.isCapturing || LiveCaptureVpnService.socksResourceSnapshot()?.running == true) {
            context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
            await("cleanup VPN") {
                !LiveCaptureStore.state.value.isCapturing && LiveCaptureVpnService.socksResourceSnapshot()?.running != true
            }
        }
        if (output != null && output.exists()) {
            val report = File(output.parentFile, "${output.name}.report.json")
            var finalReport: JSONObject? = null
            await("complete failure cleanup report") {
                finalReport = runCatching { JSONObject(report.readText()) }.getOrNull()
                finalReport != null
            }
            val copy = File(directory, report.name)
            if (!copy.exists()) copy.writeText(requireNotNull(finalReport).toString(2))
            val pcapCopy = File(directory, output.name)
            if (!pcapCopy.exists() && output.length() <= 64L * 1024 * 1024) output.copyTo(pcapCopy)
        }
    }

    private fun snapshot() = requireNotNull(LiveCaptureVpnService.socksResourceSnapshot())
    private fun activeVpn() = connectivity.activeNetwork?.takeIf {
        connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    private fun connect(vpn: Network): Socket = Socket().also { peer ->
        try {
            vpn.bindSocket(peer)
            // NetworkCapabilities can become active before Android finishes UID
            // route/source selection. An unbound socket may complete its SYN on
            // Wi-Fi and later enter TUN with the physical source address, where
            // HEV correctly resets the unknown tuple. Pin the intended source as
            // well as the network; workload connections are never retried.
            peer.bind(InetSocketAddress(localIpv4(vpn), 0))
            peer.soTimeout = 5000
            peer.tcpNoDelay = true
            peer.connect(tcpTarget, 5000)
        } catch (error: Throwable) {
            peer.close()
            throw error
        }
    }

    private fun localIpv4(network: Network): InetAddress = requireNotNull(
        connectivity.getLinkProperties(network)?.linkAddresses
            ?.firstOrNull { it.address is Inet4Address }?.address
    ) { "The selected fixture network must have an IPv4 source address" }

    private fun payload(id: Int, sequence: Long) = ByteArray(512) { (it % 251).toByte() }.also {
        ByteBuffer.wrap(it).putInt(id).putLong(sequence)
    }

    private fun echo(peer: Socket, body: ByteArray) {
        peer.getOutputStream().write(body)
        val reply = ByteArray(body.size)
        DataInputStream(peer.getInputStream()).readFully(reply)
        assertArrayEquals("TCP byte conservation", body, reply)
    }

    private fun echo(peer: DatagramSocket, body: ByteArray) {
        // Wi-Fi loss also occurs in the independent physical-network control. Count
        // each timeout and retransmission; do not report them as loss-free forwarding.
        val values = ByteBuffer.wrap(body)
        val flow = values.int
        val sequence = values.long
        repeat(3) {
            udpAttempts.incrementAndGet()
            peer.send(DatagramPacket(body, body.size))
            val deadline = SystemClock.elapsedRealtime() + 2000
            while (SystemClock.elapsedRealtime() < deadline) {
                val reply = DatagramPacket(ByteArray(body.size + 1), body.size + 1)
                peer.soTimeout = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(1).toInt()
                try {
                    peer.receive(reply)
                } catch (_: java.net.SocketTimeoutException) {
                    break
                }
                val received = reply.data.copyOfRange(reply.offset, reply.offset + reply.length)
                if (received.contentEquals(body)) return
                if (received.size == body.size) {
                    val header = ByteBuffer.wrap(received)
                    if (header.int == flow && header.long < sequence) {
                        udpLateReplies.incrementAndGet()
                        continue
                    }
                }
                assertArrayEquals("UDP byte conservation", body, received)
            }
            udpTimeouts.incrementAndGet()
        }
        throw AssertionError("UDP failed after three attempts: flow=$flow sequence=$sequence")
    }

    private fun writeResult(label: String, result: JSONObject) {
        result.put("status", "PASS").put("runId", runId).put("tlsBuilt", BuildConfig.TLS_ENABLED)
            .put("tlsInterception", false)
            .put("path", if (label == "udp-control") "physical network control" else "TUN/HEV/NIO/PCAP")
        File(directory, "$label-result.json").writeText(result.toString(2))
    }

    private fun await(label: String, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 20000
        while (!condition()) {
            check(SystemClock.elapsedRealtime() < deadline) { "$label timed out" }
            SystemClock.sleep(10)
        }
    }
}
