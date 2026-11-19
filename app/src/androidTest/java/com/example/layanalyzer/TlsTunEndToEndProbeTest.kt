package com.example.layanalyzer

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.DataInputStream
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Required P0 cases. Missing ON build/consent/network fails, never Assume/skip. */
@RunWith(AndroidJUnit4::class)
class TlsTunEndToEndProbeTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val connectivity get() = context.getSystemService(ConnectivityManager::class.java)
    private val serviceName = "com.example.layanalyzer.capture.tls.TlsTunProbeVpnService"
    private val body = "LayerAnalyzer TLS fixture v1\n".toByteArray()

    @Before fun ready() {
        assertTrue("Requires a matching probe ON application", BuildConfig.TLS_PROBE_ENABLED)
        NativeTestSupport.awaitApplicationEngine()
        assertTrue(NativeEngine.getVersion().contains("4.0.10"))
        assertTrue(JSONObject(NativeEngine.loadTlsBridgeProbe(false, 1)).getBoolean("success"))
    }

    @Test fun tls12H1Tun() = checkProtocol(0, "tls12-h1")
    @Test fun tls13H1Tun() = checkProtocol(1, "tls13-h1")
    @Test fun tls13H2Tun() = checkProtocol(2, "tls13-h2")

    @Test fun socksConnectPreservesReadAhead() {
        val payload = ByteArray(4096) { (it % 251).toByte() }
        val worker = Executors.newSingleThreadExecutor()
        try {
            ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { origin ->
                val received = worker.submit<ByteArray> {
                    origin.accept().use { peer ->
                        peer.soTimeout = 3000
                        ByteArray(payload.size).also { DataInputStream(peer.getInputStream()).readFully(it) }
                            .also { peer.getOutputStream().write(it) }
                    }
                }
                DirectSocks5Server({}, {}, { arrayOf(InetAddress.getByName(it)) }).use { socks ->
                    val port = socks.start()
                    val credentials = socks.credentials
                    val username = credentials.username.toByteArray(Charsets.US_ASCII)
                    val password = credentials.password.toByteArray(Charsets.US_ASCII)
                    Socket("127.0.0.1", port).use { client ->
                        client.soTimeout = 3000
                        // Greeting + RFC 1929 credentials + CONNECT + payload are
                        // one write, exercising NIO retained input across the whole
                        // authenticated exchange.
                        client.getOutputStream().write(
                            byteArrayOf(5, 2, 0, 2) +
                                byteArrayOf(1, username.size.toByte()) + username +
                                byteArrayOf(password.size.toByte()) + password +
                                byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1, (origin.localPort ushr 8).toByte(), origin.localPort.toByte()) +
                                payload
                        )
                        val input = DataInputStream(client.getInputStream())
                        assertEquals(5, input.readUnsignedByte()); assertEquals(2, input.readUnsignedByte())
                        assertEquals(1, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
                        assertEquals(5, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
                        assertEquals(0, input.readUnsignedByte()); assertEquals(1, input.readUnsignedByte())
                        input.readFully(ByteArray(6))
                        val echoed = ByteArray(payload.size).also(input::readFully)
                        assertArrayEquals(payload, echoed)
                        assertArrayEquals(payload, received.get(3, TimeUnit.SECONDS))
                    }
                }
            }
        } finally { worker.shutdownNow() }
    }

    private fun checkProtocol(protocol: Int, id: String) {
        assertNull("Grant VPN consent before running the test", VpnService.prepare(context))
        assertFalse("Do not replace an existing user capture", LiveCaptureStore.state.value.isCapturing)
        assertFalse("Do not replace an existing user VPN", vpnActive())
        // Warm Go, HEV, service and native dissectors before measuring resources.
        runCycle(protocol, "$id-warmup")
        val baseline = fdCount()
        val report = runCycle(protocol, id)
        val recovered = waitFor(5_000) { fdCount() <= baseline }
        report.put("fdBaseline", baseline).put("fdFinal", fdCount()).put("fdRecovered", recovered)
        reportFile(id).writeText(report.toString(2))
        assertTrue("FD count must return to warmed baseline", recovered)
        val state = JSONObject(NativeEngine.getTlsBridgeProbeState())
        assertEquals(0, state.getInt("globalRefs"))
        assertEquals(0, state.getInt("attachedThreads"))
        assertEquals(state.getLong("callbacksStarted"), state.getLong("callbacksCompleted"))
        report.put("complete", true)
        reportFile(id).writeText(report.toString(2))
    }

    private fun runCycle(protocol: Int, id: String): JSONObject {
        val report = JSONObject().put("schemaVersion", 1).put("fixtureId", id)
            .put("api", Build.VERSION.SDK_INT).put("abi", Build.SUPPORTED_ABIS[0])
            .put("captureMethod", "Android VpnService TUN / original packet relay")
            .put("embeddedVersion", NativeEngine.getVersion()).put("complete", false)
        val directory = reportFile(id).parentFile!!.apply { mkdirs() }
        reportFile(id).writeText(report.toString(2)) // invalidate previous run before starting
        var buffers: Array<ByteArray>? = null
        var handle = 0L
        var startRequested = false
        var prepares = 0
        try {
            buffers = NativeEngine.runTlsTunProbe(protocol, object : NativeEngine.TlsTunProbeCallback {
                override fun prepareTun(gatewayPort: Int, token: ByteArray): Boolean {
                    // Class is deliberately absent in OFF/release APKs. Reflective
                    // lookup keeps the common instrumentation source compilable.
                    Class.forName(serviceName).getMethod("install", Int::class.javaPrimitiveType, ByteArray::class.java)
                        .invoke(null, gatewayPort, token)
                    LiveCaptureStore.clearError()
                    startRequested = true
                    ContextCompat.startForegroundService(context, serviceIntent().apply {
                        putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
                        putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
                        putExtra(LiveCaptureVpnService.EXTRA_MAX_DURATION_MINUTES, 1)
                        putExtra(LiveCaptureVpnService.EXTRA_MAX_SIZE_MEGABYTES, 16)
                        putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
                    })
                    assertTrue("Test VPN did not start", waitFor(20_000) {
                        (LiveCaptureStore.state.value.isCapturing && vpnActive()) || LiveCaptureStore.state.value.error != null
                    })
                    assertTrue(LiveCaptureStore.state.value.error, LiveCaptureStore.state.value.isCapturing && vpnActive())
                    return true
                }

                override fun prepareSocket(fd: Int, networkGeneration: Long): String {
                    assertEquals(0L, networkGeneration)
                    assertTrue(vpnActive())
                    ParcelFileDescriptor.fromFd(fd).use { copy ->
                        try { Os.getpeername(copy.fileDescriptor); fail("Upstream connected before protect") }
                        catch (error: ErrnoException) { assertEquals(OsConstants.ENOTCONN, error.errno) }
                    }
                    assertTrue(VpnService().protect(fd)) // loopback origin, physical binding is TLS-005
                    prepares++
                    return """{"schemaVersion":1,"success":true,"errorCode":null,"error":null}"""
                }
            })
            val metadata = JSONObject(buffers[0].toString(Charsets.UTF_8))
            report.put("client", metadata).put("prepareCalls", prepares)
            reportFile(id).writeText(report.toString(2))
            val stopStart = SystemClock.elapsedRealtime()
            context.startService(serviceIntent().setAction(LiveCaptureVpnService.ACTION_STOP))
            assertTrue("VPN route not released within 2 seconds", waitFor(2_000) { !vpnActive() })
            report.put("routeReleaseMillis", SystemClock.elapsedRealtime() - stopStart)
            assertTrue("Capture not fully stopped", waitFor(5_000) { !LiveCaptureStore.state.value.isCapturing && !installed() })
            report.put("stopMillis", SystemClock.elapsedRealtime() - stopStart)
            assertTrue("Stop exceeded 5 seconds", report.getLong("stopMillis") <= 5_000)
            startRequested = false
            assertTrue(metadata.optString("errorCode"), metadata.getBoolean("success"))
            assertEquals(1, prepares)
            assertTrue(metadata.getBoolean("gatewayReady"))
            assertTrue(metadata.getBoolean("upstreamVerified"))
            assertTrue(metadata.getBoolean("configReplaced"))
            assertTrue(metadata.getBoolean("downstreamHandshake"))
            assertEquals(if (protocol == 0) 771 else 772, metadata.getInt("tlsVersion"))
            assertEquals(if (protocol == 2) "h2" else "http/1.1", metadata.getString("alpn"))
            assertEquals(TlsDissectionProbeAssertions.sha256(body), metadata.getString("bodySha256"))
            assertNotEquals(metadata.getString("downstreamClientRandom"), metadata.getString("upstreamClientRandom"))
            val stopped = LiveCaptureStore.state.value
            assertNull(stopped.error)
            assertEquals("No TUN packets may be discarded in the tiny fixture", 0L, stopped.droppedPacketCount)
            assertEquals("This bounded fixture must fit a single original segment", 1, stopped.segmentPaths.size)
            report.put("droppedPacketCount", stopped.droppedPacketCount)
            assertTrue("Missing or recursive capture", stopped.packetCount in 6..4096)
            val pcap = File(requireNotNull(stopped.outputPath))
            val raw = pcap.readBytes()
            report.put("tunPcapSha256", TlsDissectionProbeAssertions.sha256(raw))
            report.put("tunPcapBytes", raw.size).put("packetCount", stopped.packetCount)
            verifyRawTun(raw)
            assertFalse("Raw TUN must not contain the fixture plaintext", contains(raw, body))
            File(directory, "capture.pcap").writeBytes(raw)
            raw.fill(0)
            val a = File(directory, "tls-a.keys").apply { writeBytes(buffers[1]) }
            val b = File(directory, "tls-b.keys").apply { writeBytes(buffers[2]) }
            report.put("tlsAKeylogSha256", TlsDissectionProbeAssertions.sha256(buffers[1]))
                .put("tlsBKeylogSha256", TlsDissectionProbeAssertions.sha256(buffers[2]))
            handle = NativeEngine.openFile(pcap.path, null)
            assertTrue("Real TUN PCAP failed to open", handle != 0L)
            for ((phase, file) in listOf("empty" to null, "tlsB" to b, "tlsA" to a, "clear" to null, "reload" to a)) {
                val result = JSONObject(NativeEngine.runTlsDissectionProbe(handle, file?.path, 443, protocol == 2, true))
                report.put(phase, result)
                reportFile(id).writeText(report.toString(2))
                TlsDissectionProbeAssertions.check(result, body, file == a, true, protocol == 2)
            }
            return report
        } finally {
            if (handle != 0L) NativeEngine.closeFile(handle)
            buffers?.forEach { it.fill(0) }
            if (startRequested) {
                context.startService(serviceIntent().setAction(LiveCaptureVpnService.ACTION_STOP))
                waitFor(10_000) { !LiveCaptureStore.state.value.isCapturing && !installed() }
            }
            if (!LiveCaptureStore.state.value.isCapturing) Class.forName(serviceName).getMethod("clear").invoke(null)
            reportFile(id).writeText(report.toString(2))
        }
    }

    private fun verifyRawTun(raw: ByteArray) {
        assertTrue(raw.size > 24)
        val data = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(0xa1b2c3d4.toInt(), data.getInt(0))
        assertEquals(101, data.getInt(20))
        var offset = 24
        var outbound = 0
        var inbound = 0
        while (offset < raw.size) {
            assertTrue(offset + 16 <= raw.size)
            val length = data.getInt(offset + 8)
            assertTrue(length > 0 && offset.toLong() + 16 + length <= raw.size)
            val packet = offset + 16
            if (length >= 20 && (raw[packet].toInt() and 0xf0) == 0x40) {
                val source = raw.copyOfRange(packet + 12, packet + 16)
                val target = raw.copyOfRange(packet + 16, packet + 20)
                val fixture = byteArrayOf(198.toByte(), 18, 0, 8)
                if (source.contentEquals(fixture)) inbound++
                if (target.contentEquals(fixture)) outbound++
            }
            offset += 16 + length
        }
        assertTrue("Real TUN must contain both fixture directions", outbound > 0 && inbound > 0)
    }

    private fun contains(bytes: ByteArray, part: ByteArray) =
        (0..bytes.size - part.size).any { offset -> part.indices.all { bytes[offset + it] == part[it] } }
    private fun reportFile(id: String) = File(context.noBackupFilesDir, "tls-008/$id/report.json")
    private fun serviceIntent() = Intent().setClassName(context, serviceName)
    private fun installed() = Class.forName(serviceName).getMethod("isInstalled").invoke(null) as Boolean
    private fun vpnActive() = connectivity.getNetworkCapabilities(connectivity.activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun fdCount() = requireNotNull(File("/proc/self/fd").list()).size
    private fun waitFor(timeout: Long, predicate: () -> Boolean): Boolean {
        val end = SystemClock.elapsedRealtime() + timeout
        while (!predicate() && SystemClock.elapsedRealtime() < end) SystemClock.sleep(25)
        return predicate()
    }
}
