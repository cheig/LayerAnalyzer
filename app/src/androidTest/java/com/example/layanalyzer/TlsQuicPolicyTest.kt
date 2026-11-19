// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.tls.TlsCaManagerHolder
import com.example.layanalyzer.model.QuicPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureSettingsJson
import com.example.layanalyzer.model.TlsHostScope
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real production VPN/TUN/HEV/SOCKS and an independent UID outside its allowlist.
 * Requires quic_policy_fixture.py. aioquic executes on the controlled host; every
 * client QUIC datagram traverses this device's UDP socket. The TCP control channel
 * explicitly uses the physical Network. Missing fixture, consent or engine fails.
 */
@RunWith(AndroidJUnit4::class)
class TlsQuicPolicyTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val arguments = InstrumentationRegistry.getArguments()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val host get() = requireNotNull(arguments.getString("hostGateway")).also {
        require(it.matches(Regex("[0-9.]+"))) { "controlled IPv4 literal required" }
    }
    private val udpPort get() = arguments.getString("hostUdpPort")?.toIntOrNull() ?: 18081
    private val controlPort get() = arguments.getString("quicControlPort")?.toIntOrNull() ?: 18084
    private val dns53Host get() = requireNotNull(arguments.getString("dns53Host"))

    @Test fun theDefaultPolicyIntervenesOnNothingAndUdp443StillPasses() = runPolicy(QuicPolicy.Preserve)
    @Test fun theBlockingPolicyDropsOnlyTheDeclaredUdp443Scope() = runPolicy(QuicPolicy.BlockSelectedUdp443)
    @Test fun tlsOffDoesNotApplyARememberedBlock() = runPolicy(QuicPolicy.BlockSelectedUdp443, tlsEnabled = false)

    private fun runPolicy(policy: QuicPolicy, tlsEnabled: Boolean = true) {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue("device acceptance requires TLS ON", BuildConfig.TLS_ENABLED)
        assertFalse("device acceptance requires production engine", BuildConfig.TLS_PROBE_ENABLED)
        assertNull("VPN consent must already be granted", VpnService.prepare(context))
        assertFalse("stop existing capture first", LiveCaptureStore.state.value.isCapturing)
        TlsCaManagerHolder.get(context).ensureGenerated()
        LiveCaptureStore.clearError()
        val physical = requireNotNull(connectivity.activeNetwork)
        assertFalse(connectivity.getNetworkCapabilities(physical)!!.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
        DatagramSocket().use { socket ->
            physical.bindSocket(socket)
            echo(socket, 443); echo(socket, udpPort); dns(socket)
        }
        val blocked = tlsEnabled && policy == QuicPolicy.BlockSelectedUdp443
        val quic: JSONObject
        var expectedBytes = 0L
        var expectedDatagrams = 0L
        try {
            startCapture(policy, tlsEnabled)
            waitUntil("capture/VPN did not start") {
                LiveCaptureStore.state.value.error?.let { error("capture failed: $it") }
                LiveCaptureStore.state.value.isCapturing && connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
            val vpn = requireNotNull(connectivity.activeNetwork)
            DatagramSocket().use { socket ->
                vpn.bindSocket(socket)
                echo(socket, udpPort) // warm the association before counting
                dns(socket)
                repeat(10) { index ->
                    val payload = "tls314-selected-$index".toByteArray()
                    send(socket, 443, payload)
                    if (blocked) {
                        assertNull("UDP/443 must have no reply", receive(socket, 200))
                        expectedBytes += payload.size
                        expectedDatagrams++
                    } else {
                        assertArrayEquals("UDP/443 exact echo", payload, receive(socket, 3000))
                    }
                }
                echo(socket, udpPort); dns(socket)
            }
            // Ordinary, unbound shell UID socket: NOT VpnService.protect.
            // UiAutomation's command is tokenized by Runtime.exec, not a shell;
            // keep the pipeline in an explicit script instead of quoting sh -c.
            val script = File(context.getExternalFilesDir(null), "tls314-excluded.sh")
            script.writeText("id -u\nprintf tls314-excluded | toybox timeout 3 toybox nc -u -W 1 $host 443\n")
            val excluded = try {
                ParcelFileDescriptor.AutoCloseInputStream(
                    instrumentation.uiAutomation.executeShellCommand("sh ${script.absolutePath}")
                ).bufferedReader().use { it.readText() }
            } finally { script.delete() }
            assertEquals("2000\ntls314-excluded", excluded.trim())
            DatagramSocket().use { socket ->
                physical.bindSocket(socket)
                echo(socket, 443) // simultaneous positive control: peer is up
            }
            quic = quicRoundTrip(vpn, physical)
            assertFalse(quic.getBoolean("tcpFallback"))
            assertEquals("real QUIC handshake", !blocked, quic.getBoolean("handshake"))
            assertEquals("QUIC stream bytes", !blocked, quic.getBoolean("bodyEqual"))
            assertEquals(if (blocked) 0 else 37, quic.getInt("receivedBytes"))
            assertTrue(quic.getInt("datagramsSent") > 0)
            if (blocked) {
                expectedDatagrams += quic.getLong("deviceDatagramsSent")
                expectedBytes += quic.getLong("deviceBytesSent")
            }
        } finally {
            context.startService(Intent(context, LiveCaptureVpnService::class.java)
                .setAction(LiveCaptureVpnService.ACTION_STOP))
            waitUntil("capture did not stop") { !LiveCaptureStore.state.value.isCapturing }
            waitUntil("VPN route not released") {
                connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true
            }
        }
        val stopped = LiveCaptureStore.state.value
        assertNull(stopped.error)
        val capture = File(requireNotNull(stopped.outputPath))
        assertTrue(capture.length() > 24)
        val reportFile = File(capture.parentFile, "${capture.name}.report.json")
        waitUntil("fresh report not finalized") { reportFile.isFile }
        val report = JSONObject(reportFile.readText())
        assertEquals("IPv4", report.getString("ipScope"))
        if (tlsEnabled) {
            val udp = report.getJSONObject("udpIntervention")
            assertEquals(policy.name, udp.getString("policy"))
            assertEquals("no excluded/DNS/non443 packet counted", expectedDatagrams, udp.getLong("blockedDatagrams"))
            assertEquals(expectedBytes, udp.getLong("blockedBytes"))
            val tls = report.getJSONObject("tls")
            assertEquals("UDP block is not TLS decryption", 0L, tls.getLong("proxiedConnections"))
            assertEquals("STOPPED", tls.getString("status"))
        } else {
            assertFalse("disabled TLS must not publish intervention", report.has("udpIntervention"))
        }
        DatagramSocket().use { socket -> echo(socket, 443); dns(socket) }
        val evidence = JSONObject().put("tlsEnabled", tlsEnabled).put("requestedPolicy", policy.name)
            .put("ipScope", report.getString("ipScope")).put("quic", quic)
            .put("dnsBeforeDuringAfter", true).put("otherUdpDuringCapture", true)
            .put("excludedUid", 2000).put("excludedUidUdp443", true)
            .put("udpIntervention", report.optJSONObject("udpIntervention"))
            .put("tls", report.optJSONObject("tls")).put("vpnReleased", true)
        val output = File(context.getExternalFilesDir(null), "tls-314").apply { mkdirs() }
        File(output, "${if (tlsEnabled) "on" else "off"}-${policy.name}.json").writeText(evidence.toString(2))
    }

    private fun startCapture(policy: QuicPolicy, tlsEnabled: Boolean) {
        val settings = TlsCaptureSettings(enabled = tlsEnabled, candidatePorts = setOf(443),
            hostScope = TlsHostScope.SelectedApplicationsCandidates, quicPolicy = policy)
        ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
            putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
            putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS, TlsCaptureSettingsJson.encode(settings))
        })
    }

    private fun quicRoundTrip(vpn: Network, physical: Network): JSONObject {
        physical.socketFactory.createSocket().use { control ->
            control.connect(InetSocketAddress(host, controlPort), 3000)
            control.soTimeout = 8000
            val input = DataInputStream(control.getInputStream())
            val output = DataOutputStream(control.getOutputStream())
            DatagramSocket().use { socket ->
                vpn.bindSocket(socket)
                var sent = 0L
                var bytes = 0L
                while (true) {
                    val size = input.readInt()
                    if (size < 0) {
                        require(size >= -4096)
                        val result = ByteArray(-size).also { input.readFully(it) }
                        return JSONObject(String(result, Charsets.UTF_8))
                            .put("deviceDatagramsSent", sent).put("deviceBytesSent", bytes)
                    }
                    require(size <= 65535)
                    if (size > 0) {
                        val data = ByteArray(size).also { input.readFully(it) }
                        send(socket, 443, data)
                        sent++
                        bytes += size
                    }
                    val response = receive(socket, 200)
                    output.writeInt(response?.size ?: 0)
                    response?.let { output.write(it) }
                    output.flush()
                }
            }
        }
    }

    private fun echo(socket: DatagramSocket, port: Int) {
        repeat(3) {
            val payload = "tls314-echo-$port-${SystemClock.elapsedRealtime()}".toByteArray()
            send(socket, port, payload)
            val response = receive(socket, 1500)
            if (response != null) { assertArrayEquals(payload, response); return }
        }
        fail("controlled UDP/$port peer did not answer")
    }

    private fun dns(socket: DatagramSocket) {
        val query = byteArrayOf(0x31, 0x44, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            "udp.tls314.example.invalid".split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() }
                .toByteArray() + byteArrayOf(0, 0, 1, 0, 1)
        send(socket, 18053, query)
        val answer = requireNotNull(receive(socket, 3000)) { "controlled DNS must answer" }
        assertArrayEquals(query.copyOfRange(0, 2), answer.copyOfRange(0, 2))
        assertEquals(0x81, answer[2].toInt() and 255)
        assertEquals(0x80, answer[3].toInt() and 255)
        assertArrayEquals(byteArrayOf(192.toByte(), 0, 2, 14), answer.takeLast(4).toByteArray())
        // Also exercise the real DNS port, using only a reserved synthetic name.
        socket.send(DatagramPacket(query, query.size, InetSocketAddress(dns53Host, 53)))
        val port53 = requireNotNull(receive(socket, 3000)) { "DNS/53 must answer" }
        assertArrayEquals(query.copyOfRange(0, 2), port53.copyOfRange(0, 2))
        assertEquals("DNS response", 0x80, port53[2].toInt() and 0x80)
        assertEquals("reserved .invalid name must be NXDOMAIN", 3, port53[3].toInt() and 15)
    }

    private fun send(socket: DatagramSocket, port: Int, bytes: ByteArray) =
        socket.send(DatagramPacket(bytes, bytes.size, InetSocketAddress(host, port)))

    private fun receive(socket: DatagramSocket, timeout: Int): ByteArray? {
        socket.soTimeout = timeout
        val response = DatagramPacket(ByteArray(65535), 65535)
        return try {
            socket.receive(response)
            response.data.copyOfRange(response.offset, response.offset + response.length)
        } catch (_: SocketTimeoutException) { null }
    }

    private fun waitUntil(message: String, predicate: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 20000
        while (SystemClock.elapsedRealtime() < deadline) {
            if (predicate()) return
            SystemClock.sleep(100)
        }
        assertTrue(message, predicate())
    }
}
