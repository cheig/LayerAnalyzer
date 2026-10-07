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
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

@RunWith(AndroidJUnit4::class)
class LiveCaptureForwardingTest {
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
            directions.any { it.second == HOST_GATEWAY }
        )
        assertTrue(
            "inbound response was not captured; addresses=$directions",
            directions.any { it.first == HOST_GATEWAY }
        )
    }

    private fun waitUntil(message: String, timeoutMillis: Long = 20_000, predicate: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (!predicate() && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(100)
        }
        assertTrue(message, predicate())
    }

    private fun hostFixtureAvailable(): Boolean = runCatching {
        Socket().use { it.connect(InetSocketAddress(HOST_GATEWAY, HOST_HTTP_PORT), 1_000) }
    }.isSuccess

    private fun performHttpRequest(iteration: Int) {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(HOST_GATEWAY, HOST_HTTP_PORT), 10_000)
            socket.soTimeout = 10_000
            socket.getOutputStream().write(
                "HEAD / HTTP/1.0\r\nHost: $HOST_GATEWAY\r\nConnection: close\r\n\r\n"
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

    private companion object {
        const val HOST_GATEWAY = "10.0.2.2"
        const val HOST_HTTP_PORT = 18_080
        const val HTTP_REQUESTS = 50
        const val HTTP_RESPONSE_PREFIX = "HTTP/"
    }
}
