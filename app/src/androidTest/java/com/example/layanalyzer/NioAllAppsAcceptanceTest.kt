// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.model.TlsCaptureSettingsJson
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/** Opt-in real browser/all-app capture and physical network loss. The browser
 * loads only the runner's controlled resource pages. TLS ON exercises the real
 * gateway's plaintext classification; TLS interception/decryption has a separate
 * real-certificate fixture. No system certificate or saved capture is removed.
 */
class NioAllAppsAcceptanceTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val args = InstrumentationRegistry.getArguments()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private lateinit var runId: String
    private lateinit var host: String
    private var port = 0
    private lateinit var out: File

    @Before fun ready() {
        assumeTrue("Opt-in controlled device acceptance", args.getString("nio601RunId") != null)
        runId = requireNotNull(args.getString("nio601RunId"))
        require(runId.matches(Regex("[a-f0-9]{32}")))
        host = requireNotNull(args.getString("hostGateway"))
        port = requireNotNull(args.getString("hostHttpPort")).toInt()
        out = File(context.getExternalFilesDir(null), "nio-601/$runId").apply { mkdirs() }
        assertNull(VpnService.prepare(context))
        assertFalse(LiveCaptureStore.state.value.isCapturing)
        await("host preparation") { File(context.getExternalFilesDir(null), "nio-601/$runId/ready").exists() }
        NativeTestSupport.awaitApplicationEngine()
    }

    @Test fun resourcePagesAndBackgroundBrowserTrafficSurviveAllApplicationCapture() {
        val sampler = ProcessResourceSampler(File(out, "all-apps.jsonl"), runId)
        val stages = JSONArray()
        try {
            sampler.sample("before")
            startCapture(excludeSelf = true)
            repeat(3) { page ->
                stages.put(JSONObject().put("page", page).put("atMillis", System.currentTimeMillis()))
                shell("am start -a android.intent.action.VIEW -p com.android.chrome -d http://$host:$port/page/$page")
                SystemClock.sleep(8000)
                assertTrue("capture stopped while browsing", LiveCaptureStore.state.value.isCapturing)
                sampler.sample("page_$page")
            }
            stages.put(JSONObject().put("stage", "settings_with_browser_background")
                .put("atMillis", System.currentTimeMillis()))
            shell("am start -a android.settings.SETTINGS")
            SystemClock.sleep(8000)
            sampler.sample("browser_background")
            foreground()
            val metrics = Socket().use { peer ->
                // The app deliberately disallows general cleartext URL loading.
                // This explicit test socket targets only the controlled origin.
                peer.soTimeout = 5000
                peer.connect(InetSocketAddress(host, port), 5000)
                peer.getOutputStream().write("GET /metrics HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n".toByteArray())
                val response = peer.getInputStream().bufferedReader().readText()
                assertTrue(response.startsWith("HTTP/1.0 200"))
                JSONArray(response.substringAfter("\r\n\r\n"))
            }
            val paths = (0 until metrics.length()).map { metrics.getJSONObject(it).getString("path") }
            assertTrue("all three browser pages must reach origin", (0..2).all { "/page/$it" in paths })
            assertTrue("resource loading must actually occur", paths.count { it.startsWith("/asset/") } >= 144)
            assertTrue("browser background requests missing", paths.any { it.startsWith("/background/") })
            val report = stopCapture()
            assertEquals("all routed apps", report.getString("applicationScope"))
            assertEquals("COMPLETE", report.getJSONObject("integrity").getJSONObject("cleanup").getString("status"))
            assertEquals("COMPLETE", report.getJSONObject("integrity").getJSONObject("packetEvidence").getString("status"))
            if (BuildConfig.TLS_ENABLED) {
                val tls = report.getJSONObject("tls")
                assertTrue("controlled browser requests must enter gateway", tls.getLong("passthroughConnections") > 0)
                assertEquals(0L, tls.getLong("proxiedConnections"))
            }
            sampler.sample("after_stop")
            File(out, "all-apps-result.json").writeText(JSONObject().put("status", "PASS")
                .put("tlsBuilt", BuildConfig.TLS_ENABLED).put("tlsInterception", false)
                .put("stages", stages).put("originRequests", metrics.length()).put("report", report).toString(2))
        } finally {
            foreground()
            if (LiveCaptureStore.state.value.isCapturing) stopCapture()
            sampler.close()
        }
    }

    @Test fun losingPhysicalWifiStopsCaptureAndRestoredNetworkStartsAgain() {
        val ssid = requireNotNull(args.getString("nio601WifiSsid")) { "Explicit existing test Wi-Fi SSID required" }
        val physical = requireNotNull(connectivity.activeNetwork)
        assertTrue("controlled Wi-Fi required", connectivity.getNetworkCapabilities(physical)!!
            .hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
        val sampler = ProcessResourceSampler(File(out, "network-loss.jsonl"), runId)
        var disabled = false
        try {
            startCapture(excludeSelf = false)
            val vpn = requireNotNull(connectivity.activeNetwork)
            Socket().use { peer ->
                vpn.bindSocket(peer)
                peer.soTimeout = 5000
                peer.connect(InetSocketAddress(host, port), 5000)
                peer.getOutputStream().write("GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n".toByteArray())
                assertTrue(peer.getInputStream().read() >= 0)
            }
            val capture = File(requireNotNull(LiveCaptureStore.state.value.outputPath))
            sampler.sample("before_wifi_loss")
            val start = SystemClock.elapsedRealtime()
            disabled = true
            shell("svc wifi disable")
            await("capture stops on physical network loss") { !LiveCaptureStore.state.value.isCapturing }
            val elapsed = SystemClock.elapsedRealtime() - start
            assertTrue("loss stop must be bounded: $elapsed", elapsed < 10000)
            val report = report(capture)
            assertEquals("network_lost", report.getString("stopReason"))
            assertEquals("COMPLETE", report.getJSONObject("integrity").getJSONObject("cleanup").getString("status"))
            assertFalse(report.getBoolean("complete"))
            shell("svc wifi enable")
            disabled = false
            restoreWifi(ssid)
            LiveCaptureStore.clearError()
            startCapture(excludeSelf = false)
            stopCapture()
            sampler.sample("after_recovery")
            File(out, "network-loss-result.json").writeText(JSONObject().put("status", "PASS")
                .put("tlsBuilt", BuildConfig.TLS_ENABLED).put("stopMs", elapsed).put("report", report).toString(2))
        } finally {
            if (disabled) shell("svc wifi enable")
            restoreWifi(ssid)
            if (LiveCaptureStore.state.value.isCapturing) stopCapture()
            sampler.close()
        }
    }

    private fun startCapture(excludeSelf: Boolean) {
        LiveCaptureStore.clearError()
        ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, excludeSelf)
            putExtra(LiveCaptureVpnService.EXTRA_MAX_DURATION_MINUTES, 5)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
            if (BuildConfig.TLS_ENABLED) putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS,
                TlsCaptureSettingsJson.encode(TlsCaptureSettings(enabled = true,
                    candidatePorts = setOf(port), includeHosts = listOf(host))))
        })
        await("capture start") {
            LiveCaptureStore.state.value.error?.let { error(it) }
            LiveCaptureStore.state.value.isCapturing
        }
        SystemClock.sleep(500)
    }

    private fun stopCapture(): JSONObject {
        val capture = File(requireNotNull(LiveCaptureStore.state.value.outputPath))
        val start = SystemClock.elapsedRealtime()
        context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
        await("capture stop") { !LiveCaptureStore.state.value.isCapturing }
        val result = report(capture)
        assertTrue("stop exceeded 5s", SystemClock.elapsedRealtime() - start <= 5000)
        assertNull(LiveCaptureStore.state.value.error)
        return result
    }

    private fun report(capture: File): JSONObject {
        val file = File(capture.parentFile, "${capture.name}.report.json")
        await("final report") { file.exists() }
        file.copyTo(File(out, file.name), overwrite = true)
        return JSONObject(file.readText())
    }

    private fun awaitWifi() = await("Wi-Fi restore", 45000) {
        connectivity.getNetworkCapabilities(connectivity.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
    }

    private fun restoreWifi(ssid: String) {
        fun connected() = connectivity.getNetworkCapabilities(connectivity.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        if (!connected()) {
            // A saved test network may deliberately have auto-connect disabled.
            // Select that existing entry without changing its saved preference.
            shell("am start -a android.settings.WIFI_SETTINGS")
            SystemClock.sleep(3000) // Let the new scan replace the pre-disable row.
            var lastClick = 0L
            await("saved test network reconnected", 45000) {
                if (connected()) true else {
                    var node = instrumentation.uiAutomation.rootInActiveWindow
                        ?.findAccessibilityNodeInfosByText(ssid)?.firstOrNull { it.text?.toString() == ssid }
                    while (node != null && !node.isClickable) node = node.parent
                    if (node != null && SystemClock.elapsedRealtime() - lastClick > 5000) {
                        val bounds = android.graphics.Rect()
                        node.getBoundsInScreen(bounds)
                        shell("input tap ${bounds.centerX()} ${bounds.centerY()}")
                        lastClick = SystemClock.elapsedRealtime()
                    }
                    false
                }
            }
            awaitWifi()
        }
        foreground()
    }

    private fun foreground() = shell("am start -n ${context.packageName}/com.example.layanalyzer.MainActivity")
    private fun shell(command: String) = ParcelFileDescriptor.AutoCloseInputStream(
        instrumentation.uiAutomation.executeShellCommand(command)).bufferedReader().use { it.readText() }
    private fun await(label: String, timeout: Long = 20000, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeout
        while (!condition()) {
            check(SystemClock.elapsedRealtime() < deadline) { "$label timed out" }
            SystemClock.sleep(20)
        }
    }
}
