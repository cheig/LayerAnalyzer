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
import com.example.layanalyzer.capture.CaptureStartupChecks
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureSettingsJson
import com.example.layanalyzer.model.TlsHostRule
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * TLS-216 on a device: the assembled capture — real engine, real CA, real
 * gateway channel, real VPN — starts, forwards, stops and starts again, and the
 * stop leaves no listener behind.
 *
 * The destination is the same controlled host fixture the live-capture and
 * gateway-forwarding tests use (`hostGateway` is required; `hostHttpPort`
 * defaults to 18080 on an emulator). It serves plain HTTP on purpose: this card
 * is about the lifecycle, so the engine probes the connection, decides
 * `not_tls` and passes it through. That is enough to prove the gateway channel
 * is wired into the production SOCKS hop — the connection could not reach the
 * fixture otherwise — without claiming a decrypted payload, which belongs to
 * TLS-218.
 *
 * No `Assume` softens a missing fixture: an absent argument or a missing
 * controlled origin fails the test instead of skipping it, so a skipped run can
 * never be counted as a pass. The notification's stop is the same
 * [LiveCaptureVpnService.ACTION_STOP] intent the test sends.
 */
@RunWith(AndroidJUnit4::class)
class TlsVpnLifecycleTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val arguments = InstrumentationRegistry.getArguments()
    private val hostGateway = arguments.getString("hostGateway")
    private val hostHttpPort = arguments.getString("hostHttpPort")?.toIntOrNull() ?: DEFAULT_HTTP_PORT

    @Test
    fun aTlsCaptureForwardsThroughTheGatewayAndStopsWithoutLeavingAListener() {
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        val host = requireNotNull(hostGateway) {
            "Required fixture argument: hostGateway — a host reachable from the device " +
                "(10.0.2.2 on an emulator, a controlled LAN address on a real device)"
        }
        assertTrue("Host HTTP fixture is not reachable at $host:$hostHttpPort", fixtureAvailable(host))

        LiveCaptureStore.clearError()
        if (!BuildConfig.TLS_ENABLED) {
            // Without the build switch there is no engine, and an enabled request
            // must be refused rather than served by a capture that cannot do what
            // the user asked it to.
            startCapture(host)
            waitUntil("the refused capture must report its fixed code") {
                LiveCaptureStore.state.value.error != null
            }
            val error = LiveCaptureStore.state.value.error
            assertTrue("the refusal must carry the fixed code: $error", error?.contains("UNSUPPORTED") == true)
            assertFalse("a refused capture is not a running capture", LiveCaptureStore.state.value.isCapturing)
            return
        }

        waitUntilCapturing(host)

        try {
            val started = LiveCaptureStore.state.value
            assertTrue(started.error ?: "capture failed to start", started.isCapturing)
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            waitUntil("VPN did not become the active transport") {
                connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
            assertTrue("the fixture must answer through the gateway", requestFixture(host))
        } finally {
            stopCapture()
        }

        waitUntil("capture did not stop") { !LiveCaptureStore.state.value.isCapturing }
        val stopped = LiveCaptureStore.state.value
        assertTrue(stopped.error ?: "capture ended with an error", stopped.error == null)
        val captureFile = File(requireNotNull(stopped.outputPath))
        assertTrue("capture file is missing", captureFile.length() > 24)

        val tls = waitForTlsReport(captureFile)
        assertEquals("the run stopped cleanly", "STOPPED", tls.getString("status"))
        assertTrue("no lifecycle error is expected: $tls", tls.isNull("errorCode"))
        assertTrue(
            "the fixture connection must have travelled through the engine: $tls",
            tls.getLong("passthroughConnections") >= 1L
        )
        assertEquals("a plain HTTP origin is never proxied: $tls", 0L, tls.getLong("proxiedConnections"))
        assertTrue("no secret was produced, so nothing can be incomplete: $tls", tls.getBoolean("secretsComplete"))

        val gatewayPort = tls.getInt("gatewayPort")
        assertTrue("the report must name the run's gateway port: $tls", gatewayPort in 1..65535)
        assertFalse(
            "the engine is stopped, so nothing may still listen on its port",
            portAcceptsConnections(gatewayPort)
        )
    }

    @Test
    fun anImmediateStopDuringStartupLeavesNothingRunningAndTheNextCaptureStarts() {
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        val host = requireNotNull(hostGateway) {
            "Required fixture argument: hostGateway — a host reachable from the device " +
                "(10.0.2.2 on an emulator, a controlled LAN address on a real device)"
        }
        assertTrue("Host HTTP fixture is not reachable at $host:$hostHttpPort", fixtureAvailable(host))

        LiveCaptureStore.clearError()
        startCapture(host)
        // The user (or the system) stops before the forwarding components are even
        // ready: the start must notice between its stages and release what it had.
        stopCapture()
        waitUntil("an immediately stopped capture must end") { !LiveCaptureStore.state.value.isCapturing }
        assertTrue(
            "a requested stop is not a failure: ${LiveCaptureStore.state.value.error}",
            LiveCaptureStore.state.value.error == null
        )

        if (!BuildConfig.TLS_ENABLED) return

        // A start that was cancelled must not leave the service unable to start
        // again: the retry inside exists only because the request can arrive while
        // the previous run is still winding down.
        waitUntilCapturing(host)
        stopCapture()
        waitUntil("the restarted capture must stop") { !LiveCaptureStore.state.value.isCapturing }
        assertTrue(
            "the restarted capture ended with an error: ${LiveCaptureStore.state.value.error}",
            LiveCaptureStore.state.value.error == null
        )
    }

    @Test
    fun aRestartWaitsForThePreviousForegroundTeardown() {
        assumeTrue(BuildConfig.TLS_ENABLED && VpnService.prepare(context) == null)
        val host = requireNotNull(hostGateway)
        val finalizing = CountDownLatch(1)
        val release = CountDownLatch(1)
        val nextSocks = CountDownLatch(1)
        val holdFirst = AtomicBoolean(true)
        CaptureStartupChecks.observer = { stage ->
            if (stage == "finalize" && holdFirst.compareAndSet(true, false)) {
                finalizing.countDown()
                check(release.await(20, TimeUnit.SECONDS))
            } else if (stage == "socks" && finalizing.count == 0L) {
                nextSocks.countDown()
            }
        }
        try {
            LiveCaptureStore.clearError()
            waitUntilCapturing(host)
            stopCapture()
            assertTrue("old run must reach final teardown", finalizing.await(10, TimeUnit.SECONDS))
            startCapture(host)
            assertFalse("a new run must not overlap the old foreground teardown",
                nextSocks.await(750, TimeUnit.MILLISECONDS))
            release.countDown()
            assertTrue("the single queued restart must run", nextSocks.await(10, TimeUnit.SECONDS))
            waitUntil("queued restart did not publish") { LiveCaptureStore.state.value.isCapturing }
            // Keep the process alive past Android's foreground-service watchdog.
            SystemClock.sleep(12_000)
            assertTrue("the new foreground run must still forward", requestFixture(host))
            assertTrue(LiveCaptureStore.state.value.isCapturing)
        } finally {
            release.countDown()
            CaptureStartupChecks.observer = null
            stopCapture()
            waitUntil("capture did not stop") { !LiveCaptureStore.state.value.isCapturing }
        }
    }

    @Test
    fun twentyRapidStartupCancellationsCanRestartAndForward() {
        assumeTrue(BuildConfig.TLS_ENABLED && VpnService.prepare(context) == null)
        val host = requireNotNull(hostGateway)
        try {
            LiveCaptureStore.clearError()
            repeat(20) {
                startCapture(host)
                stopCapture()
                waitUntilCapturing(host)
                stopCapture()
                waitUntil("capture did not stop") { !LiveCaptureStore.state.value.isCapturing }
            }
            waitUntilCapturing(host)
            SystemClock.sleep(12_000)
            assertTrue(requestFixture(host))
        } finally {
            stopCapture()
            waitUntil("capture did not stop") { !LiveCaptureStore.state.value.isCapturing }
        }
    }

    private fun startCapture(host: String) {
        val rule = requireNotNull(TlsHostRule.parse(host)) {
            "The fixture host must be an exact IP or domain rule, not a pattern: $host"
        }
        val settings = TlsCaptureSettings(
            enabled = true,
            candidatePorts = setOf(hostHttpPort),
            includeHosts = listOf(rule.normalized)
        )
        val intent = Intent(context, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
            putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS, TlsCaptureSettingsJson.encode(settings))
        }
        ContextCompat.startForegroundService(context, intent)
    }

    private fun stopCapture() {
        context.startService(
            Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP)
        )
    }

    /** One plain HTTP request whose bytes are what the engine probes and passes through. */
    private fun requestFixture(host: String): Boolean = runCatching {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, hostHttpPort), 10_000)
            socket.soTimeout = 10_000
            socket.getOutputStream().write(
                "HEAD / HTTP/1.0\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray()
            )
            socket.getInputStream().bufferedReader(Charsets.US_ASCII).readLine()
        }
    }.getOrNull()?.startsWith("HTTP/") == true

    private fun fixtureAvailable(host: String): Boolean = runCatching {
        Socket().use { it.connect(InetSocketAddress(host, hostHttpPort), 2_000) }
    }.isSuccess

    private fun portAcceptsConnections(port: Int): Boolean = runCatching {
        Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 500) }
    }.isSuccess

    /**
     * The report is written after the capture stops, so a reader has to wait for
     * it rather than read whatever the previous run left in the same place.
     */
    private fun waitForTlsReport(captureFile: File): JSONObject {
        val report = File(captureFile.parentFile, "${captureFile.name}.report.json")
        fun read(): JSONObject? = runCatching {
            if (report.isFile) JSONObject(report.readText()).optJSONObject("tls") else null
        }.getOrNull()
        val deadline = SystemClock.elapsedRealtime() + DEFAULT_TIMEOUT_MILLIS
        while (SystemClock.elapsedRealtime() < deadline) {
            read()?.let { return it }
            SystemClock.sleep(100)
        }
        val tls = read()
        assertNotNull("the capture report must carry a TLS section: ${report.name}", tls)
        return requireNotNull(tls)
    }

    /**
     * Asks for a capture until one actually runs. A captured re-request is ignored
     * while the service is still winding down, so this is a wait for the previous
     * run to release the lifecycle rather than a retry of a failed start.
     */
    private fun waitUntilCapturing(host: String) {
        val deadline = SystemClock.elapsedRealtime() + DEFAULT_TIMEOUT_MILLIS
        while (SystemClock.elapsedRealtime() < deadline) {
            if (LiveCaptureStore.state.value.isCapturing) return
            LiveCaptureStore.state.value.error?.let { throw AssertionError("capture failed to start: $it") }
            startCapture(host)
            SystemClock.sleep(START_RETRY_INTERVAL_MILLIS)
        }
        assertTrue("capture did not start", LiveCaptureStore.state.value.isCapturing)
    }

    private fun waitUntil(message: String, timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS, predicate: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            if (predicate()) return
            SystemClock.sleep(100)
        }
        assertTrue(message, predicate())
    }

    private companion object {
        const val DEFAULT_HTTP_PORT = 18_080
        const val DEFAULT_TIMEOUT_MILLIS = 20_000L
        const val START_RETRY_INTERVAL_MILLIS = 500L
    }
}
