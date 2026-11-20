// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.annotation.TargetApi
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.CaptureStartupChecks
import com.example.layanalyzer.capture.tls.TlsCertificateManager
import com.example.layanalyzer.capture.tls.TlsSecretStore
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.data.CaptureArtifactLifecycle
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.model.DecodeAsRule
import com.example.layanalyzer.model.DecodeAsScope
import com.example.layanalyzer.model.DecodeAsTransport
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureSettingsJson
import com.example.layanalyzer.model.TlsFollowDirection
import com.example.layanalyzer.model.TlsFollowUnavailableReason
import com.example.layanalyzer.model.TlsHostRule
import com.example.layanalyzer.model.TlsHostScope
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * TLS-218 on a device: the **production** P2 stack — real VPN, real CA, real Go
 * engine, the production SOCKS/gateway wiring — captures a real TLS connection
 * into a TUN PCAP, and the P1 analysis interface then decrypts that captured
 * file and yields the exact bytes the target application sent. This is the P2
 * stage gate: it is the first place the whole chain runs without the P0 probe.
 *
 * Nothing here uses the probe: there is no `LAYANALYZER_TLS_PROBE` build, no
 * `app/src/tlsProbe` service and no `runTlsTunProbe`/`runTlsDissectionProbe`
 * call. The capture is started the way a user starts one — the service intent
 * with `EXTRA_TLS_SETTINGS` — and the file is decrypted through the same
 * `configureTlsSecrets`/`getPacketDetails` path the P1 UI uses.
 *
 * Two trust questions are separated, as the design's fixture rules require:
 *  - whether the **target application** trusts the proxy's install CA (the
 *    downstream leg). A trusting client is decrypted; a client configured with
 *    system roots except this proxy CA rejects the leaf and exchanges no data
 *    (TLS 1.3 may already have emitted handshake keylog records);
 *  - whether the **proxy** trusts the origin's certificate (the upstream leg).
 *    An origin whose chain the device does not trust fails the connection with
 *    `UPSTREAM_CERT_INVALID` and is never reported as decrypted.
 *
 * Preconditions of the controlled origin (documented so a run can provision it):
 * `hostTlsHost` (defaults to `hostGateway`) must serve TLS on `hostTlsPort` with
 * a certificate trusted by the device's system store. `hostTlsPath` defaults to
 * `/`; `hostTlsBodyBase64` optionally pins the fixture's HTTP body. The LAN host
 * at `hostGateway` independently provides HTTP and the untrusted certificate on
 * `hostBadCertPort`. This lets a public, system-trusted fixed-body endpoint serve
 * the positive case without weakening the production upstream verification.
 *
 * There is no `Assume` covering a missing fixture: a missing argument, an
 * unreachable origin or an origin the device does not trust is a *failed* gate,
 * not a skipped one, so a skipped run can never be counted as a pass. VPN
 * consent is the one precondition the platform itself must hold, and it is
 * checked with `assumeTrue` exactly as the other live-capture device tests do:
 * TLS-218's evidence records an un-granted consent as NOT RUN.
 *
 * The four protocol-matrix tests pin the downstream TLS version and ALPN,
 * preflight their origins with system trust, and assert negotiation and HTTP
 * frames in the decrypted TUN PCAP. HTTP/2 uses the pinned OkHttp 4.12 codec.
 * Matrix origins use matrixTls12/13Host, Port and optional Path arguments;
 * matrixConnectHost optionally routes through the fixture's opaque TCP relays.
 */
@RunWith(AndroidJUnit4::class)
class TlsVpnDecryptionTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val arguments = InstrumentationRegistry.getArguments()
    private val hostGateway = arguments.getString("hostGateway")
    private val hostTlsHost = arguments.getString("hostTlsHost") ?: hostGateway
    private val hostTlsPort = arguments.getString("hostTlsPort")?.toIntOrNull()
    private val hostTlsPath = (arguments.getString("hostTlsPath") ?: "/").also {
        require(it.startsWith("/") && it.none { char -> char == '\r' || char == '\n' })
    }
    private val expectedBody = arguments.getString("hostTlsBodyBase64")?.let {
        Base64.decode(it, Base64.NO_WRAP)
    }
    private val hostHttpPort = arguments.getString("hostHttpPort")?.toIntOrNull() ?: DEFAULT_HTTP_PORT
    private val hostBadCertPort = arguments.getString("hostBadCertPort")?.toIntOrNull()
    private val hostClosedPort = arguments.getString("hostClosedPort")?.toIntOrNull() ?: DEFAULT_CLOSED_PORT
    private val ownedCaptures = mutableSetOf<String>()
    private var beforeCaptures = emptySet<String>()
    private var startedByTest = false
    private var finalized = CountDownLatch(0)

    @Before
    fun engineReady() {
        NativeTestSupport.awaitApplicationEngine()
        assertFalse("Do not interrupt an existing capture", LiveCaptureStore.state.value.isCapturing)
        assertFalse("Do not replace another VPN", connectivity.getNetworkCapabilities(connectivity.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
        beforeCaptures = CaptureArtifactRepository(context).captureIds().toSet()
        CaptureStartupChecks.observer = { stage -> if (stage == "finalize") finalized.countDown() }
    }

    @After
    fun releaseCaptureEvenWhenAnAssertionFails() {
        try {
            if (startedByTest) {
                if (LiveCaptureStore.state.value.isCapturing) stopCapture()
                waitUntilStopped()
            }
            ownedCaptures.forEach { CaptureArtifactLifecycle(context).purge(it) }
        } finally {
            CaptureStartupChecks.observer = null
        }
    }

    /**
     * The core acceptance: a target application that trusts the proxy CA completes
     * a TLS exchange through the real VPN; after the capture is fully stopped, the
     * captured TUN PCAP is decrypted by the P1 interface and the decrypted
     * downstream plaintext is byte-for-byte what the application sent.
     */
    @Test
    fun aTrustingApplicationIsDecryptedToItsOwnBytesFromTheCapturedTunPcap() {
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        verifyOriginUsesSystemTrust()
        // Warm the same TLS, Keystore, VPN and Wireshark paths before measuring
        // descriptors: one-time platform initialization is not a per-run leak.
        trustingCaptureRoundTrip("warmup")
        val baselineFds = openFileDescriptors()
        trustingCaptureRoundTrip("measured")
        waitForFileDescriptors(baselineFds)
        Log.i(ACCEPTANCE_TAG, "fdBaseline=$baselineFds fdAfter=${openFileDescriptors()} fdReturned=true")
    }

    @Test
    fun selectedApplicationScopeDecryptsTheCapturedTunWithoutPerFlowAttribution() {
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        verifyOriginUsesSystemTrust()
        trustingCaptureRoundTrip("selected-applications", selectedApplications = true)
    }

    @Test
    @SdkSuppress(minSdkVersion = 29)
    fun protocolMatrixTls12Http11() = verifyProtocolMatrix("TLSv1.2", "http/1.1")

    @Test
    @SdkSuppress(minSdkVersion = 29)
    fun protocolMatrixTls12Http2() = verifyProtocolMatrix("TLSv1.2", "h2")

    @Test
    @SdkSuppress(minSdkVersion = 29)
    fun protocolMatrixTls13Http11() = verifyProtocolMatrix("TLSv1.3", "http/1.1")

    @Test
    @SdkSuppress(minSdkVersion = 29)
    fun protocolMatrixTls13Http2() = verifyProtocolMatrix("TLSv1.3", "h2")

    private data class ProtocolCase(
        val version: String, val alpn: String, val host: String, val port: Int, val path: String
    )

    private fun verifyProtocolMatrix(version: String, alpn: String) {
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        requireNotNull(expectedBody) { "hostTlsBodyBase64 must pin the matrix fixture body" }
        val prefix = if (version == "TLSv1.2") "matrixTls12" else "matrixTls13"
        val protocol = ProtocolCase(version, alpn,
            requireNotNull(arguments.getString("${prefix}Host")) { "${prefix}Host is required" },
            requireNotNull(arguments.getString("${prefix}Port")?.toIntOrNull()) { "${prefix}Port is required" },
            (arguments.getString("${prefix}Path") ?: hostTlsPath).also { path ->
                require(path.startsWith("/") && path.none { it == '\r' || it == '\n' })
            })
        matrixTlsExchange(protocol, "preflight", throughVpn = false)
        trustingCaptureRoundTrip("matrix-$version-$alpn", protocol)
    }

    private fun trustingCaptureRoundTrip(
        phase: String,
        protocol: ProtocolCase? = null,
        selectedApplications: Boolean = false
    ) {
        val host = protocol?.host ?: requireNotNull(hostTlsHost) { "hostTlsHost or hostGateway is required" }
        val port = protocol?.port ?: requireTlsPort()
        val connectHost = if (protocol == null) host else arguments.getString("matrixConnectHost") ?: host
        assertTrue("Host TLS fixture is not reachable at $connectHost:$port", tcpAvailable(connectHost, port))
        val marker = "tls-218-${SystemClock.elapsedRealtime()}"

        LiveCaptureStore.clearError()
        startCapture(host, port, enabled = true, captureIpv6 = false, excludeSelf = false,
            selectedApplications = selectedApplications)
        waitUntilCapturing()
        waitForVpnActive()

        // The target application's own TLS request. It trusts exactly the proxy's
        // install CA, so the downstream handshake reaches the proxy's leaf.
        val legacyRequest = ("GET $hostTlsPath HTTP/1.0\r\nHost: $host\r\nX-LayAnalyzer-Fixture: $marker\r\n" +
            "Connection: close\r\n\r\n").toByteArray(Charsets.US_ASCII)
        val exchange = protocol?.let { matrixTlsExchange(it, marker, throughVpn = true) }
        val request = exchange?.request ?: legacyRequest
        val response = exchange?.response ?: trustedTlsExchange(host, port, request)
        if (protocol == null) {
            assertTrue("the origin must answer through the proxy", response.startsWithHttpStatus())
            expectedBody?.let { body ->
                val headerEnd = response.toString(Charsets.ISO_8859_1).indexOf("\r\n\r\n")
                assertTrue("the fixture must return an HTTP header", headerEnd >= 0)
                assertArrayEquals("the origin must return the pinned fixture body", body,
                    response.copyOfRange(headerEnd + 4, response.size))
            }
        }

        // SSLSocket.close returns before Android/HEV necessarily finish the TCP
        // FIN/ACK exchange. Keep capturing until the per-app stream is idle;
        // stopping the VPN immediately can cut off its final transport packets.
        var lastPacketCount = -1L
        var lastChange = SystemClock.elapsedRealtime()
        waitUntil("the fixture TCP close must settle before stopping capture") {
            val count = LiveCaptureStore.state.value.packetCount
            if (count != lastPacketCount) {
                lastPacketCount = count
                lastChange = SystemClock.elapsedRealtime()
            }
            SystemClock.elapsedRealtime() - lastChange >= 750L
        }

        stopCapture()
        waitUntilStopped()
        val stopped = LiveCaptureStore.state.value
        assertTrue("capture ended with an error: ${stopped.error}", stopped.error == null)
        assertTrue("the stopped TUN capture must be complete without packet loss", stopped.captureIsComplete)
        val captureFile = File(requireNotNull(stopped.outputPath))
        assertTrue("capture file is missing", captureFile.length() > 24)
        val captureId = captureFile.name.removeSuffix(".pcap")

        val tls = tlsReport(captureFile)
        assertEquals("the run stopped cleanly: $tls", "STOPPED", tls.getString("status"))
        assertTrue("no lifecycle error is expected: $tls", tls.isNull("errorCode"))
        assertTrue("the connection must have been intercepted: $tls", tls.getLong("proxiedConnections") >= 1L)
        assertTrue("a downstream secret is required to decrypt: $tls", tls.getLong("secretRecordsAccepted") >= 1L)
        assertTrue("the secret must have reached the disk: $tls", tls.getBoolean("secretsComplete"))
        assertEquals("every accepted secret must have been persisted",
            tls.getLong("secretRecordsAccepted"), tls.getLong("secretRecordsPersisted"))
        protocol?.let {
            assertEquals("one full handshake must persist the version's expected secrets",
                if (it.version == "TLSv1.2") 1L else 4L, tls.getLong("secretRecordsPersisted"))
        }

        // P1: decrypt the *actual* captured file with the persisted downstream keylog.
        val decrypted = decryptCapturedFile(captureId, captureFile, port,
            expectedSecretRecords = tls.getLong("secretRecordsPersisted"), protocol = protocol)
        assertArrayEquals(
            "the decrypted downstream client bytes must equal what the application sent",
            request,
            decrypted.clientBytes
        )
        assertArrayEquals("the entire decrypted response must equal the bytes received by the application",
            response, decrypted.serverBytes)
        protocol?.let {
            val body = if (it.alpn == "h2") TlsHttp2TestClient.decodedBody(decrypted.serverBytes)
                else http11Body(decrypted.serverBytes)
            assertArrayEquals("the decrypted HTTP response must contain the pinned body", expectedBody, body)
        }

        // A stopped capture must not leak its listener or its file descriptors.
        val gatewayPort = tls.getInt("gatewayPort")
        assertFalse(
            "the engine is stopped, so nothing may listen on its port",
            tcpAvailable("127.0.0.1", gatewayPort)
        )
        Log.i(ACCEPTANCE_TAG, "phase=$phase proxied=${tls.getLong("proxiedConnections")} " +
            "secrets=${tls.getLong("secretRecordsAccepted")} secretsComplete=true " +
            "requestBytes=${request.size} responseBytes=${response.size} " +
            "clientBytesEqual=true serverBytesEqual=true listenerClosed=true " +
            "requestSha256=${sha256(request)} responseSha256=${sha256(response)} " +
            "bodySha256=${expectedBody?.let(::sha256)} " +
            "tlsVersion=${protocol?.version} alpn=${protocol?.alpn} pcapProtocolVerified=${protocol != null}")
    }

    /**
     * The same capture, but the target trusts system roots without this proxy CA:
     * even on a device with the CA already installed, it rejects the proxy's leaf and exchanges no application data. TLS 1.3
     * produces keylog records before the client has checked the server's chain;
     * those records are not evidence of a successful handshake or decryption.
     */
    @Test
    fun anApplicationThatDoesNotTrustTheProxyIsRejectedWithoutApplicationData() {
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        verifyOriginUsesSystemTrust()
        val host = requireNotNull(hostTlsHost) { "hostTlsHost or hostGateway is required" }
        val port = requireTlsPort()
        assertTrue("Host TLS fixture is not reachable at $host:$port", tcpAvailable(host, port))

        LiveCaptureStore.clearError()
        startCapture(host, port, enabled = true, captureIpv6 = false, excludeSelf = false)
        waitUntilCapturing()
        waitForVpnActive()

        val rejection = runCatching { untrustedTlsExchange(host, port) }.exceptionOrNull()
        Log.i(ACCEPTANCE_TAG, "untrustedClientFailure=" +
            (rejection?.let { generateSequence(it) { cause -> cause.cause }
                .joinToString(",") { cause -> cause.javaClass.simpleName } } ?: "none"))
        stopCapture()
        waitUntilStopped()
        val captureFile = File(requireNotNull(LiveCaptureStore.state.value.outputPath))
        val tls = tlsReport(captureFile)
        Log.i(ACCEPTANCE_TAG, "untrustedClientCounters proxied=${tls.optLong("proxiedConnections")} " +
            "passthrough=${tls.optLong("passthroughConnections")} failed=${tls.optLong("failedConnections")}")
        assertTrue("the client must reject the proxy certificate, not fail for a transport reason",
            rejection is SSLHandshakeException && generateSequence<Throwable>(rejection) { it.cause }
                .any { it is CertificateException || it is CertPathValidatorException })
        assertEquals("no connection may be counted as proxied: $tls", 0L, tls.getLong("proxiedConnections"))
        assertTrue("the refusal must be counted: $tls", tls.getLong("failedConnections") >= 1L)
        assertEquals("a rejected client must send no application bytes upstream", 0L, tls.getLong("bytesToUpstream"))
        assertEquals("a rejected client must receive no application bytes downstream", 0L, tls.getLong("bytesToDownstream"))
        val persisted = tls.getLong("secretRecordsPersisted")
        assertEquals(tls.getLong("secretRecordsAccepted"), persisted)
        if (persisted > 0) {
            val decrypted = decryptCapturedFile(captureFile.name.removeSuffix(".pcap"), captureFile, port,
                expectedSecretRecords = persisted, expectApplicationData = false)
            assertEquals(0, decrypted.clientBytes.size)
            assertEquals(0, decrypted.serverBytes.size)
        }
        Log.i(ACCEPTANCE_TAG, "untrustedClientRejected=true proxied=0 applicationBytes=0 " +
            "handshakeSecretsPersisted=$persisted")
    }

    /**
     * The origin certificate the device does not trust must fail the connection
     * with an upstream verification error, keep no secret and never be reported as
     * decrypted — the card's step-3 upstream check.
     */
    @Test
    fun anOriginTheDeviceDoesNotTrustIsRefusedWithoutDecryption() {
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        val host = requireHost()
        val port = requireNotNull(hostBadCertPort) {
            "Required fixture argument: hostBadCertPort — a TLS origin whose certificate the " +
                "device does not trust; upstream verification must reject it"
        }
        assertTrue("Host bad-cert fixture is not reachable at $host:$port", tcpAvailable(host, port))

        LiveCaptureStore.clearError()
        startCapture(host, port, enabled = true, captureIpv6 = false, excludeSelf = false)
        waitUntilCapturing()
        waitForVpnActive()

        runCatching { trustedTlsExchange(host, port, "GET / HTTP/1.0\r\nHost: $host\r\n\r\n".toByteArray()) }

        stopCapture()
        waitUntilStopped()
        val captureFile = File(requireNotNull(LiveCaptureStore.state.value.outputPath))
        val tls = tlsReport(captureFile)
        assertEquals("an untrusted origin is not a proxy success: $tls", 0L, tls.getLong("proxiedConnections"))
        assertEquals("no secret exists for a refused upstream: $tls", 0L, tls.getLong("secretRecordsAccepted"))
        assertTrue("the refusal must be counted: $tls", tls.getLong("failedConnections") >= 1L)
    }

    /**
     * The regression half of acceptance 1: with the feature configured but the
     * candidate port untouched, ordinary TCP and UDP still forward and are still
     * captured — the interception path must not disturb the default relay.
     */
    @Test
    fun theDefaultRelayStillCarriesTcpAndUdpWhileInterceptionIsConfigured() {
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        val host = requireHost()
        assertTrue("Host TCP fixture is not reachable at $host:$hostHttpPort", tcpAvailable(host, hostHttpPort))

        LiveCaptureStore.clearError()
        // The fixture's HTTP port is deliberately *not* a candidate, so these
        // connections take the untouched direct path while the engine runs.
        startCapture(host, candidatePort = hostTlsPort ?: DEFAULT_TLS_PORT, enabled = true,
            captureIpv6 = false, excludeSelf = false)
        waitUntilCapturing()
        waitForVpnActive()

        repeat(TCP_REQUESTS) { iteration ->
            val status = plainTcpRequest(host, hostHttpPort)
            assertTrue(
                "TCP request $iteration did not reach the fixture: $status",
                status?.startsWith("HTTP/") == true
            )
        }
        val udpReply = plainUdpProbe(host)
        assertTrue("UDP must not be blocked by the interception path: $udpReply", udpReply)

        stopCapture()
        waitUntilStopped()
        val stopped = LiveCaptureStore.state.value
        assertTrue("capture ended with an error: ${stopped.error}", stopped.error == null)
        assertTrue("the fixture traffic must have been captured: ${stopped.packetCount}", stopped.packetCount > 0)
    }

    /**
     * Card step 3's recursion check: capturing the app's own traffic
     * (`excludeSelf=false`) with IPv6 enabled must not create a VPN loop — the
     * request still terminates and the capture still stops.
     */
    @Test
    fun selfCaptureWithIpv6EnabledDoesNotRecurse() {
        assumeTrue("VPN consent must be granted before this device test", VpnService.prepare(context) == null)
        val host = requireHost()
        assertTrue("Host TCP fixture is not reachable at $host:$hostHttpPort", tcpAvailable(host, hostHttpPort))

        LiveCaptureStore.clearError()
        startCapture(host, hostHttpPort, enabled = false, captureIpv6 = true, excludeSelf = false)
        waitUntilCapturing()
        waitForVpnActive()

        val status = plainTcpRequest(host, hostHttpPort)
        assertTrue("a self-capture with IPv6 must still forward: $status", status?.startsWith("HTTP/") == true)

        stopCapture()
        waitUntilStopped()
        assertTrue("capture ended with an error: ${LiveCaptureStore.state.value.error}", LiveCaptureStore.state.value.error == null)
    }

    // ----- capture control (the production service, nothing probe-shaped) -----

    private fun startCapture(
        host: String,
        candidatePort: Int,
        enabled: Boolean,
        captureIpv6: Boolean,
        excludeSelf: Boolean,
        selectedApplications: Boolean = false
    ) {
        val rule = requireNotNull(TlsHostRule.parse(host)) {
            "The fixture host must be an exact IP or domain rule, not a pattern: $host"
        }
        val settings = TlsCaptureSettings(
            enabled = enabled,
            candidatePorts = setOf(candidatePort),
            hostScope = if (selectedApplications) TlsHostScope.SelectedApplicationsCandidates else TlsHostScope.ExplicitHosts,
            includeHosts = if (selectedApplications) emptyList() else listOf(rule.normalized)
        )
        val intent = Intent(context, LiveCaptureVpnService::class.java).apply {
            putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, excludeSelf)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, captureIpv6)
            putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS, TlsCaptureSettingsJson.encode(settings))
        }
        finalized = CountDownLatch(1)
        startedByTest = true
        ContextCompat.startForegroundService(context, intent)
    }

    private fun stopCapture() {
        context.startService(
            Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP)
        )
    }

    private fun waitUntilCapturing() {
        startWait("capture did not start") {
            val state = LiveCaptureStore.state.value
            state.isCapturing || state.error != null
        }
        val started = LiveCaptureStore.state.value
        rememberOwnedCapture()
        assertTrue(started.error ?: "capture failed to start", started.isCapturing)
    }

    private fun waitUntilStopped() {
        waitUntil("capture did not stop") { !LiveCaptureStore.state.value.isCapturing }
        assertTrue("Capture artifacts must finish publishing", finalized.await(30, TimeUnit.SECONDS))
        rememberOwnedCapture()
        waitUntil("physical network was not restored") {
            connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == false
        }
    }

    private fun rememberOwnedCapture() {
        LiveCaptureStore.state.value.outputPath?.let { path ->
            val id = File(path).nameWithoutExtension
            if (id !in beforeCaptures) ownedCaptures += id
        }
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private fun waitForVpnActive() {
        waitUntil("VPN did not become the active transport") {
            connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }

    // ----- P1: decrypt the captured file with the persisted downstream keylog -----

    private data class DecryptedStream(val clientBytes: ByteArray, val serverBytes: ByteArray)

    /**
     * Opens the *captured* TUN PCAP through the production analysis path and
     * configures the run's own persisted downstream secrets (P1), then reads the
     * followed TLS stream. This is the same interface P1 uses for an imported
     * capture; no probe entry point is involved.
     */
    private fun decryptCapturedFile(
        captureId: String, captureFile: File, port: Int,
        expectedSecretRecords: Long, expectApplicationData: Boolean = true, protocol: ProtocolCase? = null
    ): DecryptedStream =
        runBlocking {
            val repository = PacketRepository()
            val coordinator = CaptureSessionCoordinator(repository)
            val store = TlsSecretStore(context)
            try {
                val info = repository.openFile(captureFile.path).getOrThrow()
                coordinator.registerOpenedSession(info).getOrThrow()
                assertTrue(
                    "the fixture port must be dissected as TLS",
                    repository.applyDecodeAsRule(
                        DecodeAsRule("tls-fixture", DecodeAsScope.Port, DecodeAsTransport.TCP, "", "", null, port, "tls")
                    ).success
                )
                val asset = requireNotNull(store.currentAsset(captureId)) {
                    "the live capture must have persisted a secret asset for $captureId"
                }
                assertEquals("the encrypted asset watermark must match the stopped report",
                    expectedSecretRecords, asset.watermark.sequence)
                val lease = store.acquireLease(captureId, asset.assetId)
                val result = withContext(Dispatchers.Main) { coordinator.configureTlsSecrets(lease) }
                assertTrue("configuring the captured secrets must succeed: $result", result.success)
                protocol?.let { expected ->
                    suspend fun requirePacket(filter: String) {
                        val filterResult = coordinator.applyUserFilter("tcp.port == $port && ($filter)")
                        assertTrue("the protocol filter must compile: $filter; $filterResult", filterResult.success)
                        assertNotNull("the decrypted TUN capture must prove $filter", repository.getVisiblePacketSummary(0))
                    }
                    requirePacket(if (expected.version == "TLSv1.3") {
                        "tls.handshake.type == 2 && tls.handshake.extensions.supported_version == 0x0304"
                    } else {
                        "tls.handshake.type == 2 && tls.handshake.version == 0x0303 && " +
                            "!(tls.handshake.extensions.supported_version == 0x0304)"
                    })
                    requirePacket("tls.handshake.type == ${if (expected.version == "TLSv1.3") 8 else 2} && " +
                        "tls.handshake.extensions_alpn_str == \"${expected.alpn}\"")
                    if (expected.alpn == "h2") {
                        requirePacket("http2.type == 1 && http2.streamid == 1")
                        requirePacket("http2.type == 0 && http2.streamid == 1")
                    } else {
                        requirePacket("http.request.version == \"HTTP/1.1\"")
                        requirePacket("http.response.code == 200")
                    }
                }
                // DNS or other traffic can precede this connection in a real TUN
                // capture. Select its port instead of assuming frame 1 is TLS.
                assertTrue(coordinator.applyUserFilter("tls.handshake.type == 1 && tcp.port == $port").success)
                val frame = requireNotNull(repository.getVisiblePacketSummary(0)) {
                    "the TLS connection must be present in the captured TUN PCAP"
                }.frameNumber
                val followed = repository.followTlsStream(frame, repository.currentAnalysisRevision())
                if (expectApplicationData) {
                    assertTrue("the followed TLS stream must be available: ${followed.unavailableReason}", followed.success)
                    assertFalse("the followed stream must not be incomplete", followed.incomplete)
                } else {
                    assertFalse("a rejected handshake must not yield a decrypted application stream", followed.success)
                    assertTrue("the capture must contain TLS without decrypted application data",
                        followed.unavailableReason in setOf(TlsFollowUnavailableReason.HandshakeIncomplete,
                            TlsFollowUnavailableReason.NoDecryptedApplicationData))
                }
                fun bytes(direction: TlsFollowDirection): ByteArray =
                    ByteArrayOutputStream().also { out ->
                        followed.records.filter { it.direction == direction }.forEach { out.write(it.bytes) }
                    }.toByteArray()
                DecryptedStream(bytes(TlsFollowDirection.Client), bytes(TlsFollowDirection.Server))
            } finally {
                repository.closeFile()
            }
        }

    // ----- TLS client helpers (the "target application") -----

    @TargetApi(29)
    private fun matrixTlsExchange(protocol: ProtocolCase, marker: String, throughVpn: Boolean): TlsHttp2TestClient.Exchange {
        val network = requireNotNull(connectivity.activeNetwork)
        assertEquals(throughVpn, connectivity.getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
        val sslContext = if (throughVpn) {
            trustOnly(TlsCertificateManager(context).exportPublicCertificate().certificateDer)
        } else SSLContext.getDefault()
        Socket().use { raw ->
            bindFixtureSocket(network, raw)
            val connectHost = arguments.getString("matrixConnectHost") ?: protocol.host
            raw.connect(InetSocketAddress(connectHost, protocol.port), 10_000)
            raw.soTimeout = 15_000
            (sslContext.socketFactory.createSocket(raw, protocol.host, protocol.port, true) as SSLSocket).use { socket ->
                socket.enabledProtocols = arrayOf(protocol.version)
                socket.sslParameters = socket.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                    applicationProtocols = arrayOf(protocol.alpn)
                }
                socket.startHandshake()
                assertEquals("the matrix TLS version must not fall back", protocol.version, socket.session.protocol)
                assertEquals("the matrix ALPN must not fall back", protocol.alpn, socket.applicationProtocol)
                val exchange = if (protocol.alpn == "h2") {
                    TlsHttp2TestClient.exchange(socket, protocol.host, protocol.path, marker)
                } else {
                    val request = ("GET ${protocol.path} HTTP/1.1\r\nHost: ${protocol.host}\r\n" +
                        "Accept-Encoding: identity\r\nX-LayAnalyzer-Fixture: $marker\r\nConnection: close\r\n\r\n")
                        .toByteArray(Charsets.US_ASCII)
                    socket.outputStream.write(request)
                    socket.outputStream.flush()
                    val response = socket.inputStream.readBytes()
                    assertTrue("the fixture must return HTTP/1.1 200", response.toString(Charsets.ISO_8859_1)
                        .startsWith("HTTP/1.1 200 "))
                    TlsHttp2TestClient.Exchange(request, response, http11Body(response))
                }
                assertArrayEquals("the protocol fixture must return the pinned body", expectedBody, exchange.body)
                Log.i(ACCEPTANCE_TAG, "matrixHandshake=${protocol.version} alpn=${protocol.alpn} " +
                    "throughVpn=$throughVpn bodyBytes=${exchange.body.size} pinnedBodyEqual=true")
                return exchange
            }
        }
    }

    private fun http11Body(response: ByteArray): ByteArray {
        val headerEnd = response.toString(Charsets.ISO_8859_1).indexOf("\r\n\r\n")
        require(headerEnd >= 0)
        val headers = response.copyOfRange(0, headerEnd).toString(Charsets.ISO_8859_1)
        val body = response.copyOfRange(headerEnd + 4, response.size)
        if (headers.lineSequence().none { it.equals("Transfer-Encoding: chunked", ignoreCase = true) }) return body
        val input = okio.Buffer().write(body)
        val decoded = ByteArrayOutputStream()
        while (true) {
            val length = input.readUtf8LineStrict().substringBefore(';').toLong(16)
            if (length == 0L) return decoded.toByteArray()
            require(length in 1..262144)
            decoded.write(input.readByteArray(length))
            require(input.readUtf8LineStrict().isEmpty())
        }
    }

    private fun bindFixtureSocket(network: Network, socket: Socket) {
        network.bindSocket(socket)
        if (connectivity.getNetworkCapabilities(network)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
            // Pin the TUN source as well as its network. Android can announce
            // VPN capabilities before UID route/source selection has settled.
            // A certificate rejection must exercise TLS, not a reset of a tuple
            // created with the physical source address. Never retry TLS bytes.
            val source = requireNotNull(connectivity.getLinkProperties(network)?.linkAddresses
                ?.firstOrNull { it.address is Inet4Address }?.address)
            socket.bind(InetSocketAddress(source, 0))
        }
    }

    private fun verifyOriginUsesSystemTrust() {
        val host = requireNotNull(hostTlsHost) { "hostTlsHost or hostGateway is required" }
        val request = "HEAD $hostTlsPath HTTP/1.0\r\nHost: $host\r\nConnection: close\r\n\r\n"
            .toByteArray(Charsets.US_ASCII)
        assertTrue("the real origin must pass the system trust and hostname checks before capture",
            tlsExchange(host, requireTlsPort(), request, originTrustWithoutProxy(), throughVpn = false).startsWithHttpStatus())
        Log.i(ACCEPTANCE_TAG, "originSystemTrusted=true hostnameVerified=true")
    }

    /** A target application that trusts exactly the proxy's install CA. */
    private fun trustedTlsExchange(host: String, port: Int, request: ByteArray): ByteArray {
        val proxyCa = TlsCertificateManager(context).exportPublicCertificate().certificateDer
        val trusted = trustOnly(proxyCa)
        return tlsExchange(host, port, request, trusted)
    }

    /** A target that trusts system roots except this proxy, even if installed in the system store. */
    private fun untrustedTlsExchange(host: String, port: Int): ByteArray =
        tlsExchange(host, port, "GET / HTTP/1.0\r\nHost: $host\r\n\r\n".toByteArray(Charsets.US_ASCII), originTrustWithoutProxy())

    private fun originTrustWithoutProxy(): SSLContext {
        // Model a client that does not trust this install's proxy. A rooted test
        // device may already expose that CA as a system: alias. Copy system roots
        // except this specific fixture CA; never modify the device trust store.
        val androidRoots = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        val roots = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null) }
        val proxy = CertificateFactory.getInstance("X.509").generateCertificate(
            TlsCertificateManager(context).exportPublicCertificate().certificateDer.inputStream()) as X509Certificate
        var excludedProxyAnchors = 0
        androidRoots.aliases().toList().filter { it.startsWith("system:") }.forEach { alias ->
            val certificate = androidRoots.getCertificate(alias)
            if (certificate.encoded.contentEquals(proxy.encoded)) excludedProxyAnchors++
            else roots.setCertificateEntry(alias, certificate)
        }
        assertTrue("independent system trust anchors must be present", roots.size() > 0)
        val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(roots) }
        val trusted = managers.trustManagers.filterIsInstance<X509TrustManager>().single()
        assertThrows("the negative client must not trust this proxy CA", CertificateException::class.java) {
            trusted.checkServerTrusted(arrayOf(proxy), proxy.publicKey.algorithm)
        }
        Log.i(ACCEPTANCE_TAG, "negativeClientSystemRoots=${roots.size()} excludedProxyAnchors=$excludedProxyAnchors")
        return SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
    }

    private fun tlsExchange(
        host: String, port: Int, request: ByteArray, sslContext: SSLContext?, throughVpn: Boolean = true
    ): ByteArray {
        Socket().use { raw ->
            // Make the target client's route explicit, including immediately
            // after VPN establishment (the same race guarded by the UDP gate).
            val network = requireNotNull(connectivity.activeNetwork)
            val isVpn = connectivity.getNetworkCapabilities(network)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            assertEquals("the TLS client must use the intended network", throughVpn, isVpn)
            bindFixtureSocket(network, raw)
            raw.connect(InetSocketAddress(host, port), 10_000)
            raw.soTimeout = 10_000
            val socket = (sslContext?.socketFactory ?: SSLContext.getDefault().socketFactory)
                .createSocket(raw, host, port, true) as SSLSocket
            socket.use {
                it.sslParameters = it.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                it.startHandshake()
                Log.i(ACCEPTANCE_TAG, "clientHandshakeProtocol=${it.session.protocol} throughVpn=$throughVpn")
                it.outputStream.write(request)
                it.outputStream.flush()
                return it.inputStream.readBytes()
            }
        }
    }

    private fun ByteArray.startsWithHttpStatus(): Boolean =
        take(5).toByteArray().contentEquals("HTTP/".toByteArray(Charsets.US_ASCII))

    private fun trustOnly(certificateDer: ByteArray): SSLContext {
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certificateDer))
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("layeranalyzer-ca", certificate)
        }
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(store) }
        return SSLContext.getInstance("TLS").apply { init(null, factory.trustManagers, null) }
    }

    // ----- plain TCP/UDP probes and capture fixtures -----

    private fun plainTcpRequest(host: String, port: Int): String? = runCatching {
        Socket().use { socket ->
            bindFixtureSocket(requireNotNull(connectivity.activeNetwork), socket)
            socket.connect(InetSocketAddress(host, port), 10_000)
            socket.soTimeout = 10_000
            socket.getOutputStream().write(
                "HEAD / HTTP/1.0\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)
            )
            socket.getInputStream().bufferedReader(Charsets.US_ASCII).readLine()
        }
    }.getOrNull()

    /**
     * A UDP probe against the closed fixture port: the datagram must leave and the
     * ICMP port-unreachable (or a timeout) must come back, which is enough to prove
     * UDP forwarding is not blocked by the interception path. A blocked path makes
     * the send itself fail.
     */
    private fun plainUdpProbe(host: String): Boolean = runCatching {
        DatagramSocket().use { socket ->
            socket.soTimeout = 2_000
            val payload = "tls-218-udp".toByteArray(Charsets.US_ASCII)
            val port = arguments.getString("hostUdpPort")?.toIntOrNull() ?: 18081
            socket.connect(InetSocketAddress(host, port))
            socket.send(DatagramPacket(payload, payload.size))
            val reply = DatagramPacket(ByteArray(64), 64)
            socket.receive(reply)
            payload.contentEquals(reply.data.copyOfRange(reply.offset, reply.offset + reply.length))
        }
    }.getOrDefault(false)

    private fun tcpAvailable(host: String, port: Int): Boolean = runCatching {
        Socket().use { it.connect(InetSocketAddress(host, port), 2_000) }
    }.isSuccess

    // ----- report and resource helpers -----

    private fun tlsReport(captureFile: File): JSONObject {
        val report = File(captureFile.parentFile, "${captureFile.name}.report.json")
        return waitForValue("the capture report must carry a TLS section: ${report.name}") {
            runCatching {
                if (report.isFile) JSONObject(report.readText()).optJSONObject("tls") else null
            }.getOrNull()
        }
    }

    private fun openFileDescriptors(): Int =
        requireNotNull(File("/proc/self/fd").list()).size

    private fun waitForFileDescriptors(baseline: Int) {
        waitUntil("file descriptors did not return to the warmed baseline (baseline=$baseline)") {
            openFileDescriptors() <= baseline
        }
    }

    private fun requireHost(): String = requireNotNull(hostGateway) {
        "Required fixture argument: hostGateway — a host reachable from the device " +
            "(10.0.2.2 on an emulator, a controlled LAN address on a real device)"
    }

    private fun requireTlsPort(): Int = requireNotNull(hostTlsPort) {
        "Required fixture argument: hostTlsPort — the TLS origin port the target " +
            "application connects to (e.g. 443 or a fixture-specific port)"
    }

    // ----- generic waits -----

    private fun startWait(message: String, predicate: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + DEFAULT_TIMEOUT_MILLIS
        while (SystemClock.elapsedRealtime() < deadline) {
            if (predicate()) return
            SystemClock.sleep(100)
        }
        assertTrue(message, predicate())
    }

    private fun waitUntil(message: String, predicate: () -> Boolean) {
        startWait(message, predicate)
    }

    private fun <T : Any> waitForValue(message: String, producer: () -> T?): T {
        val deadline = SystemClock.elapsedRealtime() + DEFAULT_TIMEOUT_MILLIS
        while (SystemClock.elapsedRealtime() < deadline) {
            producer()?.let { return it }
            SystemClock.sleep(100)
        }
        assertNotNull(message, producer())
        return requireNotNull(producer())
    }

    private companion object {
        const val ACCEPTANCE_TAG = "TLS-218-Acceptance"
        const val DEFAULT_HTTP_PORT = 18_080
        const val DEFAULT_TLS_PORT = 443
        const val DEFAULT_CLOSED_PORT = 9
        const val TCP_REQUESTS = 8
        const val DEFAULT_TIMEOUT_MILLIS = 30_000L
    }
}
