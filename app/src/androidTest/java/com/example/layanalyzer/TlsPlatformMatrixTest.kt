// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.content.BroadcastReceiver
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.http.X509TrustManagerExtensions
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.CaptureStartupChecks
import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.data.CaptureArtifactLifecycle
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureSettingsJson
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.ServerSocket
import java.net.InetAddress
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.*
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** TLS-402 controlled peers; fixture roots are only in test-owned trust managers.
 * Gateway tests exercise real JNI/Go/platform verification, without a VPN.
 * TUN tests use the unmodified production upstream trust: the fixture must be
 * rejected when intercepted, and explicitly bypassed TLS must remain intact.
 * Neither path proves that a user CA was installed or trusted by another app.
 */
@RunWith(AndroidJUnit4::class)
class TlsPlatformMatrixTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val arguments = InstrumentationRegistry.getArguments()
    private val host get() = requireNotNull(arguments.getString("hostGateway"))
    private val controlPort get() = requireNotNull(arguments.getString("platformControlPort")?.toIntOrNull())
    private lateinit var physical: Network
    private lateinit var fixture: JSONObject
    private val body = "LayerAnalyzer TLS-402 controlled body\n".toByteArray(Charsets.US_ASCII)
    private var tunStarted = false
    private var beforeCaptures = emptySet<String>()
    private val finalized = CountDownLatch(1)

    @Before fun ready() {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue(BuildConfig.TLS_ENABLED)
        assertFalse(BuildConfig.TLS_PROBE_ENABLED)
        Log.i(TAG, "environment api=${android.os.Build.VERSION.SDK_INT} arch=${System.getProperty("os.arch")} " +
            "process64=${android.os.Process.is64Bit()} nativeAbiDirectory=${context.applicationInfo.nativeLibraryDir.substringAfterLast('/')} " +
            "tls=true probe=false build=${BuildConfig.BUILD_TYPE} targetSdk=${context.applicationInfo.targetSdkVersion}")
        physical = requireNotNull(connectivity.activeNetwork)
        assertFalse("stop VPN before the matrix", connectivity.getNetworkCapabilities(physical)!!
            .hasTransport(NetworkCapabilities.TRANSPORT_VPN))
        fixture = control()
        assertEquals(sha256(body), fixture.getString("bodySha256"))
        beforeCaptures = CaptureArtifactRepository(context).captureIds().toSet()
    }

    @After fun stopOnFailure() {
        try {
            if (tunStarted) {
                if (LiveCaptureStore.state.value.isCapturing) stopCapture()
                assertTrue("TUN fixture must finish publishing", finalized.await(30, TimeUnit.SECONDS))
                LiveCaptureStore.state.value.outputPath?.let { path ->
                    val id = File(path).nameWithoutExtension
                    assertFalse("Never delete a pre-existing capture", beforeCaptures.contains(id))
                    CaptureArtifactLifecycle(context).purge(id)
                }
            }
        } finally {
            if (tunStarted) CaptureStartupChecks.observer = null
        }
    }

    @Test fun tls12GatewayPreservesTheControlledBody() = gateway("TLSv1.2")
    @Test fun tls13GatewayPreservesTheControlledBody() = gateway("TLSv1.3")
    @Test fun tls12Http2GatewayPreservesTheControlledBody() = gateway("TLSv1.2", alpn = "h2")
    @Test fun tls13Http2GatewayPreservesTheControlledBody() = gateway("TLSv1.3", alpn = "h2")
    @Test fun pinnedTls12RejectsTheProxyWithoutReplay() {
        gateway("TLSv1.2", pin = true)
        gateway("TLSv1.2", pin = true, bypass = true)
    }
    @Test fun pinnedTls13RejectsTheProxyWithoutReplay() {
        gateway("TLSv1.3", pin = true)
        gateway("TLSv1.3", pin = true, bypass = true)
    }
    @Test fun mtlsIdentityWorksDirectlyAndIsNotForwardedByTheProxy() = gateway("TLSv1.3", mtls = true)
    @Test fun ipv4TlsOnSelfCapturePreservesExplicitBypass() = tun(ipv6 = false, bypass = true)
    @Test fun ipv6TlsOnSelfCapturePreservesExplicitBypass() = tun(ipv6 = true, bypass = true)
    @Test fun ipv4UntrustedOriginFailsWithoutReplayOrRecursion() = tun(ipv6 = false, bypass = false)
    @Test fun ipv6UntrustedOriginFailsWithoutReplayOrRecursion() = tun(ipv6 = true, bypass = false)

    @Test fun exportCurrentProxyCaForUserInstall() {
        val manager = TlsCaManagerHolder.get(context)
        manager.ensureGenerated()
        val export = manager.exportPublicCertificate()
        File(requireNotNull(context.getExternalFilesDir(null)), "tls402-public-ca.cer").writeBytes(export.certificateDer)
        Log.i(TAG, "export publicCaSha256=${export.certificateSha256} privateKeyExported=false")
    }

    /** Run once before installation and once after, in a fresh process each time.
     * The independent client uses the test APK's debug-overrides/user anchors.
     * The instrumented target's default policy must reject the same proxy both times.
     */
    @Test fun independentUserCaClientAndWebViewMatchTheSystemInstallationState() {
        val expected = arguments.getString("tls402UserCaState", "absent") == "installed"
        val root = certificate(fixture.getString("rootDer"))
        val manager = TlsCaManagerHolder.get(context)
        manager.ensureGenerated()
        val captureId = "tls-402-user-ca-${UUID.randomUUID()}"
        val secrets = TlsSecretStore(context)
        val port = fixture.getInt("tlsPort")
        val protector = UpstreamSocketProtector({ UpstreamSocketProtector.NetworkSnapshot(physical, 1L) }, { true })
        val access = object : TlsNetworkAccess {
            override val generation = 1L
            override val upstream = protector
            override fun prepareHopSocket(socket: Socket) { }
            override fun close() { }
        }
        val extension = X509TrustManagerExtensions(trust(listOf(root)))
        val verifier = AndroidUpstreamTrustVerifier { chain, authType, name -> extension.checkServerTrusted(chain, authType, name) }
        val coordinator = TlsCaptureCoordinator(captureId,
            TlsCaptureSettings(enabled = true, candidatePorts = setOf(port), includeHosts = listOf("localhost")),
            network = access, certificates = { manager }, secretStore = { secrets },
            verification = TlsUpstreamVerification(verifier::verifyUpstream))
        val peers = Collections.synchronizedList(mutableListOf<Socket>())
        val front = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
        try {
            val started = coordinator.start() as? TlsCaptureStart.Started ?: error("gateway start failed")
            val accept = Thread({
                while (!front.isClosed) {
                    val socket = try { front.accept() } catch (_: IOException) { break }
                    peers.add(socket)
                    Thread({
                        try {
                            started.gateway.withNioConnection(host, port) { hop ->
                                peers.add(hop)
                                hop.soTimeout = 15_000
                                socket.soTimeout = 15_000
                                val reverse = Thread({ copy(hop, socket) }, "tls402-return").apply { isDaemon = true; start() }
                                copy(socket, hop)
                                reverse.join(16_000)
                            }
                        } catch (_: IOException) { /* client reports a bounded TLS error */ }
                        finally { socket.close() }
                    }, "tls402-client-hop").apply { isDaemon = true; start() }
                }
            }, "tls402-client-listener").apply { isDaemon = true; start() }
            // This SSLContext belongs to the main APK, which has no user anchor.
            val defaultClient = SSLContext.getInstance("TLS").apply { init(null, null, null) }
            val defaultResult = runCatching { exchange(Socket(), "127.0.0.1", front.localPort,
                "localhost", "TLSv1.3", defaultClient) }
            assertTrue("targetSdk>=24 default policy must reject the proxy", defaultResult.exceptionOrNull() is SSLHandshakeException)
            for (mode in listOf("https", "webview")) {
                val requestId = UUID.randomUUID().toString()
                val latch = CountDownLatch(1)
                val result = AtomicReference<JSONObject>()
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(context: Context, intent: Intent) {
                        if (intent.getStringExtra("requestId") == requestId) {
                            result.set(JSONObject(requireNotNull(intent.getStringExtra("result"))))
                            latch.countDown()
                        }
                    }
                }
                ContextCompat.registerReceiver(context, receiver, IntentFilter("com.layeranalyzer.TLS402_CLIENT_RESULT"), ContextCompat.RECEIVER_EXPORTED)
                try {
                    val testPackage = InstrumentationRegistry.getInstrumentation().context.packageName
                    InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(
                        "am start -n $testPackage/com.example.layanalyzer.Tls402ClientActivity --es url https://localhost:${front.localPort}/ --es mode $mode --es requestId $requestId"
                    ).use { descriptor -> java.io.FileInputStream(descriptor.fileDescriptor).readBytes() }
                    assertTrue("independent $mode client must return", latch.await(25, TimeUnit.SECONDS))
                    val report = requireNotNull(result.get())
                    assertEquals(report.toString(), expected, report.getBoolean("ok"))
                    assertEquals(34, report.getInt("targetSdk"))
                    assertTrue("debug-overrides require a debuggable test APK", report.getBoolean("debuggable"))
                    if (expected) assertEquals(report.toString(), sha256(body), report.getString("bodySha256"))
                    Log.i(TAG, "userCa=$expected mode=$mode defaultClientRejected=true result=$report")
                } finally { context.unregisterReceiver(receiver) }
            }
            if (expected && arguments.getString("tls402BrowserPackage") == "com.android.chrome") {
                val before = counts("ipv4-tls").getInt("requests")
                val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
                automation.executeShellCommand("am start -a android.intent.action.VIEW -d https://localhost:${front.localPort}/ -p com.android.chrome")
                    .use { descriptor -> java.io.FileInputStream(descriptor.fileDescriptor).readBytes() }
                await("Chrome request must reach the controlled origin") {
                    counts("ipv4-tls").getInt("requests") > before
                }
                // Chrome 74 does not expose page text to this UiAutomation
                // service on MIUI. Keep a screenshot for explicit visual QA;
                // the origin counter alone does not prove rendered content.
                SystemClock.sleep(1_000)
                val screenshot = requireNotNull(automation.takeScreenshot())
                File(requireNotNull(context.getExternalFilesDir(null)), "tls402-chrome.png").outputStream().use {
                    assertTrue(screenshot.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it))
                }
                screenshot.recycle()
                Log.i(TAG, "userCa=true browser=com.android.chrome originRequestObserved=true screenshotRequiresVisualReview=true")
            }
            front.close()
            synchronized(peers) { peers.forEach { runCatching { it.close() } } }
            accept.join(1_000)
            coordinator.stop()
            assertListenerClosed(started.port)
        } finally {
            front.close()
            synchronized(peers) { peers.forEach { runCatching { it.close() } } }
            coordinator.close()
            secrets.purgeCapture(captureId)
        }
    }

    private fun copy(source: Socket, target: Socket) {
        try {
            source.inputStream.copyTo(target.outputStream, 8_192)
            target.shutdownOutput()
        } catch (_: IOException) { /* bounded closure on TLS rejection */ }
    }

    private fun gateway(version: String, pin: Boolean = false, mtls: Boolean = false, bypass: Boolean = false,
        alpn: String = "http/1.1") {
        val root = certificate(fixture.getString("rootDer"))
        val leafPin = sha256(certificate(fixture.getString("leafDer")).publicKey.encoded)
        val manager = TlsCaManagerHolder.get(context)
        manager.ensureGenerated()
        val proxyRoot = CertificateFactory.getInstance("X.509").generateCertificate(
            manager.exportPublicCertificate().certificateDer.inputStream()) as X509Certificate
        val captureId = "tls-402-${UUID.randomUUID()}"
        val secretStore = TlsSecretStore(context)
        val port = fixture.getInt(if (mtls) "mtlsPort" else "tlsPort")
        val counter = if (mtls) "ipv4-mtls" else "ipv4-tls"
        val identity = if (mtls) clientIdentity() else null
        val sslContext = ssl(listOf(root, proxyRoot), identity)
        // The same identity/pin must work against the real origin first.
        exchange(physical.socketFactory.createSocket(), host, port, "localhost", version, sslContext,
            if (pin) leafPin else null, alpn).also { assertBody(it, alpn) }
        val before = counts(counter)
        val protector = UpstreamSocketProtector({ UpstreamSocketProtector.NetworkSnapshot(physical, 1L) }, { true })
        val access = object : TlsNetworkAccess {
            override val generation = 1L
            override val upstream = protector
            override fun prepareHopSocket(socket: Socket) { }
            override fun close() { }
        }
        val extension = X509TrustManagerExtensions(trust(listOf(root)))
        val verifier = AndroidUpstreamTrustVerifier { chain, authType, name ->
            extension.checkServerTrusted(chain, authType, name)
        }
        val coordinator = TlsCaptureCoordinator(captureId,
            TlsCaptureSettings(enabled = true, candidatePorts = setOf(port), includeHosts = listOf("localhost"),
                bypassHosts = if (bypass) listOf("localhost") else emptyList()),
            network = access, certificates = { manager }, secretStore = { secretStore },
            verification = TlsUpstreamVerification(verifier::verifyUpstream))
        try {
            val started = coordinator.start() as? TlsCaptureStart.Started ?: error("gateway start failed")
            val result = runCatching {
                started.gateway.withNioConnection(host, port, awaitRelayClose = !mtls && (!pin || bypass)) { socket ->
                    tlsExchange(socket, "localhost", version, sslContext, if (pin) leafPin else null, alpn)
                }
            }
            if (pin && !bypass) {
                assertTrue("pin mismatch must be explicit", result.exceptionOrNull() is SSLPeerUnverifiedException)
            } else if (mtls) {
                assertTrue("origin must not return application data without the identity",
                    result.isFailure || result.getOrThrow().isEmpty())
            } else {
                assertBody(result.getOrThrow(), alpn)
            }
            await("one origin connection finishes") {
                coordinator.pump()
                val state = coordinator.state()
                state.connections.failed + state.connections.closed >= 1
            }
            val state = coordinator.stop()
            val after = counts(counter)
            Log.i(TAG, "gatewayOutcome tls=$version pin=$pin mtls=$mtls bypass=$bypass " +
                "originDials=${after.getInt("accepted") - before.getInt("accepted")} " +
                "originRequests=${after.getInt("requests") - before.getInt("requests")} " +
                "proxied=${state.connections.proxied} failed=${state.connections.failed} " +
                "closed=${state.connections.closed} passthrough=${state.connections.passthrough} " +
                "bytesToUpstream=${state.traffic.bytesToUpstream}")
            assertEquals("no request replay or fallback dial", 1, after.getInt("accepted") - before.getInt("accepted"))
            assertEquals("pin/mTLS rejection must send no HTTP request", if ((pin && !bypass) || mtls) 0 else 1,
                after.getInt("requests") - before.getInt("requests"))
            if (!pin && !mtls) assertEquals("both TLS legs must use the requested application protocol", alpn, after.getString("alpn"))
            if (mtls) assertTrue("direct control must present client identity", before.getBoolean("clientIdentity"))
            assertEquals("only explicit bypass may pass through", if (bypass) 1L else 0L, state.connections.passthrough)
            if (bypass) {
                assertEquals("bypass must not be proxied", 0L, state.connections.proxied)
                assertEquals("bypass must not fail", 0L, state.connections.failed)
                assertEquals("bypass must not persist secrets", 0L, state.secrets?.persisted ?: 0L)
            } else if (mtls) {
                assertEquals(1L, state.connections.failed)
                assertEquals(0L, state.connections.closed)
            } else if (pin) {
                // An application-side pin check after startHandshake closes TLS
                // normally. The proxy cannot infer pinning from that closure.
                assertEquals("pin rejection must finish exactly one connection", 1L,
                    state.connections.failed + state.connections.closed)
                assertEquals("pin rejection must send no application bytes upstream", 0L, state.traffic.bytesToUpstream)
            } else {
                assertEquals(1L, state.connections.proxied)
                assertEquals(0L, state.connections.failed)
                assertTrue(state.secrets!!.persisted > 0)
            }
            assertListenerClosed(started.port)
            Log.i(TAG, "gateway tls=$version alpn=$alpn pin=$pin mtls=$mtls bypass=$bypass originDials=1 " +
                "originRequests=${after.getInt("requests") - before.getInt("requests")} " +
                "failed=${state.connections.failed} proxied=${state.connections.proxied} bodySha256=${if ((pin && !bypass) || mtls) "none" else sha256(body)}")
        } finally {
            coordinator.close()
            secretStore.purgeCapture(captureId)
        }
    }

    private fun tun(ipv6: Boolean, bypass: Boolean) {
        assertNull("VPN permission is required", VpnService.prepare(context))
        val address = fixture.getString(if (ipv6) "ipv6" else "ipv4")
        val port = fixture.getInt("tlsPort")
        val counter = if (ipv6) "ipv6-tls" else "ipv4-tls"
        val client = ssl(listOf(certificate(fixture.getString("rootDer"))))
        assertBody(exchange(physical.socketFactory.createSocket(), address, port, "localhost", "TLSv1.3", client))
        val before = counts(counter)
        val settings = TlsCaptureSettings(enabled = true, candidatePorts = setOf(port),
            includeHosts = listOf("localhost"), bypassHosts = if (bypass) listOf("localhost") else emptyList())
        LiveCaptureStore.clearError()
        CaptureStartupChecks.observer = { stage -> if (stage == "finalize") finalized.countDown() }
        tunStarted = true
        ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
            putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, ipv6)
            putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS, TlsCaptureSettingsJson.encode(settings))
        })
        await("VPN start") { LiveCaptureStore.state.value.isCapturing || LiveCaptureStore.state.value.error != null }
        assertTrue(LiveCaptureStore.state.value.error, LiveCaptureStore.state.value.isCapturing)
        await("VPN active") { connectivity.getNetworkCapabilities(connectivity.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
        val vpn = requireNotNull(connectivity.activeNetwork)
        // NetworkCapabilities can announce a VPN before its UID routing/pumps
        // carry the first packet. Probe only a harmless control GET, never retry
        // the TLS application request under test.
        await("VPN forwards the controlled readiness probe") {
            runCatching {
                vpn.socketFactory.createSocket().use { socket ->
                    socket.connect(InetSocketAddress(host, controlPort), 1_000)
                    socket.soTimeout = 1_000
                    socket.outputStream.write("GET / HTTP/1.0\r\nHost: fixture\r\n\r\n".toByteArray())
                    socket.inputStream.read() == 'H'.code
                }
            }.getOrDefault(false)
        }
        val result = runCatching { exchange(vpn.socketFactory.createSocket(), address, port,
            "localhost", "TLSv1.3", client) }
        Log.i(TAG, "tunRequest ipv6=$ipv6 bypass=$bypass error=${result.exceptionOrNull()?.javaClass?.simpleName ?: "none"}")
        if (bypass) assertBody(result.getOrThrow()) else assertTrue("untrusted upstream must fail", result.isFailure)
        SystemClock.sleep(1_000)
        stopCapture()
        await("VPN stop") { !LiveCaptureStore.state.value.isCapturing }
        val stopped = LiveCaptureStore.state.value
        assertNull(stopped.error)
        await("physical route restored") { connectivity.getNetworkCapabilities(connectivity.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == false }
        val after = counts(counter)
        assertEquals("protect must prevent recursion", 1, after.getInt("accepted") - before.getInt("accepted"))
        assertEquals(if (bypass) 1 else 0, after.getInt("requests") - before.getInt("requests"))
        val capture = File(requireNotNull(stopped.outputPath))
        assertTrue("actual IP family must be in TUN PCAP", hasIpFamily(capture.readBytes(), if (ipv6) 6 else 4))
        val reportFile = File(capture.parentFile, "${capture.name}.report.json")
        await("final capture report") { reportFile.isFile }
        val report = JSONObject(reportFile.readText()).getJSONObject("tls")
        assertEquals(0L, report.getLong("proxiedConnections"))
        assertEquals(0L, report.getLong("secretRecordsAccepted"))
        if (bypass) assertTrue("bypass must be observed by the running engine: $report", report.getLong("passthroughConnections") >= 1)
        else assertTrue(report.getLong("failedConnections") >= 1)
        if (!bypass) {
            val events = requireNotNull(TlsConnectionPreviewStore.snapshot.value).connections
            assertTrue("failure must retain its upstream stage", events.any { it.error?.code?.name == "UPSTREAM_CERT_INVALID" })
        }
        Log.i(TAG, "tun ipv6=$ipv6 bypass=$bypass excludeSelf=false originDials=1 " +
            "originRequests=${after.getInt("requests") - before.getInt("requests")} " +
            "packets=${stopped.packetCount} routeRestored=true bodySha256=${if (bypass) sha256(body) else "none"}")
    }

    private fun hasIpFamily(bytes: ByteArray, version: Int): Boolean {
        require(bytes.size >= 24)
        fun le32(offset: Int) = (0..3).fold(0) { value, i -> value or ((bytes[offset + i].toInt() and 255) shl (8 * i)) }
        assertEquals("TUN captures use LINKTYPE_RAW", 101, le32(20))
        var offset = 24
        var found = false
        while (offset + 16 <= bytes.size) {
            val length = le32(offset + 8)
            require(length >= 0 && offset + 16L + length <= bytes.size)
            if (length > 0 && (bytes[offset + 16].toInt() and 255) ushr 4 == version) found = true
            offset += 16 + length
        }
        assertEquals("no truncated PCAP record", bytes.size, offset)
        return found
    }

    private fun exchange(socket: Socket, address: String, port: Int, identity: String, version: String,
        ssl: SSLContext, pin: String? = null, alpn: String = "http/1.1"): ByteArray = socket.use {
        it.connect(InetSocketAddress(address, port), 5_000)
        tlsExchange(it, identity, version, ssl, pin, alpn)
    }

    private fun tlsExchange(raw: Socket, identity: String, version: String, ssl: SSLContext, pin: String?,
        alpn: String = "http/1.1"): ByteArray =
        (ssl.socketFactory.createSocket(raw, identity, raw.port, true) as SSLSocket).use { socket ->
            socket.soTimeout = 10_000
            socket.enabledProtocols = arrayOf(version)
            socket.sslParameters = socket.sslParameters.apply {
                endpointIdentificationAlgorithm = "HTTPS"
                serverNames = listOf(SNIHostName(identity))
                if (android.os.Build.VERSION.SDK_INT >= 29) applicationProtocols = arrayOf(alpn)
            }
            socket.startHandshake()
            assertEquals(version, socket.session.protocol)
            if (android.os.Build.VERSION.SDK_INT >= 29) assertEquals(alpn, socket.applicationProtocol)
            if (pin != null && sha256(socket.session.peerCertificates.first().publicKey.encoded) != pin)
                throw SSLPeerUnverifiedException("controlled SPKI pin mismatch")
            if (alpn == "h2") return@use TlsHttp2TestClient.exchange(socket, identity, "/", "tls-402").response
            socket.outputStream.write("GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n".toByteArray())
            socket.inputStream.readBytes().also { assertTrue("bounded controlled response", it.size < 4096) }
        }

    private fun trust(roots: List<X509Certificate>): X509TrustManager {
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            roots.forEachIndexed { i, root -> setCertificateEntry("root-$i", root) }
        }
        return TrustManagerFactory.getInstance("X509").apply { init(store) }
            .trustManagers.filterIsInstance<X509TrustManager>().single()
    }

    private fun ssl(roots: List<X509Certificate>, identity: Pair<java.security.PrivateKey, X509Certificate>? = null): SSLContext {
        val managers = identity?.let { (key, cert) ->
            val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null)
                setKeyEntry("client", key, charArrayOf(), arrayOf(cert, roots.first()))
            }
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, charArrayOf()) }.keyManagers
        }
        return SSLContext.getInstance("TLS").apply { init(managers, arrayOf(trust(roots)), null) }
    }

    private fun clientIdentity(): Pair<java.security.PrivateKey, X509Certificate> {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val response = control(Base64.encodeToString(key.public.encoded, Base64.NO_WRAP))
        return key.private to certificate(response.getString("certificateDer"))
    }

    private fun control(publicKey: String? = null): JSONObject = physical.socketFactory.createSocket().use { socket ->
        socket.connect(InetSocketAddress(host, controlPort), 5_000)
        socket.soTimeout = 5_000
        val data = publicKey?.toByteArray(Charsets.US_ASCII) ?: byteArrayOf()
        socket.outputStream.write((if (publicKey == null) "GET / HTTP/1.0\r\n" else "POST /client-certificate HTTP/1.0\r\n").toByteArray())
        socket.outputStream.write("Host: fixture\r\nContent-Length: ${data.size}\r\nConnection: close\r\n\r\n".toByteArray())
        socket.outputStream.write(data)
        val response = socket.inputStream.readBytes().toString(Charsets.UTF_8)
        assertTrue("bounded control response", response.length < 16384)
        assertTrue(response.startsWith("HTTP/1.0 200"))
        JSONObject(response.substringAfter("\r\n\r\n"))
    }

    private fun counts(label: String) = control().getJSONObject("counters").getJSONObject(label)
    private fun certificate(base64: String) = CertificateFactory.getInstance("X.509")
        .generateCertificate(Base64.decode(base64, Base64.NO_WRAP).inputStream()) as X509Certificate
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun assertBody(response: ByteArray, alpn: String = "http/1.1") {
        if (alpn == "h2") {
            assertArrayEquals(body, TlsHttp2TestClient.decodedBody(response))
            return
        }
        assertTrue(response.toString(Charsets.US_ASCII).startsWith("HTTP/1.0 200"))
        val headerEnd = response.toString(Charsets.ISO_8859_1).indexOf("\r\n\r\n")
        assertTrue(headerEnd >= 0)
        assertArrayEquals(body, response.copyOfRange(headerEnd + 4, response.size))
    }
    private fun stopCapture() { context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP)) }
    private fun assertListenerClosed(port: Int) {
        assertThrows(IOException::class.java) { Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 500) } }
    }
    private fun await(message: String, predicate: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 20_000
        while (!predicate()) {
            assertTrue("timeout: $message", SystemClock.elapsedRealtime() < deadline)
            SystemClock.sleep(50)
        }
    }
    private companion object { const val TAG = "TLS-402" }
}
