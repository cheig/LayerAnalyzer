// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Process
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.CaptureStartupChecks
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.*
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Explicitly selected, USB-connected test device only. Plain HTTP through real
 * TUN/SOCKS/Go tests recovery without changing production upstream trust.
 * Run armProcessDeath separately: the HOST must terminate that process after
 * armed.json, then launch the app and run verifyProcessDeath in a new process.
 */
@RunWith(AndroidJUnit4::class)
class TlsDeviceRecoveryTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val arguments = InstrumentationRegistry.getArguments()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val host get() = requireNotNull(arguments.getString("hostGateway"))
    private val port get() = arguments.getString("failureHttpPort")?.toInt() ?: 18403
    private val runId = requireNotNull(arguments.getString("failureRunId")).also {
        require(it.matches(Regex("[a-zA-Z0-9-]{1,80}")))
    }
    private val output get() = File(context.getExternalFilesDir(null), "tls-403/$runId").apply { mkdirs() }
    private val control get() = File(context.noBackupFilesDir, "tls-403-$runId.json")
    private val caRoot = File(context.noBackupFilesDir, "tls-403-ca-${UUID.randomUUID()}")
    private val alias = "layeranalyzer.test.tls403.${UUID.randomUUID()}"
    private val captures = mutableSetOf<String>()
    private val expected = "LayerAnalyzer TLS-403 controlled recovery body\n".toByteArray()

    @Before fun ready() {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue(BuildConfig.TLS_ENABLED)
        assertFalse(BuildConfig.TLS_PROBE_ENABLED)
        assertFalse("Start with the test VPN stopped", isVpn())
        val ca = TlsCertificateManager(caRoot, AndroidTlsWrappingKeyProvider(alias))
        TlsCaManagerHolder.installForTest { ca }
        ca.ensureGenerated()
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        assertNull("Grant VPN consent before running", VpnService.prepare(context))
    }

    @After fun cleanup() {
        CaptureStartupChecks.observer = null
        stop()
        TlsCaManagerHolder.installForTest(null)
        captures.forEach { CaptureArtifactLifecycle(context).purge(it) }
        check(caRoot.canonicalFile.parentFile == context.noBackupFilesDir.canonicalFile)
        CaptureFiles.deleteTree(caRoot)
        KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
    }

    @Test fun failureAtEveryStartupBoundaryRollsBackAndCanCaptureAgain() {
        val rows = JSONArray()
        val stages = listOf("tls-capabilities", "tls-ca", "tls-secrets", "tls-engine", "tls-token",
            "tls-gateway", "socks", "packet-pair", "hev", "pcap", "vpn", "publish")
        for (stage in stages) {
            val before = File(context.filesDir, "captures").list().orEmpty().toSet()
            val hit = java.util.concurrent.atomic.AtomicBoolean()
            LiveCaptureStore.clearError()
            CaptureStartupChecks.observer = { current ->
                if (current == stage) {
                    hit.set(true)
                    throw java.io.IOException("TLS403_START_$stage")
                }
            }
            val began = SystemClock.elapsedRealtime()
            try {
                sendStart()
                await("injected $stage failure") { LiveCaptureStore.state.value.error != null }
                assertTrue("checkpoint was not reached", hit.get())
                assertFalse("failed start published RUNNING", LiveCaptureStore.state.value.isCapturing)
                await("$stage rollback") { !isVpn() && resources().getInt("captureWorkers") == 0 &&
                    resources().getLong("globalRefs") == 0L }
                rows.put(JSONObject().put("stage", stage).put("rollbackMillis", SystemClock.elapsedRealtime() - began)
                    .put("error", LiveCaptureStore.state.value.error).put("resources", resources()))
            } finally { CaptureStartupChecks.observer = null }
            File(context.filesDir, "captures").list().orEmpty().filter { it !in before && it.startsWith("live-") }
                .forEach { captures += it }
            // The manager refuses reset if the failed run retained its CA lease.
            TlsCaManagerHolder.get(context).reset()
            start(); stopAndCheck()
        }
        record("startup-boundaries", JSONObject().put("stages", rows).put("recoveryBodySha256", sha256(expected)))
    }

    @Test fun twentyCapturesReleaseRoutesListenersAndWorkers() {
        // Three warmups expose ART/Go lazy worker and descriptor creation before
        // the 20 measured rounds; report raw values as well as assertions.
        repeat(3) { start(); stopAndCheck() }
        val baseline = resources()
        val rounds = JSONArray()
        repeat(20) {
            start()
            val began = SystemClock.elapsedRealtime()
            repeat(4) { requestStop() }
            val report = stopAndCheck()
            val sample = resources().put("round", it + 1)
                .put("stopMillis", SystemClock.elapsedRealtime() - began)
                .put("gatewayPort", report.getJSONObject("tls").getInt("gatewayPort"))
            rounds.put(sample)
            // Capture-owned worker names must disappear exactly. Total ART/Go
            // workers are recorded, since their process-wide pools are elastic.
            assertEquals(0, sample.getInt("captureWorkers"))
            assertTrue("FD growth after warmup: $baseline -> $sample",
                sample.getInt("fds") <= baseline.getInt("fds") + 3)
        }
        record("twenty-rounds", JSONObject().put("baseline", baseline).put("rounds", rounds))
    }

    @Test fun platformRevocationReleasesRouteAndNextCaptureWorks() {
        start()
        val began = SystemClock.elapsedRealtime()
        try {
            shell("appops set ${context.packageName} ACTIVATE_VPN ignore")
            assertNotNull("Platform must revoke the prepared VPN owner", VpnService.prepare(context))
            val report = stopAndCheck(sendStop = false)
            val elapsed = SystemClock.elapsedRealtime() - began
            assertArrayEquals(expected, request())
            shell("appops set ${context.packageName} ACTIVATE_VPN allow")
            assertNull(VpnService.prepare(context))
            start(); stopAndCheck()
            record("revoke", JSONObject().put("routeReleaseAndDrainMillis", elapsed)
                .put("report", report).put("recoveryBodySha256", sha256(expected)))
        } finally {
            shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        }
    }

    @Test fun physicalWifiLossStopsCaptureAndNewNetworkCanCapture() {
        val physical = requireNotNull(connectivity.activeNetwork)
        assertTrue("Use the controlled Wi-Fi", connectivity.getNetworkCapabilities(physical)!!
            .hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
        start()
        val began = SystemClock.elapsedRealtime()
        try {
            shell("svc wifi disable")
            await("physical Wi-Fi disappears") { connectivity.getNetworkCapabilities(physical) == null }
            val report = stopAndCheck(sendStop = false, expectFailure = true)
            assertEquals("network_lost", report.getString("stopReason"))
            assertFalse("Network loss is incomplete", report.getBoolean("complete"))
            val elapsed = SystemClock.elapsedRealtime() - began
            shell("svc wifi enable")
            await("controlled Wi-Fi returns", 30_000) {
                connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            }
            assertArrayEquals(expected, request())
            start(); stopAndCheck()
            record("network-loss", JSONObject().put("routeReleaseAndDrainMillis", elapsed)
                .put("report", report).put("recoveryBodySha256", sha256(expected)))
        } finally {
            shell("svc wifi enable")
        }
    }

    @Test fun pcapEnospcDuringProductionCaptureReleasesRouteAndCanRestart() {
        val directory = File(context.filesDir, "captures").canonicalFile
        // Host mounts ONLY the disposable debug application's capture directory.
        // Refuse to fill anything unless the kernel confirms this exact bounded mount.
        val mounts = File("/proc/mounts").readLines().map { it.split(' ') }
        assertTrue(mounts.any { it[1] == directory.path && it[2] == "tmpfs" })
        require(directory.totalSpace in 1..(2L * 1024 * 1024))
        val filler = File(directory, "tls403-filler")
        try {
            start()
            java.io.FileOutputStream(filler).use { out ->
                try {
                    repeat(513) { out.write(ByteArray(4096)) }
                    fail("isolated capacity was not enforced")
                } catch (error: java.io.IOException) {
                    assertTrue(error.message.orEmpty().contains("ENOSPC"))
                }
            }
            // Large controlled plaintext response flushes the real PCAP writer's
            // 64 KiB buffer. The request may be interrupted by the expected stop.
            runCatching { request("/bulk") }
            await("real PCAP ENOSPC observed") { LiveCaptureStore.state.value.ioErrorCount > 0 }
            val began = SystemClock.elapsedRealtime()
            await("disk failure releases VPN route") { !isVpn() && !LiveCaptureStore.state.value.isCapturing }
            val stopped = LiveCaptureStore.state.value
            assertFalse(stopped.captureIsComplete)
            assertTrue(stopped.ioErrorCount > 0)
            val elapsed = SystemClock.elapsedRealtime() - began
            assertTrue(filler.delete())
            await("failed writer closes") { resources().getInt("captureWorkers") == 0 }
            start(); stopAndCheck()
            record("pcap-enospc-service", JSONObject().put("routeReleaseMillisAfterObservedError", elapsed)
                .put("ioErrors", stopped.ioErrorCount).put("complete", stopped.captureIsComplete)
                .put("recoveryBodySha256", sha256(expected)))
        } finally { filler.delete() }
    }

    @Test fun armProcessDeath() {
        assertFalse("Use a new runId", control.exists())
        start()
        val liveId = File(requireNotNull(LiveCaptureStore.state.value.outputPath)).nameWithoutExtension
        val fixture = TlsPassiveFixture("tls12-h1")
        val id = "tls403-${UUID.randomUUID()}"
        val artifacts = CaptureArtifactRepository(context)
        val packet = File(artifacts.captureDirectory(id).apply { mkdirs() }, "packets.pcap")
        fixture.file("pcap").copyTo(packet)
        val store = TlsSecretStore(context)
        val ref = fixture.file("keylog").inputStream().use {
            store.importRecords(id, KeyLogParser.parse(it) as KeyLogParseResult.Success)
        }
        val countHandle = fixture.open()
        val frames = try { NativeEngine.getFrameCount(countHandle).toLong() } finally { fixture.closeCapture(countHandle) }
        artifacts.writeUnfinalized(CaptureArtifactManifest(id,
            segments = listOf(CaptureSegmentRef(packet.name, 1, frames)),
            secretsPersistedSequence = ref.watermark.sequence,
            tls = CaptureTlsAssets(enabled = true, secretsAssetId = ref.assetId, complete = true)))
        val lease = store.acquireLease(id)
        val handle = NativeEngine.openFile(packet.path, null)
        assertTrue(handle != 0L)
        assertTrue(JSONObject(NativeEngine.applyDecodeAs(handle, "tcp.port", fixture.port, "tls")).getBoolean("success"))
        lease.configureNative({ NativeEngine.closeFile(handle) }) { path ->
            assertTrue(JSONObject(NativeEngine.configureTlsSecrets(handle, path, 1)).getBoolean("success"))
        }
        fixture.assertBody(handle, true)
        // A complete authenticated prefix and torn tails survive a real process
        // death, while a genuinely live plaintext lease must be swept on restart.
        packet.appendBytes(byteArrayOf(0, 1))
        File(context.noBackupFilesDir, "capture-secrets/$id/${ref.assetId}/downstream.keys.enc")
            .appendBytes(byteArrayOf(0, 0))
        val state = JSONObject().put("pid", Process.myPid()).put("captureId", id).put("liveId", liveId)
            .put("caRoot", caRoot.name).put("alias", alias).put("fixtureDirectory", fixture.directory.name)
            .put("leaseFiles", plaintextCount()).put("bodySha256", sha256(fixture.body))
        assertTrue(state.getInt("leaseFiles") > 0)
        control.writeText(state.toString())
        record("armed", state)
        // Host must kill us while VPN and lease are active. Returning normally is
        // a failure; no finally cleanup is allowed to masquerade as process death.
        SystemClock.sleep(60_000)
        lease.close(); fixture.close()
        fail("Host did not terminate the armed process within 60 seconds")
    }

    @Test fun slowTlsDownloadCancelsAndNextCaptureDecryptsTheSameStaticBody() {
        val tlsHost = requireNotNull(arguments.getString("failureTlsHost"))
        val path = requireNotNull(arguments.getString("failureTlsPath"))
        val length = requireNotNull(arguments.getString("failureTlsBytes")).toInt()
        val expectedHash = requireNotNull(arguments.getString("failureTlsSha256"))
        require(path.startsWith("/") && path.none { it == '\r' || it == '\n' })
        require(length in 1..(8 * 1024 * 1024))
        fun connect(ssl: javax.net.ssl.SSLContext): javax.net.ssl.SSLSocket {
            val raw = requireNotNull(connectivity.activeNetwork).socketFactory.createSocket()
            raw.receiveBufferSize = 8192
            try {
                // This capture's declared scope is IPv4. The origin also has
                // AAAA records; selecting those would bypass an IPv4-only VPN
                // and present the origin certificate to the proxy-only client.
                val address = java.net.InetAddress.getAllByName(tlsHost).first { it is java.net.Inet4Address }
                raw.connect(InetSocketAddress(address, 443), 10_000)
                return (ssl.socketFactory.createSocket(raw, tlsHost, 443, true) as javax.net.ssl.SSLSocket).apply {
                    soTimeout = 10_000
                    enabledProtocols = arrayOf("TLSv1.3")
                    sslParameters = sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS"
                        serverNames = listOf(javax.net.ssl.SNIHostName(tlsHost))
                        if (android.os.Build.VERSION.SDK_INT >= 29) applicationProtocols = arrayOf("http/1.1") }
                    startHandshake()
                    outputStream.write("GET $path HTTP/1.1\r\nHost: $tlsHost\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".toByteArray())
                    val header = java.io.ByteArrayOutputStream()
                    while (!header.toString("ISO-8859-1").endsWith("\r\n\r\n")) {
                        val byte = inputStream.read(); check(byte >= 0 && header.size() < 32768); header.write(byte)
                    }
                    val text = header.toString("ISO-8859-1")
                    assertTrue(text.startsWith("HTTP/1.1 200") || text.startsWith("HTTP/1.0 200"))
                    assertTrue(text.lineSequence().any { it.equals("Content-Length: $length", true) })
                }
            } catch (error: Throwable) { raw.close(); throw error }
        }
        fun download(ssl: javax.net.ssl.SSLContext, slow: Boolean): Pair<String, Long> = connect(ssl).use { socket ->
            val began = SystemClock.elapsedRealtime()
            val digest = MessageDigest.getInstance("SHA-256")
            var count = 0
            val buffer = ByteArray(4096)
            while (count < length) {
                val read = socket.inputStream.read(buffer, 0, minOf(buffer.size, length - count))
                assertTrue("TLS body ended early", read > 0)
                digest.update(buffer, 0, read); count += read
                if (slow) SystemClock.sleep(50)
            }
            digest.digest().joinToString("") { "%02x".format(it) } to (SystemClock.elapsedRealtime() - began)
        }
        // Default platform trust first: no fixture root or bypass is installed.
        assertEquals(expectedHash, download(javax.net.ssl.SSLContext.getDefault(), false).first)
        val cert = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(
            java.io.ByteArrayInputStream(TlsCaManagerHolder.get(context).exportPublicCertificate().certificateDer))
        val roots = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("test-proxy", cert) }
        val factory = javax.net.ssl.TrustManagerFactory.getInstance("X509").apply { init(roots) }
        val client = javax.net.ssl.SSLContext.getInstance("TLS").apply { init(null, factory.trustManagers, null) }
        start(tlsHost)
        val full = download(client, true)
        assertEquals(expectedHash, full.first)
        assertTrue("stream must exceed the handshake deadline", full.second > 10_000)
        var cancelledBytes = 0
        val stopMillis: Long
        connect(client).use { socket ->
            val buffer = ByteArray(4096)
            while (cancelledBytes < 65536) {
                val count = socket.inputStream.read(buffer); assertTrue(count > 0); cancelledBytes += count
                SystemClock.sleep(50)
            }
            val began = SystemClock.elapsedRealtime()
            val report = stopAndCheck(intercepted = true)
            stopMillis = SystemClock.elapsedRealtime() - began
            assertTrue(report.getJSONObject("tls").getLong("secretRecordsPersisted") > 0)
            try {
                while (cancelledBytes < length) {
                    val count = socket.inputStream.read(buffer)
                    if (count < 0) break
                    cancelledBytes += count
                }
            } catch (_: java.io.IOException) { }
            assertTrue("cancel must cut the active response short", cancelledBytes < length)
        }
        start(tlsHost)
        assertEquals(expectedHash, download(client, false).first)
        SystemClock.sleep(750)
        val report = stopAndCheck(intercepted = true)
        val capture = File(requireNotNull(LiveCaptureStore.state.value.outputPath))
        val repository = PacketRepository()
        try {
            repository.openFile(capture.path).getOrThrow()
            assertTrue(repository.configureTlsAnalysis(TlsSecretStore(context).acquireLease(capture.nameWithoutExtension),
                repository.currentAnalysisRevision(), "", {}, { _, _ -> }).success)
            val revision = repository.currentAnalysisRevision()
            val matches = repository.getHttpObjects().count {
                sha256(repository.getHttpObjectPayload(it.id, revision)) == expectedHash
            }
            assertTrue("the fresh TUN capture must decrypt the origin's exact body", matches >= 1)
        } finally { repository.closeFile() }
        record("long-tls-cancel", JSONObject().put("host", tlsHost).put("path", path).put("bytes", length)
            .put("sha256", expectedHash).put("slowDownloadMillis", full.second).put("cancelledResponseBytes", cancelledBytes)
            .put("stopMillis", stopMillis).put("recoveryNativeBodyEqual", true).put("recoveryReport", report))
    }

    @Test fun verifyProcessDeath() {
        val state = JSONObject(control.readText())
        assertNotEquals(state.getInt("pid"), Process.myPid())
        // Application engine initialization above already called recoverAtStartup.
        assertEquals("Startup leaked plaintext leases", 0, plaintextCount())
        val artifacts = CaptureArtifactRepository(context)
        val id = state.getString("captureId")
        val recovered = (artifacts.read(id) as CaptureArtifactState.Present).manifest
        assertTrue(recovered.interrupted)
        assertFalse(recovered.complete)
        assertFalse(recovered.tls.complete)
        val live = (artifacts.read(state.getString("liveId")) as CaptureArtifactState.Present).manifest
        assertTrue("Killed production capture must remain interrupted", live.interrupted)
        assertFalse(live.complete)
        TlsPassiveFixture("tls12-h1").use { fixture ->
            val packet = File(artifacts.captureDirectory(id), "packets.pcap")
            assertArrayEquals(fixture.file("pcap").readBytes(), packet.readBytes())
            val handle = NativeEngine.openFile(packet.path, null)
            try {
                assertTrue(JSONObject(NativeEngine.applyDecodeAs(handle, "tcp.port", fixture.port, "tls")).getBoolean("success"))
                TlsSecretStore(context).acquireLease(id).use { lease ->
                    lease.configureNative({ NativeEngine.closeFile(handle) }) { path ->
                        assertTrue(JSONObject(NativeEngine.configureTlsSecrets(handle, path, 1)).getBoolean("success"))
                    }
                    fixture.assertBody(handle, true)
                }
            } finally { NativeEngine.closeFile(handle) }
        }
        assertEquals(0, plaintextCount())
        start(); stopAndCheck()
        record("restart", JSONObject().put("previousPid", state.getInt("pid")).put("pid", Process.myPid())
            .put("plaintextFilesAfterStartup", 0).put("interrupted", true)
            .put("authenticatedPrefixBodySha256", state.getString("bodySha256"))
            .put("recoveryBodySha256", sha256(expected)))
        captures += id; captures += state.getString("liveId")
        val oldCa = File(context.noBackupFilesDir, state.getString("caRoot"))
        check(oldCa.canonicalFile.parentFile == context.noBackupFilesDir.canonicalFile && oldCa.name.startsWith("tls-403-ca-"))
        CaptureFiles.deleteTree(oldCa)
        val oldFixture = File(context.noBackupFilesDir, "tls-passive/${state.getString("fixtureDirectory")}")
        check(oldFixture.canonicalFile.parentFile == File(context.noBackupFilesDir, "tls-passive").canonicalFile)
        CaptureFiles.deleteTree(oldFixture)
        val oldAlias = state.getString("alias").also { require(it.startsWith("layeranalyzer.test.tls403.")) }
        KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(oldAlias) }
        control.delete()
    }

    private fun start(tlsHost: String? = null) {
        LiveCaptureStore.clearError()
        sendStart(tlsHost)
        await("VPN starts") { LiveCaptureStore.state.value.isCapturing || LiveCaptureStore.state.value.error != null }
        assertNull(LiveCaptureStore.state.value.error)
        val captureId = File(requireNotNull(LiveCaptureStore.state.value.outputPath)).nameWithoutExtension
        captures += captureId
        await("VPN becomes active") { isVpn() }
        // Android can publish TRANSPORT_VPN before the new UID routing rules
        // take effect. An early successful GET alone can have used the physical
        // network. Require this capture's gateway event before the measured GET.
        // Only the idempotent readiness GET is retried, within the same 10s bound.
        await("TUN forwarding ready") {
            val bodyMatches = runCatching { request().contentEquals(expected) }.getOrDefault(false)
            val snapshot = TlsConnectionPreviewStore.snapshot.value
            bodyMatches && snapshot?.captureId == captureId && snapshot.counts.passthrough > 0
        }
        try {
            assertArrayEquals(expected, request())
        } catch (error: Exception) {
            val state = LiveCaptureStore.state.value
            val report = state.outputPath?.let { File("$it.report.json") }?.takeIf { it.isFile }?.readText()
            record("unexpected-request-failure", JSONObject().put("error", error.javaClass.simpleName)
                .put("capturing", state.isCapturing).put("captureError", state.error)
                .put("vpn", isVpn()).put("report", report?.let(::JSONObject)).put("resources", resources()))
            throw error
        }
    }

    private fun sendStart(tlsHost: String? = null) {
        ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
            putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS, TlsCaptureSettingsJson.encode(
                TlsCaptureSettings(enabled = true, candidatePorts = if (tlsHost == null) setOf(port) else setOf(port, 443),
                    includeHosts = listOfNotNull(host, tlsHost))))
        })
    }

    private fun stopAndCheck(sendStop: Boolean = true, expectFailure: Boolean = false, intercepted: Boolean = false): JSONObject {
        val path = requireNotNull(LiveCaptureStore.state.value.outputPath)
        if (sendStop) requestStop()
        await("VPN route released") { !isVpn() }
        await("capture finished") { !LiveCaptureStore.state.value.isCapturing }
        if (!expectFailure) assertNull(LiveCaptureStore.state.value.error)
        val reportFile = File("$path.report.json")
        await("capture report committed") { reportFile.isFile && runCatching { JSONObject(reportFile.readText()) }.isSuccess }
        val report = JSONObject(reportFile.readText())
        if (sendStop && !expectFailure) assertEquals("requested_stop", report.getString("stopReason"))
        val tls = report.getJSONObject("tls")
        if (intercepted) assertTrue(tls.getLong("proxiedConnections") > 0) else assertEquals(0L, tls.getLong("proxiedConnections"))
        assertTrue("Recovery traffic must traverse the gateway: $report", tls.getLong("passthroughConnections") > 0)
        assertFalse("stale gateway listener", runCatching {
            Socket().use { it.connect(InetSocketAddress("127.0.0.1", tls.getInt("gatewayPort")), 300) }
        }.isSuccess)
        await("capture workers drained") { resources().getInt("captureWorkers") == 0 && resources().getLong("globalRefs") == 0L }
        val resources = resources()
        for (field in listOf("globalRefs", "attachedThreads", "buffersOutstanding")) assertEquals(field, 0L, resources.getLong(field))
        return report
    }

    private fun stop() {
        requestStop()
        await("cleanup stop") { !LiveCaptureStore.state.value.isCapturing && !isVpn() && resources().getInt("captureWorkers") == 0 }
    }
    private fun requestStop() {
        context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
    }
    private fun request(path: String = "/"): ByteArray = requireNotNull(connectivity.activeNetwork).socketFactory.createSocket().use {
        it.connect(InetSocketAddress(host, port), 1_000); it.soTimeout = 1_000
        it.outputStream.write("GET $path HTTP/1.0\r\nHost: fixture\r\n\r\n".toByteArray())
        val response = it.inputStream.readBytes()
        response.copyOfRange(response.toString(Charsets.ISO_8859_1).indexOf("\r\n\r\n") + 4, response.size)
    }
    private fun isVpn() = connectivity.getNetworkCapabilities(connectivity.activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun plaintextCount() = File(context.noBackupFilesDir, "tls-analysis-leases").walkTopDown()
        .count { it.isFile && it.name != "lease.lock" }
    private fun resources(): JSONObject {
        val names = Thread.getAllStackTraces().keys.filter { it.isAlive }.map { it.name }
        val capability = JSONObject(NativeEngine.getTlsProxyCapabilities())
        return JSONObject().put("fds", File("/proc/self/fd").list()!!.size)
            .put("threads", File("/proc/self/task").list()!!.size)
            .put("captureWorkers", names.count { it.startsWith("LayerAnalyzer-") &&
                (it.contains("VPN") || it.contains("SOCKS") || it.contains("PCAP") || it.contains("TUN") || it.contains("Relay")) })
            .put("globalRefs", capability.getLong("globalRefs"))
            .put("attachedThreads", capability.getLong("attachedThreads"))
            .put("buffersOutstanding", capability.getLong("buffersOutstanding"))
    }
    private fun record(name: String, value: JSONObject) {
        File(output, "$name.json").writeText(value.toString(2))
        // UTP may uninstall its test APKs at the end of a Gradle invocation.
        // Keep the counts/hashes (never payload or keys) in the device test log too.
        android.util.Log.i("TLS403-Evidence", JSONObject().put("runId", runId)
            .put("experiment", name).put("result", value).toString())
    }
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun shell(command: String) = instrumentation.uiAutomation.executeShellCommand(command).use {
        android.os.ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
    }
    private fun await(label: String, timeout: Long = 10_000, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeout
        while (SystemClock.elapsedRealtime() < deadline) { if (condition()) return; SystemClock.sleep(50) }
        assertTrue("Timed out: $label", condition())
    }
}
