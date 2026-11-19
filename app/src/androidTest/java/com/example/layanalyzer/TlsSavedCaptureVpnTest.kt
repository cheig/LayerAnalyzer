// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Process
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.compose.runtime.*
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelStore
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.tls.TlsCaManagerHolder
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.*
import com.example.layanalyzer.ui.components.SavedCaptureOpenDialog
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.PacketListViewModel
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Run each method in its own instrumentation process, with an explicit force-stop between.
 * Only the production VPN writes PCAP/manifest/secrets. The open path never imports a keylog.
 * The origin uses platform trust; only this synthetic target client trusts the local proxy CA.
 */
@RunWith(AndroidJUnit4::class)
class TlsSavedCaptureVpnTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val connectivity get() = context.getSystemService(ConnectivityManager::class.java)
    private val stateDir get() = File(context.noBackupFilesDir, "tls-310-acceptance").apply { mkdirs() }
    private val evidenceDir get() = File(context.getExternalFilesDir(null), "tls-310").apply { mkdirs() }
    private val models = ViewModelStore()
    private var packets: PacketRepository? = null

    @After fun cleanup() {
        if (LiveCaptureStore.state.value.isCapturing) stopCapture()
        instrumentation.runOnMainSync { models.clear() }
        packets?.closeFile()
    }

    @Test fun captureStopsThenAutomaticallyOpens() {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue("TLS production engine required", BuildConfig.TLS_ENABLED)
        assertEquals("Grant Android VPN consent before running", null, VpnService.prepare(context))
        val args = InstrumentationRegistry.getArguments()
        val host = requireNotNull(args.getString("tls310Host"))
        val path = requireNotNull(args.getString("tls310Path"))
        val expectedBody = android.util.Base64.decode(requireNotNull(args.getString("tls310Body")), 0)
        require(path.startsWith('/') && path.none { it == '\r' || it == '\n' })
        val request = "GET $path HTTP/1.1\r\nHost: $host\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".toByteArray()
        // Positive origin is independently verified before starting the VPN.
        assertArrayEquals(expectedBody, body(exchange(host, request, SSLContext.getDefault(), false)))
        val manager = TlsCaManagerHolder.get(context)
        manager.ensureGenerated()
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(manager.exportPublicCertificate().certificateDer))
        val trust = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null); setCertificateEntry("this-test-proxy", cert)
        }
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
        val client = SSLContext.getInstance("TLS").apply { init(null, factory.trustManagers, null) }
        LiveCaptureStore.clearError()
        ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
            putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
            putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS, TlsCaptureSettingsJson.encode(
                TlsCaptureSettings(enabled = true, includeHosts = listOf(host), retainSecrets = true)))
        })
        await("VPN running") { LiveCaptureStore.state.value.isCapturing && isVpn() }
        val response = exchange(host, request, client, true)
        assertArrayEquals(expectedBody, body(response))
        // Allow the asynchronous FIN/ACK exchange to reach TUN before pressing Stop,
        // as in TLS-218. HTTP EOF alone does not mean both TCP directions closed.
        var packetsSeen = LiveCaptureStore.state.value.packetCount
        var lastPacket = System.currentTimeMillis()
        await("TCP teardown settled") {
            val count = LiveCaptureStore.state.value.packetCount
            if (count != packetsSeen) { packetsSeen = count; lastPacket = System.currentTimeMillis() }
            System.currentTimeMillis() - lastPacket >= 750
        }
        stopCapture()
        val stopped = LiveCaptureStore.state.value
        assertEquals(null, stopped.error)
        val original = File(requireNotNull(stopped.outputPath))
        val id = original.nameWithoutExtension
        val artifacts = CaptureArtifactRepository(context)
        val manifest = (artifacts.read(id) as CaptureArtifactState.Present).manifest
        File(evidenceDir, "vpn-manifest.json").writeBytes(artifacts.manifestFile(id).readBytes())
        assertTrue("The real writer must finalize the manifest", manifest.captureIsComplete)
        assertTrue(manifest.tls.complete)
        assertNotNull(manifest.tls.secretsAssetId)
        assertEquals(CaptureRetentionPolicy.KeepCaptureAndSecrets, manifest.retentionPolicy)
        val originalHash = sha256(original)
        val model = open { it.openSavedLiveCapture() }
        assertPlaintext(request, response)
        assertEquals(originalHash, sha256(original))
        val info = requireNotNull(model.savedCaptureOpenInfo.value)
        assertEquals(CaptureMode.ActiveTlsProxy, info.captureMode)
        assertEquals(PacketVantage.AppToLocalProxy, info.vantage)
        assertEquals(manifest.segments.sumOf { it.frameCount }, info.totalFrames)
        assertTrue(info.decryptionComplete)
        assertFalse(info.contextIncomplete)
        File(stateDir, "request.bin").writeBytes(request)
        File(stateDir, "response.bin").writeBytes(response)
        val record = JSONObject().put("captureId", id).put("pid", Process.myPid())
            .put("originalPath", original.path).put("originalSha256", originalHash)
            .put("analysisPath", model.currentFile.value!!.localPath)
            .put("frames", info.totalFrames).put("bodyBytes", expectedBody.size)
        File(stateDir, "restart.json").writeText(record.toString())
        File(evidenceDir, "capture.json").writeText(record.toString(2))
        renderSummary(info, "capture")
        model.dismissSavedCaptureOpenInfo()
        assertPlaintext(request, response)
        Log.i("TLS-310", "realVpnStopped=true automaticKeys=true frames=${info.totalFrames} bodyBytes=${expectedBody.size} bodyEqual=true originalsUnchanged=true pid=${Process.myPid()}")
        assertArrayEquals(expectedBody, body(exchange(host, request, SSLContext.getDefault(), false)))
        Log.i("TLS-310", "networkRestored=true platformTrustVerified=true")
    }

    @Test fun reopenAfterProcessRestart() {
        NativeTestSupport.awaitApplicationEngine()
        val record = JSONObject(File(stateDir, "restart.json").readText())
        assertNotEquals("Must be a new Android process", record.getInt("pid"), Process.myPid())
        val path = record.getString("analysisPath")
        val model = open { vm -> vm.openRecentCapture(RecentCapture("saved-vpn.pcap", File(path).length(), path, 0)) }
        assertPlaintext(File(stateDir, "request.bin").readBytes(), File(stateDir, "response.bin").readBytes())
        val info = requireNotNull(model.savedCaptureOpenInfo.value)
        assertEquals(record.getLong("frames"), info.totalFrames)
        assertTrue(info.decryptionComplete)
        assertEquals(record.getString("originalSha256"), sha256(File(record.getString("originalPath"))))
        renderSummary(info, "restart")
        File(evidenceDir, "restart.json").writeText(JSONObject().put("previousPid", record.getInt("pid"))
            .put("pid", Process.myPid()).put("automaticKeys", true).put("bodyEqual", true)
            .put("frames", info.totalFrames).put("originalUnchanged", true).toString(2))
        Log.i("TLS-310", "restart=true previousPid=${record.getInt("pid")} pid=${Process.myPid()} automaticKeys=true bodyEqual=true originalsUnchanged=true")
    }

    private fun open(action: (PacketListViewModel) -> Unit): PacketListViewModel {
        val repository = PacketRepository().also { packets = it }
        val model = PacketListViewModel(repository, CaptureSessionCoordinator(repository), context)
        instrumentation.runOnMainSync { models.put("acceptance", model); action(model) }
        await("automatic saved open") {
            model.openError.value != null || (model.currentFile.value != null && model.savedCaptureOpenInfo.value != null &&
                model.openProgress.value == null && repository.currentAnalysisRevision().ready)
        }
        assertEquals(null, model.openError.value)
        return model
    }

    private fun assertPlaintext(request: ByteArray, response: ByteArray) {
        val repository = requireNotNull(packets)
        val revision = repository.currentAnalysisRevision()
        assertTrue(revision.ready)
        val objects = repository.getHttpObjects()
        assertEquals(1, objects.size)
        assertArrayEquals(body(response), repository.getHttpObjectPayload(objects.single().id, revision))
        val followed = repository.followTlsStream(objects.single().frameNumber, revision)
        assertTrue(followed.success)
        assertFalse(followed.incomplete)
        fun bytes(direction: TlsFollowDirection) = ByteArrayOutputStream().apply {
            followed.records.filter { it.direction == direction }.forEach { write(it.bytes) }
        }.toByteArray()
        assertArrayEquals(request, bytes(TlsFollowDirection.Client))
        assertArrayEquals(response, bytes(TlsFollowDirection.Server))
    }

    private fun renderSummary(info: SavedCaptureOpenInfo, prefix: String) {
        assertEquals(360, compose.activity.resources.configuration.screenWidthDp)
        var dark by mutableStateOf(false)
        var visible by mutableStateOf(true)
        compose.setContent { LayerAnalyzerTheme(darkTheme = dark) {
            if (visible) SavedCaptureOpenDialog(info) { visible = false }
        } }
        for (theme in listOf("light", "dark")) {
            compose.runOnIdle { dark = theme == "dark" }
            compose.onNodeWithText(info.message).assertIsDisplayed()
            compose.onNodeWithText(context.getString(R.string.saved_capture_open_vantage_proxy)).assertIsDisplayed()
            compose.waitForIdle()
            Thread.sleep(300)
            val bitmap = instrumentation.uiAutomation.takeScreenshot()
            File(evidenceDir, "$prefix-$theme-360dp.png").outputStream().use {
                assertTrue(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it))
            }
            bitmap.recycle()
        }
        compose.onNodeWithText(context.getString(R.string.close)).performClick()
        compose.onNodeWithText(info.message).assertDoesNotExist()
    }

    private fun exchange(host: String, request: ByteArray, ssl: SSLContext, vpn: Boolean): ByteArray {
        assertEquals(vpn, isVpn())
        Socket().use { raw ->
            // MIUI may announce the VPN before netd has installed its UID routing.
            // Retry only the pre-connect bind; never replay TLS or an HTTP request.
            val deadline = System.currentTimeMillis() + 5_000
            while (true) {
                try {
                    requireNotNull(connectivity.activeNetwork).bindSocket(raw)
                    break
                } catch (error: SocketException) {
                    if (!vpn || !error.message.orEmpty().contains("EPERM") || System.currentTimeMillis() >= deadline) throw error
                    Thread.sleep(50)
                }
            }
            raw.connect(InetSocketAddress(host, 443), 10_000)
            raw.soTimeout = 15_000
            (ssl.socketFactory.createSocket(raw, host, 443, true) as SSLSocket).use { socket ->
                socket.enabledProtocols = arrayOf("TLSv1.3")
                socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                socket.startHandshake()
                socket.outputStream.write(request); socket.outputStream.flush()
                return socket.inputStream.readBytes()
            }
        }
    }

    private fun body(response: ByteArray): ByteArray {
        val text = response.toString(Charsets.ISO_8859_1)
        assertTrue(text.startsWith("HTTP/1.1 200 "))
        val end = text.indexOf("\r\n\r\n")
        assertTrue(end >= 0)
        val body = response.copyOfRange(end + 4, response.size)
        if (!text.substring(0, end).contains("transfer-encoding: chunked", true)) return body
        val buffer = okio.Buffer().write(body)
        return ByteArrayOutputStream().apply {
            while (true) {
                val length = buffer.readUtf8LineStrict().substringBefore(';').toLong(16)
                if (length == 0L) break
                require(length in 1..262144)
                write(buffer.readByteArray(length)); check(buffer.readUtf8LineStrict().isEmpty())
            }
        }.toByteArray()
    }

    private fun isVpn() = connectivity.getNetworkCapabilities(connectivity.activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun stopCapture() {
        context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
        await("VPN stopped") { !LiveCaptureStore.state.value.isCapturing && !isVpn() }
    }
    private fun await(label: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 30_000
        while (System.currentTimeMillis() < deadline) { if (condition()) return; Thread.sleep(50) }
        error("Timed out: $label")
    }
    private fun sha256(file: File) = MessageDigest.getInstance("SHA-256").digest(file.readBytes())
        .joinToString("") { "%02x".format(it) }
}
