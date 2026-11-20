// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.system.Os
import android.util.Base64
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.CaptureStartupChecks
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.*
import java.io.File
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Inet4Address
import java.net.Socket
import java.net.SocketException
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** One bounded synthetic request; the VPN includes only this test's target app. */
@RunWith(AndroidJUnit4::class)
class TlsJournalVpnPrivacyTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)

    @Test fun cancellationBeforeVpnEstablishmentClosesJournalAndAllowsDeletion() {
        NativeTestSupport.awaitApplicationEngine()
        assertFalse(LiveCaptureStore.state.value.isCapturing)
        assertFalse(isVpn())
        assertNull(VpnService.prepare(context))
        val artifacts = CaptureArtifactRepository(context)
        val before = artifacts.captureIds().toSet()
        val reached = CountDownLatch(1)
        val release = CountDownLatch(1)
        val finished = CountDownLatch(1)
        var createdId: String? = null
        CaptureStartupChecks.observer = { stage ->
            if (stage == "socks") { reached.countDown(); check(release.await(20, TimeUnit.SECONDS)) }
            if (stage == "finalize") finished.countDown()
        }
        try {
            val host = requireNotNull(InstrumentationRegistry.getArguments().getString("hostTlsHost"))
            ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
                putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
                putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
                putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
                putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS, TlsCaptureSettingsJson.encode(
                    TlsCaptureSettings(enabled = true, includeHosts = listOf(host))))
            })
            assertTrue("Startup must reach the real coordinator", reached.await(20, TimeUnit.SECONDS))
            val id = (artifacts.captureIds().toSet() - before).single()
            createdId = id
            val file = artifacts.connectionEventsFile(id)
            await("journal creation") { file.isFile }
            context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
            release.countDown()
            assertTrue("Cancelled startup must finish", finished.await(20, TimeUnit.SECONDS))
            assertFalse(LiveCaptureStore.state.value.isCapturing)
            assertFalse(isVpn())
            CaptureArtifactLifecycle(context).purge(id)
            assertFalse(file.exists())
        } finally {
            release.countDown()
            CaptureStartupChecks.observer = null
            if (LiveCaptureStore.state.value.isCapturing || isVpn()) stop()
            createdId?.takeUnless(before::contains)?.let { CaptureArtifactLifecycle(context).purge(it) }
        }
    }

    @Test fun realVpnStopReopensPrivateJournalAndDecryptsSavedCapture() {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue(BuildConfig.TLS_ENABLED)
        assertFalse(BuildConfig.TLS_PROBE_ENABLED)
        assertFalse("An existing capture must not be disturbed", LiveCaptureStore.state.value.isCapturing)
        assertFalse("An existing VPN must not be disturbed", isVpn())
        assertNull("Use existing Android VPN consent", VpnService.prepare(context))
        val args = InstrumentationRegistry.getArguments()
        val host = requireNotNull(args.getString("hostTlsHost"))
        val port = requireNotNull(args.getString("hostTlsPort")?.toIntOrNull())
        val path = requireNotNull(args.getString("hostTlsPath"))
        require(path.startsWith('/') && path.none { it == '\r' || it == '\n' })
        val expected = Base64.decode(requireNotNull(args.getString("hostTlsBodyBase64")), Base64.NO_WRAP)
        val request = "GET $path HTTP/1.1\r\nHost: $host\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)
        val address = requireNotNull(connectivity.activeNetwork).getAllByName(host).first { it.address.size == 4 }
        val artifacts = CaptureArtifactRepository(context)
        val before = artifacts.captureIds().toSet()
        val ca = TlsCaManagerHolder.get(context)
        val caBefore = ca.status()
        assertTrue("Use the existing app CA without generating or resetting it", caBefore.usable)
        val trust = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("test-proxy", CertificateFactory.getInstance("X.509")
                .generateCertificate(ca.exportPublicCertificate().certificateDer.inputStream()))
        }
        val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
        val client = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
        var captureId: String? = null
        var startedByTest = false
        var receivedResponse = ByteArray(0)
        val packets = PacketRepository()
        val finished = CountDownLatch(1)
        CaptureStartupChecks.observer = { stage -> if (stage == "finalize") finished.countDown() }
        try {
            LiveCaptureStore.clearError()
            ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
                putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
                putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
                putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
                putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS, TlsCaptureSettingsJson.encode(
                    TlsCaptureSettings(enabled = true, candidatePorts = setOf(port), includeHosts = listOf(host), retainSecrets = true)))
            })
            startedByTest = true
            await("VPN start") { LiveCaptureStore.state.value.isCapturing && isVpn() }
            val original = File(requireNotNull(LiveCaptureStore.state.value.outputPath))
            captureId = original.nameWithoutExtension
            assertFalse(before.contains(captureId))
            Socket().use { raw ->
                val deadline = System.currentTimeMillis() + 5_000
                while (true) {
                    try { requireNotNull(connectivity.activeNetwork).bindSocket(raw); break }
                    catch (error: SocketException) {
                        if (!error.message.orEmpty().contains("EPERM") || System.currentTimeMillis() >= deadline) throw error
                        Thread.sleep(50)
                    }
                }
                val source = requireNotNull(connectivity.getLinkProperties(connectivity.activeNetwork)
                    ?.linkAddresses?.firstOrNull { it.address is Inet4Address }?.address)
                raw.bind(InetSocketAddress(source, 0))
                raw.connect(InetSocketAddress(address, port), 10_000)
                raw.soTimeout = 15_000
                (client.socketFactory.createSocket(raw, host, port, true) as SSLSocket).use { tls ->
                    tls.sslParameters = tls.sslParameters.apply {
                        endpointIdentificationAlgorithm = "HTTPS"
                        applicationProtocols = arrayOf("http/1.1")
                    }
                    tls.startHandshake()
                    assertEquals("http/1.1", tls.applicationProtocol)
                    tls.outputStream.write(request)
                    tls.outputStream.flush()
                    val response = ByteArrayOutputStream().also { out ->
                        val buffer = ByteArray(4096)
                        while (true) {
                            val count = tls.inputStream.read(buffer)
                            if (count < 0) break
                            check(out.size() + count <= 64 * 1024) { "Fixture response exceeded its byte budget" }
                            out.write(buffer, 0, count)
                        }
                    }.toByteArray()
                    receivedResponse = response
                    val text = response.toString(Charsets.ISO_8859_1)
                    assertTrue(text.startsWith("HTTP/1.1 200") || text.startsWith("HTTP/1.0 200"))
                    assertArrayEquals(expected, httpBody(response))
                }
            }
            var lastCount = LiveCaptureStore.state.value.packetCount
            var lastChange = System.currentTimeMillis()
            await("TCP teardown") {
                val count = LiveCaptureStore.state.value.packetCount
                if (count != lastCount) { lastCount = count; lastChange = System.currentTimeMillis() }
                System.currentTimeMillis() - lastChange >= 750
            }
            stop()
            assertTrue("Stop must finish publishing the manifest and report", finished.await(30, TimeUnit.SECONDS))
            assertNull(LiveCaptureStore.state.value.error)
            val manifest = (artifacts.read(captureId) as CaptureArtifactState.Present).manifest
            assertTrue("Final manifest must be complete: $manifest", manifest.captureIsComplete)
            assertTrue(manifest.tls.complete)
            val file = artifacts.connectionEventsFile(captureId)
            assertTrue(file.length() in 1..16L * 1024 * 1024)
            assertEquals(384, Os.stat(file.path).st_mode and 511)
            assertThrows(IllegalArgumentException::class.java) {
                FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
            }
            TlsConnectionStore(captureId, journal = TlsConnectionJournal(file, privateRoot = context.filesDir)).use { reopened ->
                val history = reopened.history()
                assertTrue(history.isNotEmpty())
                assertTrue(history.all { it.captureId == captureId })
                assertTrue(history.any { it.phase == TlsConnectionPhase.RELAYING })
            }
            val merged = artifacts.openForAnalysis(captureId) as CaptureAnalysisSource.Merged
            packets.openFile(merged.analysisFile.path).getOrThrow()
            val configured = packets.configureTlsAnalysis(TlsSecretStore(context).acquireLease(captureId),
                packets.currentAnalysisRevision(), "", {}, { _, _ -> })
            assertTrue("Saved secret configuration must succeed: $configured", configured.success)
            assertTrue("Saved capture must contain observed plaintext: $configured", configured.observedDecryptedData)
            assertTrue(packets.applyDisplayFilter("tls.handshake.type == 1 && tcp.port == $port").success)
            val frame = requireNotNull(packets.getVisiblePacketSummary(0)).frameNumber
            val followed = packets.followTlsStream(frame, packets.currentAnalysisRevision())
            assertTrue("Saved TLS stream must be available: ${followed.unavailableReason}", followed.success)
            assertFalse("Saved TLS stream must be complete", followed.incomplete)
            fun stream(direction: TlsFollowDirection) = ByteArrayOutputStream().also { out ->
                followed.records.filter { it.direction == direction }.forEach { out.write(it.bytes) }
            }.toByteArray()
            assertArrayEquals(request, stream(TlsFollowDirection.Client))
            val savedResponse = stream(TlsFollowDirection.Server)
            assertArrayEquals(receivedResponse, savedResponse)
            assertArrayEquals(expected, httpBody(savedResponse))
            assertTrue(packets.applyDisplayFilter("").success)
            val objects = packets.getHttpObjects()
            assertEquals(1, objects.size)
            assertArrayEquals(expected, packets.getHttpObjectPayload(objects.single().id, packets.currentAnalysisRevision()))
            packets.closeFile()
            val shared = CaptureArtifactLifecycle(context).exportIntegrityReport(original)
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", shared)
            context.contentResolver.openInputStream(uri)!!.use { assertTrue(it.read() >= 0) }
            CaptureArtifactLifecycle(context).purge(captureId)
            assertFalse(file.exists())
            assertFalse(shared.exists())
            if (caBefore.usable) assertEquals(caBefore.certificateSha256, ca.status().certificateSha256)
        } finally {
            try {
                if (startedByTest && (LiveCaptureStore.state.value.isCapturing || isVpn())) stop()
                if (startedByTest) assertTrue("Test capture must finish before cleanup", finished.await(30, TimeUnit.SECONDS))
                packets.closeFile()
                captureId?.takeUnless(before::contains)?.let { CaptureArtifactLifecycle(context).purge(it) }
            } finally {
                CaptureStartupChecks.observer = null
            }
        }
    }

    private fun isVpn() = connectivity.getNetworkCapabilities(connectivity.activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

    private fun httpBody(response: ByteArray): ByteArray {
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
            require(length in 1..65536 && decoded.size() + length <= 65536)
            decoded.write(input.readByteArray(length))
            require(input.readUtf8LineStrict().isEmpty())
        }
    }

    private fun stop() {
        context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
        await("VPN stop") { !LiveCaptureStore.state.value.isCapturing && !isVpn() }
    }

    private fun await(label: String, condition: () -> Boolean) {
        val end = System.currentTimeMillis() + 30_000
        while (System.currentTimeMillis() < end) { if (condition()) return; Thread.sleep(50) }
        error("Timed out: $label")
    }
}
