// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Process
import android.provider.Settings
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.*
import java.io.ByteArrayInputStream
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Explicitly selected phases: the host kills/reboots only after the durable READY marker.
 * Arm phases deliberately never complete; only verification phases count as passing tests.
 * PCAP, manifest and secrets are written by the production VPN, never fixture-imported.
 */
class TlsCaptureProcessRecoveryTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val connectivity get() = context.getSystemService(ConnectivityManager::class.java)
    private val artifacts get() = CaptureArtifactRepository(context)
    private val secrets get() = TlsSecretStore(context)
    private val lifecycle get() = CaptureArtifactLifecycle(context)
    private val evidence get() = File(context.getExternalFilesDir(null), "tls-312").apply { mkdirs() }
    private val state get() = File(context.noBackupFilesDir, "tls-312-acceptance").apply { mkdirs() }
    private val host = "httpbun.com"
    private val expectedBody = "tls-312-arm64-body\n".toByteArray()
    private val request get() = ("GET /base64/" + android.util.Base64.encodeToString(expectedBody, 2) +
        " HTTP/1.1\r\nHost: $host\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").toByteArray()

    @Test fun armRunningCaptureForForceStop() {
        start(retain = true)
        val original = File(requireNotNull(LiveCaptureStore.state.value.outputPath))
        // The writer has a 64 KiB buffer. Generate bounded, deliberate synthetic
        // requests until a real prefix is on disk, without invoking stop/flush.
        val client = proxyClient()
        repeat(32) {
            if (original.length() < 48 * 1024) assertArrayEquals(expectedBody, body(exchange(client)))
        }
        settle()
        assertTrue("A persisted prefix is required: ${original.length()}", original.length() >= 48 * 1024)
        val bytes = original.readBytes()
        val (end, frames) = completePrefix(bytes)
        val record = identity(original).put("prefixBytes", end).put("prefixFrames", frames)
            .put("prefixSha256", hash(bytes.copyOf(end)))
        assertTrue(frames > 0)
        assertFalse(manifest(record).finalized)
        expectInUse { lifecycle.purge(record.getString("captureId")) }
        park("capture", record)
    }

    @Test fun verifyForceStoppedCaptureRecoveredByApplicationStartup() {
        NativeTestSupport.awaitApplicationEngine()
        val record = previous("capture", reboot = false)
        val original = File(record.getString("originalPath"))
        assertEquals(record.getLong("prefixBytes"), original.length())
        assertEquals(record.getString("prefixSha256"), hash(original.readBytes()))
        val recovered = manifest(record)
        assertTrue(recovered.interrupted)
        assertFalse(recovered.captureIsComplete)
        assertFalse(recovered.tls.complete)
        assertEquals(record.getLong("prefixFrames"), recovered.segments.sumOf { it.frameCount })
        assertTrue(recovered.secretsPersistedSequence > 0)
        assertNotNull(secrets.currentAsset(recovered.captureId))
        open(recovered.captureId).use { repository -> assertPlaintext(repository) }
        assertTrue(LiveCaptureStore.state.value.interrupted)
        LiveCaptureStore.stop()
        assertTrue(LiveCaptureStore.state.value.incomplete)
        assertTrue(manifest(record).interrupted)
        assertFalse(manifest(record).complete)
        assertArrayEquals(expectedBody, body(exchange(SSLContext.getDefault())))
        result("capture", record, JSONObject().put("authenticatedSecretsRecovered", true)
            .put("persistedPrefixUnchanged", true).put("interruptedSurvivesStop", true)
            .put("bodyEqual", true).put("networkRestored", true))
    }

    @Test fun armTransientAnalysisAndCompleteExportForReboot() {
        start(retain = false)
        settle()
        stop()
        val original = File(requireNotNull(LiveCaptureStore.state.value.outputPath))
        val record = identity(original).put("originalSha256", hash(original.readBytes()))
        val id = record.getString("captureId")
        assertTrue(manifest(record).captureIsComplete)
        assertEquals(CaptureRetentionPolicy.KeepCaptureTransientSecrets, manifest(record).retentionPolicy)
        // Keep the preceding real capture as an independently decryptable deletion sentinel.
        val other = JSONObject(File(state, "capture.json").readText())
        record.put("otherId", other.getString("captureId"))
            .put("otherSha256", hash(File(other.getString("originalPath")).readBytes()))
            .put("caSha256", hash(TlsCaManagerHolder.get(context).exportPublicCertificate().certificateDer))
        val repository = open(id)
        assertPlaintext(repository)
        expectInUse { lifecycle.purge(id) }
        TlsCaptureBundle(context).withWorkspace { directory ->
            File(directory, "session.zip").outputStream().use {
                TlsCaptureBundle(context).writeComplete(id, it, filtered = false, confirmed = true)
            }
            record.put("workspace", directory.path)
            val leases = File(context.noBackupFilesDir, "tls-analysis-leases").listFiles()!!.filter { it.isDirectory }
            assertEquals(1, leases.size)
            record.put("lease", leases.single().path)
            // Startup cleanup invoked while resources are live must leave them alone.
            assertEquals(TlsAssetErrorCode.IN_USE,
                lifecycle.recoverAtStartup().single { it.captureId == id }.errorCode)
            assertTrue(directory.exists())
            assertTrue(leases.single().exists())
            assertPlaintext(repository)
            park("export", record)
        }
    }

    @Test fun verifyRebootExpiresSecretsAndRemovesOrphansWithoutTouchingOtherCapture() {
        NativeTestSupport.awaitApplicationEngine()
        val record = previous("export", reboot = true)
        val id = record.getString("captureId")
        val original = File(record.getString("originalPath"))
        assertEquals(record.getString("originalSha256"), hash(original.readBytes()))
        assertFalse(File(record.getString("workspace")).exists())
        assertFalse(File(record.getString("lease")).exists())
        assertFalse(File(context.noBackupFilesDir, "capture-secrets/$id").exists())
        assertNull(secrets.currentAsset(id))
        assertNull(manifest(record).tls.secretsAssetId)
        open(id).use { assertTrue(it.getHttpObjects().isEmpty()) }
        val other = JSONObject(File(state, "capture.json").readText())
        val otherId = other.getString("captureId")
        val otherFile = File(other.getString("originalPath"))
        repeat(2) { lifecycle.purge(id) }
        assertFalse(original.exists())
        assertFalse(artifacts.captureDirectory(id).exists())
        assertTrue(lifecycle.cleanupEvents().single { it.captureId == id }.completed)
        assertEquals(record.getString("otherSha256"), hash(otherFile.readBytes()))
        assertEquals(record.getString("caSha256"),
            hash(TlsCaManagerHolder.get(context).exportPublicCertificate().certificateDer))
        open(otherId).use { assertPlaintext(it) }
        assertArrayEquals(expectedBody, body(exchange(SSLContext.getDefault())))
        result("export", record, JSONObject().put("orphanLeaseRemoved", true).put("orphanBundleRemoved", true)
            .put("transientUnwrappingMaterialsRemoved", true).put("reopenCiphertextOnly", true)
            .put("pcapPreservedUntilExplicitDelete", true).put("repeatDeleteIsolated", true)
            .put("otherCaptureStillDecrypts", true).put("caUnchanged", true).put("networkRestored", true))
        lifecycle.purge(otherId)
    }

    private fun start(retain: Boolean) {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue(BuildConfig.TLS_ENABLED)
        assertNull("VPN consent must already be granted", VpnService.prepare(context))
        assertArrayEquals(expectedBody, body(exchange(SSLContext.getDefault())))
        TlsCaManagerHolder.get(context).ensureGenerated()
        ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
            putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
            putExtra(LiveCaptureVpnService.EXTRA_TLS_SETTINGS, TlsCaptureSettingsJson.encode(
                TlsCaptureSettings(enabled = true, includeHosts = listOf(host), retainSecrets = retain)))
        })
        await("VPN running") { LiveCaptureStore.state.value.isCapturing && isVpn() }
        assertArrayEquals(expectedBody, body(exchange(proxyClient())))
    }

    private fun proxyClient(): SSLContext {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(
            TlsCaManagerHolder.get(context).exportPublicCertificate().certificateDer))
        val trust = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("test", cert) }
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
        return SSLContext.getInstance("TLS").apply { init(null, factory.trustManagers, null) }
    }

    private fun open(id: String): PacketRepository {
        val repository = PacketRepository().apply { artifactLifecycle = lifecycle }
        val source = artifacts.openForAnalysis(id) as CaptureAnalysisSource.Merged
        repository.openFile(source.analysisFile.path).getOrThrow()
        secrets.currentAsset(id)?.let {
            assertTrue(repository.configureTlsAnalysis(secrets.acquireLease(id),
                repository.currentAnalysisRevision(), "", {}, { _, _ -> }).success)
        }
        return repository
    }
    private inline fun PacketRepository.use(block: (PacketRepository) -> Unit) {
        try { block(this) } finally { closeFile() }
    }
    private fun assertPlaintext(repository: PacketRepository) {
        val objects = repository.getHttpObjects()
        assertTrue("At least one complete captured response", objects.isNotEmpty())
        objects.forEach { assertArrayEquals(expectedBody,
            repository.getHttpObjectPayload(it.id, repository.currentAnalysisRevision())) }
    }
    private fun identity(original: File) = JSONObject().put("pid", Process.myPid())
        .put("bootCount", Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT))
        .put("captureId", original.nameWithoutExtension).put("originalPath", original.path)
    private fun manifest(record: JSONObject) =
        (artifacts.read(record.getString("captureId")) as CaptureArtifactState.Present).manifest
    private fun previous(kind: String, reboot: Boolean): JSONObject {
        val record = JSONObject(File(state, "$kind.json").readText())
        assertNotEquals(record.getInt("pid"), Process.myPid())
        val boots = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT)
        if (reboot) assertTrue(boots > record.getInt("bootCount")) else assertEquals(record.getInt("bootCount"), boots)
        assertFalse(isVpn())
        return record
    }
    private fun park(kind: String, record: JSONObject): Nothing {
        File(state, "$kind.json").outputStream().use { it.write(record.toString().toByteArray()); it.fd.sync() }
        File(evidence, "$kind-ready.json").writeText(record.toString(2))
        Log.i("TLS-312", "READY $kind pid=${Process.myPid()} captureId=${record.getString("captureId")}")
        val deadline = System.currentTimeMillis() + 180_000
        while (System.currentTimeMillis() < deadline) Thread.sleep(250)
        error("Host did not interrupt the READY phase")
    }
    private fun result(kind: String, old: JSONObject, result: JSONObject) {
        result.put("previousPid", old.getInt("pid")).put("pid", Process.myPid())
            .put("previousBootCount", old.getInt("bootCount"))
            .put("bootCount", Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT))
        File(evidence, "$kind-verified.json").writeText(result.toString(2))
        Log.i("TLS-312", "VERIFIED $kind $result")
    }
    private fun completePrefix(bytes: ByteArray): Pair<Int, Long> {
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(0xa1b2c3d4.toInt(), buffer.getInt(0))
        var end = 24
        var frames = 0L
        while (bytes.size - end >= 16) {
            val length = buffer.getInt(end + 8)
            require(length in 0..65535)
            if (bytes.size - end - 16 < length) break
            end += 16 + length
            frames++
        }
        return end to frames
    }
    private fun expectInUse(block: () -> Unit) {
        try { block(); fail("Expected IN_USE") } catch (error: TlsAssetException) { assertEquals(TlsAssetErrorCode.IN_USE, error.code) }
    }
    private fun settle() {
        var count = LiveCaptureStore.state.value.packetCount
        var last = System.currentTimeMillis()
        await("TCP teardown") {
            val next = LiveCaptureStore.state.value.packetCount
            if (next != count) { count = next; last = System.currentTimeMillis() }
            System.currentTimeMillis() - last >= 1000
        }
    }
    private fun stop() {
        context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
        await("VPN stopped") { !LiveCaptureStore.state.value.isCapturing && !isVpn() }
        // StateFlow publishes stopped before the atomic manifest commit completes.
        val id = File(requireNotNull(LiveCaptureStore.state.value.outputPath)).nameWithoutExtension
        await("manifest committed after stopped publication") {
            (artifacts.read(id) as? CaptureArtifactState.Present)?.manifest?.finalized == true
        }
    }
    private fun isVpn() = connectivity.getNetworkCapabilities(connectivity.activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun await(label: String, test: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 30_000
        while (System.currentTimeMillis() < deadline) { if (test()) return; Thread.sleep(50) }
        error("Timed out: $label")
    }
    private fun exchange(ssl: SSLContext): ByteArray = Socket().use { raw ->
        val deadline = System.currentTimeMillis() + 5000
        while (true) {
            try { requireNotNull(connectivity.activeNetwork).bindSocket(raw); break }
            catch (error: SocketException) {
                if (!error.message.orEmpty().contains("EPERM") || System.currentTimeMillis() > deadline) throw error
                Thread.sleep(50)
            }
        }
        raw.connect(InetSocketAddress(host, 443), 10_000); raw.soTimeout = 15_000
        (ssl.socketFactory.createSocket(raw, host, 443, true) as SSLSocket).use { socket ->
            socket.enabledProtocols = arrayOf("TLSv1.3")
            socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
            socket.startHandshake(); socket.outputStream.write(request); socket.outputStream.flush()
            socket.inputStream.readBytes()
        }
    }
    private fun body(response: ByteArray): ByteArray {
        val text = response.toString(Charsets.ISO_8859_1)
        assertTrue(text.startsWith("HTTP/1.1 200 "))
        val end = text.indexOf("\r\n\r\n"); assertTrue(end >= 0)
        val payload = response.copyOfRange(end + 4, response.size)
        if (!text.substring(0, end).contains("transfer-encoding: chunked", true)) return payload
        val buffer = okio.Buffer().write(payload)
        return java.io.ByteArrayOutputStream().apply {
            while (true) {
                val size = buffer.readUtf8LineStrict().substringBefore(';').toLong(16)
                if (size == 0L) break
                require(size in 1..262144)
                write(buffer.readByteArray(size)); check(buffer.readUtf8LineStrict().isEmpty())
            }
        }.toByteArray()
    }
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }
}
