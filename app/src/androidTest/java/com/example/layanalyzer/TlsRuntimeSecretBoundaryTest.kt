// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Base64
import android.util.Log
import androidx.core.content.FileProvider
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.TlsCaptureCoordinator
import com.example.layanalyzer.capture.tls.TlsCaptureStart
import com.example.layanalyzer.capture.tls.TlsCertificateManager
import com.example.layanalyzer.capture.tls.TlsConnectionJournal
import com.example.layanalyzer.capture.tls.TlsConnectionStore
import com.example.layanalyzer.capture.tls.TlsEngineBridge
import com.example.layanalyzer.capture.tls.TlsNetworkAccess
import com.example.layanalyzer.capture.tls.TlsPlatformCallbacks
import com.example.layanalyzer.capture.tls.TlsProxyBridge
import com.example.layanalyzer.capture.tls.TlsSecretStore
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureStatus
import java.io.File
import java.io.ByteArrayOutputStream
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.Collections
import java.util.UUID
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * TLS-218's independent runtime audit. The observing bridge delegates every call
 * to the production JNI engine, including real platform trust and secret storage.
 * It keeps comparison material only in test-process memory, never in test output.
 * This test has no VPN: the separate TlsVpnDecryptionTest proves TUN decryption.
 * The no-VPN protect callback is explicitly a no-op; physical binding is real.
 */
@RunWith(AndroidJUnit4::class)
class TlsRuntimeSecretBoundaryTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val arguments = InstrumentationRegistry.getArguments()

    @Test
    fun runtimeSecretsStayOutsideOrdinaryEventsLogsAndShareRoots() {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue("runtime audit requires production TLS", BuildConfig.TLS_ENABLED)
        assertFalse("runtime audit must not use the probe", BuildConfig.TLS_PROBE_ENABLED)
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val network = requireNotNull(connectivity.activeNetwork)
        assertFalse("run the independent audit after stopping VPN capture",
            connectivity.getNetworkCapabilities(network)!!.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
        val host = requireNotNull(arguments.getString("hostTlsHost"))
        val port = requireNotNull(arguments.getString("hostTlsPort")?.toIntOrNull())
        val path = requireNotNull(arguments.getString("hostTlsPath"))
        require(path.startsWith("/") && path.none { it == '\r' || it == '\n' })
        val expectedBody = Base64.decode(requireNotNull(arguments.getString("hostTlsBodyBase64")), Base64.NO_WRAP)
        val captureId = "tls-218-audit-${UUID.randomUUID()}"
        val journalFile = File(context.filesDir, "captures/$captureId/tls-connections.jsonl")
        val shareControl = File(context.filesDir, "exports/$captureId/provider-control.txt")
        assertTrue(journalFile.parentFile!!.mkdirs())
        val journal = TlsConnectionJournal(journalFile, privateRoot = context.filesDir)
        val store = TlsSecretStore(context)
        val ca = TlsCertificateManager(context)
        assertTrue("Use the existing app CA without generating or resetting it", ca.status().usable)
        val observer = ObservingBridge()
        val networkAccess = object : TlsNetworkAccess {
            override val generation = 1L
            override val upstream = UpstreamSocketProtector(
                { UpstreamSocketProtector.NetworkSnapshot(network, generation) }, { true })
            override fun prepareHopSocket(socket: Socket) { }
            override fun close() { }
        }
        val coordinator = TlsCaptureCoordinator(captureId,
            TlsCaptureSettings(enabled = true, candidatePorts = setOf(port), includeHosts = listOf(host)),
            network = networkAccess, certificates = { ca }, secretStore = { store }, bridge = observer,
            connectionStore = TlsConnectionStore(captureId, journal = journal))
        val marker = "audit-${UUID.randomUUID()}"
        Log.i(TAG, "$marker begin")
        try {
            val started = coordinator.start()
            assertTrue("production coordinator must start", started is TlsCaptureStart.Started)
            started as TlsCaptureStart.Started
            val trust = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null)
                setCertificateEntry("proxy", CertificateFactory.getInstance("X.509")
                    .generateCertificate(ca.exportPublicCertificate().certificateDer.inputStream()))
            }
            val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
            val ssl = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
            val address = network.getAllByName(host).first { it.address.size == 4 }.hostAddress!!
            started.gateway.withNioConnection(address, port) { raw ->
                raw.soTimeout = 15_000
                (ssl.socketFactory.createSocket(raw, host, port, true) as SSLSocket).use { socket ->
                    socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    socket.startHandshake()
                    socket.outputStream.write("GET $path HTTP/1.0\r\nHost: $host\r\nConnection: close\r\n\r\n"
                        .toByteArray(Charsets.US_ASCII))
                    socket.outputStream.flush()
                    val response = socket.inputStream.readBytes()
                    val text = response.toString(Charsets.ISO_8859_1)
                    assertTrue("audit origin must return HTTP 200", text.startsWith("HTTP/1.1 200") || text.startsWith("HTTP/1.0 200"))
                    val headerEnd = text.indexOf("\r\n\r\n")
                    assertTrue(headerEnd >= 0)
                    assertArrayEquals("audit requires the fixed fixture body", expectedBody, response.copyOfRange(headerEnd + 4, response.size))
                }
            }
            coordinator.pump()
            val stopped = coordinator.stop()
            journal.close()
            assertEquals(TlsCaptureStatus.STOPPED, stopped.status)
            assertTrue(stopped.secretsComplete)
            assertTrue("the audit must observe actual keylog callbacks", observer.secretCount > 0)
            assertEquals(observer.secretCount.toLong(), stopped.secrets!!.persisted)
            assertTrue("raw ordinary events must include a real TLS relay",
                observer.envelopes.any { it.contains("RELAYING") })
            assertTrue("ordinary events must actually reach the journal", journal.readLines().isNotEmpty())

            val asset = requireNotNull(store.currentAsset(captureId))
            val privateFiles = listOf(File(context.noBackupFilesDir, "tls-ca"),
                File(context.noBackupFilesDir, "capture-secrets/$captureId"))
                .flatMap { filesUnder(it) }
            assertTrue(privateFiles.isNotEmpty())
            privateFiles.forEach { assertNotShareable(it) }
            var leaseFile: File? = null
            store.acquireLease(captureId, asset.assetId).use { lease ->
                lease.configureNative({}) { name ->
                    leaseFile = File(name)
                    assertTrue(leaseFile!!.isFile)
                    assertNotShareable(leaseFile!!)
                }
            }
            assertFalse("analysis plaintext must be removed when its lease closes", leaseFile!!.exists())
            assertNotShareable(journalFile)
            // Positive control uses the explicit export root. Journal metadata
            // stays private even though the scanner also audits its contents.
            assertTrue(shareControl.parentFile!!.mkdirs())
            shareControl.writeText("synthetic provider control")
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", shareControl)
            context.contentResolver.openInputStream(uri)!!.use { assertTrue(it.read() >= 0) }

            val needles = observer.needles
            val scanner = needles.map(::BytePattern)
            assertTrue(observer.tokenObserved && observer.caObserved)
            needles.forEach {
                assertThrows("the scanner must reject an in-memory leak control", AssertionError::class.java) {
                    assertClean(byteArrayOf(0, 1, 2) + it, listOf(it), "in-memory control")
                }
            }
            observer.envelopes.forEach { assertClean(it.toByteArray(Charsets.UTF_8), needles, "ordinary envelope") }
            val ordinaryFiles = listOf(File(context.filesDir, "exports"), File(context.filesDir, "captures"),
                File(context.cacheDir, "rtp")).flatMap { filesUnder(it) }
            assertTrue(ordinaryFiles.contains(journalFile))
            // Long VPN acceptance runs leave large captures. Audit all existing
            // ordinary files without deleting user data or limiting the audit to
            // newly created files; memory remains bounded by one 64 KiB chunk.
            val ordinaryBytes = ordinaryFiles.sumOf { it.length() }
            assertTrue("audit file budget exceeded", ordinaryBytes <= 2L * 1024 * 1024 * 1024)
            ordinaryFiles.forEach { file ->
                file.inputStream().use { input ->
                    assertFalse("runtime material leaked to FileProvider root",
                        containsSecret(input, scanner, needles.maxOf { it.size } - 1))
                }
            }
            Log.i(TAG, "$marker end")
            val logs = ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation
                .executeShellCommand("logcat -d --pid=${Process.myPid()} -v brief")).use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    assertTrue("audit log budget exceeded", output.size() + count <= 8 * 1024 * 1024)
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            val logText = logs.toString(Charsets.UTF_8)
            assertTrue("audit start marker must remain in logcat", logText.contains("$marker begin"))
            assertTrue("audit end marker must be present in logcat", logText.contains("$marker end"))
            assertClean(logs, needles, "process logcat")
            Log.i(TAG, "PASS secretRecords=${observer.secretCount} envelopes=${observer.envelopes.size} " +
                "privateFilesDenied=${privateFiles.size + 1} ordinaryFiles=${ordinaryFiles.size} " +
                "ordinaryBytes=$ordinaryBytes " +
                "logBytes=${logs.size} exactMatches=0 scannerControl=true providerControl=true leaseDeleted=true")
        } finally {
            coordinator.close()
            journal.close()
            observer.close()
            store.purgeCapture(captureId)
            // Delete only the new UUID namespace belonging to this audit.
            check(journalFile.parentFile!!.canonicalFile.parentFile == File(context.filesDir, "captures").canonicalFile)
            journalFile.parentFile!!.deleteRecursively()
            check(shareControl.parentFile!!.canonicalFile.parentFile == File(context.filesDir, "exports").canonicalFile)
            shareControl.parentFile!!.deleteRecursively()
        }
    }

    @Test
    fun bytePatternScannerMatchesBinaryAndOverlappingControls() {
        val random = java.util.Random(603)
        repeat(200) {
            val bytes = ByteArray(256).also(random::nextBytes)
            val needle = if (it % 2 == 0) bytes.copyOfRange(17, 17 + it % 64 + 1)
                else ByteArray(it % 64 + 1).also(random::nextBytes)
            val expected = (0..bytes.size - needle.size).any { offset ->
                needle.indices.all { index -> bytes[offset + index] == needle[index] }
            }
            assertEquals("binary pattern control", expected, BytePattern(needle).contains(bytes))
        }
        assertTrue(BytePattern(byteArrayOf(-1, -1, 0, -1)).contains(byteArrayOf(-1, -1, -1, 0, -1)))
        assertFalse(BytePattern(byteArrayOf(1, 2, 3)).contains(byteArrayOf(1, 2)))
        assertThrows(IllegalArgumentException::class.java) { BytePattern(byteArrayOf()) }
    }

    @Test
    fun streamedSecretScannerRejectsEveryChunkBoundaryAndKeepsCleanFilesClean() {
        val needle = byteArrayOf(0, -128, -1, 127, 0, 42, 42)
        val patterns = listOf(BytePattern(needle))
        // Exercise every split, including a needle fragmented across more than
        // two reads. Real files need not fill the 64 KiB read buffer either.
        for (readSize in 1..needle.size + 1) {
            for (offset in 0..readSize * 2) {
                val source = ByteArray(offset) { 19 } + needle + ByteArray(17) { 19 }
                val input = object : ByteArrayInputStream(source) {
                    override fun read(buffer: ByteArray, start: Int, length: Int): Int =
                        super.read(buffer, start, minOf(length, readSize))
                }
                input.use { assertTrue("fragmented leak control", containsSecret(it, patterns, needle.size - 1)) }
            }
        }
        val source = ByteArray(64 * 1024 - 3) { 19 } + needle
        assertTrue(containsSecret(source.inputStream(), patterns, needle.size - 1))
        assertFalse(containsSecret(ByteArray(128 * 1024) { 19 }.inputStream(), patterns, needle.size - 1))
        assertFalse(containsSecret(byteArrayOf().inputStream(), patterns, needle.size - 1))
    }

    private fun assertNotShareable(file: File) {
        assertThrows("private material must not resolve through FileProvider", IllegalArgumentException::class.java) {
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        }
    }

    private fun filesUnder(root: File): List<File> {
        if (!root.exists()) return emptyList()
        val canonical = root.canonicalFile.toPath()
        return root.walkTopDown().onFail { _, error -> throw error }.filter { file ->
            check(file.canonicalFile.toPath().startsWith(canonical)) { "audit directory escaped its root" }
            file.isFile
        }.toList()
    }

    private class ObservingBridge : TlsEngineBridge, AutoCloseable {
        private val real = TlsProxyBridge()
        val envelopes = Collections.synchronizedList(mutableListOf<String>())
        val needles = Collections.synchronizedList(mutableListOf<ByteArray>())
        var tokenObserved = false
        var caObserved = false
        @Volatile var secretCount = 0
        private fun record(value: String) = value.also { envelopes.add(it) }
        override fun capabilities() = record(real.capabilities())
        override fun start(configJson: String, certificateDer: ByteArray, privateKeyPkcs8: ByteArray,
            callbacks: TlsPlatformCallbacks): String {
            remember(certificateDer)
            remember(privateKeyPkcs8)
            caObserved = true
            // Catch PEM wrapping too, using a private CRT tail, not the public modulus.
            needles.add(Base64.encode(privateKeyPkcs8, Base64.NO_WRAP).takeLast(48).toByteArray())
            val observedCallbacks = object : TlsPlatformCallbacks by callbacks {
                override fun offerSecret(captureId: String, connectionId: String, line: ByteArray): Boolean {
                    val parts = line.toString(Charsets.US_ASCII).trim().split(' ')
                    require(parts.size == 3)
                    val hex = parts[2]
                    needles.add(hex.toByteArray(Charsets.US_ASCII))
                    needles.add(hex.uppercase().toByteArray(Charsets.US_ASCII))
                    remember(hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
                    secretCount++
                    return callbacks.offerSecret(captureId, connectionId, line)
                }
            }
            return record(real.start(configJson, certificateDer, privateKeyPkcs8, observedCallbacks))
        }
        override fun gatewayToken(handle: Long): ByteArray = real.gatewayToken(handle).also {
            require(it.size == 43)
            remember(it)
            tokenObserved = true
        }
        override fun stop(handle: Long, timeoutMillis: Int) = record(real.stop(handle, timeoutMillis))
        override fun poll(handle: Long, maxEvents: Int) = record(real.poll(handle, maxEvents))
        override fun stats(handle: Long) = record(real.stats(handle))
        private fun remember(value: ByteArray) {
            needles.add(value.copyOf())
            needles.add(Base64.encode(value, Base64.NO_WRAP))
        }
        override fun close() {
            needles.forEach { it.fill(0) }
            needles.clear()
            envelopes.clear()
        }
    }

    /** Boyer-Moore-Horspool: reuse the skip table across streamed chunks. */
    private class BytePattern(private val needle: ByteArray) {
        private val skip = IntArray(256) { needle.size }.apply {
            require(needle.isNotEmpty())
            for (index in 0 until needle.lastIndex) {
                this[needle[index].toInt() and 255] = needle.lastIndex - index
            }
        }
        fun contains(bytes: ByteArray): Boolean {
            var offset = 0
            while (offset <= bytes.size - needle.size) {
                var index = needle.lastIndex
                while (index >= 0 && bytes[offset + index] == needle[index]) index--
                if (index < 0) return true
                offset += skip[bytes[offset + needle.lastIndex].toInt() and 255]
            }
            return false
        }
    }

    private companion object {
        const val TAG = "TLS-218-Boundary"
        fun containsSecret(input: InputStream, patterns: List<BytePattern>, overlap: Int): Boolean {
            var tail = ByteArray(0)
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) return false
                val chunk = tail + buffer.copyOf(count)
                if (patterns.any { it.contains(chunk) }) return true
                tail = chunk.takeLast(minOf(overlap, chunk.size)).toByteArray()
            }
        }

        fun assertClean(bytes: ByteArray, needles: List<ByteArray>, surface: String) {
            // Never interpolate a needle, log line, file content or envelope in an assertion.
            assertFalse("runtime material leaked to $surface", needles.any { BytePattern(it).contains(bytes) })
        }
    }
}
