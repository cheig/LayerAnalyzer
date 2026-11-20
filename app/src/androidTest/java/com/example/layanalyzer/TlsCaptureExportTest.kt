// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.KeyLogParseResult
import com.example.layanalyzer.capture.tls.KeyLogParser
import com.example.layanalyzer.capture.tls.TlsSecretStore
import com.example.layanalyzer.data.CaptureAnalysisSource
import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.data.CaptureArtifactState
import com.example.layanalyzer.data.TlsCaptureBundle
import com.example.layanalyzer.data.TlsRawCaptureWriter
import com.example.layanalyzer.data.TlsBundleLimits
import com.example.layanalyzer.model.CaptureArtifactManifest
import com.example.layanalyzer.model.CaptureSegmentRef
import com.example.layanalyzer.model.CaptureTlsAssets
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** TLS-311 acceptance with real Android Keystore, production JNI and public TLS fixtures. */
@RunWith(AndroidJUnit4::class)
class TlsCaptureExportTest {
    @Before fun ready() { NativeTestSupport.awaitApplicationEngine() }

    @Test fun tls12ExportImportReplaysBodyInAFreshNativeSession() = roundTrip("tls12-h1")
    @Test fun tls13ExportImportReplaysBodyInAFreshNativeSession() = roundTrip("tls13-h1")

    @Test fun searchCancellationCannotDeadlockReopenedSecretConfiguration() = TlsPassiveFixture("tls12-h1").use { fixture ->
        val handle = fixture.open()
        val start = CountDownLatch(1)
        val workers = Executors.newFixedThreadPool(2) { task -> Thread(task, "tls311-lock-regression").apply { isDaemon = true } }
        var completed = false
        try {
            assertTrue(JSONObject(NativeEngine.configureTlsSecrets(handle, fixture.file("keylog").path, 1)).getBoolean("success"))
            val configure = workers.submit {
                start.await()
                repeat(1000) {
                    assertTrue(JSONObject(NativeEngine.configureTlsSecrets(handle, fixture.file("keylog").path, 1)).getBoolean("success"))
                }
            }
            val cancel = workers.submit { start.await(); repeat(20000) { NativeEngine.cancelSearch(handle) } }
            start.countDown()
            configure.get(30, TimeUnit.SECONDS)
            cancel.get(30, TimeUnit.SECONDS)
            completed = true
            fixture.assertBody(handle, true)
        } finally {
            workers.shutdownNow()
            // A failed native lock test cannot safely enter another JNI cleanup on the wedged locks.
            // The runner's process owns cleanup on timeout; the passing path always closes normally.
            if (completed) fixture.closeCapture(handle)
        }
    }

    private fun roundTrip(fixtureId: String) = TlsPassiveFixture(fixtureId).use { fixture ->
        withCapture(fixture) { artifacts, secrets, bundle, id, root ->
            val zip = File(root, "session.zip")
            zip.outputStream().use { bundle.writeComplete(id, it, false, true) }
            val entries = unzip(zip.readBytes())
            assertEquals(setOf("packets-0001.pcap", "keys.log", "manifest.json", "checksums.json"), entries.keys)
            assertFalse(entries.values.any { it.toString(Charsets.ISO_8859_1).contains("PRIVATE KEY") })
            assertTrue(JSONObject(entries.getValue("manifest.json").toString(Charsets.UTF_8))
                .getJSONObject("tls").isNull("secretsAssetId"))
            // Only committed synthetic fixture material, for replay by an independent desktop process.
            val evidence = File(InstrumentationRegistry.getInstrumentation().targetContext.getExternalFilesDir(null),
                "tls-311/public-bundles").apply { mkdirs() }
            zip.copyTo(File(evidence, "$fixtureId.zip"), overwrite = true)
            // Close any source analysis first; imported native analysis only sees its new local assets.
            val imported = zip.inputStream().use { bundle.importComplete(it) }
            val state = artifacts.read(imported) as CaptureArtifactState.Present
            assertNotEquals(id, imported)
            val merged = artifacts.openForAnalysis(imported) as CaptureAnalysisSource.Merged
            val handle = NativeEngine.openFile(merged.analysisFile.path, null)
            assertTrue(handle != 0L)
            assertTrue(JSONObject(NativeEngine.applyDecodeAs(handle, "tcp.port", fixture.port, "tls")).getBoolean("success"))
            try {
                fixture.assertBody(handle, false)
                secrets.acquireLease(imported, state.manifest.tls.secretsAssetId).use { lease ->
                    lease.configureNative(clearNativeSecrets = {
                        assertTrue(JSONObject(NativeEngine.configureTlsSecrets(handle, null, 2)).getBoolean("success"))
                    }) { path ->
                        assertTrue(JSONObject(NativeEngine.configureTlsSecrets(handle, path, 1)).getBoolean("success"))
                    }
                    fixture.assertBody(handle, true)
                }
                fixture.assertBody(handle, false)
            } finally { fixture.closeCapture(handle) }
            assertTrue(File(root, "private/tls-analysis-leases").listFiles().orEmpty().isEmpty())
            assertTrue(File(root, "private/work").listFiles().orEmpty().isEmpty())
        }
    }

    @Test fun defaultAndFilteredPcapExportsDoNotCarryKeysOrDecryptedBody() = TlsPassiveFixture("tls12-h1").use { fixture ->
        withCapture(fixture) { _, _, _, _, root ->
            val raw = File(root, "raw.pcap")
            raw.outputStream().use { out -> fixture.file("pcap").inputStream().use { TlsRawCaptureWriter.copy(it, out) } }
            assertArrayEquals(fixture.file("pcap").readBytes(), raw.readBytes())
            val handle = fixture.open()
            val filtered = File(root, "filtered.pcap")
            try {
                assertTrue(JSONObject(NativeEngine.configureTlsSecrets(handle, fixture.file("keylog").path, 1)).getBoolean("success"))
                fixture.assertBody(handle, true)
                assertTrue(JSONObject(NativeEngine.applyDisplayFilter(handle, "tcp")).getBoolean("success"))
                assertTrue(JSONObject(NativeEngine.exportVisibleCapture(handle, filtered.path)).getBoolean("success"))
            } finally { fixture.closeCapture(handle) }
            assertFalse(filtered.readBytes().toString(Charsets.ISO_8859_1).contains("CLIENT_RANDOM"))
            for (file in listOf(raw, filtered)) {
                val bytes = file.readBytes().toString(Charsets.ISO_8859_1)
                for (line in fixture.file("keylog").readLines().filter { it.isNotBlank() && !it.startsWith("#") }) {
                    assertFalse(bytes.contains(line))
                    assertFalse(bytes.contains(line.trim().split(Regex("\\s+")).last()))
                }
                assertFalse(bytes.contains(fixture.body.toString(Charsets.ISO_8859_1)))
            }
            val reopened = NativeEngine.openFile(filtered.path, null)
            assertTrue(reopened != 0L)
            try {
                assertTrue(JSONObject(NativeEngine.applyDecodeAs(reopened, "tcp.port", fixture.port, "tls")).getBoolean("success"))
                fixture.assertBody(reopened, false)
            } finally { fixture.closeCapture(reopened) }
        }
    }

    @Test fun maliciousPathsExpandedBudgetAndBadHashesLeaveNoImportedAssets() =
        TlsPassiveFixture("tls12-h1").use { fixture ->
            withCapture(fixture) { artifacts, _, bundle, id, root ->
                val good = ByteArrayOutputStream().also { bundle.writeComplete(id, it, false, true) }.toByteArray()
                fun reject(bytes: ByteArray, importer: TlsCaptureBundle = bundle) {
                    var rejected = false
                    try { importer.importComplete(bytes.inputStream()) } catch (_: Exception) { rejected = true }
                    assertTrue("Untrusted archive must be rejected", rejected)
                    assertEquals(setOf(id), File(root, "captures").list().orEmpty().toSet())
                    assertEquals(setOf(id), File(root, "private/capture-secrets").list().orEmpty().toSet())
                    assertTrue(File(root, "private/work").listFiles().orEmpty().isEmpty())
                    assertTrue(File(root, "private/tls-analysis-leases").listFiles().orEmpty().isEmpty())
                }
                for (path in listOf("../escape", "/escape", "C:/escape", "..\\escape")) {
                    reject(zip(mapOf(path to byteArrayOf(1))))
                }
                assertFalse(File(root, "private/escape").exists())
                for (name in listOf("packets-0001.pcap", "keys.log", "manifest.json")) {
                    val changed = unzip(good)
                    changed[name] = changed.getValue(name) + byteArrayOf(32)
                    reject(zip(changed))
                }
                val bomb = zip(mapOf("packets-0001.pcap" to ByteArray(128 * 1024)))
                assertTrue(bomb.size < 4096)
                val limited = TlsCaptureBundle(artifacts,
                    TlsSecretStore(File(root, "private"), com.example.layanalyzer.capture.tls.AndroidTlsWrappingKeyProvider()),
                    File(root, "private/work"), TlsBundleLimits(maxBytes = 4096))
                reject(bomb, limited)
                // Rejection must not poison the importer or damage the source capture.
                val imported = bundle.importComplete(good.inputStream())
                assertTrue((artifacts.read(imported) as CaptureArtifactState.Present).isComplete)
            }
        }

    private fun unzip(bytes: ByteArray): MutableMap<String, ByteArray> = linkedMapOf<String, ByteArray>().apply {
        ZipInputStream(bytes.inputStream()).use { input ->
            while (true) { val entry = input.nextEntry ?: break; put(entry.name, input.readBytes()) }
        }
    }

    private fun zip(files: Map<String, ByteArray>): ByteArray = ByteArrayOutputStream().also { output ->
        ZipOutputStream(output).use { zip -> files.forEach { (name, bytes) ->
            zip.putNextEntry(ZipEntry(name)); zip.write(bytes); zip.closeEntry()
        } }
    }.toByteArray()

    @Test fun cancelledExportReleasesRealKeystorePlaintextLease() = TlsPassiveFixture("tls12-h1").use { fixture ->
        withCapture(fixture) { _, _, bundle, id, root ->
            var sawLease = false
            try {
                bundle.withWorkspace { workspace ->
                    File(workspace, "session.zip").outputStream().use { output ->
                        bundle.writeComplete(id, output, false, true) {
                            if (File(root, "private/tls-analysis-leases").walkTopDown().any {
                                    it.isFile && it.name == "keylog.tmp" && it.length() > 0 }) {
                                sawLease = true
                                throw CancellationException()
                            }
                        }
                    }
                }
                fail("Cancellation must propagate")
            } catch (_: CancellationException) { }
            assertTrue(sawLease)
            assertTrue(File(root, "private/tls-analysis-leases").listFiles().orEmpty().isEmpty())
            assertTrue(File(root, "private/work").listFiles().orEmpty().isEmpty())
        }
    }

    private fun withCapture(
        fixture: TlsPassiveFixture,
        block: (CaptureArtifactRepository, TlsSecretStore, TlsCaptureBundle, String, File) -> Unit
    ) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.noBackupFilesDir, "tls-export-test-${UUID.randomUUID()}").apply { mkdirs() }
        val artifacts = CaptureArtifactRepository(File(root, "captures"))
        val secrets = TlsSecretStore(File(root, "private").apply { mkdirs() }, com.example.layanalyzer.capture.tls.AndroidTlsWrappingKeyProvider())
        val bundle = TlsCaptureBundle(artifacts, secrets, File(root, "private/work"))
        val id = "fixture-${UUID.randomUUID()}"
        try {
            val dir = artifacts.captureDirectory(id).apply { mkdirs() }
            fixture.file("pcap").copyTo(File(dir, "packets.pcap"))
            val frames = fixture.file("pcap").inputStream().use { TlsRawCaptureWriter.copy(it, ByteArrayOutputStream()) }
            val parsed = fixture.file("keylog").inputStream().use(KeyLogParser::parse) as KeyLogParseResult.Success
            val ref = secrets.importRecords(id, parsed)
            artifacts.commit(CaptureArtifactManifest(id,
                segments = listOf(CaptureSegmentRef("packets.pcap", 1, frames)),
                secretsPersistedSequence = ref.watermark.sequence,
                tls = CaptureTlsAssets(enabled = true, secretsAssetId = ref.assetId, complete = true), complete = true))
            block(artifacts, secrets, bundle, id, root)
        } finally {
            check(root.canonicalFile.parentFile == context.noBackupFilesDir.canonicalFile)
            root.deleteRecursively()
        }
    }
}
