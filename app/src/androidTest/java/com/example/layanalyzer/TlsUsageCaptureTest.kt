// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.TlsSecretStore
import com.example.layanalyzer.data.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.Before
import org.junit.Assume.assumeTrue

/** Audit the actual UI-created TLS-407 TUN capture. Never create a synthetic replacement. */
class TlsUsageCaptureTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val expected = "tls-218-arm64-body\n".toByteArray()
    @Before fun requireIsolatedTarget() {
        assumeTrue("Manual TLS-407 audit requires its isolated installation", context.packageName == "com.layeranalyzer.android.tls407")
    }
    private fun capture(): String {
        check(context.packageName == "com.layeranalyzer.android.tls407")
        return requireNotNull(InstrumentationRegistry.getArguments().getString("tls407Capture"))
            .also { require(it.matches(Regex("live-[0-9]+"))) }
    }
    private fun report(name: String, result: JSONObject) {
        val dir = File(context.getExternalFilesDir(null), "tls-407/results").apply { mkdirs() }
        File(dir, "$name.json").writeText(result.toString(2))
    }
    private fun hasBody(handle: Long): Boolean {
        val objects = JSONObject(NativeEngine.getHttpObjects(handle)).getJSONArray("objects")
        return (0 until objects.length()).any { index ->
            val obj = objects.getJSONObject(index)
            NativeEngine.getHttpObjectPayload(handle, obj.getInt("id")).contentEquals(expected)
        }
    }
    private fun replay(id: String): Long {
        val artifacts = CaptureArtifactRepository(context)
        val state = artifacts.read(id) as CaptureArtifactState.Present
        assertTrue(state.isComplete)
        assertTrue(state.manifest.tls.complete)
        assertTrue(state.manifest.secretsPersistedSequence > 0)
        val source = artifacts.openForAnalysis(id) as CaptureAnalysisSource.Merged
        assertFalse(source.analysisFile.readBytes().toString(Charsets.ISO_8859_1).contains(expected.toString(Charsets.UTF_8)))
        val handle = NativeEngine.openFile(source.analysisFile.path, null)
        assertNotEquals(0L, handle)
        try {
            assertFalse(hasBody(handle))
            TlsSecretStore(context).acquireLease(id, state.manifest.tls.secretsAssetId).use { lease ->
                lease.configureNative(clearNativeSecrets = {
                    assertTrue(JSONObject(NativeEngine.configureTlsSecrets(handle, null, 2)).getBoolean("success"))
                }) { path ->
                    assertTrue(JSONObject(NativeEngine.configureTlsSecrets(handle, path, 1)).getBoolean("success"))
                }
                assertTrue("Expected fixed HTTP body from UI-created TUN PCAP", hasBody(handle))
            }
            assertFalse("Clear must remove decrypted body", hasBody(handle))
            return state.manifest.secretsPersistedSequence
        } finally { NativeEngine.closeFile(handle) }
    }

    @Test fun retainedUiCaptureReplaysAndExports() {
        NativeTestSupport.awaitApplicationEngine()
        val id = capture()
        val artifacts = CaptureArtifactRepository(context)
        val sequence = replay(id)
        val bundle = TlsCaptureBundle(context)
        for ((filtered, confirmed) in listOf(true to true, false to false)) {
            val out = ByteArrayOutputStream()
            val error = runCatching { bundle.writeComplete(id, out, filtered, confirmed) }.exceptionOrNull()
            assertNotNull(error)
            assertEquals(0, out.size())
        }
        val bytes = ByteArrayOutputStream().also { bundle.writeComplete(id, it, false, true) }.toByteArray()
        val imported = bundle.importComplete(ByteArrayInputStream(bytes))
        try {
            assertNotEquals(id, imported)
            assertEquals(sequence, replay(imported))
        } finally { CaptureArtifactLifecycle(context).purge(imported) }
        val source = artifacts.openForAnalysis(id) as CaptureAnalysisSource.Merged
        val raw = ByteArrayOutputStream().also { out -> source.analysisFile.inputStream().use { TlsRawCaptureWriter.copy(it, out) } }.toByteArray()
        assertFalse(raw.toString(Charsets.ISO_8859_1).contains("CLIENT_RANDOM"))
        assertFalse(raw.toString(Charsets.ISO_8859_1).contains(expected.toString(Charsets.UTF_8)))
        report("retained", JSONObject().put("capture", id).put("secretSequence", sequence)
            .put("bodyBytes", expected.size).put("bodySha256", MessageDigest.getInstance("SHA-256").digest(expected).joinToString("") { "%02x".format(it) })
            .put("actualTunReplay", true).put("clearRemovesBody", true).put("bundleNewIdentityReplay", true)
            .put("filteredAndUnconfirmedBundleRejected", true).put("rawExportNoBodyOrKeylog", true))
    }

    @Test fun closedTransientUiCaptureHasNoSecrets() {
        NativeTestSupport.awaitApplicationEngine()
        val id = capture()
        val artifacts = CaptureArtifactRepository(context)
        assertTrue(artifacts.read(id) is CaptureArtifactState.Present)
        assertNull(TlsSecretStore(context).currentAsset(id))
        val source = artifacts.openForAnalysis(id) as CaptureAnalysisSource.Merged
        val handle = NativeEngine.openFile(source.analysisFile.path, null)
        try { assertFalse(hasBody(handle)) } finally { NativeEngine.closeFile(handle) }
        report("transient", JSONObject().put("capture", id).put("closedSecretsAbsent", true).put("reopenNoBody", true))
    }

    @Test fun filteredUiCaptureExportHasNoKeys() {
        NativeTestSupport.awaitApplicationEngine()
        val id = capture()
        val artifacts = CaptureArtifactRepository(context)
        val state = artifacts.read(id) as CaptureArtifactState.Present
        val source = artifacts.openForAnalysis(id) as CaptureAnalysisSource.Merged
        val output = File(context.noBackupFilesDir, "tls407-filtered.pcap")
        val handle = NativeEngine.openFile(source.analysisFile.path, null)
        var count = 0
        try {
            TlsSecretStore(context).acquireLease(id, state.manifest.tls.secretsAssetId).use { lease ->
                lease.configureNative(clearNativeSecrets = { NativeEngine.configureTlsSecrets(handle, null, 2) }) { path ->
                    assertTrue(JSONObject(NativeEngine.configureTlsSecrets(handle, path, 1)).getBoolean("success"))
                }
                val filter = JSONObject(NativeEngine.applyDisplayFilter(handle, "http"))
                assertTrue(filter.getBoolean("success"))
                count = filter.getInt("count")
                assertTrue(count > 0)
                assertTrue(JSONObject(NativeEngine.exportVisibleCapture(handle, output.path)).getBoolean("success"))
            }
        } finally { NativeEngine.closeFile(handle) }
        try {
            val bytes = output.readBytes().toString(Charsets.ISO_8859_1)
            assertFalse(bytes.contains(expected.toString(Charsets.UTF_8)))
            assertFalse(bytes.contains("TRAFFIC_SECRET"))
            assertFalse(bytes.contains("CLIENT_RANDOM"))
            val reopened = NativeEngine.openFile(output.path, null)
            try { assertFalse(hasBody(reopened)) } finally { NativeEngine.closeFile(reopened) }
            report("filtered", JSONObject().put("capture", id).put("exportedFrames", count)
                .put("filteredCiphertextOnly", true).put("noKeyReopenNoBody", true))
        } finally { output.delete() }
    }

    @Test fun uiDeletedCaptureHasNoAssociatedAssets() {
        val id = capture()
        assertFalse(CaptureArtifactRepository(context).captureDirectory(id).exists())
        assertNull(TlsSecretStore(context).currentAsset(id))
        assertFalse(File(context.noBackupFilesDir, "capture-secrets/$id").exists())
        assertFalse(File(context.filesDir, "exports/$id").exists())
        report("deleted-$id", JSONObject().put("capture", id).put("localCaptureAndSecretsAbsent", true)
            .put("associatedExportsAbsent", true))
    }

    @Test fun uiExportedPublicFixtureMatchesGolden() {
        check(context.packageName == "com.layeranalyzer.android.tls407")
        val name = requireNotNull(InstrumentationRegistry.getArguments().getString("tls407Export"))
        require(name.matches(Regex("[0-9]+-fixture")))
        val file = File(context.filesDir, "exports").walkTopDown().filter { it.isFile && it.name == name }.single()
        val bytes = file.readBytes()
        assertArrayEquals("LayerAnalyzer TLS fixture v1\n".toByteArray(), bytes)
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("9b1ce3253f3312a2d0f896f307a944a2effe972d55ba1a33cc939feb6e6fd7c4", hash)
        report("passive-ui-export", JSONObject().put("uiExport", name).put("bodyBytes", bytes.size)
            .put("bodySha256", hash).put("actualUiExportMatchesGolden", true))
    }
}
