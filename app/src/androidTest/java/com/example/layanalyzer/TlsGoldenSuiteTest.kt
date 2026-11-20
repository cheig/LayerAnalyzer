// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.os.Build
import android.util.Base64
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest

/** TLS-401: production JNI, probe OFF. Every required fixture must execute, with no Assume. */
@RunWith(Parameterized::class)
class TlsGoldenSuiteTest(private val id: String) {
    @Before fun ready() {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue("The release golden suite must use a TLS ON candidate", BuildConfig.TLS_ENABLED)
        assertFalse("The release golden suite must use production JNI", BuildConfig.TLS_PROBE_ENABLED)
        assertTrue(NativeEngine.getVersion().contains("4.0.10"))
    }

    @Test fun goldenNegativesAndClearReload() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        // Test APK context is essential: these public keylogs must never ship in the main APK.
        val manifestBytes = instrumentation.context.assets.open("tls/fixtures/manifest.json").use { it.readBytes() }
        val manifest = JSONObject(manifestBytes.toString(Charsets.UTF_8))
        assertEquals("tls-golden-v1", manifest.getString("suiteVersion"))
        val entries = manifest.getJSONArray("fixtures")
        assertEquals(ids.toSet(), (0 until entries.length()).map { entries.getJSONObject(it).getString("fixtureId") }.toSet())
        val entry = (0 until entries.length()).map { entries.getJSONObject(it) }.single { it.getString("fixtureId") == id }
        val runId = InstrumentationRegistry.getArguments().getString("tlsSuiteRunId", "manual")!!
        require(runId.matches(Regex("[A-Za-z0-9_-]{1,80}")))
        // Only public fixture hashes/status leave private storage. Some OEMs disable run-as;
        // shell-readable test reports must never contain keylogs, CA material or body bytes.
        val reportDirectory = File(checkNotNull(instrumentation.targetContext.getExternalFilesDir(null)),
            "tls-suite-v1/$runId")
        check(reportDirectory.isDirectory || reportDirectory.mkdirs())
        val cases = JSONObject()
        var bodyHash = ""
        TlsPassiveFixture(id).use { fixture ->
            fun scan(path: File, keylog: File?): ByteArray {
                val handle = NativeEngine.openFile(path.path, null)
                assertTrue("Golden PCAP must open", handle != 0L)
                try {
                    assertTrue(JSONObject(NativeEngine.applyDecodeAs(handle, "tcp.port", fixture.port, "tls")).getBoolean("success"))
                    configure(handle, keylog?.path, 1)
                    return body(handle, fixture.http2)
                } finally { fixture.closeCapture(handle) }
            }
            val handle = fixture.open()
            try {
                configure(handle, null, 1)
                assertEquals(0, body(handle, fixture.http2).size)
                cases.put("no-key", true)
                configure(handle, fixture.file("keylog").path, 2)
                val actual = body(handle, fixture.http2)
                assertArrayEquals(fixture.body, actual)
                bodyHash = sha256(actual)
                cases.put("golden", true)
                configure(handle, null, 3)
                assertEquals(0, body(handle, fixture.http2).size)
                cases.put("clear", true)
                configure(handle, fixture.file("keylog").path, 4)
                assertArrayEquals(actual, body(handle, fixture.http2))
                cases.put("reload", true)
            } finally { fixture.closeCapture(handle) }
            for ((name, role) in listOf("wrong-key" to "wrong-keylog", "corrupt-secret" to "corrupt-keylog")) {
                assertEquals(name, 0, scan(fixture.file("pcap"), fixture.file(role)).size)
                cases.put(name, true)
            }
            for (role in listOf("missing-handshake", "missing-segment")) {
                assertEquals(role, 0, scan(fixture.file(role), fixture.file("keylog")).size)
                cases.put(role, true)
            }
            val fileEntries = entry.getJSONArray("files")
            val roles = (0 until fileEntries.length()).map { fileEntries.getJSONObject(it).getString("role") }.toSet()
            if ("upstream-pcap" in roles) {
                assertArrayEquals(fixture.body, scan(fixture.file("upstream-pcap"), fixture.file("wrong-keylog")))
                cases.put("upstream-own-key", true)
                for (role in listOf("untrusted-pcap", "wrong-name-pcap")) {
                    assertEquals(role, 0, scan(fixture.file(role), null).size)
                    cases.put(role, true)
                }
            }
        }
        val report = JSONObject().put("schemaVersion", 1).put("suiteVersion", "tls-golden-v1")
            .put("runId", runId).put("fixtureId", id).put("manifestSha256", sha256(manifestBytes))
            .put("embeddedVersion", NativeEngine.getVersion()).put("abi", Build.SUPPORTED_ABIS.first())
            .put("api", Build.VERSION.SDK_INT).put("buildType", BuildConfig.BUILD_TYPE)
            .put("tlsEnabled", BuildConfig.TLS_ENABLED).put("probeEnabled", BuildConfig.TLS_PROBE_ENABLED)
            .put("bodySha256", bodyHash).put("cases", cases).put("passed", true)
        File(reportDirectory, "$id.json").writeText(report.toString(2))
    }

    private fun configure(handle: Long, path: String?, revision: Long) {
        val result = JSONObject(NativeEngine.configureTlsSecrets(handle, path, revision))
        assertEquals(1, result.getInt("schemaVersion"))
        assertTrue(result.optString("errorCode"), result.getBoolean("success"))
        assertEquals(path != null, result.getBoolean("configured"))
    }

    /** Hash bytes read from the protocol field's own snapshot data source. */
    private fun body(handle: Long, http2: Boolean): ByteArray {
        val output = ByteArrayOutputStream()
        val filter = if (http2) "http2.data.data" else "http.file_data"
        fun visit(detail: JSONObject, node: JSONObject) {
            if (node.optString("filter") == filter) {
                assertTrue(node.getBoolean("offsetValid"))
                val sourceId = node.getString("dataSourceId")
                assertNotEquals("raw", sourceId)
                val result = JSONObject(NativeEngine.readPacketDataSource(handle, detail.getString("snapshotId"),
                    sourceId, node.getInt("start"), node.getInt("length"), detail.getLong("dissectionGeneration")))
                assertTrue(result.optString("errorCode"), result.getBoolean("success"))
                output.write(Base64.decode(result.getString("bytesBase64"), Base64.NO_WRAP))
            }
            node.optJSONArray("children")?.let { children ->
                for (index in 0 until children.length()) visit(detail, children.getJSONObject(index))
            }
        }
        for (index in 0 until NativeEngine.getFrameCount(handle)) {
            val detail = JSONObject(NativeEngine.getPacketDetails(handle, index))
            visit(detail, detail)
        }
        return output.toByteArray()
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }

    companion object {
        val ids = listOf("tls12-h1", "tls13-h1", "tls13-h2", "tls12-h2", "tls13-chacha-h1",
            "tls13-chacha-h2", "tls13-hrr-h1", "tls13-keyupdate-h1")

        @JvmStatic @Parameterized.Parameters(name = "{0}")
        fun fixtures(): List<Array<String>> = ids.map { arrayOf(it) }
    }
}
