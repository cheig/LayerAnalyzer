package com.example.layanalyzer

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest

/** TLS-007: assertions are required on each ABI; there are no Assume/skip paths. */
@RunWith(AndroidJUnit4::class)
class TlsDissectionProbeTest {
    @Before
    fun engineReady() {
        assertTrue("Build app and test APK with TLS probe ON", BuildConfig.TLS_PROBE_ENABLED)
        NativeTestSupport.awaitApplicationEngine()
        assertTrue("The embedded library must be Wireshark 4.0.10", NativeEngine.getVersion().contains("4.0.10"))
    }

    @Test fun tls12H1() = checkFixture("tls12-h1")
    @Test fun tls13H1() = checkFixture("tls13-h1")
    @Test fun tls13H2() = checkFixture("tls13-h2")

    @Test
    fun invalidInputFailsExplicitly() {
        val result = JSONObject(NativeEngine.runTlsDissectionProbe(0, null, 0, false, true))
        assertFalse(result.getBoolean("success"))
        assertEquals("INVALID_ARGUMENT", result.getString("errorCode"))
        val missing = File(InstrumentationRegistry.getInstrumentation().targetContext.noBackupFilesDir,
            "tls-007/does-not-exist.keys")
        assertFalse(missing.exists())
        val invalidFile = JSONObject(NativeEngine.runTlsDissectionProbe(0, missing.path, 443, false, true))
        assertFalse(invalidFile.getBoolean("success"))
        assertEquals("INVALID_ARGUMENT", invalidFile.getString("errorCode"))
    }

    @Test
    fun staleHandleFailsExplicitly() {
        val result = JSONObject(NativeEngine.runTlsDissectionProbe(0, null, 443, false, true))
        assertFalse(result.getBoolean("success"))
        assertEquals("NOT_READY", result.getString("errorCode"))
    }

    private fun checkFixture(id: String) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val assets = instrumentation.context.assets
        val manifest = JSONObject(assets.open("tls/fixtures/manifest.json").bufferedReader().use { it.readText() })
        assertEquals(1, manifest.getInt("schemaVersion"))
        val fixtures = manifest.getJSONArray("fixtures")
        val fixture = (0 until fixtures.length()).map { fixtures.getJSONObject(it) }
            .single { it.getString("fixtureId") == id }
        assertEquals("synthetic-local-test-only", fixture.getString("source"))
        val directory = File(instrumentation.targetContext.noBackupFilesDir, "tls-007/$id").apply { mkdirs() }
        val files = mutableMapOf<String, File>()
        val entries = fixture.getJSONArray("files")
        for (i in 0 until entries.length()) {
            val entry = entries.getJSONObject(i)
            val relative = entry.getString("path")
            require(relative.startsWith("$id/") && !relative.contains(".."))
            val bytes = assets.open("tls/fixtures/$relative").use { it.readBytes() }
            assertEquals(entry.getString("sha256"), TlsDissectionProbeAssertions.sha256(bytes))
            files[entry.getString("role")] = File(directory, File(relative).name).apply { writeBytes(bytes) }
            bytes.fill(0)
        }
        val client = JSONObject(files.getValue("client-result").readText()).getJSONObject("trusted")
        val body = files.getValue("golden-body").readBytes()
        val expected = fixture.getJSONObject("expectedBody").getString("sha256")
        assertEquals(expected, TlsDissectionProbeAssertions.sha256(body))
        assertEquals(expected, client.getString("bodySha256"))
        val port = client.getInt("destinationPort")
        val http2 = fixture.getString("alpn") == "h2"
        val handle = NativeEngine.openFile(files.getValue("pcap").path, null)
        assertTrue("Canonical fixture must open", handle != 0L)
        val report = JSONObject().put("fixtureId", id).put("embeddedVersion", NativeEngine.getVersion())
        try {
            // Same application engine and handle, including reload after clear.
            for ((phase, role, taps) in listOf(
                Triple("empty", null, true), Triple("wrong", "wrong-keylog", true),
                Triple("ordinary", "keylog", false), Triple("taps", "keylog", true),
                Triple("clear", null, true), Triple("reload", "keylog", true)
            )) {
                val result = JSONObject(NativeEngine.runTlsDissectionProbe(
                    handle, role?.let { files.getValue(it).path }, port, http2, taps))
                report.put(phase, result)
                // Private synthetic evidence is written even before assertions fail.
                File(directory, "report.json").writeText(report.toString(2))
                TlsDissectionProbeAssertions.check(result, body, role == "keylog", taps, http2)
            }
        } finally {
            NativeEngine.closeFile(handle)
            // Native cleanup precedes unlink; no production FileProvider path.
            files.values.forEach { it.delete() }
            body.fill(0)
        }
    }
}

/** Reusable by TLS-008 for its actual TUN capture; no expected plaintext is fed to JNI. */
internal object TlsDissectionProbeAssertions {
    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    fun check(result: JSONObject, body: ByteArray, decrypted: Boolean, taps: Boolean, http2: Boolean) {
        assertEquals(1, result.getInt("schemaVersion"))
        assertTrue(result.optString("errorCode"), result.getBoolean("success"))
        assertTrue(result.isNull("errorCode"))
        assertTrue(result.isNull("error"))
        assertTrue(result.getBoolean("preferenceCleared"))
        assertTrue(result.getBoolean("epanRebuilt"))
        val scan = result.getJSONObject("scan")
        assertTrue(scan.getInt("frames") > 0)
        assertEquals(1, scan.getInt("tcpStreams"))
        assertEquals("tls", scan.getString("tapName"))
        assertEquals(taps, scan.getBoolean("withTaps"))
        val sources = scan.getJSONArray("sources")
        val fields = scan.getJSONArray("bodyFields")
        val records = scan.getJSONArray("records")
        val decryptedSources = (0 until sources.length()).map { sources.getJSONObject(it) }
            .filter { it.getString("name").startsWith("Decrypted TLS") }
        if (!decrypted) {
            assertEquals(0, scan.getInt("bodyBytes"))
            assertEquals(0, fields.length())
            assertEquals(0, records.length())
            assertTrue(decryptedSources.isEmpty())
            return
        }
        assertEquals(body.size, scan.getInt("bodyBytes"))
        assertEquals(sha256(body), scan.getString("bodySha256"))
        assertTrue("Actual Decrypted TLS source required", decryptedSources.isNotEmpty())
        assertTrue("Body must come from real protocol fields", fields.length() > 0)
        for (i in 0 until fields.length()) {
            val field = fields.getJSONObject(i)
            assertEquals(if (http2) "http2.data.data" else "http.file_data", field.getString("field"))
            assertTrue(field.getBoolean("offsetValid"))
            assertNotEquals("raw", field.getString("dataSourceId"))
            val source = (0 until sources.length()).map { sources.getJSONObject(it) }.single {
                it.getInt("frameNumber") == field.getInt("frameNumber") &&
                    it.getString("id") == field.getString("dataSourceId")
            }
            assertTrue(field.getInt("start") >= 0)
            assertTrue(field.getInt("start") + field.getInt("length") <= source.getInt("byteLength"))
        }
        if (!taps) {
            assertEquals("Ordinary dissection is not equivalent to a tap run", 0, records.length())
            return
        }
        assertTrue("Registered follower must yield application records", records.length() > 0)
        assertTrue(scan.getBoolean("directionKnown"))
        val serverBytes = ByteArrayOutputStream()
        for (i in 0 until records.length()) {
            val record = records.getJSONObject(i)
            val bytes = Base64.decode(record.getString("bytesBase64"), Base64.DEFAULT)
            assertEquals(record.getInt("byteLength"), bytes.size)
            assertTrue(record.getInt("frameNumber") in 1..scan.getInt("frames"))
            if (record.getBoolean("fromServer")) serverBytes.write(bytes)
            bytes.fill(0)
        }
        val bytes = serverBytes.toByteArray()
        assertTrue("Server TLS application stream must contain the independently known body",
            (0..bytes.size - body.size).any { offset -> body.indices.all { bytes[offset + it] == body[it] } })
        bytes.fill(0)
    }
}
