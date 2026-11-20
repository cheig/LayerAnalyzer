// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import android.util.Base64
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Production JNI tests: no probe dependency, no Assume/skip, no injected plaintext. */
@RunWith(AndroidJUnit4::class)
class TlsSecretsConfigurationTest {
    @Before fun engineReady() {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue(NativeEngine.getVersion().contains("4.0.10"))
    }

    @Test fun tls12LoadClearReload() = loadClearReload("tls12-h1")
    @Test fun tls13LoadClearReload() = loadClearReload("tls13-h1")
    @Test fun tls13Http2LoadClearReload() = loadClearReload("tls13-h2")

    private fun loadClearReload(id: String) = TlsPassiveFixture(id).use { fixture ->
        val handle = fixture.open()
        var lastGeneration = 0L
        try {
            for ((index, role) in listOf(null, "keylog", null, "wrong-keylog", "keylog").withIndex()) {
                val result = configure(handle, role?.let { fixture.file(it).path }, index + 1L)
                assertTrue(result.getLong("dissectionGeneration") > lastGeneration)
                lastGeneration = result.getLong("dissectionGeneration")
                assertEquals(index + 1L, result.getLong("secretsGeneration"))
                assertEquals(role != null, result.getBoolean("configured"))
                fixture.assertBody(handle, role == "keylog")
            }
        } finally { fixture.closeCapture(handle) }
    }

    @Test fun revisionsAndInvalidInputPreserveCurrentConfiguration() = TlsPassiveFixture("tls12-h1").use { fixture ->
        val handle = fixture.open()
        try {
            val configured = configure(handle, fixture.file("keylog").path, 1)
            val same = configure(handle, fixture.file("keylog").path, 1)
            assertEquals(configured.getLong("dissectionGeneration"), same.getLong("dissectionGeneration"))
            for ((path, revision, code) in listOf(
                Triple(null, 0L, "STALE_GENERATION"),
                Triple(null, 1L, "STALE_GENERATION"),
                Triple(fixture.file("wrong-keylog").path, 1L, "STALE_GENERATION"),
                Triple("", 2L, "INVALID_ARGUMENT"),
                Triple("relative.keys", 2L, "INVALID_ARGUMENT"),
                Triple(fixture.file("keylog").path + "\u0000extra", 2L, "INVALID_ARGUMENT"),
                Triple(fixture.file("keylog").path, -1L, "INVALID_ARGUMENT"),
                Triple(File(fixture.directory, "missing.keys").path, 2L, "IO_ERROR")
            )) {
                val result = JSONObject(NativeEngine.configureTlsSecrets(handle, path, revision))
                assertFalse(result.getBoolean("success"))
                assertEquals(code, result.getString("errorCode"))
                assertFalse(result.getBoolean("sessionClosed"))
                assertFalse("No private paths in responses", result.toString().contains(fixture.directory.path))
            }
            assertEquals(configured.getLong("dissectionGeneration"),
                configure(handle, fixture.file("keylog").path, 1).getLong("dissectionGeneration"))
            fixture.assertBody(handle, true)
        } finally { fixture.closeCapture(handle) }
        val closed = JSONObject(NativeEngine.configureTlsSecrets(handle, null, 3))
        assertFalse(closed.getBoolean("success"))
        assertEquals("NOT_READY", closed.getString("errorCode"))
    }

    @Test fun closeAndCaptureSwitchDoNotInheritSecrets() = TlsPassiveFixture("tls12-h1").use { a ->
        TlsPassiveFixture("tls13-h1").use { b ->
            var handle = a.open()
            try {
                configure(handle, a.file("keylog").path, 1)
                a.assertBody(handle, true)
                val second = NativeEngine.openFile(b.file("pcap").path, null)
                assertEquals("A second global Wireshark file scope must be refused", 0L, second)
            } finally { a.closeCapture(handle) }
            handle = b.open()
            try {
                assertFalse(configure(handle, null, 0).getBoolean("configured"))
                b.assertBody(handle, false)
                configure(handle, a.file("keylog").path, 1)
                b.assertBody(handle, false)
                configure(handle, b.file("keylog").path, 2)
                b.assertBody(handle, true)
            } finally { b.closeCapture(handle) }
            handle = a.open()
            try { a.assertBody(handle, false) } finally { a.closeCapture(handle) }
        }
    }

    @Test fun concurrentQueriesAndClearFinish() = TlsPassiveFixture("tls13-h1").use { fixture ->
        val handle = fixture.open()
        val executor = Executors.newFixedThreadPool(2)
        try {
            configure(handle, fixture.file("keylog").path, 1)
            fixture.assertBody(handle, true)
            val start = CountDownLatch(1)
            val read = executor.submit {
                start.await()
                repeat(30) { NativeEngine.getPacketSummaries(handle, 0, NativeEngine.getFrameCount(handle)) }
            }
            val clear = executor.submit<JSONObject> {
                start.await()
                configure(handle, null, 2)
            }
            start.countDown()
            read.get(30, TimeUnit.SECONDS)
            assertFalse(clear.get(30, TimeUnit.SECONDS).getBoolean("configured"))
            fixture.assertBody(handle, false)
        } finally {
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            fixture.closeCapture(handle)
        }
    }

    private fun configure(handle: Long, path: String?, revision: Long): JSONObject {
        val result = JSONObject(NativeEngine.configureTlsSecrets(handle, path, revision))
        assertEquals(1, result.getInt("schemaVersion"))
        assertTrue(result.optString("errorCode"), result.getBoolean("success"))
        assertTrue(result.isNull("errorCode"))
        assertTrue(result.isNull("error"))
        assertFalse(result.getBoolean("sessionClosed"))
        return result
    }
}

/** Canonical synthetic fixtures shared by later passive JNI integration tests. */
internal class TlsPassiveFixture(id: String) : AutoCloseable {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    val directory = File(instrumentation.targetContext.noBackupFilesDir, "tls-passive/${UUID.randomUUID()}")
    private val files = mutableMapOf<String, File>()
    val http2: Boolean
    val port: Int
    val body: ByteArray

    init {
        check(directory.mkdirs())
        val assets = instrumentation.context.assets
        val manifest = JSONObject(assets.open("tls/fixtures/manifest.json").bufferedReader().use { it.readText() })
        val entries = manifest.getJSONArray("fixtures")
        val fixture = (0 until entries.length()).map { entries.getJSONObject(it) }
            .single { it.getString("fixtureId") == id }
        check(fixture.getString("source") == "synthetic-local-test-only")
        val fileEntries = fixture.getJSONArray("files")
        for (index in 0 until fileEntries.length()) {
            val entry = fileEntries.getJSONObject(index)
            val relative = entry.getString("path")
            require(relative.startsWith("$id/") && !relative.contains(".."))
            val bytes = assets.open("tls/fixtures/$relative").use { it.readBytes() }
            assertEquals(entry.getString("sha256"), sha256(bytes))
            files[entry.getString("role")] = File(directory, File(relative).name).apply { writeBytes(bytes) }
            bytes.fill(0)
        }
        port = JSONObject(file("client-result").readText()).getJSONObject("trusted").getInt("destinationPort")
        http2 = fixture.getString("alpn") == "h2"
        body = file("golden-body").readBytes()
        assertEquals(fixture.getJSONObject("expectedBody").getString("sha256"), sha256(body))
    }

    fun file(role: String): File = files.getValue(role)
    fun open(): Long {
        val handle = NativeEngine.openFile(file("pcap").path, null)
        assertTrue("Canonical capture must open", handle != 0L)
        assertTrue(JSONObject(NativeEngine.applyDecodeAs(handle, "tcp.port", port, "tls")).getBoolean("success"))
        return handle
    }

    fun closeCapture(handle: Long) {
        try { NativeEngine.resetDecodeAs(handle, "tcp.port", port) }
        finally { NativeEngine.closeFile(handle) }
    }

    /**
     * Sequential native dissection, then compare actual body fields to independent client bytes.
     * Body bytes come from the field's own data-source range: Wireshark renders `http.file_data` as
     * FT_STRING (a quoted string), so its rendered value is not a byte encoding the way the
     * FT_BYTES `http2.data.data` value is.
     */
    fun assertBody(handle: Long, decrypted: Boolean) {
        val output = ByteArrayOutputStream()
        val field = if (http2) "http2.data.data" else "http.file_data"
        var bodyFields = 0
        fun visit(detail: JSONObject, node: JSONObject) {
            if (node.optString("filter") == field) {
                ++bodyFields
                assertTrue("Body field must have a real source range", node.getBoolean("offsetValid"))
                val sourceId = node.getString("dataSourceId")
                assertNotEquals("raw", sourceId)
                output.write(sourceBytes(handle, detail, sourceId, node.getInt("start"), node.getInt("length")))
            }
            node.optJSONArray("children")?.let { children ->
                for (i in 0 until children.length()) visit(detail, children.getJSONObject(i))
            }
        }
        for (index in 0 until NativeEngine.getFrameCount(handle)) {
            val detail = JSONObject(NativeEngine.getPacketDetails(handle, index))
            visit(detail, detail)
        }
        if (decrypted) {
            assertTrue("Configured secrets must expose body fields", bodyFields > 0)
            assertArrayEquals(body, output.toByteArray())
        } else {
            assertEquals("Absent/wrong/cleared secrets cannot expose body fields", 0, output.size())
        }
    }

    private fun sourceBytes(handle: Long, detail: JSONObject, sourceId: String,
                            offset: Int, length: Int): ByteArray {
        val result = JSONObject(NativeEngine.readPacketDataSource(handle, detail.getString("snapshotId"),
            sourceId, offset, length, detail.getLong("dissectionGeneration")))
        assertTrue(result.optString("errorCode"), result.getBoolean("success"))
        return Base64.decode(result.getString("bytesBase64"), Base64.NO_WRAP)
    }

    /** Shared golden assertions for native Follow and the complete passive-import chain. */
    fun assertApplicationBytes(client: ByteArray, server: ByteArray) {
        assertTrue(client.isNotEmpty() && server.isNotEmpty())
        if (http2) {
            assertTrue(client.toString(Charsets.ISO_8859_1).startsWith("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
            // Parse HTTP/2 DATA frames instead of finding an arbitrary substring.
            val actualBody = ByteArrayOutputStream()
            var offset = 0
            while (offset + 9 <= server.size) {
                val size = ((server[offset].toInt() and 255) shl 16) or
                    ((server[offset + 1].toInt() and 255) shl 8) or (server[offset + 2].toInt() and 255)
                assertTrue(offset + 9 + size <= server.size)
                if (server[offset + 3].toInt() == 0) actualBody.write(server, offset + 9, size)
                offset += 9 + size
            }
            assertEquals(server.size, offset)
            assertArrayEquals(body, actualBody.toByteArray())
        } else {
            val expectedRequest = "GET /fixture HTTP/1.1\r\nHost: fixture.layeranalyzer.test:${port}\r\n" +
                "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
            assertArrayEquals(expectedRequest.toByteArray(), client)
            val response = server.toString(Charsets.ISO_8859_1)
            assertTrue(response.startsWith("HTTP/1.1 200 OK\r\n"))
            val bodyStart = response.indexOf("\r\n\r\n")
            assertTrue(bodyStart >= 0)
            assertArrayEquals(body, server.copyOfRange(bodyStart + 4, server.size))
        }
    }

    override fun close() {
        body.fill(0)
        files.values.forEach { check(it.delete()) }
        check(directory.delete())
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
}
