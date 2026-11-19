// Copyright (c) 2026 cheig; GPL-3.0.
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
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/** Real production JNI snapshots. Tests intentionally require a device and Wireshark. */
@RunWith(AndroidJUnit4::class)
class TlsDataSourceTest {
    @Before fun engineReady() { NativeTestSupport.awaitApplicationEngine() }

    @Test fun tls12BodyRangesMatchClientBytes() = bodyRanges("tls12-h1")
    @Test fun tls13BodyRangesMatchClientBytes() = bodyRanges("tls13-h1")
    @Test fun tls13Http2BodyRangesMatchClientBytes() = bodyRanges("tls13-h2")

    private fun bodyRanges(id: String) = TlsPassiveFixture(id).use { fixture ->
        val handle = fixture.open()
        try {
            val generation = configure(handle, fixture.file("keylog").path, 1)
            val actualBody = ByteArrayOutputStream()
            var derivedBodyFields = 0
            var generatedFields = 0
            var decryptedSources = 0
            for (index in 0 until NativeEngine.getFrameCount(handle)) {
                val detail = details(handle, index)
                assertEquals(generation, detail.getLong("dissectionGeneration"))
                assertEquals(index + 1, detail.getInt("frameNumber"))
                val sources = describe(handle, detail).getJSONArray("sources")
                val byId = (0 until sources.length()).associate {
                    sources.getJSONObject(it).let { source -> source.getString("id") to source }
                }
                val raw = NativeEngine.getPacketBytes(handle, index)
                assertArrayEquals(raw, range(handle, detail, "raw", 0, raw.size))
                assertEquals("raw_frame", byId.getValue("raw").getString("kind"))
                assertTrue(byId.values.sumOf { it.getLong("availableLength") } <= BYTE_LIMIT)
                decryptedSources += byId.values.count { it.getString("kind") == "decrypted_tls" }
                visit(detail) { node ->
                    if (node.optBoolean("generated")) {
                        ++generatedFields
                        assertFalse(node.getBoolean("offsetValid"))
                    }
                    if (node.isNull("dataSourceId")) assertFalse(node.getBoolean("offsetValid"))
                    if (node.getBoolean("offsetValid")) {
                        val source = byId.getValue(node.getString("dataSourceId"))
                        assertTrue(node.getLong("start") >= 0)
                        assertTrue(node.getLong("start") + node.getLong("length") <= source.getLong("availableLength"))
                    }
                    val bodyField = if (fixture.http2) "http2.data.data" else "http.file_data"
                    if (node.optString("filter") == bodyField) {
                        assertTrue("Body field must have a real source range", node.getBoolean("offsetValid"))
                        val sourceId = node.getString("dataSourceId")
                        assertNotEquals("raw", sourceId)
                        ++derivedBodyFields
                        val bytes = range(handle, detail, sourceId, node.getInt("start"), node.getInt("length"))
                        // Wireshark renders FT_BYTES (http2.data.data) as colon-hex and FT_STRING
                        // (http.file_data, per `tshark -G fields`) as a quoted string; the range is the
                        // byte-exact source of truth for both.
                        val rendered = node.getString("filterValue")
                        if (fixture.http2) {
                            assertEquals(bytes.joinToString(":") { "%02x".format(it) }, rendered)
                        } else {
                            assertTrue("FT_STRING body field must render its bytes",
                                rendered.length > 2 && rendered.first() == '"' && rendered.last() == '"')
                        }
                        actualBody.write(bytes)
                    }
                }
            }
            assertTrue(derivedBodyFields > 0)
            assertTrue(generatedFields > 0)
            assertTrue(decryptedSources > 0)
            assertArrayEquals(fixture.body, actualBody.toByteArray())
            assertFalse("Original PCAP must not contain the golden plaintext body",
                containsBytes(fixture.file("pcap").readBytes(), fixture.body))
        } finally { fixture.closeCapture(handle) }
    }

    @Test fun identitiesRangesAndEvictionAreValidated() {
        TlsPassiveFixture("tls12-h1").use { fixture ->
        val handle = fixture.open()
        try {
            val first = details(handle, 0)
            val second = details(handle, 1)
            describe(handle, first) // Two snapshots coexist; describing creates no new snapshot.
            repeat(3) { describe(handle, second) }
            val rawLength = NativeEngine.getPacketBytes(handle, 1).size
            assertEquals(0, range(handle, second, "raw", rawLength, 0).size)
            for ((offset, length) in listOf(-1 to 1, 0 to -1, 0 to RANGE_LIMIT + 1,
                Int.MAX_VALUE to 1, Int.MAX_VALUE to Int.MAX_VALUE, rawLength to 1)) {
                error("INVALID_ARGUMENT", NativeEngine.readPacketDataSource(handle, second.getString("snapshotId"),
                    "raw", offset, length, second.getLong("dissectionGeneration")))
            }
            error("INVALID_ARGUMENT", NativeEngine.readPacketDataSource(handle, second.getString("snapshotId"),
                "missing", 0, 0, second.getLong("dissectionGeneration")))
            error("INVALID_ARGUMENT", NativeEngine.getPacketDataSources(handle, "bad\u0000id", 0))
            error("INVALID_ARGUMENT", NativeEngine.getPacketDataSources(handle, first.getString("snapshotId"), -1))
            val third = details(handle, 2)
            error("STALE_GENERATION", NativeEngine.getPacketDataSources(handle, first.getString("snapshotId"),
                first.getLong("dissectionGeneration")))
            error("STALE_GENERATION", NativeEngine.readPacketDataSource(handle, first.getString("snapshotId"),
                "raw", 0, 1, first.getLong("dissectionGeneration")))
            describe(handle, second)
            describe(handle, third)
            val refreshed = details(handle, 0)
            assertNotEquals(first.getString("snapshotId"), refreshed.getString("snapshotId"))
            describe(handle, refreshed)
        } finally { fixture.closeCapture(handle) }
        }
    }

    @Test fun resetClearAndCaptureSwitchRejectOldSnapshots() = TlsPassiveFixture("tls13-h1").use { fixture ->
        var handle = fixture.open()
        val old: JSONObject
        try {
            configure(handle, fixture.file("keylog").path, 1)
            fixture.assertBody(handle, true)
            old = details(handle, NativeEngine.getFrameCount(handle) - 1)
            val generation = configure(handle, null, 2)
            assertTrue(generation > old.getLong("dissectionGeneration"))
            error("STALE_GENERATION", NativeEngine.getPacketDataSources(handle, old.getString("snapshotId"),
                old.getLong("dissectionGeneration")))
            error("STALE_GENERATION", NativeEngine.getPacketDataSources(handle, old.getString("snapshotId"), generation))
            fixture.assertBody(handle, false)
        } finally { fixture.closeCapture(handle) }
        error("NOT_READY", NativeEngine.getPacketDataSources(handle, old.getString("snapshotId"),
            old.getLong("dissectionGeneration")))
        handle = fixture.open()
        try {
            val fresh = details(handle, 0)
            assertNotEquals(old.getString("snapshotId"), fresh.getString("snapshotId"))
            error("STALE_GENERATION", NativeEngine.getPacketDataSources(handle, old.getString("snapshotId"),
                fresh.getLong("dissectionGeneration")))
        } finally { fixture.closeCapture(handle) }
    }

    @Test fun oversizedSourceIsTruncatedBeforeCopyAndEvictsPreviousSnapshot() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val file = File(context.noBackupFilesDir, "tls-source-budget-${UUID.randomUUID()}.pcap")
        // DLT_DBUS allows 128 MiB wiretap frames. Synthetic malformed/opaque
        // message body avoids network/secrets and exercises a real >8 MiB tvb.
        val largeSize = BYTE_LIMIT.toInt() + 1024
        fun le(vararg values: Int): ByteArray = ByteBuffer.allocate(values.size * 4)
            .order(ByteOrder.LITTLE_ENDIAN).apply { values.forEach(::putInt) }.array()
        try {
            file.outputStream().buffered().use { out ->
                out.write(le(0xa1b2c3d4.toInt(), 0x00040002, 0, 0, largeSize, 231))
                for (size in listOf(16, largeSize, 16)) {
                    out.write(le(1, 0, size, size))
                    out.write(byteArrayOf('l'.code.toByte(), 1, 0, 1))
                    out.write(le(size - 16, 1, 0))
                    val zeros = ByteArray(8192)
                    var remaining = size - 16
                    while (remaining > 0) {
                        val count = minOf(remaining, zeros.size)
                        out.write(zeros, 0, count)
                        remaining -= count
                    }
                }
            }
            val handle = NativeEngine.openFile(file.path, null)
            assertTrue(handle != 0L)
            try {
                val first = details(handle, 0)
                val large = details(handle, 1)
                val sources = describe(handle, large).getJSONArray("sources")
                val raw = (0 until sources.length()).map { sources.getJSONObject(it) }.single { it.getString("id") == "raw" }
                assertEquals(largeSize.toLong(), raw.getLong("byteLength"))
                assertEquals(BYTE_LIMIT, raw.getLong("availableLength"))
                assertTrue(raw.getBoolean("truncated"))
                assertEquals(RANGE_LIMIT, range(handle, large, "raw", 0, RANGE_LIMIT).size)
                error("INVALID_ARGUMENT", NativeEngine.readPacketDataSource(handle, large.getString("snapshotId"),
                    "raw", BYTE_LIMIT.toInt(), 1, large.getLong("dissectionGeneration")))
                error("STALE_GENERATION", NativeEngine.getPacketDataSources(handle, first.getString("snapshotId"),
                    first.getLong("dissectionGeneration")))
                details(handle, 2)
                error("STALE_GENERATION", NativeEngine.getPacketDataSources(handle, large.getString("snapshotId"),
                    large.getLong("dissectionGeneration")))
            } finally { NativeEngine.closeFile(handle) }
        } finally { assertTrue(file.delete()) }
    }

    private fun configure(handle: Long, path: String?, revision: Long): Long =
        success(NativeEngine.configureTlsSecrets(handle, path, revision)).getLong("dissectionGeneration")

    private fun details(handle: Long, index: Int) = success(NativeEngine.getPacketDetails(handle, index))

    private fun describe(handle: Long, detail: JSONObject): JSONObject =
        success(NativeEngine.getPacketDataSources(handle, detail.getString("snapshotId"),
            detail.getLong("dissectionGeneration"))).also {
            assertEquals(detail.getString("snapshotId"), it.getString("snapshotId"))
            assertEquals(detail.getLong("frameNumber"), it.getLong("frameNumber"))
        }

    private fun range(handle: Long, detail: JSONObject, source: String, offset: Int, length: Int): ByteArray {
        val result = success(NativeEngine.readPacketDataSource(handle, detail.getString("snapshotId"), source,
            offset, length, detail.getLong("dissectionGeneration")))
        assertEquals(offset, result.getInt("offset"))
        assertEquals(length, result.getInt("length"))
        assertEquals(source, result.getString("sourceId"))
        return Base64.decode(result.getString("bytesBase64"), Base64.NO_WRAP).also { assertEquals(length, it.size) }
    }

    private fun success(raw: String): JSONObject = JSONObject(raw).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertTrue("Production JNI operation must succeed", it.getBoolean("success"))
        assertTrue(it.isNull("errorCode"))
        assertTrue(it.isNull("error"))
    }

    private fun error(code: String, raw: String) = JSONObject(raw).let {
        assertEquals(1, it.getInt("schemaVersion"))
        assertFalse(it.getBoolean("success"))
        assertEquals(code, it.getString("errorCode"))
        assertFalse(it.has("bytesBase64"))
    }

    private fun visit(node: JSONObject, action: (JSONObject) -> Unit) {
        action(node)
        node.optJSONArray("children")?.let { children ->
            for (index in 0 until children.length()) visit(children.getJSONObject(index), action)
        }
    }

    private fun containsBytes(haystack: ByteArray, needle: ByteArray): Boolean =
        needle.isNotEmpty() && (0..haystack.size - needle.size).any { offset ->
            needle.indices.all { haystack[offset + it] == needle[it] }
        }

    private companion object {
        const val BYTE_LIMIT = 8L * 1024 * 1024
        const val RANGE_LIMIT = 256 * 1024
    }
}
