// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.util.Log
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
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * HTTP object extraction over the production JNI only (TLS-309). The scan must
 * run through the tap-aware dissection entry: plain dissect_frame() never fires
 * the export tap, so the old code returned a false "success, no objects" for
 * HTTP/1 over TLS. This suite proves the callback actually runs, proves a rescan
 * is not duplicated, and proves HTTP/2 is reported unsupported rather than as an
 * empty success. It also covers the pre-existing plaintext HTTP path.
 */
@RunWith(AndroidJUnit4::class)
class TlsHttpObjectsTest {
    @Before fun engineReady() {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue(NativeEngine.getVersion().contains("4.0.10"))
        assertFalse("Acceptance must exercise production JNI", BuildConfig.TLS_PROBE_ENABLED)
    }

    /** Card acceptance 1: known HTTP/1 body byte-for-byte, rescan adds no duplicates. */
    @Test fun http1OverTlsExtractsFixtureBodyByteForByteWithoutDuplicates() {
        for (id in listOf("tls12-h1", "tls13-h1")) {
            TlsPassiveFixture(id).use { fixture ->
                val handle = fixture.open()
                try {
                    configure(handle, fixture.file("keylog").path, 1)
                    // Prime every frame through ordinary dissection before the
                    // tap scan: acceptance must also prove visited-frame replay.
                    fixture.assertBody(handle, true)
                    val result = scan(handle)
                    val objects = result.getJSONArray("objects")
                    assertEquals("$id must expose exactly one object", 1, objects.length())
                    val object0 = objects.getJSONObject(0)
                    assertEquals(fixture.body.size.toLong(), object0.getLong("size"))
                    assertEquals("fixture", object0.getString("filename"))
                    assertEquals("application/octet-stream", object0.getString("contentType"))
                    assertArrayEquals(fixture.body, payload(handle, object0.getInt("id")))

                    // A second scan clears the previous entries first: ids stay
                    // stable and no duplicate object is appended.
                    val rescanned = scan(handle)
                    val again = rescanned.getJSONArray("objects")
                    assertEquals("$id rescan must not duplicate objects", 1, again.length())
                    assertEquals(object0.getInt("id"), again.getJSONObject(0).getInt("id"))
                    assertArrayEquals(fixture.body, payload(handle, again.getJSONObject(0).getInt("id")))
                    Log.i("TLS-309", "$id objects=1 filename=fixture bytes=${fixture.body.size} " +
                        "sha256=${sha256(fixture.body)} visitedReplay=true rescanDuplicates=0")
                } finally {
                    fixture.closeCapture(handle)
                }
            }
        }
    }

    /** Card step 3: HTTP/2 that this Wireshark build cannot export is not a fake empty success. */
    @Test fun http2CaptureReportsUnsupportedInsteadOfEmptySuccess(): Unit = TlsPassiveFixture("tls13-h2").use { fixture ->
        val handle = fixture.open()
        try {
            configure(handle, fixture.file("keylog").path, 1)
            val result = JSONObject(NativeEngine.getHttpObjects(handle))
            assertEquals(1, result.getInt("schemaVersion"))
            assertFalse("HTTP/2 must not be a fake empty success", result.getBoolean("success"))
            assertEquals("UNSUPPORTED", result.getString("errorCode"))
            assertTrue("the capture carries HTTP/2", result.getBoolean("http2Present"))
            assertFalse("this build has no HTTP/2 export tap", result.getBoolean("http2Supported"))
            assertEquals(0, result.getJSONArray("objects").length())
            assertEquals("HTTP2_UNSUPPORTED", result.getString("unavailableReason"))
            Log.i("TLS-309", "tls13-h2 success=false errorCode=UNSUPPORTED " +
                "http2Present=true http2Supported=false objects=0")
        } finally {
            fixture.closeCapture(handle)
        }
    }

    /** Card acceptance 2: the pre-existing unencrypted HTTP object path keeps working. */
    @Test fun plainHttpObjectsRemainExtractable() {
        val capture = stagePlainHttp()
        try {
            val handle = NativeEngine.openFile(capture.path, null)
            assertTrue(handle != 0L)
            try {
                val result = scan(handle)
                assertEquals("complete_capture", result.getString("scope"))
                assertFalse(result.getBoolean("http2Present"))
                val objects = result.getJSONArray("objects")
                assertEquals("all plaintext HTTP objects must remain extractable", 4, objects.length())
                val expected = listOf("/cart", "/stock", "/pay", "/receipt").map {
                    "{\"error\":\"try again later\",\"path\":\"$it\"}".toByteArray()
                }
                val bodies = mutableSetOf<String>()
                for (index in 0 until objects.length()) {
                    val entry = objects.getJSONObject(index)
                    val bytes = payload(handle, entry.getInt("id"))
                    assertEquals(entry.getLong("size"), bytes.size.toLong())
                    assertTrue(expected.any { it.contentEquals(bytes) })
                    assertTrue("no duplicate object body", bodies.add(bytes.toString(Charsets.ISO_8859_1)))
                }
                Log.i("TLS-309", "plain-http objects=4 allBodiesEqual=true duplicates=0")
            } finally {
                NativeEngine.closeFile(handle)
            }
        } finally {
            assertTrue(capture.delete())
        }
    }

    /** Keys own the object cache: clear/replacement must invalidate it before a rescan. */
    @Test fun keyReplacementClearAndCloseInvalidateSavedObjects() {
        for (id in listOf("tls12-h1", "tls13-h1")) {
            TlsPassiveFixture(id).use { fixture ->
                val handle = fixture.open()
                var objectId = -1
                try {
                    configure(handle, fixture.file("keylog").path, 1)
                    objectId = scan(handle).getJSONArray("objects").getJSONObject(0).getInt("id")
                    assertArrayEquals(fixture.body, payload(handle, objectId))
                    for ((index, role) in listOf("wrong-keylog", "keylog", null, "keylog").withIndex()) {
                        configure(handle, role?.let { fixture.file(it).path }, index + 2L)
                        assertEquals("$id old object must be invalidated by $role", 0, payload(handle, objectId).size)
                        val objects = scan(handle).getJSONArray("objects")
                        assertEquals(if (role == "keylog") 1 else 0, objects.length())
                        if (role == "keylog") {
                            objectId = objects.getJSONObject(0).getInt("id")
                            assertArrayEquals(fixture.body, payload(handle, objectId))
                        } else {
                            assertEquals(0, payload(handle, objectId).size)
                        }
                    }
                    // Close with a populated cache, not an already cleared one.
                } finally {
                    fixture.closeCapture(handle)
                }
                assertEquals(0, payload(handle, objectId).size)
                val closed = JSONObject(NativeEngine.getHttpObjects(handle))
                assertFalse(closed.getBoolean("success"))
                assertEquals("NOT_READY", closed.getString("errorCode"))
                val reopened = fixture.open()
                try {
                    assertEquals("reopening cannot inherit keys or objects", 0,
                        scan(reopened).getJSONArray("objects").length())
                } finally {
                    fixture.closeCapture(reopened)
                }
                Log.i("TLS-309", "$id wrongKeyClearReload=true oldPayloadInvalidated=true " +
                    "closedPayloadBytes=0 closedScan=NOT_READY reopenedObjects=0")
            }
        }
    }

    /** A display filter cannot remove handshake context from the complete-capture scan. */
    @Test fun filteredViewStillExtractsCompleteCaptureObjects(): Unit = TlsPassiveFixture("tls13-h1").use { fixture ->
        val handle = fixture.open()
        try {
            configure(handle, fixture.file("keylog").path, 1)
            assertTrue(JSONObject(NativeEngine.applyDisplayFilter(handle, "frame.number == 1")).getBoolean("success"))
            assertEquals(1, NativeEngine.getFilteredFrameCount(handle))
            val result = scan(handle)
            val objects = result.getJSONArray("objects")
            assertEquals(1, objects.length())
            assertTrue(objects.getJSONObject(0).getInt("frameNumber") > 1)
            assertArrayEquals(fixture.body, payload(handle, objects.getJSONObject(0).getInt("id")))
            Log.i("TLS-309", "filteredFrames=1 scope=complete_capture objects=1 bodyEqual=true")
        } finally {
            fixture.closeCapture(handle)
        }
    }

    /** Cancel and close must never leave an index that getHttpObjectPayload can dereference. */
    @Test fun cancelledScanPublishesNothingAndServesNoPayload() {
        TlsPassiveFixture("tls12-h1").use { fixture ->
            val large = File(fixture.directory, "cancel-http.pcap")
            try {
                large.writeBytes(multiplyRecords(fixture.file("pcap").readBytes(), 4_000))
                val handle = NativeEngine.openFile(large.path, null)
                assertTrue(handle != 0L)
                try {
                    assertTrue(JSONObject(NativeEngine.applyDecodeAs(handle, "tcp.port", fixture.port, "tls")).getBoolean("success"))
                    configure(handle, fixture.file("keylog").path, 1)
                    val executor = Executors.newSingleThreadExecutor()
                    try {
                        val pending = executor.submit<String> { NativeEngine.getHttpObjects(handle) }
                        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
                        while (!pending.isDone && System.nanoTime() < deadline) {
                            NativeEngine.cancelLongRunningOperations()
                            Thread.sleep(2)
                        }
                        val cancelled = JSONObject(pending.get(5, TimeUnit.SECONDS))
                        assertFalse(cancelled.getBoolean("success"))
                        assertEquals("CANCELLED", cancelled.getString("errorCode"))
                        assertEquals(0, cancelled.getJSONArray("objects").length())
                        // Nothing was published, so index 0 must not resolve to a freed entry.
                        assertEquals(0, NativeEngine.getHttpObjectPayload(handle, 0).size)
                        Log.i("TLS-309", "cancelledScan=CANCELLED objects=0 payloadBytes=0")
                    } finally {
                        executor.shutdownNow()
                        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
                    }
                } finally {
                    NativeEngine.closeFile(handle)
                }
            } finally {
                assertTrue(large.delete())
            }
        }
    }

    private fun scan(handle: Long): JSONObject = JSONObject(NativeEngine.getHttpObjects(handle)).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertTrue(it.optString("errorCode"), it.getBoolean("success"))
        assertTrue(it.isNull("errorCode"))
        assertTrue(it.optString("error").isBlank())
        assertEquals("complete_capture", it.getString("scope"))
    }

    private fun payload(handle: Long, id: Int): ByteArray = NativeEngine.getHttpObjectPayload(handle, id)

    private fun configure(handle: Long, path: String?, revision: Long) {
        val result = JSONObject(NativeEngine.configureTlsSecrets(handle, path, revision))
        assertTrue(result.optString("errorCode"), result.getBoolean("success"))
    }

    /** Plaintext HTTP/1.1 fixture already shipped for the agent golden suite. */
    private fun stagePlainHttp(): File {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = File(instrumentation.targetContext.noBackupFilesDir, "http-objects/${UUID.randomUUID()}.pcap")
        check(target.parentFile!!.isDirectory || target.parentFile!!.mkdirs())
        instrumentation.context.assets.open("agent_golden/captures/http_5xx_storm.pcap").use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        return target
    }

    private fun multiplyRecords(source: ByteArray, times: Int): ByteArray =
        ByteArrayOutputStream().also { out ->
            out.write(source, 0, 24)
            repeat(times) { out.write(source, 24, source.size - 24) }
        }.toByteArray()

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
}
