// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.model.TLS_FOLLOW_EXPORT_LIMIT
import com.example.layanalyzer.model.TLS_FOLLOW_PREVIEW_LIMIT
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * TLS-308 device acceptance for the bounded full-stream export. Runs the real production JNI
 * (`exportTlsFollowStream` + `followTlsStream`) against the synthetic fixtures; the Compose pixels
 * are the separate `U` walkthrough. Probe is OFF; no simulated decryption.
 */
@RunWith(AndroidJUnit4::class)
class TlsFollowExportTest {
    @Before fun engineReady() { NativeTestSupport.awaitApplicationEngine() }

    @Test fun fullExportDigestMatchesTheFixtureAndItsEnvelope() = fullExport("tls12-h1")
    @Test fun tls13FullExportMatchesFixture() = fullExport("tls13-h1")
    @Test fun http2FullExportRemainsAnApplicationByteStream() = fullExport("tls13-h2")

    private fun fullExport(id: String) = TlsPassiveFixture(id).use { fixture ->
        val handle = fixture.open()
        try {
            val generation = configure(handle, fixture.file("keylog").path, 1)
            val selected = NativeEngine.getFrameCount(handle) - 1
            // The bounded preview is the reference for the same connection's application bytes.
            val preview = follow(handle, selected, generation)
            fixture.assertApplicationBytes(recordsBytes(preview, "client"), recordsBytes(preview, "server"))

            val exportFile = File(fixture.directory, "tls-stream.bin")
            try {
                val envelope = success(
                    NativeEngine.exportTlsFollowStream(handle, selected, generation, exportFile.path, EXPORT_LIMIT)
                )
                val fileBytes = exportFile.readBytes()
                assertFalse(envelope.getBoolean("truncated"))
                assertEquals("Export must not invent gaps for contiguous application records",
                    preview.getBoolean("incomplete"), envelope.getBoolean("incomplete"))
                assertEquals("Export length is the preview's plaintext length",
                    preview.getInt("byteLength").toLong(), envelope.getLong("byteLength"))
                assertEquals("Digest is of exactly the written bytes",
                    sha256(fileBytes), envelope.getString("sha256"))
                assertEquals(envelope.getLong("byteLength"), fileBytes.size.toLong())
                assertArrayEquals("Every exported byte follows the validated record order",
                    recordsBytes(preview), fileBytes)
                assertEquals(sha256(recordsBytes(preview)), envelope.getString("sha256"))
                assertTrue("The exported stream contains the golden body", contains(fileBytes, fixture.body))
                writeEvidence("$id-full", fileBytes)
            } finally {
                assertTrue(exportFile.delete() || !exportFile.exists())
            }
        } finally { fixture.closeCapture(handle) }
    }

    @Test fun aTruncatedPreviewIsBoundedAndNeverClaimsCompleteness() = TlsPassiveFixture("tls13-h1").use { fixture ->
        val handle = fixture.open()
        try {
            val generation = configure(handle, fixture.file("keylog").path, 1)
            val full = follow(handle, 0, generation)
            val budget = (full.getInt("byteLength") - 1).coerceAtLeast(1)
            val limited = follow(handle, 0, generation, budget)
            assertTrue(limited.getBoolean("truncated"))
            assertTrue(limited.getBoolean("incomplete"))
            assertEquals(budget, limited.getInt("byteLength"))
            assertTrue(limited.getInt("byteLength") < full.getInt("byteLength"))
            val expected = recordsBytes(full).copyOf(budget)
            assertArrayEquals(expected, recordsBytes(limited))
            assertEquals(sha256(expected), sha256(recordsBytes(limited)))
            writeEvidence("tls13-h1-preview-prefix", recordsBytes(limited))
            val exported = File(fixture.directory, "bounded-export.bin")
            try {
                val result = success(NativeEngine.exportTlsFollowStream(handle, 0, generation,
                    exported.path, budget))
                assertTrue(result.getBoolean("truncated"))
                assertTrue(result.getBoolean("incomplete"))
                assertArrayEquals(expected, exported.readBytes())
                assertEquals(sha256(expected), result.getString("sha256"))
            } finally { assertTrue(exported.delete() || !exported.exists()) }
        } finally { fixture.closeCapture(handle) }
    }

    @Test fun finalFlushFailureReturnsNoSuccessfulLengthOrDigest() = TlsPassiveFixture("tls12-h1").use { fixture ->
        val handle = fixture.open()
        try {
            val generation = configure(handle, fixture.file("keylog").path, 1)
            // /dev/full accepts open but rejects writes with ENOSPC. A small
            // fwrite can succeed into stdio's buffer; flush/close must still fail.
            exportError("IO_ERROR", NativeEngine.exportTlsFollowStream(handle, 0,
                generation, "/dev/full", EXPORT_LIMIT))
            Unit
        } finally { fixture.closeCapture(handle) }
    }

    @Test fun retransmittedPacketsNeverDuplicateExportedPlaintext() = TlsPassiveFixture("tls13-h1").use { fixture ->
        val repeated = File(fixture.directory, "retransmitted.pcap")
        val exportFile = File(fixture.directory, "retransmitted.bin")
        var handle = 0L
        try {
            rewrite(fixture.file("pcap"), repeated) { _, packet -> listOf(packet, packet) }
            handle = openDerived(fixture, repeated)
            val generation = configure(handle, fixture.file("keylog").path, 1)
            val preview = follow(handle, 0, generation)
            fixture.assertApplicationBytes(recordsBytes(preview, "client"), recordsBytes(preview, "server"))
            val exported = success(NativeEngine.exportTlsFollowStream(handle, 0,
                generation, exportFile.path, EXPORT_LIMIT))
            assertArrayEquals(recordsBytes(preview), exportFile.readBytes())
            assertEquals(preview.getBoolean("incomplete"), exported.getBoolean("incomplete"))
            assertEquals(sha256(exportFile.readBytes()), exported.getString("sha256"))
        } finally {
            if (handle != 0L) fixture.closeCapture(handle)
            exportFile.delete()
            repeated.delete()
        }
    }

    @Test fun changedGenerationCannotExportOldPlaintext() = TlsPassiveFixture("tls12-h1").use { fixture ->
        val handle = fixture.open()
        val exportFile = File(fixture.directory, "stale.bin")
        try {
            val old = configure(handle, fixture.file("keylog").path, 1)
            assertTrue(follow(handle, 0, old).getInt("byteLength") > 0)
            val current = configure(handle, null, 2)
            assertTrue(current > old)
            exportError("STALE_GENERATION",
                NativeEngine.exportTlsFollowStream(handle, 0, old, exportFile.path, EXPORT_LIMIT))
            assertFalse(exportFile.exists())
        } finally { fixture.closeCapture(handle) }
    }

    @Test fun cancelledExportNeverLeavesACompletedFileOrASuccessEnvelope() = TlsPassiveFixture("tls12-h1").use { fixture ->
        val large = File(fixture.directory, "export-cancel.pcap")
        val exportFile = File(fixture.directory, "cancelled-export.bin")
        var handle = 0L
        val executor = Executors.newSingleThreadExecutor()
        try {
            rewrite(fixture.file("pcap"), large) { index, packet ->
                if (index == 0) List(20_000) { packet } else listOf(packet)
            }
            handle = openDerived(fixture, large)
            val generation = configure(handle, fixture.file("keylog").path, 1)
            val pending = executor.submit<String> {
                NativeEngine.exportTlsFollowStream(handle, 0, generation, exportFile.path, EXPORT_LIMIT)
            }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
            while (!pending.isDone && System.nanoTime() < deadline) {
                NativeEngine.cancelLongRunningOperations()
                Thread.sleep(2)
            }
            exportError("CANCELLED", pending.get(5, TimeUnit.SECONDS))
            // A cancelled export must not leave a partial file behind.
            assertFalse("A cancelled export never keeps the partial file", exportFile.exists())
        } finally {
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            if (handle != 0L) fixture.closeCapture(handle)
            exportFile.delete()
            assertTrue(large.delete() || !large.exists())
        }
    }

    @Test fun anUnavailableConnectionExportsNothingAndKeepsNoFile() = TlsPassiveFixture("tls13-h1").use { fixture ->
        val handle = fixture.open()
        val exportFile = File(fixture.directory, "no-secrets.bin")
        try {
            val generation = configure(handle, null, 1)
            exportError("NOT_READY",
                NativeEngine.exportTlsFollowStream(handle, 0, generation, exportFile.path, EXPORT_LIMIT))
            assertEquals("SECRETS_NOT_CONFIGURED",
                JSONObject(NativeEngine.followTlsStream(handle, 0, generation, PREVIEW_LIMIT))
                    .getString("unavailableReason"))
            assertFalse("No file is kept when there is no plaintext", exportFile.exists())
        } finally { fixture.closeCapture(handle) }
    }

    private fun recordsBytes(result: JSONObject, direction: String? = null): ByteArray =
        ByteArrayOutputStream().also { out ->
            val records = result.getJSONArray("records")
            for (index in 0 until records.length()) {
                val record = records.getJSONObject(index)
                if (direction == null || direction == record.getString("direction")) {
                    out.write(Base64.decode(record.getString("bytesBase64"), Base64.NO_WRAP))
                }
            }
        }.toByteArray()

    private fun follow(handle: Long, index: Int, generation: Long, budget: Int = PREVIEW_LIMIT): JSONObject =
        success(NativeEngine.followTlsStream(handle, index, generation, budget))

    private fun configure(handle: Long, path: String?, revision: Long) =
        success(NativeEngine.configureTlsSecrets(handle, path, revision)).getLong("dissectionGeneration")

    private fun success(raw: String) = JSONObject(raw).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertTrue("Production JNI must succeed: ${it.optString("errorCode")}", it.getBoolean("success"))
        assertTrue(it.isNull("errorCode") && it.isNull("error"))
    }

    private fun exportError(code: String, raw: String) = JSONObject(raw).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertFalse(it.getBoolean("success"))
        assertEquals(code, it.getString("errorCode"))
        assertTrue(it.isNull("sha256"))
        assertEquals(0L, it.getLong("byteLength"))
    }

    private fun sha256(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun writeEvidence(name: String, bytes: ByteArray) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.getExternalFilesDir(null), "tls-308/digests").apply { mkdirs() }
        File(directory, "$name.txt").writeText("bytes=${bytes.size}\nsha256=${sha256(bytes)}\n")
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean =
        needle.isNotEmpty() && (0..haystack.size - needle.size).any { offset ->
            needle.indices.all { haystack[offset + it] == needle[it] }
        }

    private fun openDerived(fixture: TlsPassiveFixture, file: File): Long =
        NativeEngine.openFile(file.path, null).also {
            assertTrue(it != 0L)
            assertTrue(JSONObject(NativeEngine.applyDecodeAs(it, "tcp.port", fixture.port, "tls")).getBoolean("success"))
        }

    /** Derive only from manifest-verified public synthetic captures, in noBackupFilesDir. */
    private fun rewrite(input: File, output: File, transform: (Int, ByteArray) -> List<ByteArray>) {
        val source = input.readBytes()
        val buffer = ByteBuffer.wrap(source).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(0xa1b2c3d4.toInt(), buffer.int)
        assertEquals(0, buffer.getInt(20))
        output.outputStream().buffered().use { out ->
            out.write(source, 0, 24)
            var offset = 24
            var index = 0
            while (offset < source.size) {
                val size = buffer.getInt(offset + 8)
                val header = source.copyOfRange(offset, offset + 16)
                val packet = source.copyOfRange(offset + 16, offset + 16 + size)
                for (changed in transform(index++, packet)) {
                    ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).apply {
                        putInt(8, changed.size); putInt(12, changed.size)
                    }
                    out.write(header); out.write(changed)
                }
                offset += 16 + size
            }
        }
    }

    private companion object {
        const val PREVIEW_LIMIT = TLS_FOLLOW_PREVIEW_LIMIT
        const val EXPORT_LIMIT = TLS_FOLLOW_EXPORT_LIMIT
    }
}
