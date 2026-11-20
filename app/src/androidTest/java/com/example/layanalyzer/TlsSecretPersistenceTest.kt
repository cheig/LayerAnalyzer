// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import android.system.Os
import androidx.core.content.FileProvider
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.capture.tls.AndroidTlsWrappingKeyProvider
import com.example.layanalyzer.capture.tls.KeyLogParseResult
import com.example.layanalyzer.capture.tls.KeyLogParser
import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsLiveSecretLimits
import com.example.layanalyzer.capture.tls.TlsSecretStore
import java.io.File
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Device half of TLS-210: the real Keystore, the real private filesystem and the
 * real FileProvider on the real-time secret path.
 *
 * What this class cannot prove, and does not claim: the C05 callback hop itself
 * (Go offer_secret -> JNI -> `TlsPlatformCallbacks.offerSecret` -> `TlsLiveSecretSink.offer`).
 * `la_tls_start` has no production factory until TLS-213 assembles the engine, so
 * no device test can reach that hop yet; the records here are handed to the sink
 * exactly as that callback delivers them (capture id, connection id, one NSS
 * line, copied and enqueued before returning). TLS-213 and TLS-218 own the
 * end-to-end gate.
 */
@RunWith(AndroidJUnit4::class)
class TlsSecretPersistenceTest {
    private val id = UUID.randomUUID().toString()
    private val alias = "layeranalyzer.tls.live-test.$id"
    private val captureId = "capture-live-device"
    private val connectionId = "connection-device-1"
    private lateinit var context: Context
    private lateinit var root: File
    private val lineA = "CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}"
    private val lineB = "CLIENT_TRAFFIC_SECRET_0 ${"ef".repeat(32)} ${"12".repeat(32)}"
    private fun store() = TlsSecretStore(root, AndroidTlsWrappingKeyProvider(alias))
    private fun capture() = File(root, "capture-secrets/$captureId")
    private fun bytes(text: String) = text.toByteArray(Charsets.US_ASCII)
    private fun assetDirectories() = capture().listFiles().orEmpty().filter { it.isDirectory }.map { it.name }
    private fun allFiles(directory: File): List<File> =
        directory.listFiles().orEmpty().flatMap { if (it.isDirectory) allFiles(it) else listOf(it) }

    /** A consumer that cannot start until the test releases it, so the queue is observable. */
    private class Gate {
        private val open = CountDownLatch(1)
        var thread: Thread? = null
        val factory: (Runnable) -> Thread = { runnable ->
            Thread({ open.await(); runnable.run() }, "tls-live-secrets-device-test").also { thread = it }
        }
        fun release() = open.countDown()
        fun awaitExit(millis: Long = 10_000) { thread?.join(millis) }
    }

    @Before fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        root = File(context.noBackupFilesDir, "tls-live-test-$id")
        assertTrue(root.mkdir())
    }

    @After fun tearDown() {
        // Only this test's UUID namespace and alias; never a user capture or CA key.
        if (::root.isInitialized) root.deleteRecursively()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
    }

    @Test fun liveCaptureUsesTheRealKeystoreAndReopensFromAFreshStoreInstance() {
        val sink = store().openLiveSecrets(captureId)
        try {
            assertTrue(sink.offer(connectionId, bytes(lineA)))
            assertTrue(sink.offer(connectionId, bytes(lineB)))
        } finally {
            val persistence = sink.finish()
            assertEquals(2L, persistence.accepted)
            assertEquals(2L, persistence.persisted)
            assertTrue(persistence.complete)
            assertFalse(persistence.mitmSuspended)
        }
        val reference = required(store().currentAsset(captureId), "the live capture published no asset")
        assertEquals(2L, reference.watermark.sequence)

        // A store instance that has never seen this sink reopens the asset with the
        // Keystore-wrapped key alone.
        val reopened = store()
        assertEquals(reference, reopened.currentAsset(captureId))
        reopened.acquireLease(captureId, reference.assetId).use { lease ->
            assertEquals("$lineA\n$lineB\n", lease.configureNative({}) { File(it) }.readText())
        }
        val assetDirectory = File(capture(), reference.assetId)
        assertEquals(448, Os.stat(assetDirectory.absolutePath).st_mode and 511) // 0700
        val encrypted = File(assetDirectory, "downstream.keys.enc")
        assertEquals(384, Os.stat(encrypted.absolutePath).st_mode and 511) // 0600
        assertFalse(encrypted.readBytes().toString(Charsets.ISO_8859_1).contains("cd".repeat(48)))
        // The real-time path never writes a plaintext keylog at all, so there is
        // nothing for a share URI to point at.
        assertTrue(allFiles(capture()).none { it.name == "keylog.tmp" })
        for (file in allFiles(capture())) {
            try {
                FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
                fail("a secrets asset must not have a FileProvider URI")
            } catch (_: IllegalArgumentException) { }
        }
    }

    @Test fun aQueueThatCannotHoldAnythingRefusesOnTheDeviceFilesystemToo() {
        // One byte of budget is less than any record, so every offer is refused.
        val sink = store().openLiveSecrets(captureId, TlsLiveSecretLimits(queueBytes = 1))
        assertFalse(sink.offer(connectionId, bytes(lineA)))
        val result = sink.finish()
        assertEquals(0L, result.accepted)
        assertEquals(0L, result.persisted)
        assertEquals(1L, result.rejected)
        assertFalse(result.complete)
        assertTrue(result.mitmSuspended)
        assertNull(result.asset)
        assertNull(store().currentAsset(captureId))
        assertTrue("a capture that published nothing leaves no asset", assetDirectories().isEmpty())
    }

    @Test fun aConsumerThatCannotFinishIsBoundedAndLeavesOnlyAnUnpublishedLeftover() {
        val gate = Gate()
        val sink = store().openLiveSecrets(captureId, TlsLiveSecretLimits(drainTimeoutMillis = 100), gate.factory)
        assertTrue(sink.offer(connectionId, bytes(lineA)))
        val started = System.nanoTime()
        val result = sink.finish()
        assertTrue("finish must not wait without bound", System.nanoTime() - started < 3_000_000_000L)
        assertEquals(TlsAssetErrorCode.IO_ERROR, result.failure)
        assertFalse(result.complete)
        assertNull(result.asset)
        assertNull(store().currentAsset(captureId))
        assertEquals(1, assetDirectories().size)

        // Once the consumer returns, the leftover is an unpublished asset with no
        // index, which is what the startup sweep removes.
        gate.release()
        gate.awaitExit()
        assertNull(store().currentAsset(captureId))
        store().cleanupOrphans()
        assertTrue(assetDirectories().isEmpty())
    }

    @Test fun aLiveCaptureKeepsThePublishedAssetUntilItReplacesIt() {
        val first = store().importRecords(captureId, parsed())
        val gate = Gate()
        val sink = store().openLiveSecrets(captureId, TlsLiveSecretLimits(), gate.factory)
        assertTrue(sink.offer(connectionId, bytes(lineB)))
        assertEquals(first, store().currentAsset(captureId))
        assertEquals(2, assetDirectories().size)
        gate.release()
        assertTrue(sink.finish().complete)
        val replacement = required(store().currentAsset(captureId), "the live capture published no asset")
        assertNotEquals(first.assetId, replacement.assetId)
        assertEquals(listOf(replacement.assetId), assetDirectories())
    }

    /** JUnit's fail() returns Unit in Kotlin, which cannot narrow a nullable. */
    private fun <T> required(value: T?, message: String): T = value ?: throw AssertionError(message)

    private fun parsed() = KeyLogParser.parse(lineA.byteInputStream()) as KeyLogParseResult.Success
}
