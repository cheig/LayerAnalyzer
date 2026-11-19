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
import com.example.layanalyzer.capture.tls.TlsAssetException
import com.example.layanalyzer.capture.tls.TlsSecretStore
import java.io.File
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CancellationException
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Real Keystore/filesystem/FileProvider; native cleanup callbacks here are explicit test fakes. */
@RunWith(AndroidJUnit4::class)
class TlsSecretLeaseTest {
    private val id = UUID.randomUUID().toString()
    private val alias = "layeranalyzer.tls.lease-test.$id"
    private lateinit var context: Context
    private lateinit var root: File
    private val line = "CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}"
    private fun parsed() = KeyLogParser.parse(line.byteInputStream()) as KeyLogParseResult.Success
    private fun store() = TlsSecretStore(root, AndroidTlsWrappingKeyProvider(alias))
    private val leases get() = File(root, "tls-analysis-leases")

    @Before fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        root = File(context.noBackupFilesDir, "tls-lease-test-$id")
        assertTrue(root.mkdir())
    }

    @After fun tearDown() {
        // Only this test's UUID namespace and alias; never touch user captures or CA keys.
        if (::root.isInitialized) root.deleteRecursively()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
    }

    @Test fun realKeystoreReopenPrivatePermissionsAndFileProviderExclusion() {
        val ref = store().importRecords("capture-a", parsed())
        repeat(2) {
            val lease = store().acquireLease("capture-a", ref.assetId)
            lateinit var plaintext: File
            var nativeCleared = false
            try {
                plaintext = lease.configureNative({
                    assertTrue(plaintext.exists())
                    nativeCleared = true
                }) { File(it) }
                assertEquals("$line\n", plaintext.readText())
                assertEquals(384, Os.stat(plaintext.absolutePath).st_mode and 511) // 0600
                assertEquals(448, Os.stat(plaintext.parentFile!!.absolutePath).st_mode and 511) // 0700
                try {
                    FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", plaintext)
                    fail("A plaintext lease must not have a FileProvider URI")
                } catch (_: IllegalArgumentException) { }
            } finally { lease.close() }
            assertTrue(nativeCleared)
            assertFalse(plaintext.exists())
        }
    }

    @Test fun manualAnalysisLeaseKeepsRetainedKeysAndUsesPrivateTemporaryStorage() {
        val store = store()
        val original = store.importRecords("capture-a", parsed())
        val index = File(root, "capture-secrets/capture-a/current.json")
        val originalIndex = index.readBytes()
        val replacementLine = "CLIENT_RANDOM ${"ef".repeat(32)} ${"12".repeat(48)}"
        val replacement = KeyLogParser.parse(replacementLine.byteInputStream()) as KeyLogParseResult.Success
        store.acquireImportedLease("capture-a", replacement).use { lease ->
            val plaintext = lease.configureNative({}) { File(it) }
            assertEquals("$replacementLine\n", plaintext.readText())
            assertEquals(384, Os.stat(plaintext.absolutePath).st_mode and 511)
            assertArrayEquals(originalIndex, index.readBytes())
            assertEquals(original, store.currentAsset("capture-a"))
        }
        assertTrue(leases.listFiles()!!.isEmpty())
        store.acquireLease("capture-a", original.assetId).use { lease ->
            val plaintext = lease.configureNative({}) { File(it) }
            assertEquals("$line\n", plaintext.readText())
        }
    }

    @Test fun orphanSweepKeepsCurrentlyLockedLeaseAndDeletesDeadOwnerFixture() {
        val store = store()
        store.importRecords("capture-a", parsed())
        store.acquireLease("capture-a").use { lease ->
            val plaintext = lease.configureNative({}) { File(it) }
            val orphan = File(leases, UUID.randomUUID().toString()).also { assertTrue(it.mkdir()) }
            File(orphan, "keylog.tmp").writeText(line)
            assertEquals(1, store().cleanupOrphans())
            assertFalse(orphan.exists())
            assertTrue(plaintext.exists())
            assertEquals(0, store().cleanupOrphans())
        }
        assertTrue(leases.listFiles()!!.isEmpty())
    }

    @Test fun cancelledOutputLeavesNoPlaintextAndCanAcquireAgain() {
        val store = store()
        store.importRecords("capture-a", parsed())
        var checks = 0
        try {
            store.acquireLease("capture-a") { if (++checks == 4) throw CancellationException() }
            fail("Expected cancellation after writing output")
        } catch (_: CancellationException) { }
        assertTrue(leases.listFiles()!!.isEmpty())
        store.acquireLease("capture-a").close()
    }

    @Test fun symlinkCaptureCannotReadOrDeleteAnotherCapture() {
        val store = store()
        store.importRecords("capture-a", parsed())
        val source = File(root, "capture-secrets/capture-a")
        val link = File(root, "capture-secrets/capture-b")
        Os.symlink(source.absolutePath, link.absolutePath)
        try {
            try {
                store.acquireLease("capture-b")
                fail("Expected symlink rejection")
            } catch (error: TlsAssetException) {
                assertEquals(TlsAssetErrorCode.INVALID_ARGUMENT, error.code)
            }
            assertTrue(File(source, "current.json").exists())
        } finally { java.nio.file.Files.delete(link.toPath()) }
        store.acquireLease("capture-a").close()
    }
}
