// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.os.Process
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.TlsAnalysisSecretLease
import java.io.File
import java.security.KeyStore
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Select phases separately. Instrumentation exit releases OS locks; no app force-stop or reboot. */
class TlsLeaseProcessRecoveryTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val run = requireNotNull(InstrumentationRegistry.getArguments().getString("r07ProcessRun")).also {
        require(it.matches(Regex("[a-zA-Z0-9-]{1,80}")))
    }
    private val root = File(context.noBackupFilesDir, "r07-process-$run")
    private val alias = "layeranalyzer.r07.process.$run"
    private val marker = File(root, "phase.json")
    private fun store() = TlsSecretStore(root, AndroidTlsWrappingKeyProvider(alias))

    @Test fun createDisposableLeaseForProcessExit() {
        assertFalse("A run must use a fresh UUID", root.exists())
        assertTrue(root.mkdir())
        val line = "CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}"
        val store = store()
        val asset = store.importRecords("synthetic", KeyLogParser.parse(line.byteInputStream()) as KeyLogParseResult.Success)
        heldLease = store.acquireLease("synthetic", asset.assetId)
        var path = ""
        heldLease!!.configureNative({}) { path = it }
        assertTrue(File(path).isFile)
        store.cleanupOrphans()
        assertTrue("An active OS lock must protect its lease", File(path).isFile)
        marker.writeText(JSONObject().put("pid", Process.myPid()).put("lease", path).toString())
        // Deliberately retain this synthetic lease until this instrumentation process exits.
    }

    @Test fun freshProcessSweepsDeadLeaseAndPreservesEncryptedAsset() {
        try {
            val phase = JSONObject(marker.readText())
            assertNotEquals("Phases must run in different Android processes", phase.getInt("pid"), Process.myPid())
            val lease = File(phase.getString("lease"))
            assertTrue(lease.canonicalFile.toPath().startsWith(root.canonicalFile.toPath()))
            assertTrue(lease.exists())
            val store = store()
            assertNotNull(store.currentAsset("synthetic"))
            store.cleanupOrphans()
            assertFalse("A dead owner's plaintext lease must be swept", lease.exists())
            assertNotNull("Recovery must preserve the authenticated encrypted asset", store.currentAsset("synthetic"))
            store.acquireLease("synthetic").use { next ->
                next.configureNative({}) { assertTrue(File(it).isFile) }
            }
        } finally {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
            check(root.canonicalFile.parentFile == context.noBackupFilesDir.canonicalFile)
            assertTrue(root.deleteRecursively())
        }
    }

    private companion object { var heldLease: TlsAnalysisSecretLease? = null }
}
