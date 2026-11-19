// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.AndroidTlsWrappingKeyProvider
import com.example.layanalyzer.capture.tls.KeyLogParseResult
import com.example.layanalyzer.capture.tls.KeyLogParser
import com.example.layanalyzer.capture.tls.TlsSecretStore
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.model.DecodeAsRule
import com.example.layanalyzer.model.DecodeAsTransport
import com.example.layanalyzer.model.DecodeAsScope
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.UUID

/** Production parser -> Keystore store -> coordinator -> repository -> native path, probe OFF. */
@RunWith(AndroidJUnit4::class)
class TlsRedissectionTest {
    @Before fun ready() { NativeTestSupport.awaitApplicationEngine() }

    @Test fun tls12OriginalFilterRefreshesAndClearRemovesPlaintext() = roundTrip("tls12-h1")
    @Test fun tls13OriginalFilterRefreshesAndClearRemovesPlaintext() = roundTrip("tls13-h1")
    @Test fun tls13Http2FilterRefreshesAndClearRemovesPlaintext() = roundTrip("tls13-h2")
    @Test fun cancelledScanClosesSessionAndCanReopenWithoutSecrets() = roundTrip("tls12-h1", cancelScan = true)

    private fun roundTrip(id: String, cancelScan: Boolean = false) = runBlocking {
        TlsPassiveFixture(id).use { fixture ->
            val uuid = UUID.randomUUID().toString()
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val root = File(context.noBackupFilesDir, "tls-redissection-$uuid").apply { check(mkdir()) }
            val alias = "layeranalyzer.tls.redissection-test.$uuid"
            val store = TlsSecretStore(root, AndroidTlsWrappingKeyProvider(alias))
            val repository = PacketRepository()
            val coordinator = CaptureSessionCoordinator(repository)
            try {
                val file = repository.openFile(fixture.file("pcap").path).getOrThrow()
                coordinator.registerOpenedSession(file).getOrThrow()
                assertTrue(repository.applyDecodeAsRule(
                    DecodeAsRule("tls-fixture", DecodeAsScope.Port, DecodeAsTransport.TCP,
                        "", "", null, fixture.port, "tls")
                ).success)
                val filter = if (fixture.http2) "http2.data.data" else "http.file_data"
                assertTrue(coordinator.applyUserFilter(filter).success)
                assertEquals(0, repository.getVisibleFrameCount())
                val original = repository.currentAnalysisRevision()
                if (cancelScan) {
                    val parsed = fixture.file("keylog").inputStream().use(KeyLogParser::parse) as KeyLogParseResult.Success
                    val asset = store.importRecords(uuid, parsed)
                    try {
                        coordinator.configureTlsSecrets(store.acquireLease(uuid, asset.assetId)) { _, _ ->
                            throw CancellationException("Test scan cancellation")
                        }
                        fail("Cancelled scan must not succeed")
                    } catch (_: CancellationException) { }
                    assertEquals(0L, repository.currentSessionHandle())
                    assertFalse(coordinator.state.value.hasSession)
                    assertEquals(0, File(root, "tls-analysis-leases").listFiles()?.size ?: 0)
                    repository.openFile(fixture.file("pcap").path).getOrThrow()
                    fixture.assertBody(repository.currentSessionHandle(), false)
                    return@use
                }
                for (role in listOf("keylog", "wrong-keylog", "keylog")) {
                    val parsed = fixture.file(role).inputStream().use(KeyLogParser::parse) as KeyLogParseResult.Success
                    val asset = store.importRecords(uuid, parsed)
                    val result = coordinator.configureTlsSecrets(store.acquireLease(uuid, asset.assetId))
                    assertTrue(result.success)
                    assertEquals(filter, repository.getAppliedDisplayFilter())
                    assertEquals(filter, coordinator.state.value.appliedDisplayFilter)
                    assertEquals(result.analysis.dissectionGeneration, coordinator.state.value.dissectionGeneration)
                    assertFalse(repository.isAnalysisCurrent(original))
                    fixture.assertBody(repository.currentSessionHandle(), role == "keylog")
                    if (role == "keylog") assertTrue(repository.getVisibleFrameCount() > 0)
                    else assertEquals(0, repository.getVisibleFrameCount())
                }
                val clear = coordinator.configureTlsSecrets(null)
                assertTrue(clear.success)
                assertFalse(clear.analysis.configured)
                assertEquals(0, repository.getVisibleFrameCount())
                fixture.assertBody(repository.currentSessionHandle(), false)
                assertEquals(0, File(root, "tls-analysis-leases").listFiles()?.size ?: 0)
            } finally {
                repository.closeFile()
                root.deleteRecursively()
                KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
            }
        }
    }
}
