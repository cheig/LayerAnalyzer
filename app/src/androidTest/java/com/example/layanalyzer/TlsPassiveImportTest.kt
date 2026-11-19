// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.*
import com.example.layanalyzer.viewmodel.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID

/** Production UI controller -> parser -> Android Keystore -> transaction -> fixed native engine.
 * SAF system picker automation is a separate manual check; no probe or test-native substitute. */
@RunWith(AndroidJUnit4::class)
class TlsPassiveImportTest {
    @Before fun ready() { NativeTestSupport.awaitApplicationEngine() }

    @Test fun tls12ImportsWrongKeysClearsAndReimports() = roundTrip("tls12-h1")
    @Test fun tls13ImportsWrongKeysClearsAndReimports() = roundTrip("tls13-h1")
    @Test fun tls13Http2ImportsWrongKeysClearsAndReimports() = roundTrip("tls13-h2")
    @Test fun cancelledRedissectionClosesAnalysisAndReleasesSecrets() = roundTrip("tls12-h1", true)

    @Test fun ordinaryCaptureOpensAndClearsWithoutChangingOriginalBytes() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val file = File(context.noBackupFilesDir, "tls-ordinary-${UUID.randomUUID()}.pcap")
        context.assets.open("test.pcap").use { input -> file.outputStream().use { input.copyTo(it) } }
        val repository = PacketRepository()
        val coordinator = CaptureSessionCoordinator(repository)
        try {
            val before = sha256(file)
            val info = repository.openFile(file.path).getOrThrow()
            coordinator.registerOpenedSession(info).getOrThrow()
            assertTrue(info.frameCount > 0)
            val clear = coordinator.configureTlsSecrets(null)
            assertTrue(clear.success)
            assertFalse(clear.analysis.configured)
            assertNotNull(repository.getPacketDetails(1))
            assertArrayEquals(before, sha256(file))
        } finally { repository.closeFile(); assertTrue(file.delete()) }
    }

    private fun roundTrip(id: String, cancelScan: Boolean = false) = runBlocking {
        TlsPassiveFixture(id).use { fixture ->
            val uuid = UUID.randomUUID().toString()
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val root = File(context.noBackupFilesDir, "tls-passive-import-$uuid").apply { check(mkdir()) }
            val alias = "layeranalyzer.tls.passive-import-test.$uuid"
            val store = TlsSecretStore(root, AndroidTlsWrappingKeyProvider(alias))
            val repository = PacketRepository()
            val coordinator = CaptureSessionCoordinator(repository)
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
            val originalHash = sha256(fixture.file("pcap"))
            var captureId = uuid
            lateinit var controller: TlsKeyLogImportController
            controller = TlsKeyLogImportController(scope, object : TlsKeyLogImportBackend {
                override fun currentAnalysis() = repository.currentAnalysisRevision()
                override fun currentTarget() = coordinator.currentToken()?.let {
                    TlsKeyLogImportTarget(captureId, it, currentAnalysis())
                }
                override fun acquire(target: TlsKeyLogImportTarget, parsed: KeyLogParseResult.Success,
                                     checkCancelled: () -> Unit): TlsAnalysisSecretLease {
                    val asset = store.importRecords(target.captureId, parsed, checkCancelled)
                    return store.acquireLease(target.captureId, asset.assetId, checkCancelled)
                }
                override suspend fun configure(target: TlsKeyLogImportTarget, lease: TlsAnalysisSecretLease?,
                                               progress: (Int, Int) -> Unit) =
                    coordinator.configureTlsSecrets(lease, target.session, target.analysis) { done, total ->
                        progress(done, total)
                        if (cancelScan) {
                            // Controller actions belong to the main thread; native progress
                            // is delivered on the coordinator's IO dispatcher.
                            InstrumentationRegistry.getInstrumentation().runOnMainSync { controller.cancel() }
                        }
                    }
            })
            suspend fun done(): TlsKeyLogImportState = withTimeout(60_000) { controller.state.first { !it.busy } }
            suspend fun import(role: String): TlsKeyLogImportState {
                withContext(Dispatchers.Main) {
                    assertTrue(controller.beginSelection())
                    controller.selected { fixture.file(role).inputStream() }
                }
                return done()
            }
            suspend fun open(active: TlsPassiveFixture, file: File = active.file("pcap")) {
                withContext(Dispatchers.Main) { controller.invalidate() }
                captureId = UUID.randomUUID().toString()
                val info = repository.openFile(file.path).getOrThrow()
                coordinator.registerOpenedSession(info).getOrThrow()
                assertTrue(repository.applyDecodeAsRule(DecodeAsRule("tls-fixture", DecodeAsScope.Port,
                    DecodeAsTransport.TCP, "", "", null, active.port, "tls")).success)
                assertTrue(coordinator.applyUserFilter(bodyFilter(active)).success)
            }
            fun phase(name: String, decrypted: Boolean, previous: CaptureAnalysisRevision? = null,
                      active: TlsPassiveFixture = fixture): CaptureAnalysisRevision {
                val revision = repository.currentAnalysisRevision()
                if (previous != null) {
                    assertTrue(revision.revision > previous.revision)
                    assertTrue(revision.dissectionGeneration > previous.dissectionGeneration)
                    assertEquals(previous.secretsGeneration + 1, revision.secretsGeneration)
                    assertFalse(repository.isAnalysisCurrent(previous))
                    try {
                        repository.followTlsStream(1, previous)
                        fail("Old analysis must not return a TLS stream")
                    } catch (_: StaleCaptureAnalysisException) { }
                }
                assertAnalysis(active, repository, decrypted)
                assertEquals(bodyFilter(active), coordinator.state.value.appliedDisplayFilter)
                // Test-only metadata. No paths, keys, bytes or native handles enter the report.
                Log.i("TLS-P1-Acceptance", "fixture=$id phase=$name revision=${revision.revision} " +
                    "dissection=${revision.dissectionGeneration} secrets=${revision.secretsGeneration} " +
                    "configured=${revision.configured} bodyVerified=$decrypted")
                return revision
            }
            try {
                open(fixture)
                val before = phase("no-key", false)
                withContext(Dispatchers.Main) {
                    assertTrue(controller.beginSelection()); controller.selected(null)
                }
                assertEquals(before, repository.currentAnalysisRevision())
                withContext(Dispatchers.Main) {
                    assertTrue(controller.beginSelection())
                    controller.selected { "invalid key log".byteInputStream() }
                }
                assertNotNull(done().parseError)
                assertEquals(before, repository.currentAnalysisRevision())
                val imported = import("keylog")
                if (cancelScan) {
                    assertTrue(imported.cancelled)
                    assertTrue(imported.reopenRequired)
                    assertEquals(0L, repository.currentSessionHandle())
                    assertEquals(0, File(root, "tls-analysis-leases").listFiles().orEmpty().size)
                    return@use
                }
                assertNull(imported.errorCode)
                assertTrue(imported.configured)
                assertTrue(imported.observedDecryptedData)
                val correctRevision = phase("correct-key", true, before)
                // Hold a real snapshot across the replacement, not just a Kotlin revision.
                val oldDetail = repository.getPacketDetailSnapshot(1, correctRevision)
                val wrong = import("wrong-keylog")
                assertNull(wrong.errorCode)
                assertTrue(wrong.configured)
                assertFalse(wrong.observedDecryptedData)
                val wrongRevision = phase("wrong-key", false, correctRevision)
                val oldSnapshot = requireNotNull(oldDetail.snapshot)
                try {
                    repository.getPacketDataSources(oldSnapshot, wrongRevision)
                    fail("Old snapshot must not survive a key replacement")
                } catch (error: PacketDataSourceException) {
                    assertEquals("STALE_GENERATION", error.errorCode)
                }
                withContext(Dispatchers.Main) { controller.clear() }
                assertFalse(done().configured)
                val cleared = phase("clear", false, wrongRevision)
                assertEquals(0, File(root, "tls-analysis-leases").listFiles().orEmpty().size)
                assertNotNull(store.currentAsset(captureId))
                assertTrue(import("keylog").observedDecryptedData)
                val reimported = phase("reimport", true, cleared)
                val exports = File(root, "exports").apply { check(mkdir()) }
                val fullExport = File(exports, "capture.pcap")
                val filteredExport = File(exports, "filtered.pcap")
                repository.exportFilteredCapture(filteredExport)
                assertTrue(coordinator.applyUserFilter("").success)
                repository.exportFilteredCapture(fullExport)
                // Classic PCAP equality proves there is no appended DSB, plaintext or keylog.
                assertArrayEquals(fixture.file("pcap").readBytes(), fullExport.readBytes())
                assertCiphertextSubset(fixture.file("pcap"), filteredExport)
                assertEquals(setOf("capture.pcap", "filtered.pcap"), exports.list().orEmpty().toSet())
                TlsPassiveFixture(if (id == "tls12-h1") "tls13-h1" else "tls12-h1").use { other ->
                    val otherHash = sha256(other.file("pcap"))
                    open(other)
                    assertFalse(repository.isAnalysisCurrent(reimported))
                    assertEquals(0L, repository.currentAnalysisRevision().secretsGeneration)
                    phase("switch-file", false, active = other)
                    assertEquals(0, File(root, "tls-analysis-leases").listFiles().orEmpty().size)
                    assertArrayEquals(otherHash, sha256(other.file("pcap")))
                    // Close before the fixture deletes its files.
                    repository.closeFile()
                }
                open(fixture)
                phase("return-original", false)
                assertFalse(controller.state.value.observedDecryptedData)
                assertTrue(import("keylog").observedDecryptedData)
                phase("return-reimport", true)
                open(fixture, fullExport)
                phase("open-default-export", false)
                open(fixture, filteredExport)
                phase("open-filtered-export", false)
                assertEquals(0, File(root, "tls-analysis-leases").listFiles().orEmpty().size)
                assertArrayEquals(originalHash, sha256(fixture.file("pcap")))
            } finally {
                withContext(Dispatchers.Main) { controller.invalidate() }
                scope.coroutineContext[Job]?.cancelAndJoin()
                repository.closeFile()
                assertEquals(0, File(root, "tls-analysis-leases").listFiles().orEmpty().size)
                root.deleteRecursively()
                KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
            }
        }
    }

    private fun bodyFilter(fixture: TlsPassiveFixture) =
        if (fixture.http2) "http2.data.data" else "http.file_data"

    /** All observations use the same production analysis revision and actual JNI bytes. */
    private fun assertAnalysis(fixture: TlsPassiveFixture, repository: PacketRepository, decrypted: Boolean) {
        val revision = repository.currentAnalysisRevision()
        assertTrue(revision.ready)
        fixture.assertBody(repository.currentSessionHandle(), decrypted)
        assertEquals(bodyFilter(fixture), repository.getAppliedDisplayFilter())
        assertEquals(decrypted, repository.getVisibleFrameCount() > 0)
        val body = ByteArrayOutputStream()
        var decryptedSources = 0
        for (frame in 1..repository.getFrameCount()) {
            val detail = repository.getPacketDetailSnapshot(frame.toLong(), revision)
            val snapshot = requireNotNull(detail.snapshot)
            assertEquals(revision.dissectionGeneration, snapshot.dissectionGeneration)
            val sources = detail.sources.associateBy { it.id }
            assertTrue(detail.sources.sumOf { it.availableLength.toLong() } <= PACKET_DATA_SNAPSHOT_LIMIT)
            decryptedSources += detail.sources.count {
                it.kind == PacketDataSourceKind.DecryptedTls && it.availableLength > 0
            }
            val raw = sources.getValue("raw")
            assertEquals(PacketDataSourceKind.RawFrame, raw.kind)
            assertFalse(raw.truncated)
            assertArrayEquals(NativeEngine.getPacketBytes(repository.currentSessionHandle(), frame - 1),
                repository.readPacketDataSource(snapshot, raw, 0, raw.availableLength, revision).bytes)
            fun visit(node: ProtocolNode) {
                if (node.generated || node.dataSourceId == null) assertFalse(node.offsetValid)
                if (node.filter == bodyFilter(fixture)) {
                    assertTrue(node.offsetValid)
                    assertNotEquals("raw", node.dataSourceId)
                    val source = sources.getValue(requireNotNull(node.dataSourceId))
                    val bytes = repository.readPacketDataSource(snapshot, source, node.start, node.length, revision).bytes
                    // Wireshark renders FT_BYTES (http2.data.data) as colon-hex and FT_STRING
                    // (http.file_data, per `tshark -G fields`) as a quoted string; the range is the
                    // byte-exact source of truth for both.
                    val rendered = requireNotNull(node.filterValue)
                    if (fixture.http2) {
                        assertEquals(bytes.joinToString(":") { "%02x".format(it) }, rendered)
                    } else {
                        assertTrue("FT_STRING body field must render its bytes",
                            rendered.length > 2 && rendered.first() == '"' && rendered.last() == '"')
                    }
                    body.write(bytes)
                }
                node.children.forEach(::visit)
            }
            visit(detail.root)
        }
        assertEquals(decrypted, decryptedSources > 0)
        assertArrayEquals(if (decrypted) fixture.body else byteArrayOf(), body.toByteArray())
        val followed = repository.followTlsStream(1, revision)
        assertEquals("tls", followed.protocol)
        assertEquals(TlsFollowScope.CompleteConnection, followed.scope)
        assertEquals(revision.dissectionGeneration, followed.dissectionGeneration)
        if (decrypted) {
            assertTrue(followed.success)
            assertFalse(followed.incomplete)
            assertFalse(followed.truncated)
            assertTrue(followed.directionKnown)
            fun bytes(direction: TlsFollowDirection) = ByteArrayOutputStream().also { out ->
                followed.records.filter { it.direction == direction }.forEach { out.write(it.bytes) }
            }.toByteArray()
            fixture.assertApplicationBytes(bytes(TlsFollowDirection.Client), bytes(TlsFollowDirection.Server))
        } else {
            assertFalse(followed.success)
            assertTrue(followed.incomplete)
            assertTrue(followed.records.isEmpty())
            assertNotNull(followed.unavailableReason)
        }
        assertTrue(repository.isAnalysisCurrent(revision))
    }

    /** The default filtered export can add reassembly dependencies, but only raw source records. */
    private fun assertCiphertextSubset(source: File, exported: File) {
        fun records(bytes: ByteArray): List<ByteArray> {
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            assertEquals(0xa1b2c3d4.toInt(), buffer.int)
            val records = mutableListOf<ByteArray>()
            var offset = 24
            while (offset < bytes.size) {
                assertTrue(offset + 16 <= bytes.size)
                val size = buffer.getInt(offset + 8)
                assertTrue(size >= 0 && size <= bytes.size - offset - 16)
                records += bytes.copyOfRange(offset, offset + 16 + size)
                offset += 16 + size
            }
            assertEquals(bytes.size, offset)
            return records
        }
        val original = source.readBytes()
        val actual = exported.readBytes()
        assertArrayEquals(original.copyOf(24), actual.copyOf(24))
        val sourceRecords = records(original)
        val exportedRecords = records(actual)
        assertTrue(exportedRecords.isNotEmpty())
        var cursor = 0
        exportedRecords.forEach { record ->
            while (cursor < sourceRecords.size && !sourceRecords[cursor].contentEquals(record)) cursor++
            assertTrue("Export contains only original records, once and in order", cursor < sourceRecords.size)
            cursor++
        }
    }

    private fun sha256(file: File): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val bytes = ByteArray(8192)
            while (true) { val n = input.read(bytes); if (n < 0) break; digest.update(bytes, 0, n) }
        }
        return digest.digest()
    }
}
