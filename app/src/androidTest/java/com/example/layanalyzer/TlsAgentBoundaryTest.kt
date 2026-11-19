// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.cache.AgentTlsEvidenceInvalidator
import com.example.layanalyzer.ai.cache.AgentToolCache
import com.example.layanalyzer.ai.privacy.AgentDecryptedContentPolicy
import com.example.layanalyzer.ai.privacy.AgentTlsEvidence
import com.example.layanalyzer.ai.tools.*
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID

/** TLS-313: real Android Keystore -> native dissection -> production Agent tool boundary.
 * Everything is synthetic and offline; no cloud model, probe, user capture or user CA is used.
 * Assertions never print secrets or unfiltered tool payloads into instrumentation output.
 */
@RunWith(AndroidJUnit4::class)
class TlsAgentBoundaryTest {
    @Before fun ready() { NativeTestSupport.awaitApplicationEngine() }

    @Test fun tls12NativePlaintextIsExcludedFromEveryCloudToolExit() = privacy("tls12")
    @Test fun tls13NativePlaintextIsExcludedFromEveryCloudToolExit() = privacy("tls13")

    private fun privacy(version: String) = runBlocking {
        Harness().use { h ->
            h.open(version)
            val snapshot = h.snapshot()
            val fields = listOf("http.cookie", "http.authorization", "http.file_data", "http.request.uri")
            val found = linkedMapOf<String, MutableList<ProtocolNode>>()
            val frames = (1L..snapshot.frameCount.toLong()).filter { frame ->
                val detail = h.agent.getPacketDetail(snapshot, frame).getOrNull()!!
                nodes(detail.root!!).filter { it.filter in fields }.onEach { node ->
                    found.getOrPut(node.filter!!) { mutableListOf() }.add(node)
                    assertTrue("Native HTTP field must carry its actual decrypted source",
                        node.dataSourceId in detail.decryptedSourceIds)
                }.isNotEmpty()
            }
            fields.forEach { assertTrue("Fixture must expose $it before filtering", found[it].orEmpty().isNotEmpty()) }
            val rawValues = found.values.flatten().joinToString { "${it.value} ${it.filterValue}" }
            MARKERS.forEach { assertTrue("Native positive control missing", rawValues.contains(it)) }
            assertFalse("PCAP must contain ciphertext", h.capture.readBytes().toString(Charsets.ISO_8859_1).contains(MARKERS[0]))
            val arguments = mapOf("frames" to frames, "fields" to fields)
            val local = h.run("get_packet_fields", arguments, snapshot, AgentPrivacyMode.LocalOnly)
            assertTrue("Local positive control must retain the URI", encode(local).contains("TLS313_PRIVATE_URI"))
            for (mode in listOf(AgentPrivacyMode.RedactedMetadata, AgentPrivacyMode.UnredactedMetadata,
                AgentPrivacyMode.SelectedPayload)) {
                val result = h.run("get_packet_fields", arguments, snapshot, mode)
                assertClean(result, h.secretValues)
                assertTrue(encode(result).contains(AgentDecryptedContentPolicy.DECRYPTED_TLS_SOURCE))
                assertTrue(encode(result).contains(AgentDecryptedContentPolicy.BLOCKED))
            }
            assertClean(h.run("get_packet_fields", arguments, snapshot,
                AgentPrivacyMode.SelectedPayload, AgentPolicy(allowPayload = true)), h.secretValues)
            val exits = listOf(
                "query_packet_summaries" to emptyMap<String, Any?>(),
                "query_packet_field_aggregate" to mapOf("fields" to fields, "filter" to "tcp"),
                "get_capture_overview" to emptyMap(),
                "get_statistics" to emptyMap(),
                "follow_stream_metadata" to mapOf("frameNumber" to frames.first(), "protocol" to "tcp")
            )
            exits.forEach { (tool, args) -> assertClean(h.run(tool, args, snapshot), h.secretValues) }
            assertTrue(encode(h.run("query_packet_summaries", emptyMap(), snapshot,
                AgentPrivacyMode.LocalOnly)).contains("TLS313_PRIVATE_URI"))
            for (mode in listOf(AgentPrivacyMode.UnredactedMetadata, AgentPrivacyMode.SelectedPayload)) {
                assertClean(h.run("query_packet_summaries", emptyMap(), snapshot, mode), h.secretValues)
            }
            assertFalse(AgentToolRegistry.phase3().contains("get_http_object"))
        }
    }

    @Test fun http2DecryptedBodyKeepsItsSourceThroughProductionProjection() = runBlocking {
        TlsPassiveFixture("tls13-h2").use { fixture ->
            Harness().use { h ->
                h.openFiles(fixture.file("pcap"), fixture.file("keylog"), fixture.port)
                val snapshot = h.snapshot()
                val frames = (1L..snapshot.frameCount.toLong()).filter { frame ->
                    nodes(h.agent.getPacketDetail(snapshot, frame).getOrNull()!!.root!!)
                        .any { it.filter == "http2.data.data" }
                }
                assertTrue(frames.isNotEmpty())
                val result = h.run("get_packet_fields", mapOf("frames" to frames,
                    "fields" to listOf("http2.data.data")), snapshot)
                val sourceDescriptions = frames.map { frame ->
                    val detail = h.repository.getPacketDetailSnapshot(frame)
                    "frame=$frame sources=${detail.sources.map { "${it.id}:${it.kind}:${it.name}" }} " +
                        "fields=${nodes(detail.root).filter { it.filter == "http2.data.data" }.map { it.dataSourceId }}"
                }
                assertTrue("HTTP2 source provenance missing: $sourceDescriptions", encode(result).contains("decrypted_tls"))
                assertFalse(encode(result).contains(fixture.body.toString(Charsets.UTF_8).trim()))
                assertFalse(encode(result).contains(fixture.body.joinToString(":") { "%02x".format(it) }))
                assertClean(result, h.secretValues)
            }
        }
    }

    @Test fun caAndRealFixtureSecretsAreWithheldInAllModesIncludingCacheHits() = runBlocking {
        Harness().use { h ->
            h.open("tls13")
            val values = mapOf("keylog" to h.keys.readText(), "private_key" to "TLS313_SYNTHETIC_CA_PRIVATE",
                "client_random" to h.secretValues.first(), "traffic_secret" to h.secretValues.last())
            val tool = object : AgentTool {
                override val definition = AgentToolDefinition("tls313_secret_boundary",
                    inputSchema = mapOf("type" to "object"), sensitivity = AgentDataSensitivity.Aggregate)
                override suspend fun execute(arguments: Map<String, Any?>, context: AgentToolContext) =
                    context.success(mapOf("nested" to values), 1, 1)
            }
            val snapshot = h.snapshot()
            for (mode in AgentPrivacyMode.entries.filter { it != AgentPrivacyMode.Unknown }) {
                val runner = AgentToolRunner(AgentToolRegistry(tool), h.agent, AgentPolicy(allowPayload = true),
                    cache = h.cache, nativeBuildMarker = "tls313-device")
                repeat(2) { index ->
                    val result = runner.execute(AgentToolCall("secret-$mode-$index", tool.definition.name), snapshot, mode)
                    assertTrue(result.success)
                    values.values.forEach { assertFalse("Never-allowed value escaped", encode(result).contains(it)) }
                    assertTrue(encode(result).contains(AgentDecryptedContentPolicy.WITHHELD))
                }
            }
            assertTrue("Repeat calls must exercise the cache", h.cache.stats().hits > 0)
            h.cache.storageDirectory!!.walkTopDown().filter { it.isFile }.forEach { file ->
                values.values.forEach { assertFalse("Secret reached disk cache", file.readText().contains(it)) }
            }
        }
    }

    @Test fun realKeyChangesClearAndFileSwitchCannotServeOldGenerationCache() = runBlocking {
        Harness().use { h ->
            h.open("tls12")
            val before = h.snapshot()
            val bodyFrame = (1L..before.frameCount.toLong()).first { frame ->
                nodes(h.agent.getPacketDetail(before, frame).getOrNull()!!.root!!).any { it.filter == "http.request.uri" }
            }
            val args = mapOf("frames" to listOf(bodyFrame), "fields" to listOf("http.request.uri"))
            h.run("get_packet_fields", args, before)
            val hits = h.cache.stats().hits
            h.run("get_packet_fields", args, before)
            assertEquals(hits + 1, h.cache.stats().hits)
            val wrong = h.copyAsset("tls13", "session.keys")
            h.configure(wrong)
            val after = h.snapshot()
            assertEquals(before.captureFingerprint, after.captureFingerprint)
            assertNotEquals(before.analysisCacheIdentity, after.analysisCacheIdentity)
            val misses = h.cache.stats().misses
            val absent = h.run("get_packet_fields", args, after)
            assertTrue(h.cache.stats().misses > misses)
            assertFalse("Wrong keys must not replay a decrypted occurrence", encode(absent).contains("decrypted_tls"))
            assertFalse("Old in-flight snapshot must fail", h.execute("get_packet_fields", args, before).success)
            h.configure(h.keys)
            val restored = h.run("get_packet_fields", args, h.snapshot())
            assertTrue(encode(restored).contains("decrypted_tls"))
            assertTrue(h.coordinator.configureTlsSecrets(null).success)
            assertFalse(encode(h.run("get_packet_fields", args, h.snapshot())).contains("decrypted_tls"))
            h.open("tls13")
            val other = h.snapshot()
            assertNotEquals(before.captureFingerprint, other.captureFingerprint)
            val priorMisses = h.cache.stats().misses
            h.run("get_packet_fields", args, other)
            assertTrue(h.cache.stats().misses > priorMisses)
        }
    }

    @Test fun upstreamEventsHaveNoInventedFrameAndDownstreamUsesRealNativeHello() = runBlocking {
        Harness().use { h ->
            h.open("tls13")
            val analysis = h.repository.currentAnalysisRevision()
            val native = JSONObject(NativeEngine.projectTlsClientHellos(analysis.sessionHandle,
                analysis.dissectionGeneration, 0))
            assertTrue(native.getBoolean("success"))
            val hello = native.getJSONArray("observations").getJSONObject(0)
            val observation = ClientHelloObservation(hello.getLong("frameNumber"), hello.getLong("frameTimeMillis"),
                hello.getString("clientRandom"), hello.getString("destinationIp"), hello.getInt("destinationPort"))
            val event = TlsConnectionEvent(h.id, "connection", 1, 1, observation.frameTimeMillis,
                observation.destinationIp, observation.destinationPort, networkGeneration = 1,
                phase = TlsConnectionPhase.UPSTREAM_HANDSHAKE, upstreamTls = "TLS1.3")
            val correlator = TlsConnectionCorrelator(h.id)
            val upstream = correlator.associate(listOf(event), listOf(observation), TlsFrameMapping { it }).single()
            val evidence = AgentTlsEvidence.fromEvent(event, upstream)
            assertNull(evidence.globalFrameNumber)
            assertEquals(false, evidence.toAgentJson()["frameNumberKnown"])
            assertEquals("app_to_proxy", evidence.source)
            val downstream = event.copy(downstreamClientRandom = observation.clientRandom,
                phase = TlsConnectionPhase.DOWNSTREAM_HANDSHAKE)
            val association = correlator.associate(listOf(downstream), listOf(observation), TlsFrameMapping { it }).single()
            assertEquals(observation.frameNumber, AgentTlsEvidence.fromEvent(downstream, association).globalFrameNumber)
        }
    }

    @Test fun applicationCleanupSubscriberDropsOnlyDeletedCaptureCacheAndHistory() = runBlocking {
        Harness().use { h ->
            h.open("tls12")
            val app = context.applicationContext as LayerAnalyzerApplication
            val directory = File(context.filesDir, "captures").apply { mkdirs() }
            val capture = File(directory, "tls313-${h.id}.pcap")
            h.capture.copyTo(capture)
            val fingerprint = CaptureFingerprintCalculator().calculate(capture)
            val otherFingerprint = "tls313-other-${h.id}"
            val key = cacheKey(fingerprint)
            val otherKey = cacheKey(otherFingerprint)
            try {
                for ((fp, cacheKey) in listOf(fingerprint to key, otherFingerprint to otherKey)) {
                    app.agentToolCache.put(cacheKey, mapOf("value" to "TLS313_DERIVED"), AgentDataSensitivity.Aggregate, 1, 1, false)
                    assertTrue(app.agentSessionStore.save(AgentReport(summary = "TLS313_DERIVED"), "synthetic",
                        null, captureFingerprint = fp, conversationId = "tls313-$fp").isSuccess)
                }
                assertNotNull(app.agentToolCache.get(key, AgentDataSensitivity.Aggregate))
                val lifecycle = CaptureArtifactLifecycle(context)
                val captureId = lifecycle.identityForFile(capture)
                lifecycle.purgeFile(capture)
                // No explicit invalidator call: this must be the Application's real subscription.
                withTimeout(10_000) {
                    while (app.agentSessionStore.listForCapture(fingerprint).isNotEmpty() ||
                        app.agentToolCache.get(key, AgentDataSensitivity.Aggregate) != null) delay(50)
                }
                assertFalse(capture.exists())
                assertEquals(1, app.agentSessionStore.listForCapture(otherFingerprint).size)
                assertNotNull(app.agentToolCache.get(otherKey, AgentDataSensitivity.Aggregate))
                val durable = lifecycle.cleanupEvents().single { it.captureId == captureId }
                assertTrue(durable.completed)
                assertTrue(fingerprint in durable.captureFingerprints)
                assertEquals(0, app.agentTlsEvidenceInvalidator.replay(listOf(durable)))
            } finally {
                if (capture.exists()) CaptureArtifactLifecycle(context).purgeFile(capture)
                app.agentTlsEvidenceInvalidator.invalidateFingerprint(fingerprint)
                app.agentTlsEvidenceInvalidator.invalidateFingerprint(otherFingerprint)
            }
        }
    }

    @Test fun persistedCleanupJournalReplaysIntoReopenedDiskStores() = runBlocking {
        Harness().use { h ->
            h.open("tls13")
            val files = File(h.root, "files")
            val packet = File(files, "captures/replay.pcap").apply { parentFile!!.mkdirs() }
            h.capture.copyTo(packet)
            val fp = CaptureFingerprintCalculator().calculate(packet)
            val key = cacheKey(fp)
            val cacheDir = File(h.root, "replay-cache")
            val sessionDir = File(h.root, "replay-sessions")
            AgentToolCache(cacheDir).put(key, mapOf("value" to "TLS313_DERIVED"), AgentDataSensitivity.Aggregate, 1, 1, false)
            assertTrue(AgentSessionStore(sessionDir).save(AgentReport(summary = "TLS313_DERIVED"), "synthetic",
                null, captureFingerprint = fp, conversationId = h.id).isSuccess)
            CaptureArtifactLifecycle(files, h.privateDir, h.store).purgeFile(packet)
            val reopenedCache = AgentToolCache(cacheDir)
            val reopenedSessions = AgentSessionStore(sessionDir)
            assertNotNull(reopenedCache.get(key, AgentDataSensitivity.Aggregate))
            assertEquals(1, reopenedSessions.listForCapture(fp).size)
            val journal = CaptureArtifactLifecycle(files, h.privateDir, h.store).cleanupEvents()
            val invalidator = AgentTlsEvidenceInvalidator(reopenedCache, reopenedSessions)
            assertEquals(1, invalidator.replay(journal))
            assertEquals(0, invalidator.replay(journal))
            assertNull(AgentToolCache(cacheDir).get(key, AgentDataSensitivity.Aggregate))
            assertTrue(AgentSessionStore(sessionDir).listForCapture(fp).isEmpty())
        }
    }

    private class Harness : AutoCloseable {
        val id = UUID.randomUUID().toString()
        val root = File(context.noBackupFilesDir, "tls313-$id").apply { check(mkdir()) }
        val privateDir = File(root, "private").apply { mkdir() }
        private val alias = "layeranalyzer.test.tls313.$id"
        val store = TlsSecretStore(privateDir, AndroidTlsWrappingKeyProvider(alias))
        val repository = PacketRepository()
        val coordinator = CaptureSessionCoordinator(repository)
        val agent = AgentAnalysisRepository(repository, coordinator)
        val cache = AgentToolCache(File(root, "cache"))
        lateinit var capture: File
        lateinit var keys: File
        val secretValues get() = keys.readLines().filter { it.isNotBlank() && !it.startsWith("#") }
            .flatMap { it.trim().split(Regex("\\s+")).drop(1) }.distinct()

        fun copyAsset(version: String, name: String): File {
            val assets = InstrumentationRegistry.getInstrumentation().context.assets
            val manifest = JSONObject(assets.open("tls/ai-privacy/manifest.json").bufferedReader().use { it.readText() })
            assertEquals("synthetic-offline-test-only", manifest.getString("source"))
            val target = File(root, "$version-$name")
            assets.open("tls/ai-privacy/$version/$name").use { input -> target.outputStream().use { input.copyTo(it) } }
            val hash = MessageDigest.getInstance("SHA-256").digest(target.readBytes()).joinToString("") { "%02x".format(it) }
            assertEquals(manifest.getJSONObject("fixtures").getJSONObject(version).getJSONObject("files").getString(name), hash)
            return target
        }
        suspend fun open(version: String) = openFiles(copyAsset(version, "capture.pcap"), copyAsset(version, "session.keys"))
        suspend fun openFiles(file: File, keylog: File, port: Int = 443) {
            repository.closeFile()
            coordinator.invalidateSession()
            capture = file
            keys = keylog
            val info = repository.openFile(file.path).getOrThrow()
            coordinator.registerOpenedSession(info).getOrThrow()
            if (port != 443) {
                assertTrue(repository.applyDecodeAsRule(DecodeAsRule("fixture", DecodeAsScope.Port,
                    DecodeAsTransport.TCP, "", "", null, port, "tls")).success)
                coordinator.registerOpenedSession(repository.currentFile()!!).getOrThrow()
            }
            configure(keylog)
        }
        suspend fun configure(keylog: File) {
            val asset = keylog.inputStream().use { store.importRecords(UUID.randomUUID().toString(),
                KeyLogParser.parse(it) as KeyLogParseResult.Success) }
            assertTrue(coordinator.configureTlsSecrets(store.acquireLease(asset.captureId, asset.assetId)).success)
        }
        suspend fun snapshot() = agent.createSnapshot(AnalysisScope.CompleteFile).getOrNull()!!
        suspend fun execute(tool: String, args: Map<String, Any?>, snapshot: AgentCaptureSnapshot,
            mode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata, policy: AgentPolicy = AgentPolicy()): AgentToolResult =
            AgentToolRunner(AgentToolRegistry.phase3(), agent, policy, cache = cache, nativeBuildMarker = "tls313-device")
                .execute(AgentToolCall(UUID.randomUUID().toString(), tool, args), snapshot, mode)
        suspend fun run(tool: String, args: Map<String, Any?>, snapshot: AgentCaptureSnapshot,
            mode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata, policy: AgentPolicy = AgentPolicy()): AgentToolResult =
            execute(tool, args, snapshot, mode, policy).also {
                assertTrue("$tool failed: ${it.error?.code} ${it.error?.userMessage} ${it.error?.details}", it.success)
            }
        override fun close() {
            coordinator.invalidateSession()
            repository.closeFile()
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
            check(root.canonicalFile.parentFile == context.noBackupFilesDir.canonicalFile)
            check(root.name.startsWith("tls313-"))
            check(root.deleteRecursively())
        }
    }

    companion object {
        private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
        private val MARKERS = listOf("TLS313_COOKIE_SECRET", "TLS313_AUTH_SECRET", "TLS313_BODY_IGNORE",
            "TLS313_RESPONSE_PRIVATE_CONTENT", "TLS313_PRIVATE_URI")
        private fun nodes(node: ProtocolNode): List<ProtocolNode> = listOf(node) + node.children.flatMap(::nodes)
        private fun encode(result: AgentToolResult) = AgentResultTruncator.encode(result.data ?: emptyMap())
        private fun assertClean(result: AgentToolResult, secrets: List<String>) {
            assertTrue(result.success)
            assertTrue(result.asModelMessage().untrustedCaptureData)
            (MARKERS + secrets + listOf("IGNORE PREVIOUS INSTRUCTIONS")).forEach {
                assertFalse("Capture content escaped ${result.toolName}", encode(result).contains(it))
            }
        }
        private fun cacheKey(fingerprint: String) = AgentToolCacheKey(fingerprint, 1, "get_capture_overview",
            "tls313-args", "tls313-device", "1", "CompleteFile|")
    }
}
