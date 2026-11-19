// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.privacy

import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.cache.AgentTlsEvidenceInvalidator
import com.example.layanalyzer.ai.cache.AgentToolCache
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.ai.tools.AgentToolRunner
import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.ai.tools.FakeTool
import com.example.layanalyzer.data.AgentSessionStore
import com.example.layanalyzer.data.CaptureCleanupEvent
import com.example.layanalyzer.data.CaptureCleanupReason
import com.example.layanalyzer.data.ClientHelloObservation
import com.example.layanalyzer.data.TlsAssociationReason
import com.example.layanalyzer.data.TlsAssociationState
import com.example.layanalyzer.data.TlsConnectionAssociation
import com.example.layanalyzer.data.TlsConnectionCorrelator
import com.example.layanalyzer.data.TlsFrameMapping
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentToolCacheKey
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.TlsConnectionEvent
import com.example.layanalyzer.model.TlsConnectionPhase
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * TLS-313 acceptance 2: a key change or a file change must stop old-generation
 * results from being served, and an upstream (proxy-only) event must never be
 * given a fabricated capture frame number.
 */
class TlsEvidenceGenerationTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    // ---- generation isolation -------------------------------------------------

    @Test
    fun `a key change gives a new analysis identity so the old cache entry is not served`() =
        runBlocking {
            AgentToolTestHarness.create().use { harness ->
                val tool = countingTool()
                val cache = AgentToolCache(directory = temporaryFolder.root)
                val runner = runner(harness, tool, cache)

                // First key configuration and its snapshot.
                assertTrue(harness.coordinator.configureTlsSecrets(null).success)
                val before = checkNotNull(harness.repository.createSnapshot(harness.snapshot.scope).getOrNull())
                runner.execute(tool.call("a"), before, AgentPrivacyMode.RedactedMetadata)
                assertEquals(1, tool.executionCount)

                // Changing the secrets (a different keylog, or clearing it) is a
                // new analysis epoch for the same capture and file fingerprint.
                val info = checkNotNull(harness.source.currentFile())
                harness.coordinator.registerOpenedSession(info).getOrThrow()
                assertTrue(harness.coordinator.configureTlsSecrets(null).success)
                val after = checkNotNull(harness.repository.createSnapshot(harness.snapshot.scope).getOrNull())

                assertEquals("same capture file", before.captureFingerprint, after.captureFingerprint)
                assertEquals("config version unchanged", before.analysisConfigVersion, after.analysisConfigVersion)
                assertNotEquals(
                    "the analysis epoch must change with the keys",
                    before.analysisCacheIdentity,
                    after.analysisCacheIdentity
                )

                // The old-generation entry must not be reused for the new epoch.
                runner.execute(tool.call("b"), after, AgentPrivacyMode.RedactedMetadata)
                assertEquals(2, tool.executionCount)
            }
        }

    @Test
    fun `a different capture file never reuses another file's cached result`() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = countingTool()
            val cache = AgentToolCache(directory = temporaryFolder.root)
            val runner = runner(harness, tool, cache)

            val first = checkNotNull(harness.repository.createSnapshot(harness.snapshot.scope).getOrNull())
            runner.execute(tool.call("a"), first, AgentPrivacyMode.RedactedMetadata)

            // A different file is a different fingerprint; the same tool call must
            // run again rather than serve the other capture's rows.
            val otherFile = temporaryFolder.newFile("other.pcap").apply { writeText("other") }
            harness.source.switchSession(2L, otherFile)
            harness.coordinator.registerOpenedSession(checkNotNull(harness.source.currentFile())).getOrThrow()
            val second = checkNotNull(harness.repository.createSnapshot(harness.snapshot.scope).getOrNull())

            assertNotEquals(first.captureFingerprint, second.captureFingerprint)
            runner.execute(tool.call("b"), second, AgentPrivacyMode.RedactedMetadata)
            assertEquals(2, tool.executionCount)
        }
    }

    // ---- proxy / upstream frame honesty --------------------------------------

    @Test
    fun `an upstream-only connection never gets a fabricated frame number`() {
        val correlator = TlsConnectionCorrelator("capture-1")
        // An event that reached the upstream handshake but never reported a
        // downstream client_random, and a real capture frame that exists.
        val event = TlsConnectionEvent(
            captureId = "capture-1",
            connectionId = "conn-1",
            eventSequence = 3,
            monotonicNanos = 30,
            wallTimeMillis = 1_000,
            destinationIp = "203.0.113.9",
            destinationPort = 443,
            networkGeneration = 1,
            phase = TlsConnectionPhase.UPSTREAM_HANDSHAKE,
            upstreamTls = "TLS1.3",
            alpn = "h2"
        )
        val associations = correlator.associate(
            events = listOf(event),
            observations = listOf(
                ClientHelloObservation(7, 1_000, "aa".repeat(32), "203.0.113.9", 443)
            ),
            frameMapping = TlsFrameMapping { frame -> frame }
        )

        val association = associations.single()
        assertEquals(TlsAssociationState.UNMATCHED, association.state)
        assertEquals(TlsAssociationReason.NO_CLIENT_RANDOM, association.reason)
        assertNull(association.globalFrameNumber)

        val observation = AgentTlsEvidence.fromEvent(event, association)
        assertNull(observation.globalFrameNumber)
        assertTrue(observation.toAgentJson()["frameNumberKnown"] == false)
        assertEquals(AgentTlsEvidence.SOURCE, observation.source)
    }

    @Test
    fun `only a matched downstream client hello yields a frame number`() {
        val matched = TlsConnectionAssociation(
            captureId = "capture-1",
            connectionId = "conn-1",
            state = TlsAssociationState.MATCHED,
            reason = TlsAssociationReason.MATCHED,
            destinationIp = "203.0.113.9",
            destinationPort = 443,
            clientRandom = "aa".repeat(32),
            globalFrameNumber = 42L,
            clientHelloFrames = 1,
            helloRetryRequest = false
        )
        assertEquals(42L, AgentTlsEvidence.frameNumberFor(matched))

        // A matched association whose ClientHello fell outside the merged
        // capture still carries no frame, and neither does an ambiguous one.
        assertNull(AgentTlsEvidence.frameNumberFor(matched.copy(globalFrameNumber = null)))
        assertNull(
            AgentTlsEvidence.frameNumberFor(
                matched.copy(state = TlsAssociationState.AMBIGUOUS, globalFrameNumber = null)
            )
        )
        assertNull(AgentTlsEvidence.frameNumberFor(null))
    }

    // ---- cleanup invalidation (TLS-312) --------------------------------------

    @Test
    fun `a capture cleanup event drops cached results and saved conversations`() {
        val cache = AgentToolCache(directory = temporaryFolder.root)
        val sessions = AgentSessionStore(temporaryFolder.newFolder("agent_sessions"))
        val invalidator = AgentTlsEvidenceInvalidator(cache, sessions)

        val key = cacheKey("fingerprint-a", "get_capture_overview")
        val otherKey = cacheKey("fingerprint-b", "get_capture_overview")
        cache.put(key, mapOf("value" to "a"), AgentDataSensitivity.Aggregate, 1L, 1L, false)
        cache.put(otherKey, mapOf("value" to "b"), AgentDataSensitivity.Aggregate, 1L, 1L, false)
        assertTrue(
            sessions.save(
                report = AgentReport(summary = "kept"),
                userQuestion = "q",
                runRecord = null,
                captureFingerprint = "fingerprint-a",
                conversationId = "conversation-a"
            ).isSuccess
        )
        assertTrue(
            sessions.save(
                report = AgentReport(summary = "other"),
                userQuestion = "q",
                runRecord = null,
                captureFingerprint = "fingerprint-b",
                conversationId = "conversation-b"
            ).isSuccess
        )

        val removed = invalidator.onCaptureCleanup(
            CaptureCleanupEvent(
                captureId = "capture-a",
                reason = CaptureCleanupReason.Deleted,
                completed = true,
                captureFingerprints = setOf("fingerprint-a")
            )
        )

        assertEquals(1, removed)
        assertNull("the deleted capture's cached result survived", cache.get(key, AgentDataSensitivity.Aggregate))
        assertTrue("another capture's cached result was dropped", cache.get(otherKey, AgentDataSensitivity.Aggregate) != null)
        assertTrue(sessions.listForCapture("fingerprint-a").isEmpty())
        assertEquals(1, sessions.listForCapture("fingerprint-b").size)
    }

    @Test
    fun `replaying the cleanup journal is idempotent`() {
        val cache = AgentToolCache(directory = temporaryFolder.root)
        val sessions = AgentSessionStore(temporaryFolder.newFolder("agent_sessions-2"))
        val invalidator = AgentTlsEvidenceInvalidator(cache, sessions)
        val event = CaptureCleanupEvent(
            captureId = "capture-a",
            reason = CaptureCleanupReason.Deleted,
            completed = true,
            captureFingerprints = setOf("fingerprint-a")
        )

        assertEquals(0, invalidator.replay(listOf(event)))
        assertEquals(0, invalidator.replay(listOf(event)))
    }

    private fun cacheKey(fingerprint: String, tool: String) = AgentToolCacheKey(
        captureFingerprint = fingerprint,
        analysisConfigVersion = 1,
        toolName = tool,
        normalizedArgumentsHash = "args",
        nativeBuildMarker = "wireshark-test",
        toolVersion = "1",
        scopeKey = "CompleteFile|"
    )

    private fun countingTool() = FakeTool(
        name = "counting_tool",
        sensitivity = AgentDataSensitivity.Aggregate
    ) { _, context ->
        context.success(mapOf("value" to "fresh"), returnedCount = 1L, totalCount = 1L)
    }

    private fun runner(
        harness: AgentToolTestHarness,
        tool: FakeTool,
        cache: AgentToolCache,
        policy: AgentPolicy = AgentPolicy()
    ) = AgentToolRunner(
        registry = AgentToolRegistry(tool),
        repository = harness.repository,
        policy = policy,
        cache = cache,
        nativeBuildMarker = "wireshark-test"
    )

    private fun FakeTool.call(id: String) =
        AgentToolCall(toolCallId = id, toolName = definition.name, arguments = emptyMap())
}
