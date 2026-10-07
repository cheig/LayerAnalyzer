package com.example.layanalyzer.ai.background

import com.example.layanalyzer.ai.agent.AgentRunIdentity
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.agent.ProtocolAnalysisAgent
import com.example.layanalyzer.ai.audit.AgentDiagnosticsRecorder
import com.example.layanalyzer.ai.client.MockAiModelClient
import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.ai.playbook.AgentPlaybookStore
import com.example.layanalyzer.ai.playbook.TestScenarioPackages
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AnalysisJobPhase
import com.example.layanalyzer.model.AnalysisScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The coordinator owns the run on an injected scope, so these tests run the
 * whole agent without a ViewModel and without a Main dispatcher.
 */
class AgentRunCoordinatorTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun aRunCompletesAndPublishesTheTranscript() = runBlocking {
        harness().use { harness ->
            val coordinator = coordinator(harness)

            val started = coordinator.start(request("Why is this capture slow?"))
            assertTrue(started)
            coordinator.awaitIdle()

            val snapshot = coordinator.snapshot.value
            assertEquals(AgentRunPhase.Completed, snapshot.phase)
            assertNotNull(snapshot.report)
            assertTrue(snapshot.messages.isNotEmpty())
            assertEquals(AnalysisJobPhase.Completed, coordinator.jobState.value.phase)
            assertFalse(coordinator.isRunning)
        }
    }

    @Test
    fun aSecondStartIsRefusedWhileOneIsRunning() = runBlocking {
        harness().use { harness ->
            val coordinator = coordinator(harness, turnDelayMillis = 400L)

            assertTrue(coordinator.start(request("first")))
            // Let the first run actually get going.
            withTimeout(2_000) { while (!coordinator.isRunning) delay(10) }

            assertFalse(coordinator.start(request("second")))
            coordinator.awaitIdle()
            assertEquals(AgentRunPhase.Completed, coordinator.snapshot.value.phase)
        }
    }

    @Test
    fun cancelStopsTheRunAndPublishesCancelled() = runBlocking {
        harness().use { harness ->
            val coordinator = coordinator(harness, turnDelayMillis = 1_000L)

            assertTrue(coordinator.start(request("long running")))
            withTimeout(2_000) { while (!coordinator.isRunning) delay(10) }

            coordinator.cancel()

            assertFalse(coordinator.isRunning)
            assertEquals(AgentRunPhase.Cancelled, coordinator.snapshot.value.phase)
            assertEquals(AnalysisJobPhase.Cancelled, coordinator.jobState.value.phase)
        }
    }

    @Test
    fun foregroundServiceIsNotifiedAroundTheRun() = runBlocking {
        harness().use { harness ->
            val activations = mutableListOf<Boolean>()
            val coordinator = coordinator(harness, onRunActiveChanged = { activations += it })

            coordinator.start(request("tracked"))
            coordinator.awaitIdle()

            assertEquals(listOf(true, false), activations)
        }
    }

    /**
     * A follow-up request carries the prior round's visible items so the fresh
     * snapshot starts with them and the new run appends below, not replaces.
     */
    @Test
    fun aFollowUpSnapshotStartsWithItsCarriedVisibleItems() = runBlocking {
        harness().use { harness ->
            val coordinator = coordinator(harness)
            val carriedMessage = com.example.layanalyzer.model.AgentConversationItem(
                id = "run-prior:message-0",
                role = com.example.layanalyzer.model.AgentConversationRole.User,
                content = "Why is this capture slow?",
                createdAtMillis = 1L
            )
            val carriedInteraction = com.example.layanalyzer.model.AgentModelInteraction(
                id = "run-prior:interaction-0",
                request = com.example.layanalyzer.model.AgentModelRequest(
                    requestId = "req-prior",
                    messages = listOf(com.example.layanalyzer.model.AgentModelMessage.user("prior"))
                ),
                response = AgentModelResponse.Final(
                    report = com.example.layanalyzer.model.AgentReport(summary = "Prior.")
                )
            )

            assertTrue(
                coordinator.start(
                    request("go deeper").copy(
                        appendQuestion = true,
                        visibleMessages = listOf(carriedMessage),
                        visibleModelInteractions = listOf(carriedInteraction)
                    )
                )
            )
            coordinator.awaitIdle()

            // The run appended below the carried items instead of replacing them.
            val completed = coordinator.snapshot.value
            assertEquals(AgentRunPhase.Completed, completed.phase)
            assertTrue(completed.messages.size > 1)
            assertEquals("run-prior:message-0", completed.messages.first().id)
            assertEquals(carriedMessage, completed.messages.first())
            assertEquals("run-prior:interaction-0", completed.modelInteractions.first().id)
        }
    }

    /** A retry passes no seeds; its screen starts clean even after a prior run. */
    @Test
    fun aRunWithoutVisibleSeedsStartsFromAnEmptyScreen() = runBlocking {
        harness().use { harness ->
            val coordinator = coordinator(harness)

            coordinator.start(request("first"))
            coordinator.awaitIdle()
            val firstRunMessages = coordinator.snapshot.value.messages
            assertTrue(firstRunMessages.isNotEmpty())

            coordinator.start(request("second"))
            coordinator.awaitIdle()
            // The second run replays nothing from the first: ids differ and
            // none of the prior run's items survive the snapshot reset.
            val secondRunMessages = coordinator.snapshot.value.messages
            assertTrue(secondRunMessages.isNotEmpty())
            assertTrue(secondRunMessages.none { it.id in firstRunMessages.map { m -> m.id }.toSet() })
        }
    }

    // ------------------------------------------------------------------ setup

    /**
     * SRE-RUN-02: the request's explicit playbook id must survive the
     * coordinator and reach [ProtocolAnalysisAgent.run] — the question matches
     * no intent hint of the extra scenario, so only the forwarded id can
     * select it.
     */
    @Test
    fun theRequestPlaybookIdReachesTheAgentRun() = runBlocking {
        harness().use { harness ->
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.root,
                clock = { 27_000L }
            )
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
                modelClient = MockAiModelClient(
                    MockModelScriptLibrary.require(
                        MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS
                    )
                ),
                diagnostics = recorder,
                playbookStore = playbookStoreWithExtraScenario()
            )
            val coordinator = AgentRunCoordinator(
                agent = agent,
                scope = CoroutineScope(Dispatchers.Unconfined)
            )

            assertTrue(
                coordinator.start(
                    request("Why is this capture slow?").copy(
                        playbookId = "tcp-retransmission-deep-dive"
                    )
                )
            )
            coordinator.awaitIdle()

            assertEquals(AgentRunPhase.Completed, coordinator.snapshot.value.phase)
            assertEquals(
                "tcp-retransmission-deep-dive@3",
                singleRunPlaybookVersion(recorder)
            )
        }
    }

    private fun playbookStoreWithExtraScenario(
        extraPlaybookId: String = "tcp-retransmission-deep-dive",
        extraVersion: Int = 3
    ): AgentPlaybookStore {
        val general = JSONObject(TestScenarioPackages.MINIMAL_PLAYBOOKS)
            .getJSONArray("playbooks")
            .getJSONObject(0)
        val json = JSONObject()
            .put("schemaVersion", AgentPlaybookStore.SCHEMA_VERSION)
            .put(
                "playbooks",
                JSONArray()
                    .put(general)
                    .put(
                        JSONObject(general.toString())
                            .put("id", extraPlaybookId)
                            .put("version", extraVersion)
                            .put("intentHints", JSONArray().put("retransmission deep dive"))
                    )
            )
        return AgentPlaybookStore(
            assetLoader = { json.toString() },
            availableTools = TestScenarioPackages.availableTools
        )
    }

    /** The one run record's playbookVersion from a redacted diagnostics export. */
    private fun singleRunPlaybookVersion(recorder: AgentDiagnosticsRecorder): String {
        val runs = JSONObject(recorder.exportRedacted()).getJSONArray("runs")
        assertEquals(1, runs.length())
        return runs.getJSONObject(0).getString("playbookVersion")
    }

    private fun request(question: String) = AgentRunRequest(
        question = question,
        scope = AnalysisScope.CompleteFile,
        privacyMode = AgentPrivacyMode.RedactedMetadata,
        appendQuestion = false,
        identity = AgentRunIdentity.newConversation()
    )

    private suspend fun coordinator(
        harness: AgentToolTestHarness,
        turnDelayMillis: Long = 0L,
        onRunActiveChanged: (Boolean) -> Unit = {}
    ): AgentRunCoordinator {
        // A copy of the success script whose tool turn can be made to linger,
        // giving the cancel/refuse tests a real in-flight window.
        val base = MockModelScriptLibrary.require(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)
        val script = if (turnDelayMillis <= 0L) {
            base
        } else {
            base.copy(
                id = "${base.id}-slow",
                responses = base.responses.map { it.copy(delayMillis = turnDelayMillis) }
            )
        }
        val client = MockAiModelClient(script)
        val agent = ProtocolAnalysisAgent(
            repository = harness.repository,
            registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
            modelClient = client,
            policy = AgentPolicy()
        )
        return AgentRunCoordinator(
            agent = agent,
            scope = CoroutineScope(Dispatchers.Unconfined),
            onRunActiveChanged = onRunActiveChanged
        )
    }

    private suspend fun AgentRunCoordinator.awaitIdle() {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (isRunning) delay(POLL_MILLIS)
        }
    }

    private suspend fun harness() = AgentToolTestHarness.create(frameCount = 120)

    private companion object {
        const val AWAIT_TIMEOUT_MILLIS = 10_000L
        const val POLL_MILLIS = 5L
    }
}
