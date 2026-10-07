// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.agent.AgentSettingsStore
import com.example.layanalyzer.ai.agent.ProtocolAnalysisAgent
import com.example.layanalyzer.ai.background.AgentRunCoordinator
import com.example.layanalyzer.ai.client.MockAiModelClient
import com.example.layanalyzer.ai.client.MockModelScript
import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.ai.client.MockScriptedResponse
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.resolveDisplayFilter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * EVL-CONTEXT-03: the `displayFilterOverride` pipeline.
 *
 * An evidence-workflow submission ("analyze with this evidence") passes a
 * compiled filter so the run's snapshot is framed with it instead of the
 * session's applied display filter.  These tests pin down the three contract
 * points: the substitution decision itself, the end-to-end replacement in the
 * run snapshot, and the fact that follow-ups and retries never carry the
 * override — they stay framed against the session's applied filter.
 */
class AgentDisplayFilterOverrideTest {

    // ------------------------------------------------- substitution decision

    @Test
    fun aNullOverrideKeepsTheSessionFilter() {
        assertEquals("tcp", resolveDisplayFilter("tcp", null))
    }

    @Test
    fun aBlankOverrideKeepsTheSessionFilter() {
        assertEquals("tcp", resolveDisplayFilter("tcp", ""))
        assertEquals("tcp", resolveDisplayFilter("tcp", "   "))
    }

    @Test
    fun aUsableOverrideReplacesTheSessionFilterTrimmed() {
        assertEquals("frame.number==5", resolveDisplayFilter("tcp", "frame.number==5"))
        assertEquals("frame.number==5", resolveDisplayFilter("tcp", "  frame.number==5  "))
    }

    // ---------------------------------------------- snapshot at data level

    @Test
    fun anOverrideChangesOnlyTheSnapshotDisplayFilter() = runBlocking {
        harness().use { harness ->
            assertTrue(harness.coordinator.applyUserFilter("tcp").success)

            val base = checkNotNull(
                harness.repository.createSnapshot(AnalysisScope.CompleteFile).getOrNull()
            )
            val overridden = checkNotNull(
                harness.repository.createSnapshot(
                    AnalysisScope.CompleteFile,
                    "frame.number==5"
                ).getOrNull()
            )

            assertEquals("tcp", base.displayFilter)
            assertEquals("frame.number==5", overridden.displayFilter)
            // No new AnalysisScope value and no other snapshot field touched:
            // generations and timestamps differ per call by design.
            assertEquals(base.sessionHandle, overridden.sessionHandle)
            assertEquals(base.fileFingerprint, overridden.fileFingerprint)
            assertEquals(base.frameCount, overridden.frameCount)
            assertEquals(base.scope, overridden.scope)
            assertEquals(base.sessionGeneration, overridden.sessionGeneration)
            assertEquals(base.analysisConfigVersion, overridden.analysisConfigVersion)
        }
    }

    // ------------------------------------------ end-to-end through the VM

    @Test
    fun aSubmissionWithoutOverrideFramesTheRunWithTheSessionAppliedFilter() = runBlocking {
        harness().use { harness ->
            val modelClient = MockAiModelClient(oneRoundScript())
            val viewModel = viewModel(harness, modelClient)

            assertTrue(harness.coordinator.applyUserFilter("tcp").success)
            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)

            assertEquals(listOf("tcp"), modelClient.observedRoundFilters())
        }
    }

    @Test
    fun aSubmissionWithOverrideFramesTheRunSnapshotWithTheOverride() = runBlocking {
        harness().use { harness ->
            val modelClient = MockAiModelClient(oneRoundScript())
            val viewModel = viewModel(harness, modelClient)

            assertTrue(harness.coordinator.applyUserFilter("tcp").success)
            viewModel.submitQuestion(
                "Why is this capture slow?",
                displayFilterOverride = "frame.number==5"
            )
            viewModel.awaitIdle()
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)

            // The run snapshot carries the override; the scope mechanism is
            // untouched (the request kept AnalysisScope.CompleteFile).
            assertEquals(listOf("frame.number==5"), modelClient.observedRoundFilters())
            assertEquals(listOf("CompleteFile"), modelClient.observedToolScopes())
        }
    }

    @Test
    fun aFollowUpDoesNotCarryTheOverride() = runBlocking {
        harness().use { harness ->
            val modelClient = MockAiModelClient(twoRoundScript())
            val viewModel = viewModel(harness, modelClient)

            assertTrue(harness.coordinator.applyUserFilter("tcp").success)
            viewModel.submitQuestion(
                "Why is this capture slow?",
                displayFilterOverride = "frame.number==5"
            )
            viewModel.awaitIdle()
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)

            viewModel.continueConversation("What caused finding 1?")
            viewModel.awaitIdle()
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)

            // The first run was framed with the override; the follow-up went
            // back to the session's applied filter.
            assertEquals(
                listOf("frame.number==5", "tcp"),
                modelClient.observedRoundFilters()
            )
        }
    }

    @Test
    fun aRetryDoesNotCarryTheOverride() = runBlocking {
        harness().use { harness ->
            val modelClient = MockAiModelClient(twoRoundScript())
            val viewModel = viewModel(harness, modelClient)

            assertTrue(harness.coordinator.applyUserFilter("tcp").success)
            viewModel.submitQuestion(
                "Why is this capture slow?",
                displayFilterOverride = "frame.number==5"
            )
            viewModel.awaitIdle()
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)

            viewModel.retry()
            viewModel.awaitIdle()
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)

            assertEquals(
                listOf("frame.number==5", "tcp"),
                modelClient.observedRoundFilters()
            )
        }
    }

    // --------------------------------------------- report provenance (04)

    @Test
    fun theReportProvenanceRecordsTheEffectiveOverrideAndEvidenceFrameCount() = runBlocking {
        harness().use { harness ->
            val modelClient = MockAiModelClient(oneRoundScript())
            val viewModel = viewModel(harness, modelClient)

            assertTrue(harness.coordinator.applyUserFilter("tcp").success)
            viewModel.submitQuestion(
                "Why is this capture slow?",
                displayFilterOverride = "frame.number==5",
                evidenceFrameCount = 12
            )
            viewModel.awaitIdle()
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)

            val provenance = checkNotNull(viewModel.uiState.value.report?.provenance)
            // The effective (override) filter and the frame count recorded at
            // submission time, not the session's applied filter.
            assertEquals("frame.number==5", provenance.displayFilter)
            assertEquals(12, provenance.evidenceFrameCount)
        }
    }

    @Test
    fun aRunWithoutOverrideRecordsTheSessionFilterAndNoEvidenceCount() = runBlocking {
        harness().use { harness ->
            val modelClient = MockAiModelClient(oneRoundScript())
            val viewModel = viewModel(harness, modelClient)

            assertTrue(harness.coordinator.applyUserFilter("tcp").success)
            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)

            val provenance = checkNotNull(viewModel.uiState.value.report?.provenance)
            assertEquals("tcp", provenance.displayFilter)
            assertEquals(null, provenance.evidenceFrameCount)
        }
    }

    // ------------------------------------------------------------- helpers

    /**
     * The snapshot display filter each scripted round was framed with, in
     * order.
     *
     * Each round produces exactly two model requests: the first one, seeded
     * with the host's baseline Analysis Bootstrap tool result, and the request
     * that follows the round's scripted tool call.  The bootstrap result also
     * carries provenance, so round *n*'s own snapshot filter is read from the
     * last Tool message of request 2n+1 — the second request of that round.
     */
    private fun MockAiModelClient.observedRoundFilters(): List<String> =
        observedRequests.filterIndex { it % 2 == 1 }.map { provenanceField(it, "displayFilter") }

    private fun MockAiModelClient.observedToolScopes(): List<String> =
        observedRequests.filterIndex { it % 2 == 1 }.map { provenanceField(it, "scope") }

    private fun <T> List<T>.filterIndex(predicate: (Int) -> Boolean): List<T> =
        mapIndexed { index, value -> index to value }.filter { predicate(it.first) }.map { it.second }

    private fun provenanceField(request: com.example.layanalyzer.model.AgentModelRequest, field: String): String {
        val lastToolMessage = request.messages.last { it.role == AgentModelMessageRole.Tool }
        val provenance = checkNotNull(lastToolMessage.structuredContent?.get("provenance") as? Map<*, *>)
        return checkNotNull(provenance[field] as? String)
    }

    private suspend fun harness() = AgentToolTestHarness.create(frameCount = 120)

    private fun viewModel(
        harness: AgentToolTestHarness,
        modelClient: MockAiModelClient
    ): ProtocolAgentViewModel {
        val agent = ProtocolAnalysisAgent(
            repository = harness.repository,
            registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
            modelClient = modelClient,
            policy = AgentPolicy()
        )
        return ProtocolAgentViewModel(
            agent = agent,
            coordinator = harness.coordinator,
            settings = settings(),
            runCoordinator = AgentRunCoordinator(
                agent = agent,
                scope = CoroutineScope(Dispatchers.Unconfined)
            ),
            externalScope = CoroutineScope(Dispatchers.Unconfined)
        )
    }

    /** One round: a tool call (whose provenance reveals the snapshot filter), then a final report. */
    private fun oneRoundScript() = MockModelScript(
        id = "one-round-with-tool",
        description = "Tool call, then final.",
        responses = listOf(overviewToolTurn(), overviewTurn())
    )

    private fun twoRoundScript() = MockModelScript(
        id = "two-rounds-with-tool",
        description = "Two rounds, each a tool call then a final report.",
        responses = listOf(
            overviewToolTurn(), overviewTurn(),
            overviewToolTurn(), overviewTurn()
        )
    )

    private fun overviewToolTurn() = MockScriptedResponse.tool(
        toolCallId = "call-overview",
        toolName = "get_capture_overview"
    )

    private fun overviewTurn() = MockScriptedResponse.final(
        AgentReport(
            summary = "TCP dominates the capture and Expert Info reports retransmissions.",
            completeness = AgentReportCompleteness.Partial
        )
    )

    private fun settings() = object : AgentSettingsStore {
        override val modelScriptId = MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS
        override val privacyMode = AgentPrivacyMode.RedactedMetadata
    }

    private suspend fun ProtocolAgentViewModel.awaitIdle() {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (uiState.value.isRunning) delay(POLL_MILLIS)
        }
    }

    private companion object {
        const val AWAIT_TIMEOUT_MILLIS = 10_000L
        const val POLL_MILLIS = 5L
    }
}
