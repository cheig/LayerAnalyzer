// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.agent.AgentSettingsStore
import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.ai.agent.PromptAssembler
import com.example.layanalyzer.ai.agent.ProtocolAnalysisAgent
import com.example.layanalyzer.ai.background.AgentRunCoordinator
import com.example.layanalyzer.ai.client.MockAiModelClient
import com.example.layanalyzer.ai.client.MockModelScript
import com.example.layanalyzer.ai.client.MockScriptedResponse
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentRunPhase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Reproduction of the production wiring: MainActivity always constructs the
 * ViewModel with the Application-owned [AgentRunCoordinator], so a follow-up
 * travels startRun -> coordinator.start -> agent.run(history=...).  The
 * existing follow-up tests only cover the legacy in-ViewModel path.
 */
class AgentCoordinatorFollowUpHistoryTest {

    @Test
    fun aFollowUpThroughTheCoordinatorReplaysThePriorRound() = runBlocking {
        harness().use { harness ->
            val modelClient = MockAiModelClient(repeatedOverviewScript())
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
                modelClient = modelClient,
                policy = AgentPolicy()
            )
            val runCoordinator = AgentRunCoordinator(
                agent = agent,
                scope = CoroutineScope(Dispatchers.Unconfined)
            )
            val viewModel = ProtocolAgentViewModel(
                agent = agent,
                coordinator = harness.coordinator,
                settings = settings(),
                runCoordinator = runCoordinator,
                externalScope = CoroutineScope(Dispatchers.Unconfined)
            )

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)

            viewModel.continueConversation("What caused finding 1?")
            viewModel.awaitIdle()
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)

            val followUpRequest = modelClient.observedRequests.last { request ->
                request.messages.any { message ->
                    message.role == AgentModelMessageRole.User &&
                        message.content.contains(PromptAssembler.CONTINUATION_NOTICE)
                }
            }
            assertTrue(
                "Follow-up must replay the first round's question",
                followUpRequest.messages.any { message ->
                    message.role == AgentModelMessageRole.User &&
                        message.content == "Why is this capture slow?"
                }
            )
            assertTrue(
                "Follow-up must replay the first round's assistant answer",
                followUpRequest.messages.any { message ->
                    message.role == AgentModelMessageRole.Assistant &&
                        message.content.contains(
                            "TCP dominates the capture and Expert Info reports retransmissions."
                        )
                }
            )
        }
    }

    // ------------------------------------------------------------------ setup

    private suspend fun harness() = AgentToolTestHarness.create(frameCount = 120)

    private fun repeatedOverviewScript() = MockModelScript(
        id = "repeated-overview",
        description = "The overview trajectory, twice.",
        responses = listOf(overviewTurn(), overviewTurn())
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
