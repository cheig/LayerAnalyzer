// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.client.MockAiModelClient
import com.example.layanalyzer.ai.client.MockModelScript
import com.example.layanalyzer.ai.client.MockScriptedResponse
import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentRunPhase
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Direct coverage of the AI-06 phase-transition table.
 *
 * The revision-turn bug (a tool-call answer during Revising misreported as a
 * user cancellation) lived exactly in the gap this table closes: the loop has
 * to know which edges Revising actually has, and a refused edge from a live
 * phase must never be conflated with the terminal Cancelled latch.
 */
class AgentRunControllerTest {

    @Test
    fun revisingPermitsOnlyValidationFinalizingOrATerminal() {
        assertTrue(AgentRunPhase.Revising.canTransitionTo(AgentRunPhase.ValidatingReport))
        assertTrue(AgentRunPhase.Revising.canTransitionTo(AgentRunPhase.Finalizing))
        assertTrue(AgentRunPhase.Revising.canTransitionTo(AgentRunPhase.Failed))
        assertTrue(AgentRunPhase.Revising.canTransitionTo(AgentRunPhase.FailedWithPartialReport))
        assertTrue(AgentRunPhase.Revising.canTransitionTo(AgentRunPhase.Cancelled))
        // No tool turn and no plain model turn exist during a revision — the
        // loop resolves a tool-call revision answer inline, without ever
        // attempting one of these transitions.
        assertFalse(AgentRunPhase.Revising.canTransitionTo(AgentRunPhase.RunningTool))
        assertFalse(AgentRunPhase.Revising.canTransitionTo(AgentRunPhase.WaitingForModel))
        // Completion goes through the terminal finish(), not transitionTo.
        assertFalse(AgentRunPhase.Revising.canTransitionTo(AgentRunPhase.Completed))
    }

    @Test
    fun revisingIsEnteredFromModelValidationOrFinalizingPhases() {
        assertTrue(AgentRunPhase.WaitingForModel.canTransitionTo(AgentRunPhase.Revising))
        assertTrue(AgentRunPhase.ValidatingReport.canTransitionTo(AgentRunPhase.Revising))
        assertTrue(AgentRunPhase.Finalizing.canTransitionTo(AgentRunPhase.Revising))
        assertFalse(AgentRunPhase.Investigating.canTransitionTo(AgentRunPhase.Revising))
        assertFalse(AgentRunPhase.RunningTool.canTransitionTo(AgentRunPhase.Revising))
    }

    @Test
    fun terminalPhasesLatchAgainstEveryTransition() {
        val terminals = listOf(
            AgentRunPhase.Completed,
            AgentRunPhase.Failed,
            AgentRunPhase.FailedWithPartialReport,
            AgentRunPhase.Cancelled
        )
        for (terminal in terminals) {
            assertTrue(terminal.isTerminal)
            for (next in AgentRunPhase.values()) {
                assertFalse("$terminal -> $next must latch", terminal.canTransitionTo(next))
            }
        }
    }

    @Test
    fun cancelLatchesOnceAndASecondCancelDoesNotBumpTheGeneration() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val controller = AgentRunController(
                identity = AgentRunIdentity(
                    conversationId = "conv_test",
                    runId = "run_test"
                ),
                modelClient = MockAiModelClient(
                    MockModelScript(
                        id = "controller-test",
                        responses = listOf(
                            MockScriptedResponse.final(
                                AgentReport(summary = "unused", findings = emptyList())
                            )
                        )
                    )
                ),
                repository = harness.repository
            )
            assertTrue(controller.transitionTo(AgentRunPhase.Preparing).moved)
            val generationBefore = controller.agentGeneration

            controller.cancel()

            assertTrue(controller.isCancelled)
            assertEquals(AgentRunPhase.Cancelled, controller.phase)
            assertEquals(generationBefore + 1, controller.agentGeneration)
            // Idempotent: a UI cancel followed by onCleared must not invalidate
            // a new run by bumping the generation twice.
            controller.cancel()
            assertEquals(generationBefore + 1, controller.agentGeneration)
            // After the latch, a refused transition reports the terminal phase.
            val refused = controller.transitionTo(AgentRunPhase.WaitingForModel)
            assertFalse(refused.moved)
            assertEquals(AgentRunPhase.Cancelled, refused.previous)
        }
    }
}
