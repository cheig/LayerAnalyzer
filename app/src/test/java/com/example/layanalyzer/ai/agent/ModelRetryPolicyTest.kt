// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.client.AgentTruncationTarget
import com.example.layanalyzer.ai.client.AiModelErrors
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentRunPhase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ModelRetryPolicyTest {
    private val truncated = AgentError(
        code = AgentErrorCode.MODEL_OUTPUT_TRUNCATED,
        userMessage = "truncated",
        retryable = true
    )

    @Test
    fun toolCallTruncationExpandsWhileItCanAndThenHandsOff() {
        val first = decide(AgentTruncationTarget.ToolCalls, 4_096, 8_192, 0)
        val second = decide(AgentTruncationTarget.ToolCalls, 8_192, 8_192, 1)

        assertEquals(ModelRetryDecisionKind.RetryWithOutputLimit, first.kind)
        assertEquals(8_192, first.outputTokens)
        // At the model's own ceiling the allowance cannot grow again. Truncation
        // is deterministic, so replaying the identical request would reproduce
        // it rather than spend the remaining configured retries usefully.
        assertEquals(ModelRetryDecisionKind.ForceSummary, second.kind)
    }

    @Test
    fun finalReportAndUnknownTruncationDoNotExpand() {
        assertEquals(
            ModelRetryDecisionKind.Stop,
            decide(AgentTruncationTarget.FinalReport, 4_096, 8_192, 0).kind
        )
        assertEquals(
            ModelRetryDecisionKind.Stop,
            decide(AgentTruncationTarget.Unknown, 4_096, 8_192, 0).kind
        )
    }

    @Test
    fun unavailableUsesAllFiveConfiguredRetries() {
        val error = AiModelErrors.unavailable("upstream_down")

        repeat(5) { retriesUsed ->
            val decision = ModelRetryPolicy.decide(
                error = error,
                phase = AgentRunPhase.Investigating,
                retriesUsed = retriesUsed,
                currentOutputTokens = 4_096,
                maximumOutputTokens = 4_096,
                userMaxRetries = 5
            )
            assertEquals(ModelRetryDecisionKind.RetrySame, decision.kind)
            assertEquals(5, decision.retryLimit)
        }

        assertEquals(
            ModelRetryDecisionKind.ForceSummary,
            ModelRetryPolicy.decide(
                error = error,
                phase = AgentRunPhase.Investigating,
                retriesUsed = 5,
                currentOutputTokens = 4_096,
                maximumOutputTokens = 4_096,
                userMaxRetries = 5
            ).kind
        )
    }

    @Test
    fun finalizingDoesNotRetryBecauseItIsAlreadyTheRecoveryPath() {
        val decision = ModelRetryPolicy.decide(
            error = AiModelErrors.unavailable("upstream_down"),
            phase = AgentRunPhase.Finalizing,
            retriesUsed = 0,
            currentOutputTokens = 4_096,
            maximumOutputTokens = 4_096,
            userMaxRetries = 5
        )

        // The forced summary is itself the bounded recovery hand-off, and its
        // caller degrades to a synthesized report. Retrying here would spend
        // the same escape hatch twice.
        assertEquals(ModelRetryDecisionKind.Stop, decision.kind)
        assertEquals(5, decision.retryLimit)
    }

    @Test
    fun responseTooLargeShrinksToTheFloorThenHandsOff() {
        val error = AiModelErrors.responseTooLarge()
        val atFloor = ModelRetryPolicy.decide(
            error = error,
            phase = AgentRunPhase.Investigating,
            retriesUsed = 0,
            currentOutputTokens = 2_048,
            maximumOutputTokens = 8_192,
            userMaxRetries = 5
        )

        assertEquals(ModelRetryDecisionKind.RetryWithOutputLimit, atFloor.kind)
        assertEquals(ModelRetryPolicy.MIN_RETRY_OUTPUT_TOKENS, atFloor.outputTokens)

        // Already at the floor: shrinking further would leave an allowance too
        // small to hold a report, and replaying it unchanged is deterministic.
        val exhausted = ModelRetryPolicy.decide(
            error = error,
            phase = AgentRunPhase.Investigating,
            retriesUsed = 1,
            currentOutputTokens = ModelRetryPolicy.MIN_RETRY_OUTPUT_TOKENS,
            maximumOutputTokens = 8_192,
            userMaxRetries = 5
        )

        assertEquals(ModelRetryDecisionKind.ForceSummary, exhausted.kind)
    }

    @Test
    fun anOversizedInputRetriesOnlyWhileCompactionCanStillShrinkIt() {
        val error = AiModelErrors.inputContextLimit()
        val first = ModelRetryPolicy.decide(
            error = error,
            phase = AgentRunPhase.Investigating,
            retriesUsed = 0,
            currentOutputTokens = 4_096,
            maximumOutputTokens = 8_192,
            userMaxRetries = 5
        )

        assertEquals(ModelRetryDecisionKind.RetrySame, first.kind)
        assertTrue(first.requiresInputCompaction)

        // Compaction already ran, so a further attempt would resend a payload
        // that has been proven not to fit.
        val second = ModelRetryPolicy.decide(
            error = error,
            phase = AgentRunPhase.Investigating,
            retriesUsed = 1,
            currentOutputTokens = 4_096,
            maximumOutputTokens = 8_192,
            userMaxRetries = 5
        )

        assertEquals(ModelRetryDecisionKind.ForceSummary, second.kind)
        assertFalse(second.requiresInputCompaction)
    }

    private fun decide(
        target: AgentTruncationTarget,
        current: Int,
        maximum: Int,
        retries: Int
    ) = ModelRetryPolicy.decide(
        error = truncated,
        phase = AgentRunPhase.Investigating,
        requestStage = AgentModelRequestStage.ToolSelection,
        truncationTarget = target,
        retriesUsed = retries,
        currentOutputTokens = current,
        maximumOutputTokens = maximum,
        userMaxRetries = 3
    )
}
