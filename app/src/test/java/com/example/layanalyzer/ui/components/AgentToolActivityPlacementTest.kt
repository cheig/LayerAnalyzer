package com.example.layanalyzer.ui.components

import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AgentToolCall
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentToolActivityPlacementTest {
    @Test
    fun placesMultiToolExchangeInFirstExistingStepOnly() {
        val activities = listOf(activity("call-1"), activity("call-2"))
        val interaction = interaction(
            id = "interaction-1",
            response = AgentModelResponse.ToolCalls(
                calls = listOf(toolCall("missing"), toolCall("call-2"), toolCall("call-1"))
            )
        )

        val result = placeModelInteractions(activities, listOf(interaction))

        assertTrue(result.byToolCallId["call-1"].isNullOrEmpty())
        assertEquals(listOf("interaction-1"), result.byToolCallId["call-2"]?.map { it.interaction.id })
        assertTrue(result.unassigned.isEmpty())
    }

    @Test
    fun placesTerminalExchangeInLastExistingStep() {
        val activities = listOf(activity("call-1"), activity("call-2"))
        val interaction = interaction("interaction-final", AgentModelResponse.Final("{}"))

        val result = placeModelInteractions(activities, listOf(interaction))

        assertEquals(
            listOf("interaction-final"),
            result.byToolCallId["call-2"]?.map { it.interaction.id }
        )
        assertTrue(result.unassigned.isEmpty())
    }

    @Test
    fun placesFailedRetryWithLaterSuccessfulAttemptInSameTurn() {
        val activities = listOf(activity("call-retry"), activity("call-last"))
        val failedAttempt = interaction(
            id = "interaction-failed",
            response = AgentModelResponse.Failure(
                AgentError(AgentErrorCode.MODEL_UNAVAILABLE, "Unavailable", retryable = true)
            ),
            turn = 3,
            attempt = 1
        )
        val successfulAttempt = interaction(
            id = "interaction-success",
            response = AgentModelResponse.ToolCalls(listOf(toolCall("call-retry"))),
            turn = 3,
            attempt = 2
        )

        val result = placeModelInteractions(
            activities,
            listOf(failedAttempt, successfulAttempt)
        )

        assertEquals(
            listOf("interaction-failed", "interaction-success"),
            result.byToolCallId["call-retry"]?.map { it.interaction.id }
        )
        assertTrue(result.byToolCallId["call-last"].isNullOrEmpty())
    }

    @Test
    fun keepsExchangeVisibleWhenThereAreNoToolSteps() {
        val interaction = interaction("interaction-final", AgentModelResponse.Final("{}"))

        val result = placeModelInteractions(emptyList(), listOf(interaction))

        assertTrue(result.byToolCallId.isEmpty())
        assertEquals(listOf("interaction-final"), result.unassigned.map { it.interaction.id })
    }

    private fun activity(toolCallId: String) = AgentToolActivity(toolCallId = toolCallId)

    private fun toolCall(toolCallId: String) = AgentToolCall(toolCallId = toolCallId)

    private fun interaction(
        id: String,
        response: AgentModelResponse,
        turn: Int? = null,
        attempt: Int = 1
    ) = AgentModelInteraction(
        id = id,
        turn = turn,
        attempt = attempt,
        request = AgentModelRequest(requestId = "request-$id"),
        response = response
    )
}
