package com.example.layanalyzer.ai.serialization

import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentReport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class AgentConversationCodecCacheBreakpointTest {
    @Test
    fun savedInteractionDropsRollingMessageBreakpointsButKeepsSystemHint() {
        val interaction = AgentModelInteraction(
            id = "interaction-1",
            request = AgentModelRequest(
                requestId = "request-1",
                messages = listOf(
                    AgentModelMessage.system("System", cacheable = true),
                    AgentModelMessage.user("Question").withCacheBreakpoint(),
                    AgentModelMessage.assistant("Answer").withCacheBreakpoint()
                )
            ),
            response = AgentModelResponse.Final(AgentReport(summary = "Done")),
            startedAtMillis = 1_000L,
            firstTokenAtMillis = 1_150L,
            completedAtMillis = 1_400L
        )

        val restored = AgentConversationCodec.interactionsFromArray(
            AgentConversationCodec.interactionsToArray(listOf(interaction))
        ).single()

        assertNotNull(restored.request.messages[0].cacheControl)
        assertNull(restored.request.messages[1].cacheControl)
        assertNull(restored.request.messages[2].cacheControl)
        assertEquals(1_150L, restored.firstTokenAtMillis)
        assertEquals(400L, restored.responseDurationMillis)
        assertEquals(150L, restored.timeToFirstTokenMillis)
    }
}
