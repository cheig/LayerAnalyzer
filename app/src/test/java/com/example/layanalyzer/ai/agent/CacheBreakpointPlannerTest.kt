// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CacheBreakpointPlannerTest {
    @Test
    fun marksTheLatestThreeCompleteToolTurnsWithoutMutatingTheSource() {
        val source = buildList {
            add(AgentModelMessage.system("System", cacheable = true))
            add(AgentModelMessage.user("Question").withCacheBreakpoint())
            repeat(4) { turn -> addAll(completeTurn(turn + 1)) }
        }

        val planned = CacheBreakpointPlanner.mark(source)

        val markedToolIds = planned
            .filter { it.role == AgentModelMessageRole.Tool && it.cacheControl != null }
            .mapNotNull { it.toolCallId }
        assertEquals(listOf("call-2", "call-3", "call-4"), markedToolIds)
        assertEquals(4, planned.count { it.cacheControl != null })
        assertTrue(source.drop(1).all { message ->
            message.role != AgentModelMessageRole.User || message.cacheControl != null
        })
        assertNull(planned[1].cacheControl)
        source.filter { it.role == AgentModelMessageRole.Tool }.forEach { message ->
            assertNull(message.cacheControl)
        }
    }

    @Test
    fun doesNotMarkAnIncompleteAssistantToolGroup() {
        val complete = completeTurn(1)
        val source = listOf(
            AgentModelMessage.system("System", cacheable = true),
            AgentModelMessage.user("Question")
        ) + complete + listOf(
            AgentModelMessage.assistant(
                toolCalls = listOf(AgentToolCall("call-incomplete", "tool"))
            ),
            AgentModelMessage.user("The group was interrupted"),
            toolMessage("call-incomplete")
        )

        val planned = CacheBreakpointPlanner.mark(source)

        assertEquals(
            listOf("call-1"),
            planned.filter { it.role == AgentModelMessageRole.Tool && it.cacheControl != null }
                .mapNotNull { it.toolCallId }
        )
        assertNull(planned.last().cacheControl)
    }

    @Test
    fun refusesACompleteTurnWhoseBreakpointWouldExceedTheBlockGap() {
        val calls = (1..8).map { index -> AgentToolCall("wide-$index", "tool-$index") }
        val source = buildList {
            add(AgentModelMessage.system("System", cacheable = true))
            add(AgentModelMessage.user("Question"))
            add(AgentModelMessage.assistant(toolCalls = calls))
            calls.forEach { call -> add(toolMessage(call.toolCallId, call.toolName)) }
        }

        val planned = CacheBreakpointPlanner.mark(source)

        assertEquals(1, planned.count { it.cacheControl != null })
        assertTrue(planned.filter { it.role != AgentModelMessageRole.System }
            .all { it.cacheControl == null })
    }

    private fun completeTurn(turn: Int): List<AgentModelMessage> {
        val callId = "call-$turn"
        return listOf(
            AgentModelMessage.assistant(
                toolCalls = listOf(AgentToolCall(callId, "tool-$turn"))
            ),
            toolMessage(callId, "tool-$turn")
        )
    }

    private fun toolMessage(
        toolCallId: String,
        toolName: String = "tool"
    ): AgentModelMessage = AgentModelMessage.fromToolResult(
        AgentToolResult(
            toolCallId = toolCallId,
            toolName = toolName,
            data = mapOf("ok" to true)
        )
    )
}
