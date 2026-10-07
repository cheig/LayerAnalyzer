package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ContextPlannerEstimateCacheTest {
    @Test
    fun completePlanEstimatesEachMessageInstanceOnlyOnce() {
        val estimator = CountingTokenEstimator()
        val source = listOf(
            AgentModelMessage.system(SYSTEM_CONTENT),
            AgentModelMessage.user(USER_CONTENT),
            AgentModelMessage.assistant(
                content = ASSISTANT_CONTENT,
                toolCalls = listOf(
                    AgentToolCall("call-1", "tool-one"),
                    AgentToolCall("call-2", "tool-two")
                )
            ),
            toolMessage("call-1", "tool-one", TOOL_ONE_CONTENT),
            toolMessage("call-2", "tool-two", TOOL_TWO_CONTENT)
        )

        val plan = planner(estimator).plan(
            source = source,
            reportedContextLimit = 1_000,
            reportedOutputLimit = 1
        )

        assertEquals(source, plan.messages)
        assertTrue(plan.trimmed)
        listOf(
            SYSTEM_CONTENT,
            USER_CONTENT,
            ASSISTANT_CONTENT,
            TOOL_ONE_CONTENT,
            TOOL_TWO_CONTENT
        ).forEach { content ->
            assertEquals("Unexpected estimate count for $content", 1, estimator.callsFor(content))
        }
    }

    @Test
    fun equalMessagesWithDifferentIdentitiesAreEstimatedSeparately() {
        val estimator = CountingTokenEstimator()
        val first = AgentModelMessage.user(DUPLICATE_CONTENT)
        val second = AgentModelMessage.user(DUPLICATE_CONTENT)
        assertEquals(first, second)
        assertNotSame(first, second)

        planner(estimator).plan(
            source = listOf(first, second),
            reportedContextLimit = 1_000,
            reportedOutputLimit = 1
        )

        assertEquals(2, estimator.callsFor(DUPLICATE_CONTENT))
    }

    @Test
    fun consecutivePlanCallsDoNotShareMessageEstimates() {
        val estimator = CountingTokenEstimator()
        val message = AgentModelMessage.user(REQUEST_SCOPED_CONTENT)
        val planner = planner(estimator)

        planner.plan(listOf(message), reportedContextLimit = 1_000, reportedOutputLimit = 1)
        assertEquals(1, estimator.callsFor(REQUEST_SCOPED_CONTENT))

        planner.plan(listOf(message), reportedContextLimit = 1_000, reportedOutputLimit = 1)
        assertEquals(2, estimator.callsFor(REQUEST_SCOPED_CONTENT))
    }

    @Test
    fun compactToolMessageGetsItsOwnEstimateAsANewInstance() {
        val estimator = CountingTokenEstimator { text ->
            when {
                FULL_PAYLOAD_SENTINEL in text -> 500
                text.isEmpty() -> 0
                else -> 1
            }
        }
        val full = toolMessage(
            toolCallId = "call-compact",
            toolName = "large-tool",
            content = FULL_TOOL_CONTENT,
            data = mapOf("payload" to FULL_PAYLOAD_SENTINEL)
        )
        val source = listOf(
            AgentModelMessage.system("compact-system"),
            AgentModelMessage.user("compact-user"),
            AgentModelMessage.assistant(
                toolCalls = listOf(AgentToolCall("call-compact", "large-tool"))
            ),
            full
        )

        val plan = planner(estimator).plan(
            source = source,
            reportedContextLimit = 50,
            reportedOutputLimit = 1
        )

        val compact = checkNotNull(plan.compactedByToolCallId["call-compact"])
        assertNotSame(full, compact)
        assertSame(compact, plan.messages.first { it.toolCallId == "call-compact" })
        assertEquals(1, estimator.callsFor(FULL_TOOL_CONTENT))
        assertEquals(1, estimator.callsContaining(FULL_PAYLOAD_SENTINEL))
        assertEquals(1, estimator.callsFor(COMPACT_TOOL_CONTENT))
        assertEquals(40, plan.estimatedInputTokens)
        assertTrue(plan.trimmed)
        assertFalse(plan.partial)
    }

    @Test
    fun protectedPartialReturnReusesFixedEstimatesAndDoesNotMutateSource() {
        val estimator = CountingTokenEstimator()
        val system = AgentModelMessage.system(PARTIAL_SYSTEM_CONTENT)
        val user = AgentModelMessage.user(PARTIAL_USER_CONTENT)
        val protectedTool = toolMessage(
            toolCallId = "protected-call",
            toolName = "protected-tool",
            content = PROTECTED_TOOL_CONTENT,
            truncated = true
        )
        val source = mutableListOf(system, user, protectedTool)
        val sourceValues = source.map { it.copy() }
        val sourceReferences = source.toList()

        val plan = planner(estimator).plan(
            source = source,
            reportedContextLimit = 26,
            reportedOutputLimit = 1
        )

        assertEquals(listOf(system, user), plan.messages)
        assertSame(system, plan.messages[0])
        assertSame(user, plan.messages[1])
        assertEquals(20, plan.estimatedInputTokens)
        assertEquals(1, plan.reservedOutputTokens)
        assertEquals(26, plan.contextLimitTokens)
        assertTrue(plan.trimmed)
        assertTrue(plan.partial)
        assertTrue("protected-call" in plan.compactedByToolCallId)
        assertEquals(1, estimator.callsFor(PARTIAL_SYSTEM_CONTENT))
        assertEquals(1, estimator.callsFor(PARTIAL_USER_CONTENT))
        assertEquals(1, estimator.callsFor(PROTECTED_TOOL_CONTENT))
        assertEquals(1, estimator.callsFor(COMPACT_TOOL_CONTENT))

        assertEquals(sourceValues, source)
        sourceReferences.indices.forEach { index ->
            assertSame(sourceReferences[index], source[index])
        }
    }

    @Test
    fun finalSummaryPlanningUsesTheSamePerRequestEstimateCache() {
        val estimator = CountingTokenEstimator()
        val source = listOf(
            AgentModelMessage.system(SUMMARY_SYSTEM_CONTENT),
            AgentModelMessage.user(SUMMARY_QUESTION_CONTENT),
            AgentModelMessage.assistant(
                content = SUMMARY_ASSISTANT_CONTENT,
                toolCalls = listOf(AgentToolCall("summary-call", "summary-tool"))
            ),
            toolMessage("summary-call", "summary-tool", "summary-full-tool-content"),
            AgentModelMessage.user(SUMMARY_FINAL_CONTENT)
        )

        val plan = planner(estimator).planForFinalSummary(
            source = source,
            reportedContextLimit = 1_000,
            reportedOutputLimit = 1
        )

        assertFalse(plan.partial)
        listOf(
            SUMMARY_SYSTEM_CONTENT,
            SUMMARY_QUESTION_CONTENT,
            SUMMARY_FINAL_CONTENT,
            COMPACT_TOOL_CONTENT
        ).forEach { content ->
            assertEquals("Unexpected estimate count for $content", 1, estimator.callsFor(content))
        }
        val summaryAssistant = plan.messages.single {
            it.role == AgentModelMessageRole.Assistant &&
                it.toolCalls.any { call -> call.toolCallId == "summary-call" }
        }
        assertTrue(summaryAssistant.content.isEmpty())
    }

    private fun planner(estimator: TokenEstimator): ContextPlanner = ContextPlanner(
        estimator = estimator,
        defaultContextTokens = 1_000,
        defaultOutputReserve = 1
    )

    private fun toolMessage(
        toolCallId: String,
        toolName: String,
        content: String,
        data: Map<String, Any?> = mapOf("ok" to true),
        truncated: Boolean = false
    ): AgentModelMessage = AgentModelMessage.fromToolResult(
        AgentToolResult(
            toolCallId = toolCallId,
            toolName = toolName,
            truncated = truncated,
            data = data
        ),
        content
    )

    private class CountingTokenEstimator(
        private val estimateTokens: (String) -> Int = { text ->
            if (text.isEmpty()) 0 else 1
        }
    ) : TokenEstimator {
        private val callsByText = linkedMapOf<String, Int>()

        override fun estimate(text: String): Int {
            callsByText[text] = callsByText.getOrDefault(text, 0) + 1
            return estimateTokens(text)
        }

        fun callsFor(text: String): Int = callsByText[text] ?: 0

        fun callsContaining(fragment: String): Int = callsByText.entries
            .filter { (text, _) -> fragment in text }
            .sumOf { (_, count) -> count }
    }

    private companion object {
        const val SYSTEM_CONTENT = "estimate-cache-system-content"
        const val USER_CONTENT = "estimate-cache-user-content"
        const val ASSISTANT_CONTENT = "estimate-cache-assistant-content"
        const val TOOL_ONE_CONTENT = "estimate-cache-tool-one-content"
        const val TOOL_TWO_CONTENT = "estimate-cache-tool-two-content"
        const val DUPLICATE_CONTENT = "estimate-cache-duplicate-content"
        const val REQUEST_SCOPED_CONTENT = "estimate-cache-request-scoped-content"
        const val FULL_TOOL_CONTENT = "estimate-cache-full-tool-content"
        const val FULL_PAYLOAD_SENTINEL = "estimate-cache-full-payload-sentinel"
        const val COMPACT_TOOL_CONTENT = "Earlier tool result compacted by host."
        const val PARTIAL_SYSTEM_CONTENT = "estimate-cache-partial-system-content"
        const val PARTIAL_USER_CONTENT = "estimate-cache-partial-user-content"
        const val PROTECTED_TOOL_CONTENT = "estimate-cache-protected-tool-content"
        const val SUMMARY_SYSTEM_CONTENT = "estimate-cache-summary-system-content"
        const val SUMMARY_QUESTION_CONTENT = "estimate-cache-summary-question-content"
        const val SUMMARY_ASSISTANT_CONTENT = "estimate-cache-summary-assistant-content"
        const val SUMMARY_FINAL_CONTENT = "estimate-cache-summary-final-content"
    }
}
