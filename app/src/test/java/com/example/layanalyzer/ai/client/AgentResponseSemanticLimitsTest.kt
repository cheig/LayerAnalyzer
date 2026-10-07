// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentToolCall
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentResponseSemanticLimitsTest {
    @Test
    fun finalReportAndReasoningHaveIndependentSemanticLimits() {
        val largeReport = AgentModelResponse.Final(
            report = AgentReport(summary = "r".repeat(AgentResponseSemanticLimits.MAX_FINAL_REPORT_BYTES.toInt()))
        )
        val largeReasoning = AgentModelResponse.Final(
            report = AgentReport(summary = "ok"),
            reasoningContent = "q".repeat(AgentResponseSemanticLimits.MAX_REASONING_BYTES.toInt() + 1)
        )

        assertLimit(largeReport, "final_report", AgentResponseSemanticLimits.MAX_FINAL_REPORT_BYTES)
        assertLimit(largeReasoning, "reasoning", AgentResponseSemanticLimits.MAX_REASONING_BYTES)
    }

    @Test
    fun toolArgumentLimitsDistinguishSingleAndAggregatePayloads() {
        val single = AgentModelResponse.ToolCalls(
            calls = listOf(
                AgentToolCall(
                    toolCallId = "one",
                    toolName = "inspect",
                    arguments = mapOf("value" to "x".repeat(
                        AgentResponseSemanticLimits.MAX_SINGLE_TOOL_ARGUMENT_BYTES.toInt() + 1
                    ))
                )
            )
        )
        val unit = "x".repeat(40 * 1024)
        val aggregate = AgentModelResponse.ToolCalls(
            calls = listOf(
                AgentToolCall("one", "inspect", mapOf("value" to unit)),
                AgentToolCall("two", "inspect", mapOf("value" to unit)),
                AgentToolCall("three", "inspect", mapOf("value" to unit)),
                AgentToolCall("four", "inspect", mapOf("value" to unit)),
                AgentToolCall("five", "inspect", mapOf("value" to unit)),
                AgentToolCall("six", "inspect", mapOf("value" to unit)),
                AgentToolCall("seven", "inspect", mapOf("value" to unit))
            )
        )

        assertLimit(single, "tool_arguments[0]", AgentResponseSemanticLimits.MAX_SINGLE_TOOL_ARGUMENT_BYTES)
        assertLimit(aggregate, "tool_arguments_total", AgentResponseSemanticLimits.MAX_TOTAL_TOOL_ARGUMENT_BYTES)
    }

    private fun assertLimit(
        response: AgentModelResponse,
        field: String,
        limit: Long
    ) {
        val failure = AgentResponseSemanticLimits.validate(response) as AgentModelResponse.Failure
        assertEquals(AgentErrorCode.MODEL_RESPONSE_TOO_LARGE, failure.error.code)
        assertEquals("semantic_limit", failure.error.details["reason"])
        assertEquals(field, failure.error.details["semanticField"])
        assertEquals(limit, failure.error.details["semanticLimitBytes"])
        assertTrue(failure.error.details.values.none { it.toString().contains("xxxxx") })
    }
}
