// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentToolCall

/**
 * One scripted turn: what the client answers, and how long it pretends to think.
 *
 * [delayMillis] exists so UI and cancellation tests have something to interrupt.
 * It is served with a cancellable `delay`, never a blocking sleep.
 */
data class MockScriptedResponse(
    val response: AgentModelResponse,
    val delayMillis: Long = 0L
) {
    init {
        require(delayMillis >= 0L) { "delayMillis must not be negative." }
    }

    companion object {
        fun toolCalls(calls: List<AgentToolCall>, delayMillis: Long = 0L): MockScriptedResponse =
            MockScriptedResponse(AgentModelResponse.ToolCalls(calls), delayMillis)

        /** A single tool call, which is what the sequential MVP loop expects. */
        fun tool(
            toolCallId: String,
            toolName: String,
            arguments: Map<String, Any?> = emptyMap(),
            delayMillis: Long = 0L
        ): MockScriptedResponse = toolCalls(
            calls = listOf(AgentToolCall(toolCallId, toolName, arguments)),
            delayMillis = delayMillis
        )

        fun final(report: AgentReport, delayMillis: Long = 0L): MockScriptedResponse =
            MockScriptedResponse(
                // Spelled out across all three parameters so the call resolves to
                // the primary constructor rather than one of Final's single-argument
                // convenience overloads.
                AgentModelResponse.Final(report = report, reportJson = null, json = null),
                delayMillis
            )

        /** A Final the host still has to decode, so decoding stays under test. */
        fun finalJson(reportJson: String, delayMillis: Long = 0L): MockScriptedResponse =
            MockScriptedResponse(
                AgentModelResponse.Final(report = null, reportJson = reportJson, json = reportJson),
                delayMillis
            )

        fun refusal(reason: String, delayMillis: Long = 0L): MockScriptedResponse =
            MockScriptedResponse(AgentModelResponse.Refusal(reason), delayMillis)

        fun failure(error: AgentError, delayMillis: Long = 0L): MockScriptedResponse =
            MockScriptedResponse(AgentModelResponse.Failure(error), delayMillis)
    }
}

/**
 * What the script asserts about the request it is about to answer.
 *
 * The point of an expectation is to make a wrong tool trajectory fail loudly at
 * the turn where it diverged, instead of producing a plausible-looking report
 * built from the wrong evidence.  Every field is optional, so a script only
 * pins down what it actually cares about.
 */
data class MockRequestExpectation(
    /**
     * Tool result the previous turn must have delivered.  Checked against the
     * most recent Tool-role message, which is how AgentLoop reports results.
     */
    val expectedToolName: String? = null,
    val expectedToolCallId: String? = null,
    /** The request must carry a definition for each of these tools. */
    val requiredToolDefinitions: Set<String> = emptySet(),
    /** The request must ask for structured output. */
    val requiresResponseSchema: Boolean = false,
    /** Minimum number of messages, e.g. to assert the system prompt survived. */
    val minMessageCount: Int = 0
) {
    /** Describe the first violation, or null when the request is acceptable. */
    fun violation(request: AgentModelRequest): MockExpectationViolation? {
        if (request.messages.size < minMessageCount) {
            return MockExpectationViolation(
                reason = "message_count_too_low",
                expected = minMessageCount.toString(),
                actual = request.messages.size.toString()
            )
        }
        if (requiresResponseSchema && request.responseSchema == null) {
            return MockExpectationViolation(
                reason = "missing_response_schema",
                expected = "responseSchema",
                actual = "null"
            )
        }
        val missingDefinitions = requiredToolDefinitions -
            request.toolDefinitions.map { it.name }.toSet()
        if (missingDefinitions.isNotEmpty()) {
            return MockExpectationViolation(
                reason = "missing_tool_definitions",
                expected = requiredToolDefinitions.sorted().joinToString(),
                actual = missingDefinitions.sorted().joinToString()
            )
        }

        if (expectedToolName == null && expectedToolCallId == null) return null

        val lastToolMessage = request.messages.lastOrNull {
            it.role == AgentModelMessageRole.Tool
        } ?: return MockExpectationViolation(
            reason = "missing_tool_result",
            expected = expectedToolName ?: expectedToolCallId.orEmpty(),
            actual = "none"
        )

        return toolMessageViolation(lastToolMessage)
    }

    private fun toolMessageViolation(message: AgentModelMessage): MockExpectationViolation? {
        if (expectedToolName != null && message.toolName != expectedToolName) {
            return MockExpectationViolation(
                reason = "unexpected_tool_name",
                expected = expectedToolName,
                actual = message.toolName ?: "null"
            )
        }
        if (expectedToolCallId != null && message.toolCallId != expectedToolCallId) {
            return MockExpectationViolation(
                reason = "unexpected_tool_call_id",
                expected = expectedToolCallId,
                actual = message.toolCallId ?: "null"
            )
        }
        return null
    }
}

/** A single failed expectation, rendered into a diagnosable error. */
data class MockExpectationViolation(
    val reason: String,
    val expected: String,
    val actual: String
)

/**
 * A deterministic, offline conversation an [AiModelClient] can replay.
 *
 * A script is a fixed sequence: turn *n* of the run is answered by
 * `responses[n]`, optionally after checking `expectedRequests[n]`.  It never
 * loops, never randomises, and never reads a capture file — running the same
 * script twice produces byte-identical results, which is what makes it usable
 * for both unit tests and Compose previews.
 */
data class MockModelScript(
    val id: String,
    val responses: List<MockScriptedResponse>,
    /**
     * Per-turn assertions, index-aligned with [responses].  A shorter list is
     * fine: turns past its end are answered without checking.
     */
    val expectedRequests: List<MockRequestExpectation?> = emptyList(),
    val capabilities: AiModelCapabilities = AiModelCapabilities.PHASE0,
    /** Human-readable purpose, shown by the debug script picker. */
    val description: String = ""
) {
    init {
        require(id.isNotBlank()) { "MockModelScript id must not be blank." }
        require(responses.isNotEmpty()) { "MockModelScript $id has no responses." }
        require(expectedRequests.size <= responses.size) {
            "MockModelScript $id has more expectations than responses."
        }
    }

    val turnCount: Int
        get() = responses.size

    fun responseAt(turnIndex: Int): MockScriptedResponse? = responses.getOrNull(turnIndex)

    fun expectationAt(turnIndex: Int): MockRequestExpectation? =
        expectedRequests.getOrNull(turnIndex)
}
