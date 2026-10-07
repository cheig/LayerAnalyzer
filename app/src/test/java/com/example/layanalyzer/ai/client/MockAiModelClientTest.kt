package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolDefinition
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MockAiModelClientTest {

    @Test
    fun bootstrapAwareScriptReturnsTheFinalReportInOneTurn() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

        val response = client.respond(request("req-1"))
        val report = (response as AgentModelResponse.Final).report
        assertNotNull(report)
        assertEquals(1, report?.findings?.size)
        assertEquals(1, client.servedTurnCount)
    }

    @Test
    fun requestOffTheExpectedToolTrajectoryFailsDiagnosably() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.INVALID_FILTER_RECOVERY)
        client.respond(request("req-1"))

        // Turn 2 expects the invalid-filter result; hand it the wrong tool instead.
        val response = client.respond(
            request("req-2", toolResult("call-overview", "get_capture_overview"))
        )

        val error = (response as AgentModelResponse.Failure).error
        assertEquals(AgentErrorCode.INTERNAL_ERROR, error.code)
        assertEquals("unexpected_request", error.details["reason"])
        assertEquals("unexpected_tool_name", error.details["violation"])
        assertEquals("validate_display_filter", error.details["expected"])
        assertEquals("get_capture_overview", error.details["actual"])
        // A rejected turn must not consume the script.
        assertEquals(1, client.servedTurnCount)
    }

    @Test
    fun explicitCancelEndsADelayedResponse() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.CANCELLATION)

        val pending = async(Dispatchers.Default) { client.respond(request("req-slow")) }
        client.cancel("req-slow")

        val response = withTimeout(CANCEL_TIMEOUT_MILLIS) { pending.await() }

        val error = (response as AgentModelResponse.Failure).error
        assertEquals(AgentErrorCode.CANCELLED, error.code)
        assertEquals("req-slow", error.details["requestId"])
        // The cancelled turn was never committed, so the script is still at 0.
        assertEquals(0, client.servedTurnCount)
    }

    @Test
    fun cancelIsIdempotentAndScopedToOneRequestId() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.CANCELLATION)

        client.cancel("other-request")
        client.cancel("other-request")

        // A different id is unaffected, so this turn still serves normally.
        val response = withTimeout(CANCEL_TIMEOUT_MILLIS) {
            val pending = async(Dispatchers.Default) { client.respond(request("req-live")) }
            client.cancel("req-live")
            pending.await()
        }

        assertEquals(AgentErrorCode.CANCELLED, (response as AgentModelResponse.Failure).error.code)
        client.cancel("req-live")
        client.cancel("req-live")
    }

    @Test
    fun coroutineCancellationPropagatesInsteadOfBecomingAFailure() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.CANCELLATION)

        val pending = async(Dispatchers.Default) { client.respond(request("req-structured")) }
        pending.cancel()

        val outcome = runCatching { pending.await() }

        assertTrue(outcome.exceptionOrNull() is CancellationException)
        assertEquals(0, client.servedTurnCount)
    }

    @Test
    fun exhaustedScriptReportsADiagnosableErrorInsteadOfRepeatingTheLastTurn() = runBlocking {
        val script = MockModelScript(
            id = "single-turn",
            responses = listOf(
                MockScriptedResponse.tool("call-1", "get_capture_overview")
            )
        )
        val client = MockAiModelClient(script)

        assertToolCalls(client.respond(request("req-1")))
        val exhausted = client.respond(request("req-2"))

        val error = (exhausted as AgentModelResponse.Failure).error
        assertEquals(AgentErrorCode.INTERNAL_ERROR, error.code)
        assertEquals("script_exhausted", error.details["reason"])
        assertEquals("single-turn", error.details["scriptId"])
        assertEquals(1, error.details["turnIndex"])
        assertEquals(1, error.details["turnCount"])
        assertFalse(error.retryable)
    }

    @Test
    fun replayingACommittedRequestIdIsRejected() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)
        client.respond(request("req-1"))

        val replayed = client.respond(request("req-1"))

        val error = (replayed as AgentModelResponse.Failure).error
        assertEquals("duplicate_request_id", error.details["reason"])
        assertEquals(1, client.servedTurnCount)
    }

    @Test
    fun textOnlyCapabilitiesAreVisibleToCallersBeforeAnyRequest() {
        val script = MockModelScript(
            id = "prose-only",
            responses = listOf(MockScriptedResponse.refusal("Tool calling is unavailable.")),
            capabilities = AiModelCapabilities.TEXT_ONLY
        )

        val client = MockAiModelClient(script)

        assertFalse(client.capabilities.toolCalling)
        assertFalse(client.capabilities.parallelToolCalls)
        assertFalse(client.capabilities.structuredOutput)
        assertEquals("mock:prose-only", client.id)
    }

    @Test
    fun parallelToolCallsAreOnlyAnnouncedNotRequired() = runBlocking {
        val script = MockModelScript(
            id = "parallel-capable",
            responses = listOf(
                MockScriptedResponse.toolCalls(
                    listOf(
                        AgentToolCall("call-a", "get_capture_overview"),
                        AgentToolCall("call-b", "get_expert_info")
                    )
                )
            ),
            capabilities = AiModelCapabilities.PHASE0.copy(parallelToolCalls = true)
        )
        val client = MockAiModelClient(script)

        // The client may return two calls at once; AI-05 leaves it to the loop to
        // run them sequentially, so the client itself imposes no ordering.
        val calls = assertToolCalls(client.respond(request("req-1")))

        assertEquals(listOf("call-a", "call-b"), calls.map { it.toolCallId })
    }

    @Test
    fun repeatedRunsOfTheSameScriptProduceIdenticalResults() = runBlocking {
        val firstRun = replayCaptureOverview()
        val secondRun = replayCaptureOverview()

        assertEquals(firstRun, secondRun)
    }

    @Test
    fun resetReplaysTheScriptFromTheFirstTurn() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)
        val before = (client.respond(request("req-1")) as AgentModelResponse.Final).report?.summary

        client.reset()
        val after = (client.respond(request("req-1")) as AgentModelResponse.Final).report?.summary

        assertEquals(before, after)
        assertEquals(1, client.servedTurnCount)
    }

    @Test
    fun responsesCarryNoVendorSpecificFields() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.MAX_STEPS)

        val calls = assertToolCalls(client.respond(request("req-1")))

        // AgentToolCall arguments are the only model-supplied payload, and they
        // must be plain JSON values: no provider envelope, no ids beyond the
        // tool call id the host issued the schema for.
        val arguments = calls.single().arguments
        assertEquals(setOf("scope"), arguments.keys)
        assertTrue(arguments.values.all { it is String || it is Number || it is Boolean })
        assertNull(arguments["type"])
        assertNull(arguments["function"])
    }

    @Test
    fun blankRequestIdIsRejectedBeforeAnyTurnIsServed() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

        val response = client.respond(request(""))

        assertEquals("blank_request_id", (response as AgentModelResponse.Failure).error.details["reason"])
        assertEquals(0, client.servedTurnCount)
    }

    @Test
    fun maxStepsScriptNeverOffersAFinalReport() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.MAX_STEPS)
        val script = MockModelScriptLibrary.require(MockModelScriptLibrary.MAX_STEPS)

        assertTrue(script.turnCount > DEFAULT_MAX_STEPS)
        repeat(DEFAULT_MAX_STEPS) { turn ->
            assertToolCalls(client.respond(request("req-$turn")))
        }
        assertTrue(script.responses.none { it.response is AgentModelResponse.Final })
    }

    @Test
    fun sessionChangedScriptSurfacesTheHostErrorCode() = runBlocking {
        val client = MockAiModelClient.of(MockModelScriptLibrary.SESSION_CHANGED)

        assertToolCalls(client.respond(request("req-1")))
        assertToolCalls(client.respond(request("req-2", toolResult("call-overview", "get_capture_overview"))))
        val failure = client.respond(request("req-3", toolResult("call-expert", "get_expert_info")))

        assertEquals(
            AgentErrorCode.SESSION_CHANGED,
            (failure as AgentModelResponse.Failure).error.code
        )
    }

    @Test
    fun everyBuiltInScriptIsResolvableAndNonEmpty() {
        val ids = MockModelScriptLibrary.ids

        assertTrue(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS in ids)
        assertTrue(MockModelScriptLibrary.INVALID_FILTER_RECOVERY in ids)
        assertTrue(MockModelScriptLibrary.CANCELLATION in ids)
        assertTrue(MockModelScriptLibrary.MAX_STEPS in ids)
        assertTrue(MockModelScriptLibrary.SESSION_CHANGED in ids)
        ids.forEach { id ->
            assertTrue(id, MockModelScriptLibrary.require(id).turnCount > 0)
        }
        assertNull(MockModelScriptLibrary.find("no_such_script"))
    }

    /**
     * Replay the whole happy path, feeding each turn's tool call back as a
     * result, and describe the run as comparable plain data.
     */
    private suspend fun replayCaptureOverview(): List<String> {
        val client = MockAiModelClient.of(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)
        val turnCount = MockModelScriptLibrary
            .require(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)
            .turnCount
        val trace = mutableListOf<String>()
        var pendingResult: AgentModelMessage? = null

        repeat(turnCount) { turn ->
            val request = pendingResult
                ?.let { request("req-$turn", it) }
                ?: request("req-$turn")
            when (val response = client.respond(request)) {
                is AgentModelResponse.ToolCalls -> {
                    val call = response.calls.single()
                    pendingResult = toolResult(call.toolCallId, call.toolName)
                    trace += "tool:${call.toolName}:${call.toolCallId}:${call.arguments}"
                }
                is AgentModelResponse.Final -> trace += "final:${response.report?.summary}"
                is AgentModelResponse.Refusal -> trace += "refusal:${response.reason}"
                is AgentModelResponse.Failure -> trace += "failure:${response.error.code}"
            }
        }
        return trace
    }

    private fun assertToolCalls(response: AgentModelResponse) =
        (response as AgentModelResponse.ToolCalls).calls

    private fun request(
        requestId: String,
        vararg extraMessages: AgentModelMessage
    ) = AgentModelRequest(
        requestId = requestId,
        messages = listOf(AgentModelMessage.user("Why is this capture slow?")) + extraMessages,
        toolDefinitions = TOOL_DEFINITIONS,
        responseSchema = mapOf("type" to "object"),
        maxOutputTokens = 2048
    )

    /**
     * A Tool-role message shaped the way AgentLoop reports a result, which is
     * what the script's expectations inspect.
     */
    private fun toolResult(toolCallId: String, toolName: String) = AgentModelMessage(
        role = AgentModelMessageRole.Tool,
        content = "{}",
        toolCallId = toolCallId,
        toolName = toolName,
        untrustedCaptureData = true
    )

    private companion object {
        const val CANCEL_TIMEOUT_MILLIS = 2_000L

        /** Matches AgentPolicy's default step ceiling. */
        const val DEFAULT_MAX_STEPS = 12

        val TOOL_DEFINITIONS = listOf(
            AgentToolDefinition(name = "get_capture_overview"),
            AgentToolDefinition(name = "get_expert_info"),
            AgentToolDefinition(name = "validate_display_filter")
        )
    }
}
