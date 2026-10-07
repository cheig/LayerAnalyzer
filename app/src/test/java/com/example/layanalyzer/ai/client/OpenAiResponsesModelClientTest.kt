package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.agent.AgentReasoningEffort
import com.example.layanalyzer.ai.agent.ConversationHistorySanitizer
import com.example.layanalyzer.ai.agent.PromptAssembler
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OpenAiResponsesModelClientTest {
    @Test
    fun sendsResponsesInputAndMapsFunctionCall() = runBlocking {
        val transport = FakeTransport(
            AgentHttpResponse(
                200,
                body = """
                    {
                      "output": [{
                        "type": "function_call",
                        "id": "fc_1",
                        "call_id": "call-overview",
                        "name": "get_capture_overview",
                        "arguments": "{\"scope\":\"complete_file\"}"
                      }],
                      "status": "completed",
                      "usage": {
                        "input_tokens": 140,
                        "output_tokens": 22,
                        "input_tokens_details": {"cached_tokens": 64}
                      }
                    }
                """.trimIndent()
            )
        )
        val client = client(transport)

        val response = client.respond(request())

        val call = (response as AgentModelResponse.ToolCalls).calls.single()
        assertEquals("call-overview", call.toolCallId)
        assertEquals("complete_file", call.arguments["scope"])
        assertEquals("fc_1", call.responseItemId)
        assertEquals(140, response.usage?.inputTokens)
        assertEquals(22, response.usage?.outputTokens)
        assertEquals(64, response.usage?.cachedInputTokens)
        val sent = transport.requests.single()
        assertEquals("https://api.example/v1/responses", sent.url)
        assertEquals("Bearer secret-key", sent.headers["Authorization"])
        val body = JSONObject(sent.body.orEmpty())
        assertEquals("real-model", body.getString("model"))
        assertTrue(body.has("instructions"))
        assertTrue(body.has("text"))
        assertEquals(
            "function",
            body.getJSONArray("tools").getJSONObject(0).getString("type")
        )
        val replay = JSONObject(
            client.encodeRequest(
                request().copy(
                    messages = request().messages + AgentModelMessage.assistant(toolCalls = listOf(call))
                )
            )
        )
        val replayedCall = (0 until replay.getJSONArray("input").length())
            .map { replay.getJSONArray("input").getJSONObject(it) }
            .first { it.optString("type") == "function_call" }
        assertEquals("fc_1", replayedCall.getString("id"))
        assertFalse(sent.body.orEmpty().contains("secret-key"))
    }

    @Test
    fun reasoningEffortIsEncodedAsResponsesReasoningObject() {
        val omitted = JSONObject(client(FakeTransport(AgentHttpResponse(200, body = "{}"))).encodeRequest(request()))
        val configured = JSONObject(
            client(
                FakeTransport(AgentHttpResponse(200, body = "{}")),
                reasoningEffort = AgentReasoningEffort.HIGH
            ).encodeRequest(request())
        )

        assertFalse(omitted.has("reasoning"))
        assertEquals("high", configured.getJSONObject("reasoning").getString("effort"))
        assertFalse(configured.getJSONObject("reasoning").has("context"))
        assertFalse(configured.has("reasoning_effort"))
    }

    @Test
    fun serializesAHostBootstrapCallAndItsPairedOutputInTheFirstRequest() {
        val client = client(FakeTransport(AgentHttpResponse(200, body = "{}")))
        val call = AgentToolCall(
            toolCallId = "host-bootstrap-overview-1",
            toolName = "get_capture_overview"
        )
        val result = AgentToolResult(
            toolCallId = call.toolCallId,
            toolName = call.toolName,
            success = true,
            data = mapOf("frameCount" to 12)
        )
        val encoded = JSONObject(
            client.encodeRequest(
                request().copy(
                    messages = request().messages +
                        AgentModelMessage.assistant(toolCalls = listOf(call)) +
                        AgentModelMessage.fromToolResult(result)
                )
            )
        ).getJSONArray("input")
        val items = (0 until encoded.length()).map { encoded.getJSONObject(it) }

        val functionCall = items.first { it.optString("type") == "function_call" }
        val functionOutput = items.first { it.optString("type") == "function_call_output" }
        assertEquals(call.toolCallId, functionCall.getString("call_id"))
        assertFalse(functionCall.has("id"))
        assertEquals(call.toolCallId, functionOutput.getString("call_id"))
        assertTrue(functionOutput.getString("output").contains("frameCount"))
    }

    @Test
    fun mapsStructuredResponseTextToFinalReport() = runBlocking {
        val transport = FakeTransport(
            AgentHttpResponse(
                200,
                body = JSONObject()
                    .put(
                        "output",
                        org.json.JSONArray().put(
                            JSONObject()
                                .put("type", "message")
                                .put("role", "assistant")
                                .put(
                                    "content",
                                    org.json.JSONArray().put(
                                        JSONObject()
                                            .put("type", "output_text")
                                            .put(
                                                "text",
                                                "{\"summary\":\"Responses final\",\"findings\":[]}"
                                            )
                                    )
                                )
                        )
                    )
                    .put("status", "completed")
                    .toString()
            )
        )

        val response = client(transport).respond(request())

        assertTrue(
            "Unexpected response: $response",
            response is AgentModelResponse.Final
        )
        assertEquals("Responses final", (response as AgentModelResponse.Final).report?.summary)
    }

    /**
     * Wire-format smoke for the P1 continuation flow, and the written-down
     * answer to the plan's §11.1 question: a replayed history whose tool calls
     * carry no response item id serializes as function_call/function_call_output
     * pairs keyed only by call_id. The Responses path therefore does not depend
     * on replaying provider-side response items.
     */
    @Test
    fun replayedContinuationHistoryEncodesFunctionCallPairsWithoutResponseItemIds() {
        val body = JSONObject(
            client(FakeTransport(AgentHttpResponse(200, body = "{}")))
                .encodeRequest(continuationRequest())
        )
        val bodyText = body.toString()

        assertTrue(body.getString("instructions").contains("approved tools"))

        val input = body.getJSONArray("input")
        val items = (0 until input.length()).map { input.getJSONObject(it) }
        assertEquals(6, items.size)

        val priorQuestion = items[0]
        assertEquals("message", priorQuestion.getString("type"))
        assertEquals("user", priorQuestion.getString("role"))
        assertEquals(
            PRIOR_QUESTION,
            priorQuestion.getJSONArray("content").getJSONObject(0).getString("text")
        )

        val toolNarration = items[1]
        assertEquals("message", toolNarration.getString("type"))
        assertEquals("assistant", toolNarration.getString("role"))

        // The pair is keyed by call_id alone: no item may carry an `id`, which
        // references state from the HTTP session that produced it.
        val functionCall = items[2]
        assertEquals("function_call", functionCall.getString("type"))
        assertEquals("call-overview", functionCall.getString("call_id"))
        assertEquals("get_capture_overview", functionCall.getString("name"))
        assertEquals("{\"scope\":\"complete_file\"}", functionCall.getString("arguments"))
        assertFalse(functionCall.has("id"))

        val functionOutput = items[3]
        assertEquals("function_call_output", functionOutput.getString("type"))
        assertEquals("call-overview", functionOutput.getString("call_id"))
        assertTrue(functionOutput.getString("output").contains("frameCount"))

        val conclusion = items[4]
        assertEquals("message", conclusion.getString("type"))
        assertEquals("assistant", conclusion.getString("role"))
        assertEquals(PRIOR_CONCLUSION, conclusion.getJSONArray("content").getJSONObject(0).getString("text"))

        val followUp = items[5]
        assertEquals("message", followUp.getString("type"))
        assertEquals("user", followUp.getString("role"))
        val followUpText = followUp.getJSONArray("content").getJSONObject(0).getString("text")
        assertTrue(followUpText.startsWith(FOLLOW_UP))
        assertTrue(followUpText.contains(PromptAssembler.CONTINUATION_NOTICE.trim()))

        // Belt and braces over the per-item assertions: no stale response item
        // id anywhere in the encoded request.
        assertFalse(bodyText.contains("\"id\""))
        assertFalse(bodyText.contains(RESPONSE_ITEM_ID_LEFTOVER))
    }

    /**
     * A follow-up request exactly as PromptAssembler assembles it: fresh system,
     * the sanitized prior-round transcript, then the continuation user message.
     * The prior transcript carries deliberate producing-session leftovers (a
     * cache breakpoint, a response item id, vendor reasoning) to prove they are
     * gone by the time the request is encoded.
     */
    private fun continuationRequest(): AgentModelRequest {
        val overview = AgentToolCall(
            toolCallId = "call-overview",
            toolName = "get_capture_overview",
            arguments = mapOf("scope" to "complete_file"),
            responseItemId = RESPONSE_ITEM_ID_LEFTOVER
        )
        val priorTranscript = listOf(
            AgentModelMessage.user(PRIOR_QUESTION).withCacheBreakpoint(),
            AgentModelMessage.assistant(
                content = "I will inspect the capture overview.",
                toolCalls = listOf(overview),
                reasoningContent = ""
            ),
            AgentModelMessage.fromToolResult(
                AgentToolResult(
                    toolCallId = overview.toolCallId,
                    toolName = overview.toolName,
                    success = true,
                    data = mapOf("frameCount" to 12)
                )
            ),
            AgentModelMessage.assistant(content = PRIOR_CONCLUSION)
                .copy(reasoningContent = "vendor thinking that must not replay")
                .withCacheBreakpoint()
        )
        return AgentModelRequest(
            requestId = "req-followup",
            messages = listOf(
                AgentModelMessage.system("Use the approved tools.", cacheable = true)
            ) +
                ConversationHistorySanitizer.sanitize(priorTranscript) +
                AgentModelMessage.user("$FOLLOW_UP\n\n${PromptAssembler.CONTINUATION_NOTICE.trim()}"),
            toolDefinitions = listOf(
                AgentToolDefinition(
                    name = "get_capture_overview",
                    inputSchema = mapOf("type" to "object")
                )
            ),
            responseSchema = mapOf("type" to "object"),
            privacyMode = AgentPrivacyMode.RedactedMetadata
        )
    }

    private companion object {
        const val PRIOR_QUESTION = "Which TLS servers appear in this capture?"
        const val PRIOR_CONCLUSION = "The previous round concluded that 10.0.0.5 spoke TLS on port 443."
        const val FOLLOW_UP = "How many frames involved that server?"
        const val RESPONSE_ITEM_ID_LEFTOVER = "resp-item-forgotten-1"
    }

    private fun client(
        transport: AgentHttpTransport,
        reasoningEffort: AgentReasoningEffort = AgentReasoningEffort.UNSPECIFIED
    ) = OpenAiResponsesModelClient(
        apiBaseUrl = "https://api.example",
        transport = transport,
        providerId = "provider",
        modelId = "real-model",
        apiKeyProvider = { "secret-key" },
        reasoningEffort = reasoningEffort
    )

    private fun request() = AgentModelRequest(
        requestId = "req-1",
        messages = listOf(
            AgentModelMessage.system("Use the approved tools."),
            AgentModelMessage.user("Analyze the capture")
        ),
        toolDefinitions = listOf(
            AgentToolDefinition(
                name = "get_capture_overview",
                inputSchema = mapOf("type" to "object")
            )
        ),
        responseSchema = mapOf("type" to "object"),
        privacyMode = AgentPrivacyMode.RedactedMetadata
    )

    private class FakeTransport(private val response: AgentHttpResponse) : AgentHttpTransport {
        val requests = mutableListOf<AgentHttpRequest>()

        override suspend fun execute(request: AgentHttpRequest): AgentHttpResponse {
            requests += request
            return response
        }

        override fun cancel(requestId: String) = Unit
    }
}
