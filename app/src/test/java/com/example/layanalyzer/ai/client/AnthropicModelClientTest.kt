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

class AnthropicModelClientTest {
    @Test
    fun sendsMessagesHeadersAndMapsToolUse() = runBlocking {
        val transport = FakeTransport(
            AgentHttpResponse(
                200,
                body = """
                    {
                      "type": "message",
                      "role": "assistant",
                      "content": [{
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "get_capture_overview",
                        "input": {"scope":"complete_file"}
                      }],
                      "stop_reason": "tool_use",
                      "usage": {
                        "input_tokens": 120,
                        "output_tokens": 18,
                        "cache_read_input_tokens": 40,
                        "cache_creation_input_tokens": 12
                      }
                    }
                """.trimIndent()
            )
        )

        val response = client(transport).respond(request())

        val call = (response as AgentModelResponse.ToolCalls).calls.single()
        assertEquals("toolu_1", call.toolCallId)
        assertEquals("complete_file", call.arguments["scope"])
        assertEquals(172, response.usage?.inputTokens)
        assertEquals(18, response.usage?.outputTokens)
        assertEquals(40, response.usage?.cachedInputTokens)
        assertEquals(12, response.usage?.cacheCreationTokens)
        assertEquals(132, response.usage?.billableInputTokens)
        val sent = transport.requests.single()
        assertEquals("https://api.anthropic.com/v1/messages", sent.url)
        assertEquals("secret-key", sent.headers["x-api-key"])
        assertEquals("2023-06-01", sent.headers["anthropic-version"])
        val body = JSONObject(sent.body.orEmpty())
        assertEquals("claude-model", body.getString("model"))
        val system = body.getJSONArray("system")
        assertTrue(system.getJSONObject(0).getString("text").contains("approved tools"))
        assertEquals(
            "ephemeral",
            system.getJSONObject(0).getJSONObject("cache_control").getString("type")
        )
        assertEquals("user", body.getJSONArray("messages").getJSONObject(0).getString("role"))
        assertEquals(
            "get_capture_overview",
            body.getJSONArray("tools").getJSONObject(0).getString("name")
        )
        assertFalse(sent.body.orEmpty().contains("secret-key"))
    }

    @Test
    fun reasoningEffortIsEncodedAsAnthropicThinkingBudget() {
        val omitted = JSONObject(client(FakeTransport(AgentHttpResponse(200, body = "{}"))).encodeRequest(request()))
        val disabled = JSONObject(
            client(
                FakeTransport(AgentHttpResponse(200, body = "{}")),
                reasoningEffort = AgentReasoningEffort.NONE
            ).encodeRequest(request())
        )
        val enabled = JSONObject(
            client(
                FakeTransport(AgentHttpResponse(200, body = "{}")),
                reasoningEffort = AgentReasoningEffort.XHIGH
            ).encodeRequest(request())
        )

        assertFalse(omitted.has("thinking"))
        assertEquals("disabled", disabled.getJSONObject("thinking").getString("type"))
        assertEquals(omitted.getInt("max_tokens"), disabled.getInt("max_tokens"))
        assertEquals("enabled", enabled.getJSONObject("thinking").getString("type"))
        assertEquals(
            AgentReasoningEffort.ANTHROPIC_BUDGET_XHIGH,
            enabled.getJSONObject("thinking").getInt("budget_tokens")
        )
        assertEquals(
            omitted.getInt("max_tokens") + AgentReasoningEffort.ANTHROPIC_BUDGET_XHIGH,
            enabled.getInt("max_tokens")
        )
    }

    @Test
    fun cacheReadAndCreationAreIncludedInNormalizedTotalInput() {
        val usage = AgentTokenUsageParser.anthropic(
            JSONObject(
                """{"usage":{"input_tokens":21,"output_tokens":9,"cache_read_input_tokens":188000,"cache_creation_input_tokens":1000}}"""
            )
        )

        assertEquals(189_021, usage?.inputTokens)
        assertEquals(188_000, usage?.cachedInputTokens)
        assertEquals(1_000, usage?.cacheCreationTokens)
        assertEquals(1_021, usage?.billableInputTokens)
    }

    @Test
    fun encodesToolResultAsUserToolResultAndParsesFinalText() = runBlocking {
        val transport = FakeTransport(
            AgentHttpResponse(
                200,
                body = """
                    {
                      "type": "message",
                      "role": "assistant",
                      "content": [{
                        "type": "text",
                        "text": "{\"summary\":\"Anthropic final\",\"findings\":[]}"
                      }],
                      "stop_reason": "end_turn"
                    }
                """.trimIndent()
            )
        )
        val request = request().copy(
            messages = request().messages +
                AgentModelMessage.assistant(
                    toolCalls = listOf(
                        com.example.layanalyzer.model.AgentToolCall(
                            "toolu_1",
                            "get_capture_overview"
                        )
                    )
                ) +
                AgentModelMessage.fromToolResult(
                    com.example.layanalyzer.model.AgentToolResult(
                        toolCallId = "toolu_1",
                        toolName = "get_capture_overview",
                        data = mapOf("packetCount" to 4)
                    )
                )
        )

        val response = client(transport).respond(request)

        assertEquals("Anthropic final", (response as AgentModelResponse.Final).report?.summary)
        val messages = JSONObject(transport.requests.single().body.orEmpty())
            .getJSONArray("messages")
        assertEquals("assistant", messages.getJSONObject(1).getString("role"))
        assertEquals("user", messages.getJSONObject(2).getString("role"))
        assertEquals(
            "tool_result",
            messages.getJSONObject(2).getJSONArray("content").getJSONObject(0).getString("type")
        )
    }

    @Test
    fun messageBreakpointsAttachOnlyToEachMessagesLastContentBlock() {
        val request = request().copy(
            messages = listOf(
                AgentModelMessage.system("Use the approved tools.", cacheable = true),
                AgentModelMessage.user("Analyze the capture").withCacheBreakpoint(),
                AgentModelMessage.assistant(
                    content = "I will inspect two views.",
                    toolCalls = listOf(
                        com.example.layanalyzer.model.AgentToolCall("toolu_1", "first_tool"),
                        com.example.layanalyzer.model.AgentToolCall("toolu_2", "second_tool")
                    )
                ).withCacheBreakpoint(),
                AgentModelMessage.assistant("Additional assistant text."),
                AgentModelMessage.fromToolResult(
                    com.example.layanalyzer.model.AgentToolResult(
                        toolCallId = "toolu_1",
                        toolName = "first_tool",
                        data = mapOf("ok" to true)
                    )
                ).withCacheBreakpoint(),
                AgentModelMessage.fromToolResult(
                    com.example.layanalyzer.model.AgentToolResult(
                        toolCallId = "toolu_2",
                        toolName = "second_tool",
                        data = mapOf("ok" to true)
                    )
                )
            )
        )

        val body = JSONObject(
            client(FakeTransport(AgentHttpResponse(200))).encodeRequest(request)
        )
        val messages = body.getJSONArray("messages")
        val userText = messages.getJSONObject(0).getJSONArray("content")
        val assistant = messages.getJSONObject(1).getJSONArray("content")
        val toolResults = messages.getJSONObject(2).getJSONArray("content")

        assertTrue(userText.getJSONObject(0).has("cache_control"))
        assertFalse(assistant.getJSONObject(0).has("cache_control"))
        assertFalse(assistant.getJSONObject(1).has("cache_control"))
        assertTrue(assistant.getJSONObject(2).has("cache_control"))
        assertFalse(assistant.getJSONObject(3).has("cache_control"))
        assertTrue(toolResults.getJSONObject(0).has("cache_control"))
        assertFalse(toolResults.getJSONObject(1).has("cache_control"))

        val system = body.getJSONArray("system")
        assertTrue(system.getJSONObject(0).has("cache_control"))
        assertFalse(system.getJSONObject(1).has("cache_control"))
        assertEquals(4, countCacheBreakpoints(body))
    }

    private fun countCacheBreakpoints(body: JSONObject): Int {
        var count = 0
        val system = body.getJSONArray("system")
        for (index in 0 until system.length()) {
            if (system.getJSONObject(index).has("cache_control")) count += 1
        }
        val messages = body.getJSONArray("messages")
        for (messageIndex in 0 until messages.length()) {
            val content = messages.getJSONObject(messageIndex).getJSONArray("content")
            for (blockIndex in 0 until content.length()) {
                if (content.getJSONObject(blockIndex).has("cache_control")) count += 1
            }
        }
        return count
    }

    /**
     * Wire-format smoke for the P1 continuation flow: a sanitized prior-round
     * transcript re-assembled per PromptAssembler must reach the Anthropic
     * Messages API as tool_use/tool_result blocks with no thinking, cache, or
     * response-item state from the producing session.
     */
    @Test
    fun replayedContinuationHistoryEncodesSanitizedMessagesWireFormat() {
        val body = JSONObject(
            client(FakeTransport(AgentHttpResponse(200))).encodeRequest(continuationRequest())
        )
        val bodyText = body.toString()

        // The fresh host system block holds the only cache breakpoint.
        assertEquals(1, countCacheBreakpoints(body))
        assertTrue(
            body.getJSONArray("system").getJSONObject(0).getString("text")
                .contains("approved tools")
        )

        val messages = body.getJSONArray("messages")
        assertEquals(5, messages.length())

        val priorQuestion = messages.getJSONObject(0)
        assertEquals("user", priorQuestion.getString("role"))
        assertEquals(
            PRIOR_QUESTION,
            priorQuestion.getJSONArray("content").getJSONObject(0).getString("text")
        )

        val toolTurn = messages.getJSONObject(1)
        assertEquals("assistant", toolTurn.getString("role"))
        val toolTurnBlocks = toolTurn.getJSONArray("content")
        assertEquals(2, toolTurnBlocks.length())
        assertEquals("text", toolTurnBlocks.getJSONObject(0).getString("type"))
        val toolUse = toolTurnBlocks.getJSONObject(1)
        assertEquals("tool_use", toolUse.getString("type"))
        assertEquals("call-overview", toolUse.getString("id"))
        assertEquals("get_capture_overview", toolUse.getString("name"))
        assertEquals("complete_file", toolUse.getJSONObject("input").getString("scope"))

        val toolResultTurn = messages.getJSONObject(2)
        assertEquals("user", toolResultTurn.getString("role"))
        val toolResult = toolResultTurn.getJSONArray("content").getJSONObject(0)
        assertEquals("tool_result", toolResult.getString("type"))
        assertEquals("call-overview", toolResult.getString("tool_use_id"))
        assertTrue(toolResult.getString("content").contains("frameCount"))

        val conclusionTurn = messages.getJSONObject(3)
        assertEquals("assistant", conclusionTurn.getString("role"))
        assertEquals(
            PRIOR_CONCLUSION,
            conclusionTurn.getJSONArray("content").getJSONObject(0).getString("text")
        )

        val followUp = messages.getJSONObject(4)
        assertEquals("user", followUp.getString("role"))
        assertTrue(
            followUp.getJSONArray("content").getJSONObject(0).getString("text")
                .startsWith(FOLLOW_UP)
        )
        assertTrue(
            followUp.getJSONArray("content").getJSONObject(0).getString("text")
                .contains(PromptAssembler.CONTINUATION_NOTICE.trim())
        )

        // Nothing vendor-session-shaped may survive export: no thinking blocks,
        // no stale response item ids, no message-level cache breakpoints.
        assertFalse(bodyText.contains("\"thinking\""))
        assertFalse(bodyText.contains("\"reasoning\""))
        assertFalse(bodyText.contains(RESPONSE_ITEM_ID_LEFTOVER))
        assertFalse(bodyText.contains("vendor thinking that must not replay"))
    }

    private fun client(
        transport: AgentHttpTransport,
        reasoningEffort: AgentReasoningEffort = AgentReasoningEffort.UNSPECIFIED
    ) = AnthropicModelClient(
        apiBaseUrl = "https://api.anthropic.com",
        transport = transport,
        providerId = "provider",
        modelId = "claude-model",
        apiKeyProvider = { "secret-key" },
        reasoningEffort = reasoningEffort
    )

    private fun request() = AgentModelRequest(
        requestId = "req-1",
        messages = listOf(
            AgentModelMessage.system("Use the approved tools.", cacheable = true),
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

    private class FakeTransport(private val response: AgentHttpResponse) : AgentHttpTransport {
        val requests = mutableListOf<AgentHttpRequest>()

        override suspend fun execute(request: AgentHttpRequest): AgentHttpResponse {
            requests += request
            return response
        }

        override fun cancel(requestId: String) = Unit
    }
}
