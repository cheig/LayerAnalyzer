package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ModelStreamingTest {
    @Test
    fun openAiChatNormalizesTextDeltasAndBuildsFinalReport() = runBlocking {
        val transport = StreamingTransport(
            listOf(
                """{"choices":[{"delta":{"reasoning_content":"Synthesize ","content":"{\"summary\":\"stream"}}]}""",
                """{"choices":[{"delta":{"reasoning_content":"evidence.","content":"ed\",\"findings\":[]}"},"finish_reason":"stop"}]}"""
            )
        )
        val client = OpenAiCompatibleModelClient(
            apiBaseUrl = "http://localhost/v1",
            transport = transport,
            providerId = "test",
            modelId = "chat",
            apiKeyProvider = { "secret" },
            allowInsecureHttpForTests = true
        )
        val chunks = mutableListOf<StreamChunk>()

        val response = client.respondStreaming(request()) { chunks += it }

        response as AgentModelResponse.Final
        assertEquals("streamed", response.report?.summary)
        assertEquals("Synthesize evidence.", response.reasoningContent)
        assertEquals(
            "{\"summary\":\"streamed\",\"findings\":[]}",
            chunks.filterIsInstance<StreamChunk.TextDelta>().joinToString("") { it.text }
        )
        assertTrue(JSONObject(requireNotNull(transport.requestBody)).getBoolean("stream"))
        assertTrue(chunks.last() is StreamChunk.Done)
    }

    @Test
    fun openAiChatNormalizesToolCallFragments() = runBlocking {
        val transport = StreamingTransport(
            listOf(
                """{"choices":[{"delta":{"reasoning_content":"Inspect ","tool_calls":[{"index":0,"id":"call-1","function":{"name":"get_statistics","arguments":"{\"filter\":"}}]}}]}""",
                """{"choices":[{"delta":{"reasoning_content":"statistics.","tool_calls":[{"index":0,"function":{"arguments":"\"tcp\"}"}}]},"finish_reason":"tool_calls"}]}"""
            )
        )
        val client = OpenAiCompatibleModelClient(
            apiBaseUrl = "http://localhost/v1",
            transport = transport,
            providerId = "test",
            modelId = "chat",
            apiKeyProvider = { "secret" },
            allowInsecureHttpForTests = true
        )
        val chunks = mutableListOf<StreamChunk>()

        val response = client.respondStreaming(request()) { chunks += it }

        response as AgentModelResponse.ToolCalls
        val call = response.calls.single()
        assertEquals("call-1", call.toolCallId)
        assertEquals("get_statistics", call.toolName)
        assertEquals("tcp", call.arguments["filter"])
        assertEquals("Inspect statistics.", response.reasoningContent)
        assertEquals(1, chunks.filterIsInstance<StreamChunk.ToolCallStart>().size)
        assertEquals(2, chunks.filterIsInstance<StreamChunk.ToolCallArgumentDelta>().size)
    }

    @Test
    fun anthropicContentBlockDeltasBuildFinalReport() = runBlocking {
        val transport = StreamingTransport(
            listOf(
                """{"type":"message_start","message":{"usage":{"input_tokens":10}}}""",
                """{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}""",
                """{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"{\"summary\":\"anthropic\",\"findings\":[]}"}}""",
                """{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":8}}""",
                """{"type":"message_stop"}"""
            )
        )
        val client = AnthropicModelClient(
            apiBaseUrl = "http://localhost/v1",
            transport = transport,
            providerId = "test",
            modelId = "claude",
            apiKeyProvider = { "secret" },
            allowInsecureHttpForTests = true
        )
        val chunks = mutableListOf<StreamChunk>()

        val response = client.respondStreaming(request()) { chunks += it }

        val final = response as AgentModelResponse.Final
        assertEquals("anthropic", final.report?.summary)
        assertEquals(10, final.usage?.inputTokens)
        assertEquals(8, final.usage?.outputTokens)
        assertTrue(chunks.any { it is StreamChunk.TextDelta })
    }

    @Test
    fun openAiResponsesNormalizesTextDeltasAndCompletedUsage() = runBlocking {
        val transport = StreamingTransport(
            listOf(
                """{"type":"response.output_text.delta","delta":"partial"}""",
                """{"type":"response.completed","response":{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"{\"summary\":\"responses\",\"findings\":[]}"}]}],"usage":{"input_tokens":12,"output_tokens":7}}}"""
            )
        )
        val client = OpenAiResponsesModelClient(
            apiBaseUrl = "http://localhost/v1",
            transport = transport,
            providerId = "test",
            modelId = "responses",
            apiKeyProvider = { "secret" },
            allowInsecureHttpForTests = true
        )
        val chunks = mutableListOf<StreamChunk>()

        val response = client.respondStreaming(request()) { chunks += it }

        val final = response as AgentModelResponse.Final
        assertEquals("responses", final.report?.summary)
        assertEquals(12, final.usage?.inputTokens)
        assertEquals(7, final.usage?.outputTokens)
        assertEquals("partial", chunks.filterIsInstance<StreamChunk.TextDelta>().single().text)
    }

    @Test
    fun okHttpTransportReadsAChunkedSseResponse() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "text/event-stream")
                .setChunkedBody("data: first\n\ndata: second\n\n", 3)
        )
        server.start()
        try {
            val transport = OkHttpAgentHttpTransport(allowInsecureHttpForTests = true)
            val rawChunks = mutableListOf<String>()
            val response = transport.executeStreaming(
                AgentHttpRequest(
                    requestId = "transport-stream",
                    url = server.url("/stream").toString()
                )
            ) { rawChunks += it }
            val events = mutableListOf<String>()
            val decoder = ServerSentEventDecoder { events += it }
            rawChunks.forEach { decoder.accept(it) }
            decoder.finish()

            assertEquals(200, response.statusCode)
            assertEquals("", response.body)
            assertEquals(listOf("first", "second"), events)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun okHttpStreamingCancellationStopsARequestWaitingForHeaders() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        server.start()
        try {
            val transport = OkHttpAgentHttpTransport(allowInsecureHttpForTests = true)
            val request = async(Dispatchers.IO) {
                transport.executeStreaming(
                    AgentHttpRequest(
                        requestId = "cancelled-stream",
                        url = server.url("/stream").toString()
                    )
                ) {}
            }
            assertTrue(server.takeRequest(3, TimeUnit.SECONDS) != null)

            withTimeout(1_000L) {
                request.cancelAndJoin()
            }
            assertTrue(request.isCancelled)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun sseDecoderHandlesTransportBoundariesInsideLines() = runBlocking {
        val events = mutableListOf<String>()
        val decoder = ServerSentEventDecoder { events += it }

        decoder.accept("data: {\"a\":")
        decoder.accept("1}\r\n\r")
        decoder.accept("\ndata: [DONE]\n\n")
        decoder.finish()

        assertEquals(listOf("{\"a\":1}"), events)
    }

    private fun request() = AgentModelRequest(requestId = "stream-request")

    private class StreamingTransport(
        private val events: List<String>
    ) : AgentHttpTransport {
        var requestBody: String? = null

        override suspend fun execute(request: AgentHttpRequest): AgentHttpResponse =
            error("buffered transport should not be used")

        override suspend fun executeStreaming(
            request: AgentHttpRequest,
            onChunk: suspend (String) -> Unit
        ): AgentHttpResponse {
            requestBody = request.body
            events.forEach { event -> onChunk("data: $event\n\n") }
            return AgentHttpResponse(200, mapOf("content-type" to "text/event-stream"))
        }

        override fun cancel(requestId: String) = Unit
    }
}
