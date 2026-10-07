// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.AgentToolDefinition
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudAiModelClientTest {
    @Test
    fun mapsGatewayToolCallsAndPreservesReasoningForTheNextRequest() = runBlocking {
        val transport = FakeTransport(
            AgentHttpResponse(
                statusCode = 200,
                body = """
                    {
                      "type":"tool_calls",
                      "assistantContent":"I will inspect the capture overview.",
                      "reasoningContent":"Inspect the capture overview before answering.",
                      "toolCalls":[{"id":"call-1","name":"get_capture_overview","arguments":{"scope":"complete_file"}}],
                      "usage":{"inputTokens":75,"outputTokens":9,"cachedInputTokens":20,"cacheCreationTokens":5}
                    }
                """.trimIndent()
            )
        )
        val client = CloudAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = transport,
            providerId = "preview",
            modelId = "model-1"
        )

        val response = client.respond(request())

        response as AgentModelResponse.ToolCalls
        val calls = response.calls
        assertEquals("get_capture_overview", calls.single().toolName)
        assertEquals("I will inspect the capture overview.", response.assistantContent)
        assertEquals(
            "Inspect the capture overview before answering.",
            response.reasoningContent
        )
        assertEquals(75, response.usage?.inputTokens)
        assertEquals(9, response.usage?.outputTokens)
        assertEquals(20, response.usage?.cachedInputTokens)
        assertEquals(5, response.usage?.cacheCreationTokens)
        val body = transport.requests.single().body.orEmpty()
        assertTrue(body.contains("\"requestId\":\"req-1\""))
        assertTrue(body.contains("\"modelId\":\"model-1\""))
        assertTrue(body.contains("\"tools\""))
        assertTrue(body.contains("\"responseSchema\""))
        assertTrue(body.contains("\"privacyMode\":\"RedactedMetadata\""))
        assertFalse(body.contains("Authorization"))

        val nextBody = JSONObject(
            client.encodeRequest(
                request().copy(
                    messages = request().messages +
                        AgentModelMessage.assistant(
                            content = response.assistantContent,
                            toolCalls = response.calls,
                            reasoningContent = response.reasoningContent
                        )
                )
            )
        )
        val nextMessages = nextBody.getJSONArray("messages")
        val assistant = (0 until nextMessages.length())
            .map { nextMessages.getJSONObject(it) }
            .first { it.getString("role") == "assistant" }
        assertEquals(
            "Inspect the capture overview before answering.",
            assistant.getString("reasoningContent")
        )
    }

    @Test
    fun preservesSafeToolDataWhileBlockingPayloadAndCredentials() = runBlocking {
        val transport = FakeTransport(AgentHttpResponse(200, body = "{}"))
        val client = CloudAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = transport
        )
        val request = request().copy(
            messages = listOf(
                AgentModelMessage.fromToolResult(
                    AgentToolResult(
                        toolCallId = "call-1",
                        toolName = "get_capture_overview",
                        data = mapOf(
                            "packetCount" to 4,
                            "payload" to "raw bytes",
                            "authorization" to "Bearer secret"
                        )
                    )
                )
            )
        )

        val body = client.encodeRequest(request)
        assertTrue(body.contains("\"packetCount\":4"))
        assertTrue(body.contains("\"payload\":\"PRIVACY_BLOCKED\""))
        assertTrue(body.contains("\"authorization\""))
        assertTrue(body.contains("\"present\":true"))
        assertFalse(body.contains("Bearer secret"))
        assertFalse(body.contains("raw bytes"))
    }

    @Test
    fun unredactedStructuredContentKeepsIdentifiersButBlocksForbiddenFields() {
        val client = CloudAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = FakeTransport(AgentHttpResponse(200, body = "{}"))
        )
        val request = request().copy(
            privacyMode = AgentPrivacyMode.UnredactedMetadata,
            messages = listOf(
                AgentModelMessage(
                    role = com.example.layanalyzer.model.AgentModelMessageRole.Tool,
                    untrustedCaptureData = true,
                    structuredContent = mapOf(
                        "data" to mapOf(
                            "source" to "192.0.2.10",
                            "payload" to "raw bytes",
                            "authorization" to "Bearer secret"
                        )
                    )
                )
            )
        )

        val body = client.encodeRequest(request)

        assertTrue(body.contains("\"privacyMode\":\"UnredactedMetadata\""))
        assertTrue(body.contains("192.0.2.10"))
        assertTrue(body.contains("PRIVACY_BLOCKED"))
        assertTrue(body.contains("\"present\":true"))
        assertFalse(body.contains("raw bytes"))
        assertFalse(body.contains("Bearer secret"))
    }

    @Test
    fun mapsFinalReasoningWithoutPuttingItInTheReport() = runBlocking {
        val report = AgentReport(summary = "Gateway final")
        val transport = FakeTransport(
            AgentHttpResponse(
                200,
                body = """
                    {"type":"final","reasoningContent":"Synthesize verified evidence.","report":${AgentJsonCodec.encodeReport(report)}}
                """.trimIndent()
            )
        )
        val response = CloudAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = transport
        ).respond(request())

        response as AgentModelResponse.Final
        assertEquals("Gateway final", response.report?.summary)
        assertEquals("Synthesize verified evidence.", response.reasoningContent)
        assertFalse(AgentJsonCodec.encodeReport(response.report!!).contains("reasoning"))
    }

    @Test
    fun ordinaryMessagesDoNotGainAReasoningField() {
        val ordinaryRequest = request().copy(
            messages = listOf(
                AgentModelMessage(
                    role = com.example.layanalyzer.model.AgentModelMessageRole.User,
                    content = "Question",
                    reasoningContent = "must not be sent on a user message"
                )
            )
        )
        val body = JSONObject(
            CloudAiModelClient(
                gatewayBaseUrl = "https://gateway.example",
                transport = FakeTransport(AgentHttpResponse(200, body = "{}"))
            ).encodeRequest(ordinaryRequest)
        )

        val message = body.getJSONArray("messages").getJSONObject(0)
        assertFalse(message.has("reasoningContent"))
    }

    @Test
    fun mapsAuthenticationRateLimitServiceAndMalformedResponses() = runBlocking {
        assertEquals(AgentErrorCode.MODEL_AUTH_FAILED, failure(401).error.code)
        assertEquals(AgentErrorCode.MODEL_RATE_LIMITED, failure(429).error.code)
        assertEquals(AgentErrorCode.MODEL_UNAVAILABLE, failure(503).error.code)
        assertEquals(
            AgentErrorCode.MODEL_RESPONSE_MALFORMED,
            CloudAiModelClient(
                gatewayBaseUrl = "https://gateway.example",
                transport = FakeTransport(AgentHttpResponse(200, body = "not-json"))
            ).respond(request()).let { (it as AgentModelResponse.Failure).error.code }
        )
    }

    @Test
    fun aGatewayTimeoutIsDistinguishableFromAnUnavailableUpstream() = runBlocking {
        // An ALB 504 carries an HTML body and none of the provider's error
        // fields, so the reason is what tells the loop to shrink rather than
        // replay the identical request.
        val timeout = CloudAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = FakeTransport(
                AgentHttpResponse(
                    504,
                    body = "<html><head><title>504 Gateway Time-out</title></head></html>"
                )
            )
        ).respond(request()).let { it as AgentModelResponse.Failure }

        assertEquals(AgentErrorCode.MODEL_TIMEOUT, timeout.error.code)
        assertTrue(timeout.error.retryable)
        assertEquals(AiModelErrors.GATEWAY_TIMEOUT_REASON, timeout.error.details["reason"])
        assertEquals(AiModelErrors.GATEWAY_TIMEOUT_REASON, failure(504).error.details["reason"])
        assertNotEquals(AiModelErrors.GATEWAY_TIMEOUT_REASON, failure(503).error.details["reason"])
    }

    @Test
    fun permanentAccountStatusesAreNotRetryable() = runBlocking {
        listOf(402, 451).forEach { statusCode ->
            assertFalse("status $statusCode should not be retried", failure(statusCode).error.retryable)
        }
    }

    @Test
    fun providerUrisAreRedactedFromRemoteErrorDetails() = runBlocking {
        val rawUri = "sip:+8613800138000@ims.mnc001.mcc460.3gppnetwork.org"
        val transport = FakeTransport(
            AgentHttpResponse(
                statusCode = 400,
                body = "{\"error\":{\"message\":\"Blocked: INVITE $rawUri\"}}"
            )
        )
        val response = CloudAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = transport
        ).respond(request())

        val remoteMessage = (response as AgentModelResponse.Failure).error.details["remoteMessage"].toString()
        assertFalse(remoteMessage.contains("+8613800138000"))
        assertFalse(remoteMessage.contains("ims.mnc001.mcc460.3gppnetwork.org"))
        assertTrue(remoteMessage.contains("sip:<redacted>"))
    }

    @Test
    fun normalizedGatewayErrorDetailsReachTheForegroundErrorCard() = runBlocking {
        val transport = FakeTransport(
            AgentHttpResponse(
                statusCode = 503,
                body = """
                    {"error":{"code":"provider_overloaded","type":"upstream","message":"temporary gateway outage"}}
                """.trimIndent()
            )
        )
        val response = CloudAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = transport
        ).respond(request())

        val error = (response as AgentModelResponse.Failure).error
        assertEquals("provider_overloaded", error.details["remoteCode"])
        assertEquals("temporary gateway outage", error.details["remoteMessage"])
        assertEquals(503, error.details["httpStatus"])
    }

    @Test
    fun localOnlyNeverTouchesTheTransport() = runBlocking {
        val transport = FakeTransport(AgentHttpResponse(200, body = "{}"))
        val response = CloudAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = transport
        ).respond(request().copy(privacyMode = AgentPrivacyMode.LocalOnly))

        assertEquals(AgentErrorCode.PRIVACY_BLOCKED, (response as AgentModelResponse.Failure).error.code)
        assertTrue(transport.requests.isEmpty())
    }

    @Test
    fun capabilityResponseMarksOneShotFallback() = runBlocking {
        val transport = FakeTransport(
            AgentHttpResponse(
                200,
                body = """
                    {"type":"final","capabilities":{"toolCalling":false,"structuredOutput":false},"report":{"summary":"Fallback"}}
                """.trimIndent()
            )
        )
        val client = CloudAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = transport
        )

        val response = client.respond(request())

        assertTrue(response is AgentModelResponse.Final)
        assertTrue(client.oneShotFallback)
        assertFalse(client.capabilities.toolCalling)
    }

    @Test
    fun cancelDelegatesByRequestId() {
        val transport = FakeTransport(AgentHttpResponse(200, body = "{}"))
        CloudAiModelClient("https://gateway.example", transport).cancel("req-1")
        assertEquals(listOf("req-1"), transport.cancelled)
    }

    private fun failure(statusCode: Int): AgentModelResponse.Failure = runBlocking {
        val transport = FakeTransport(AgentHttpResponse(statusCode, body = "{}"))
        val result = CloudAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = transport
        ).respond(request())
        result as AgentModelResponse.Failure
    }

    private fun request() = AgentModelRequest(
        requestId = "req-1",
        messages = listOf(AgentModelMessage.user("Question")),
        toolDefinitions = listOf(AgentToolDefinition("get_capture_overview")),
        responseSchema = mapOf("type" to "object"),
        privacyMode = AgentPrivacyMode.RedactedMetadata
    )

    private class FakeTransport(private val response: AgentHttpResponse) : AgentHttpTransport {
        val requests = mutableListOf<AgentHttpRequest>()
        val cancelled = mutableListOf<String>()

        override suspend fun execute(request: AgentHttpRequest): AgentHttpResponse {
            requests += request
            return response
        }

        override fun cancel(requestId: String) {
            cancelled += requestId
        }
    }
}
