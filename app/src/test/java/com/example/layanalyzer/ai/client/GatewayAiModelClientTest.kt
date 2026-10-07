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
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GatewayAiModelClientTest {
    @Test
    fun accountEndpointsExposeModelsAndUsageWithoutExposingToken() = runBlocking {
        FakeAgentGateway().use { gateway ->
            gateway.start()
            val client = client(gateway)

            val models = client.getModels()
            val usage = client.getUsage()

            assertTrue(models is GatewayResult.Success)
            val modelResult = models as GatewayResult.Success<List<GatewayModel>>
            assertEquals("fake-model", modelResult.value.single().id)
            assertTrue(usage is GatewayResult.Success)
            val usageResult = usage as GatewayResult.Success<GatewayUsage>
            assertEquals(60L, usageResult.value.quota.requestsPerMinute)
            assertEquals("fake-user", client.account?.userId)
        }
    }

    @Test
    fun respondUsesAi23SchemaAndMapsToolCalls() = runBlocking {
        FakeAgentGateway().use { gateway ->
            gateway.start()
            gateway.enqueue(
                FakeGatewayResponse.ToolCalls(
                    listOf(
                        AgentToolCall(
                            toolCallId = "call-1",
                            toolName = "get_capture_overview",
                            arguments = mapOf("scope" to "complete_file")
                        )
                    ),
                    assistantContent = "I will inspect the capture overview.",
                    reasoningContent = "Inspect the overview first."
                )
            )
            val client = client(gateway, negotiateBeforeRun = false)

            val response = client.respond(request())

            assertTrue(response is AgentModelResponse.ToolCalls)
            response as AgentModelResponse.ToolCalls
            assertEquals(
                "get_capture_overview",
                response.calls.single().toolName
            )
            assertEquals("I will inspect the capture overview.", response.assistantContent)
            assertEquals("Inspect the overview first.", response.reasoningContent)
            val audit = gateway.auditRecords.single()
            assertEquals("req-1", audit.requestId)
            assertTrue(audit.parameterHashes.single().matches(Regex("[0-9a-f]{64}")))
            assertTrue(client.encodeRequest(request()).contains("\"clientSchemaVersion\":\"ai-23-gateway-v2\""))
            val continuedRequest = request().copy(
                messages = request().messages + AgentModelMessage.assistant(
                    content = response.assistantContent,
                    toolCalls = response.calls,
                    reasoningContent = response.reasoningContent
                )
            )
            assertTrue(
                client.encodeRequest(continuedRequest)
                    .contains("\"reasoningContent\":\"Inspect the overview first.\"")
            )
        }
    }

    @Test
    fun serverPrivacyRejectionMapsToPrivacyBlocked() = runBlocking {
        FakeAgentGateway().use { gateway ->
            gateway.start()
            val client = client(gateway, negotiateBeforeRun = false)
            val request = request().copy(
                messages = listOf(
                    AgentModelMessage.fromToolResult(
                        AgentToolResult(
                            toolCallId = "call-1",
                            toolName = "unsafe",
                            sensitivity = com.example.layanalyzer.model.AgentDataSensitivity.Payload,
                            data = mapOf("payload" to "raw")
                        )
                    )
                )
            )

            val response = client.respond(request)

            assertEquals(
                AgentErrorCode.PRIVACY_BLOCKED,
                (response as AgentModelResponse.Failure).error.code
            )
            assertEquals("privacy_category_blocked", gateway.auditRecords.single().errorCode)
        }
    }

    @Test
    fun quotaResponsePreservesSafeRetryAndQuotaDetails() = runBlocking {
        FakeAgentGateway(
            quota = GatewayQuota(requestsPerMinute = 0)
        ).use { gateway ->
            gateway.start()
            val client = client(gateway, negotiateBeforeRun = false)

            val response = client.respond(request())

            val error = (response as AgentModelResponse.Failure).error
            assertEquals(AgentErrorCode.MODEL_RATE_LIMITED, error.code)
            assertEquals("requests_per_minute", error.details["quotaType"])
            assertEquals(60L, error.details["retryAfterSeconds"])
            assertEquals(60_000L, error.details["retryAfterMillis"])
        }
    }

    @Test
    fun permanentAccountStatusesAreNotRetryable() = runBlocking {
        listOf(402, 451).forEach { statusCode ->
            FakeAgentGateway().use { gateway ->
                gateway.start()
                gateway.enqueue(FakeGatewayResponse.Error(statusCode, "account_action_required"))
                val error = (client(gateway, negotiateBeforeRun = false).respond(request())
                    as AgentModelResponse.Failure).error

                assertFalse("status $statusCode should not be retried", error.retryable)
            }
        }
    }

    @Test
    fun missingOrExpiredTokenMapsToAuthenticationFailure() = runBlocking {
        FakeAgentGateway().use { gateway ->
            gateway.start()
            var rejected = false
            val client = GatewayAiModelClient(
                gatewayBaseUrl = gateway.baseUrl,
                transport = OkHttpAgentHttpTransport(allowInsecureHttpForTests = true),
                modelId = "fake-model",
                accessTokenProvider = { null },
                negotiateBeforeRun = false,
                allowInsecureHttpForTests = true,
                onAuthenticationRejected = { rejected = true }
            )

            val response = client.respond(request())

            assertEquals(AgentErrorCode.MODEL_AUTH_FAILED, (response as AgentModelResponse.Failure).error.code)
            assertTrue(rejected)
        }
    }

    @Test
    fun cancelSendsRequestIdToLocalAndRemoteTransport() {
        val transport = RecordingTransport()
        GatewayAiModelClient(
            gatewayBaseUrl = "https://gateway.example",
            transport = transport,
            accessTokenProvider = { "short-lived" }
        ).cancel("req-1")

        assertEquals(listOf("req-1"), transport.localCancelled)
        assertEquals("cancel-req-1", transport.remoteCancelled.single().requestId)
        assertEquals("req-1", org.json.JSONObject(transport.remoteCancelled.single().body).optString("requestId"))
    }

    @Test
    fun finalResponseRetainsReasoningWithoutPuttingItInTheReportOrAudit() = runBlocking {
        FakeAgentGateway().use { gateway ->
            gateway.start()
            gateway.enqueue(
                FakeGatewayResponse.Final(
                    AgentReport(summary = "safe final"),
                    reasoningContent = "Synthesize verified evidence."
                )
            )
            val client = client(gateway, negotiateBeforeRun = false)

            val response = client.respond(request())

            val final = response as AgentModelResponse.Final
            assertEquals("safe final", final.report?.summary)
            assertEquals("Synthesize verified evidence.", final.reasoningContent)
            assertFalse(AgentJsonCodec.encodeReport(final.report!!).contains("reasoning"))
            assertNotNull(gateway.auditRecords.single())
        }
    }

    private fun client(
        gateway: FakeAgentGateway,
        negotiateBeforeRun: Boolean = true
    ) = GatewayAiModelClient(
        gatewayBaseUrl = gateway.baseUrl,
        transport = OkHttpAgentHttpTransport(allowInsecureHttpForTests = true),
        providerId = "fake",
        modelId = "fake-model",
        accessTokenProvider = { "fake-access-token" },
        negotiateBeforeRun = negotiateBeforeRun,
        allowInsecureHttpForTests = true
    )

    private fun request() = AgentModelRequest(
        requestId = "req-1",
        messages = listOf(AgentModelMessage.user("Question")),
        responseSchema = mapOf("type" to "object"),
        privacyMode = AgentPrivacyMode.RedactedMetadata
    )

    private class RecordingTransport : AgentHttpTransport {
        val localCancelled = mutableListOf<String>()
        val remoteCancelled = mutableListOf<AgentHttpRequest>()

        override suspend fun execute(request: AgentHttpRequest): AgentHttpResponse =
            AgentHttpResponse(200, body = "{}")

        override fun cancel(requestId: String) {
            localCancelled += requestId
        }

        override fun cancelRemote(request: AgentHttpRequest) {
            remoteCancelled += request
        }
    }
}
