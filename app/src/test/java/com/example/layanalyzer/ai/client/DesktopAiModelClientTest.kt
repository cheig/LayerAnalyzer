package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class DesktopAiModelClientTest {
    private lateinit var gateway: FakeAgentGateway
    private var pairingExpiredCallCount = 0

    @Before
    fun setup() {
        gateway = FakeAgentGateway(
            accessToken = "fake-desktop-token",
            models = listOf(
                GatewayModel(
                    id = "test-model",
                    displayName = "Test Model",
                    capabilities = AiModelCapabilities.PHASE0,
                    dataPolicy = "redacted_metadata"
                )
            )
        )
        gateway.start()
        pairingExpiredCallCount = 0
    }

    @After
    fun teardown() {
        gateway.close()
    }

    @Test
    fun usesAi23NormalizedProtocol() = runBlocking {
        val validPairing = DesktopPairingToken(
            token = "fake-desktop-token",
            deviceId = "desktop-1",
            expiresAtMillis = System.currentTimeMillis() + 3600_000
        )
        gateway.enqueue(
            FakeGatewayResponse.Final(AgentReport(summary = "Desktop response"))
        )
        val client = createDesktopClient(validPairing)

        val response = client.respond(simpleRequest())

        assertTrue(response is AgentModelResponse.Final)
        val audit = gateway.auditRecords.single()
        assertEquals("req-1", audit.requestId)
        // AI-25: desktop uses same schema version as AI-23 production gateway
        assertTrue(client.encodeRequest(simpleRequest()).contains("\"clientSchemaVersion\":\"ai-23-gateway-v2\""))
    }

    @Test
    fun tlsEnforcementRejectsPlaintextUrls() = runBlocking {
        val insecureUrl = "http://192.168.1.100:8080"
        val client = DesktopAiModelClient(
            configuration = DesktopModelConfiguration(
                modelId = "test-model",
                gatewayBaseUrl = insecureUrl,
                requireTls = true
            ),
            transport = OkHttpAgentHttpTransport(allowInsecureHttpForTests = false),
            pairingTokenProvider = { null },
            negotiateBeforeRun = false
        )

        val response = client.respond(simpleRequest())

        assertTrue(response is AgentModelResponse.Failure)
        assertEquals(
            AgentErrorCode.MODEL_UNAVAILABLE,
            (response as AgentModelResponse.Failure).error.code
        )
        assertEquals("tls_required", response.error.details["reason"])
    }

    @Test
    fun testModeAllowsPlaintextConnections() = runBlocking {
        gateway.close()
        val insecureGateway = FakeAgentGateway(
            accessToken = "fake-desktop-token",
            models = listOf(
                GatewayModel(
                    id = "test-model",
                    displayName = "Test Model",
                    capabilities = AiModelCapabilities.PHASE0
                )
            )
        )
        insecureGateway.start()
        val insecureUrl = insecureGateway.baseUrl.replace("https://", "http://")
        insecureGateway.enqueue(FakeGatewayResponse.Final(AgentReport(summary = "Test response")))

        val validPairing = DesktopPairingToken(
            token = "fake-desktop-token",
            deviceId = "test-device",
            expiresAtMillis = System.currentTimeMillis() + 3600_000
        )
        val client = DesktopAiModelClient(
            configuration = DesktopModelConfiguration(
                modelId = "test-model",
                gatewayBaseUrl = insecureUrl,
                requireTls = true
            ),
            transport = OkHttpAgentHttpTransport(allowInsecureHttpForTests = true),
            pairingTokenProvider = { validPairing },
            negotiateBeforeRun = false,
            allowInsecureHttpForTests = true
        )

        val response = client.respond(simpleRequest())

        assertTrue(response is AgentModelResponse.Final)
        insecureGateway.close()
    }

    @Test
    fun expiredPairingTriggersCallback() = runBlocking {
        val expiredPairing = DesktopPairingToken(
            token = "expired-token",
            deviceId = "desktop-1",
            expiresAtMillis = System.currentTimeMillis() - 1000
        )
        val client = createDesktopClient(expiredPairing)

        val response = client.respond(simpleRequest())

        assertTrue(response is AgentModelResponse.Failure)
        assertEquals(
            AgentErrorCode.MODEL_AUTH_FAILED,
            (response as AgentModelResponse.Failure).error.code
        )
        assertEquals(1, pairingExpiredCallCount)
    }

    @Test
    fun missingPairingReturnsAuthFailure() = runBlocking {
        val client = createDesktopClient(null)

        val response = client.respond(simpleRequest())

        assertTrue(response is AgentModelResponse.Failure)
        assertEquals(
            AgentErrorCode.MODEL_AUTH_FAILED,
            (response as AgentModelResponse.Failure).error.code
        )
    }

    @Test
    fun capabilityNegotiationDetectsToolCalling() = runBlocking {
        val validPairing = DesktopPairingToken(
            token = "fake-desktop-token",
            deviceId = "desktop-1",
            expiresAtMillis = System.currentTimeMillis() + 3600_000
        )
        val client = createDesktopClient(validPairing)

        val error = client.negotiateCapabilities()

        assertEquals(null, error)
        assertTrue(client.capabilities.toolCalling)
        assertFalse(client.oneShotFallback)
    }

    @Test
    fun desktopModelsWorkWithRedactedMetadata() = runBlocking {
        // AI-25: desktop/LAN models are remote, so they receive redacted data.
        // LocalOnly would skip redaction entirely, which is unsafe for network.
        val validPairing = DesktopPairingToken(
            token = "fake-desktop-token",
            deviceId = "desktop-1",
            expiresAtMillis = System.currentTimeMillis() + 3600_000
        )
        gateway.enqueue(FakeGatewayResponse.Final(AgentReport(summary = "Desktop response")))
        val client = createDesktopClient(validPairing)

        val response = client.respond(
            AgentModelRequest(
                requestId = "req-1",
                messages = listOf(AgentModelMessage.user("test")),
                privacyMode = AgentPrivacyMode.RedactedMetadata
            )
        )

        assertTrue(response is AgentModelResponse.Final)
    }

    private fun createDesktopClient(pairing: DesktopPairingToken?): DesktopAiModelClient {
        return DesktopAiModelClient(
            configuration = DesktopModelConfiguration(
                modelId = "test-model",
                gatewayBaseUrl = gateway.baseUrl,
                deviceName = "Test Desktop"
            ),
            transport = OkHttpAgentHttpTransport(allowInsecureHttpForTests = true),
            pairingTokenProvider = { pairing },
            onPairingExpired = { pairingExpiredCallCount++ },
            negotiateBeforeRun = false,
            allowInsecureHttpForTests = true
        )
    }

    private fun simpleRequest(): AgentModelRequest = AgentModelRequest(
        requestId = "req-1",
        messages = listOf(AgentModelMessage.user("test")),
        privacyMode = AgentPrivacyMode.RedactedMetadata
    )
}
