package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentModelBackendTest {
    @Test
    fun apiUrlMigratesDefaultLocalProviderToDirectByok() {
        val settings = AgentSettings(
            providerId = AgentSettings.LOCAL_PROVIDER_ID,
            modelId = "real-model",
            gatewayBaseUrl = " https://api.example/v1/ ",
            byokConfigured = true
        ).normalized()

        assertEquals(AgentSettings.OPENAI_COMPATIBLE_PROVIDER_ID, settings.providerId)
        assertEquals("https://api.example/v1", settings.gatewayBaseUrl)
        assertEquals(AgentModelBackend.OpenAiCompatibleByok, settings.selectModelBackend())
    }

    @Test
    fun configuredRemoteModelNeverFallsBackToMock() {
        val incomplete = AgentSettings(
            providerId = "openai-compatible",
            modelId = "real-model",
            gatewayBaseUrl = ""
        ).selectModelBackend()
        val localOnly = AgentSettings(
            providerId = "openai-compatible",
            modelId = "real-model",
            gatewayBaseUrl = "https://api.example",
            privacyMode = AgentPrivacyMode.LocalOnly,
            byokConfigured = true
        ).selectModelBackend()

        assertTrue(incomplete is AgentModelBackend.Unavailable)
        assertTrue(localOnly is AgentModelBackend.Unavailable)
        assertEquals(
            AgentErrorCode.PRIVACY_BLOCKED,
            (localOnly as AgentModelBackend.Unavailable).error.code
        )
    }

    @Test
    fun onlyExplicitKnownOfflineScriptUsesMock() {
        val backend = AgentSettings(
            modelId = MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS
        ).selectModelBackend()

        assertEquals(
            MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS,
            (backend as AgentModelBackend.Mock).scriptId
        )
    }

    @Test
    fun unredactedMetadataCanUseARemoteBackend() {
        val backend = AgentSettings(
            providerId = "provider",
            modelId = "model",
            gatewayBaseUrl = "https://api.example",
            privacyMode = AgentPrivacyMode.UnredactedMetadata,
            byokConfigured = true,
            providers = listOf(
                AgentProviderConfig(
                    id = "provider",
                    baseUrl = "https://api.example",
                    models = listOf(AgentModelConfig("model")),
                    apiKeyConfigured = true
                )
            )
        ).selectModelBackend()

        assertEquals(AgentModelBackend.OpenAiCompatibleByok, backend)
    }

    @Test
    fun selectsDirectBackendForEachConfiguredApiType() {
        fun settings(apiType: AgentApiType) = AgentSettings(
            providerId = "provider",
            modelId = "model",
            gatewayBaseUrl = "https://api.example",
            byokConfigured = true,
            providers = listOf(
                AgentProviderConfig(
                    id = "provider",
                    baseUrl = "https://api.example",
                    models = listOf(AgentModelConfig("model")),
                    apiKeyConfigured = true,
                    apiType = apiType
                )
            )
        )

        assertEquals(
            AgentModelBackend.OpenAiCompatibleByok,
            settings(AgentApiType.OPENAI_CHAT_COMPLETIONS).selectModelBackend()
        )
        assertEquals(
            AgentModelBackend.OpenAiResponsesByok,
            settings(AgentApiType.OPENAI_RESPONSES).selectModelBackend()
        )
        assertEquals(
            AgentModelBackend.AnthropicByok,
            settings(AgentApiType.ANTHROPIC_API).selectModelBackend()
        )
    }

    @Test
    fun gatewayUsesConfiguredKeyWithoutRequiringAccountLogin() {
        val settings = AgentSettings(
            providerId = AgentSettings.GATEWAY_PROVIDER_ID,
            modelId = "real-model",
            gatewayBaseUrl = "https://gateway.example",
            byokConfigured = true
        )

        assertEquals(AgentModelBackend.NormalizedByokGateway, settings.selectModelBackend())
        assertEquals(
            AgentModelBackend.AccountGateway,
            settings.copy(byokConfigured = false).selectModelBackend()
        )
    }
}
