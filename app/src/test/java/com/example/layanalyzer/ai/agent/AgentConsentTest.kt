package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentPrivacyMode
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentConsentTest {
    @Test
    fun cloudSettingsRequireConsentUntilCurrentVersionIsAccepted() {
        val settings = AgentSettings(
            providerId = AgentSettings.GATEWAY_PROVIDER_ID,
            modelId = "model-1",
            gatewayBaseUrl = "https://gateway.example",
            privacyMode = AgentPrivacyMode.RedactedMetadata
        )

        assertTrue(AgentConsent.requiresConsent(settings))
        assertFalse(
            AgentConsent.requiresConsent(
                settings.copy(firstUseConsentVersion = AgentConsent.CURRENT_VERSION)
            )
        )
        assertTrue(
            AgentConsent.requiresConsent(
                settings.copy(firstUseConsentVersion = "old-policy")
            )
        )
    }

    @Test
    fun localOnlyNeverNeedsCloudConsent() {
        val settings = AgentSettings(
            providerId = AgentSettings.GATEWAY_PROVIDER_ID,
            modelId = "model-1",
            gatewayBaseUrl = "https://gateway.example",
            privacyMode = AgentPrivacyMode.LocalOnly
        )

        assertFalse(AgentConsent.requiresConsent(settings))
    }

    @Test
    fun unredactedMetadataRequiresExplicitCloudConsent() {
        val settings = AgentSettings(
            providerId = AgentSettings.GATEWAY_PROVIDER_ID,
            modelId = "model-1",
            gatewayBaseUrl = "https://gateway.example",
            privacyMode = AgentPrivacyMode.UnredactedMetadata
        )

        assertTrue(AgentConsent.requiresConsent(settings))
    }
}
