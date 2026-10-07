package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode

/** Pure selection result so production wiring cannot silently fall back to Mock. */
sealed interface AgentModelBackend {
    data class Mock(val scriptId: String) : AgentModelBackend
    data object OpenAiCompatibleByok : AgentModelBackend
    data object OpenAiResponsesByok : AgentModelBackend
    data object AnthropicByok : AgentModelBackend
    data object NormalizedByokGateway : AgentModelBackend
    data object AccountGateway : AgentModelBackend
    /** AI-25: on-device local model */
    data class LocalModel(val modelId: String) : AgentModelBackend
    /** AI-25: desktop/LAN gateway */
    data class DesktopGateway(val deviceId: String) : AgentModelBackend
    data class Unavailable(val reason: String, val error: AgentError) : AgentModelBackend
}

fun AgentSettings.selectModelBackend(): AgentModelBackend {
    val current = normalized()
    val mockScript = MockModelScriptLibrary.find(current.modelId)?.id

    if (!current.hasRemoteConfiguration) {
        return mockScript?.let(AgentModelBackend::Mock)
            ?: unavailableBackend(
                reason = "unknown_local_model",
                message = "The selected model is not an offline demo model. Configure an HTTPS API URL."
            )
    }

    if (current.privacyMode == AgentPrivacyMode.LocalOnly) {
        return AgentModelBackend.Unavailable(
            reason = "local_only_blocks_remote",
            error = AgentError(
                code = AgentErrorCode.PRIVACY_BLOCKED,
                userMessage = "A remote model is configured, but privacy mode is Local only.",
                retryable = false,
                details = mapOf("reason" to "local_only_blocks_remote")
            )
        )
    }

    if (!current.isCloudConfigured) {
        return unavailableBackend(
            reason = "remote_configuration_incomplete",
            message = "Remote model configuration requires a provider, model, and HTTPS API URL."
        )
    }

    if (current.byokConfigured) {
        return if (current.providerId == AgentSettings.GATEWAY_PROVIDER_ID) {
            AgentModelBackend.NormalizedByokGateway
        } else {
            when (current.activeProvider?.apiType ?: AgentApiType.OPENAI_CHAT_COMPLETIONS) {
                AgentApiType.OPENAI_CHAT_COMPLETIONS -> AgentModelBackend.OpenAiCompatibleByok
                AgentApiType.OPENAI_RESPONSES -> AgentModelBackend.OpenAiResponsesByok
                AgentApiType.ANTHROPIC_API -> AgentModelBackend.AnthropicByok
            }
        }
    }
    return AgentModelBackend.AccountGateway
}

private fun unavailableBackend(reason: String, message: String) = AgentModelBackend.Unavailable(
    reason = reason,
    error = AgentError(
        code = AgentErrorCode.MODEL_UNAVAILABLE,
        userMessage = message,
        retryable = false,
        details = mapOf("reason" to reason)
    )
)
