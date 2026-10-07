package com.example.layanalyzer.model

/** Safe, non-editable projection of the next gateway request. */
data class AgentPreviewMessage(
    val role: AgentModelMessageRole,
    val toolName: String? = null,
    val characterCount: Int = 0,
    val estimatedTokens: Int = 0
)

data class AgentPreviewCategory(
    val category: AgentDataSensitivity,
    val itemCount: Int,
    /** Examples are already redacted and are never credentials or payloads. */
    val examples: List<String> = emptyList()
)

data class AgentRequestPreview(
    val messages: List<AgentPreviewMessage> = emptyList(),
    val toolNames: List<String> = emptyList(),
    val categories: List<AgentPreviewCategory> = emptyList(),
    val totalCharacters: Int = 0,
    val estimatedTokens: Int = 0,
    val privacyMode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata,
    val scope: AnalysisScope = AnalysisScope.CompleteFile,
    val truncated: Boolean = false
) {
    val hasCredentialExample: Boolean
        get() = categories
            .filter { it.category == AgentDataSensitivity.Credential }
            .flatMap { it.examples }
            .isNotEmpty()
}

data class AgentConsentPrompt(
    val providerId: String,
    val modelId: String,
    /** User-facing labels; the ids above stay stable for auditing. */
    val providerName: String = "",
    val modelName: String = "",
    val privacyMode: AgentPrivacyMode,
    val scope: AnalysisScope,
    val frameCount: Int,
    val appliedDisplayFilter: String,
    val preview: AgentRequestPreview,
    val expectedCostNotice: String = "Cloud model usage may incur charges.",
    val rawCaptureGuarantee: String =
        "Original PCAP, packet bytes, complete payloads and credential values are not sent."
)
