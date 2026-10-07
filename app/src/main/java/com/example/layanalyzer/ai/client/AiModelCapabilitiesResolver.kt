package com.example.layanalyzer.ai.client

import java.util.Locale

/**
 * Applies documented context/output limits for model IDs whose families are known.
 *
 * Adapter behavior remains authoritative for tools, structured output and streaming.
 * Unknown IDs keep the adapter's conservative fallback, but the source remains
 * explicit so a fallback can never be presented as a provider-reported value.
 */
object AiModelCapabilitiesResolver {
    fun resolve(
        modelId: String,
        adapterDefaults: AiModelCapabilities,
        userContextLimitTokens: Int? = null,
        userOutputLimitTokens: Int? = null
    ): AiModelCapabilities {
        require(userContextLimitTokens == null ||
            userContextLimitTokens in MIN_CONTEXT_LIMIT_TOKENS..MAX_CONTEXT_LIMIT_TOKENS
        ) { "userContextLimitTokens is outside the supported range." }
        require(userOutputLimitTokens == null ||
            userOutputLimitTokens in MIN_OUTPUT_LIMIT_TOKENS..MAX_OUTPUT_LIMIT_TOKENS
        ) { "userOutputLimitTokens is outside the supported range." }
        val limits = documentedLimits(modelId) ?: return adapterDefaults.copy(
            maxContextTokens = userContextLimitTokens ?: adapterDefaults.maxContextTokens,
            maxOutputTokens = userOutputLimitTokens ?: adapterDefaults.maxOutputTokens,
            tokenLimitSource = if (
                userContextLimitTokens != null || userOutputLimitTokens != null
            ) {
                TokenLimitSource.UserConfigured
            } else {
                when (adapterDefaults.tokenLimitSource) {
                    TokenLimitSource.Negotiated,
                    TokenLimitSource.UserConfigured,
                    TokenLimitSource.AdapterFallback -> adapterDefaults.tokenLimitSource
                    TokenLimitSource.KnownModel,
                    TokenLimitSource.Unknown -> TokenLimitSource.AdapterFallback
                }
            }
        )
        return adapterDefaults.copy(
            maxContextTokens = userContextLimitTokens ?: limits.contextTokens
                ?: adapterDefaults.maxContextTokens,
            maxOutputTokens = userOutputLimitTokens ?: limits.outputTokens
                ?: adapterDefaults.maxOutputTokens,
            tokenLimitSource = if (
                userContextLimitTokens != null || userOutputLimitTokens != null
            ) TokenLimitSource.UserConfigured else TokenLimitSource.KnownModel
        )
    }

    private fun documentedLimits(modelId: String): TokenLimits? {
        val id = modelId.trim().lowercase(Locale.ROOT)
        if (id.isBlank()) return null
        return when {
            id.isClaudeOneMillionFamily() -> TokenLimits(1_000_000, 128_000)
            id.isClaudeTwoHundredThousandFamily() -> TokenLimits(200_000, 64_000)
            id.isGptFivePointSixFamily() -> TokenLimits(1_050_000, 128_000)
            id.isGptFivePointFiveFamily() -> TokenLimits(1_050_000, 128_000)
            id.isGptFivePointFourLargeFamily() -> TokenLimits(1_050_000, 128_000)
            id.isGptFivePointFourSmallFamily() -> TokenLimits(400_000, 128_000)
            id.isEarlierGptFiveFamily() -> TokenLimits(400_000, 128_000)
            id.isGptFourPointOneFamily() -> TokenLimits(1_047_576, 32_768)
            id.isOpenAiReasoningFamily() -> TokenLimits(200_000, 100_000)
            id.isGptFourOFamily() -> TokenLimits(128_000, 16_384)
            id.isDeepSeekV4FlashFamily() -> TokenLimits(
                contextTokens = null,
                outputTokens = 328_000
            )
            else -> null
        }
    }

    private fun String.isClaudeOneMillionFamily(): Boolean = listOf(
        "claude-fable-5",
        "claude-opus-5",
        "claude-sonnet-5",
        "claude-opus-4-8",
        "claude-opus-4-7",
        "claude-opus-4-6",
        "claude-sonnet-4-6"
    ).any(::contains)

    private fun String.isClaudeTwoHundredThousandFamily(): Boolean = listOf(
        "claude-haiku-4-5",
        "claude-sonnet-4-5",
        "claude-opus-4-5"
    ).any(::contains)

    private fun String.isGptFivePointSixFamily(): Boolean = matchesFamily("gpt-5.6")

    private fun String.isGptFivePointFiveFamily(): Boolean =
        matchesFamily("gpt-5.5") &&
            !startsWith("gpt-5.5-mini") &&
            !startsWith("gpt-5.5-nano")

    private fun String.isGptFivePointFourLargeFamily(): Boolean =
        matchesFamily("gpt-5.4") &&
            !startsWith("gpt-5.4-mini") &&
            !startsWith("gpt-5.4-nano")

    private fun String.isGptFivePointFourSmallFamily(): Boolean =
        startsWith("gpt-5.4-mini") || startsWith("gpt-5.4-nano")

    private fun String.isEarlierGptFiveFamily(): Boolean =
        // Match a provider-qualified id only after its namespace has been
        // removed by the adapter.  In particular, z-ai/glm-5.2 is not GPT-5.2.
        startsWith("gpt-5.3-codex") ||
            startsWith("gpt-5.2") ||
            startsWith("gpt-5.1") ||
            this == "gpt-5" ||
            startsWith("gpt-5-")

    private fun String.isGptFourPointOneFamily(): Boolean = matchesFamily("gpt-4.1")

    private fun String.isOpenAiReasoningFamily(): Boolean =
        this == "o1" || startsWith("o1-") ||
            this == "o3" || startsWith("o3-") ||
            this == "o4-mini" || startsWith("o4-mini-")

    private fun String.isGptFourOFamily(): Boolean =
        this == "gpt-4o" || startsWith("gpt-4o-")

    private fun String.isDeepSeekV4FlashFamily(): Boolean =
        this == "deepseek-v4-flash" || startsWith("deepseek-v4-flash-")

    private fun String.matchesFamily(family: String): Boolean =
        this == family || startsWith("$family-")

    private data class TokenLimits(
        val contextTokens: Int?,
        val outputTokens: Int?
    )

    private const val MIN_CONTEXT_LIMIT_TOKENS = 4_096
    private const val MAX_CONTEXT_LIMIT_TOKENS = 2_000_000
    private const val MIN_OUTPUT_LIMIT_TOKENS = 512
    private const val MAX_OUTPUT_LIMIT_TOKENS = 2_000_000
}
