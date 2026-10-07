package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentTokenUsage
import org.json.JSONObject

/** Provider-specific token vocabularies stay at the HTTP adapter boundary. */
internal object AgentTokenUsageParser {
    fun anthropic(root: JSONObject): AgentTokenUsage? {
        val usage = root.optJSONObject("usage") ?: return null
        val uncached = nonNegativeInt(usage, "input_tokens")
        val cacheRead = nonNegativeInt(usage, "cache_read_input_tokens")
        val cacheCreation = nonNegativeInt(usage, "cache_creation_input_tokens")
        return AgentTokenUsage(
            inputTokens = saturatedSum(uncached, cacheRead, cacheCreation),
            outputTokens = nonNegativeInt(usage, "output_tokens"),
            cachedInputTokens = cacheRead,
            cacheCreationTokens = cacheCreation
        )
    }

    fun openAiChat(root: JSONObject): AgentTokenUsage? {
        val usage = root.optJSONObject("usage") ?: return null
        return AgentTokenUsage(
            inputTokens = nonNegativeInt(usage, "prompt_tokens"),
            outputTokens = nonNegativeInt(usage, "completion_tokens"),
            cachedInputTokens = nonNegativeInt(
                usage.optJSONObject("prompt_tokens_details"),
                "cached_tokens"
            )
        )
    }

    fun openAiResponses(root: JSONObject): AgentTokenUsage? {
        val usage = root.optJSONObject("usage") ?: return null
        return AgentTokenUsage(
            inputTokens = nonNegativeInt(usage, "input_tokens"),
            outputTokens = nonNegativeInt(usage, "output_tokens"),
            cachedInputTokens = nonNegativeInt(
                usage.optJSONObject("input_tokens_details"),
                "cached_tokens"
            )
        )
    }

    /** Normalized gateway responses accept camelCase and provider-style names. */
    fun normalized(root: JSONObject, envelope: JSONObject): AgentTokenUsage? {
        val usage = envelope.optJSONObject("usage")
            ?: root.optJSONObject("usage")
            ?: return null
        val cachedDetails = usage.optJSONObject("inputTokensDetails")
            ?: usage.optJSONObject("input_tokens_details")
            ?: usage.optJSONObject("prompt_tokens_details")
        val inputTokens = firstNonNegativeInt(
            usage,
            "inputTokens",
            "input_tokens",
            "promptTokens",
            "prompt_tokens"
        )
        val cachedInputTokens = firstNonNegativeInt(
            usage,
            "cachedInputTokens",
            "cached_input_tokens",
            "cache_read_input_tokens"
        ).takeIf { it > 0 }
            ?: firstNonNegativeInt(cachedDetails, "cachedTokens", "cached_tokens")
        val cacheCreationTokens = firstNonNegativeInt(
            usage,
            "cacheCreationTokens",
            "cache_creation_tokens",
            "cache_creation_input_tokens"
        )
        val usesRawAnthropicVocabulary = usage.has("input_tokens") &&
            !usage.has("inputTokens") &&
            (usage.has("cache_read_input_tokens") || usage.has("cache_creation_input_tokens"))
        return AgentTokenUsage(
            inputTokens = if (usesRawAnthropicVocabulary) {
                saturatedSum(inputTokens, cachedInputTokens, cacheCreationTokens)
            } else {
                inputTokens
            },
            outputTokens = firstNonNegativeInt(
                usage,
                "outputTokens",
                "output_tokens",
                "completionTokens",
                "completion_tokens"
            ),
            cachedInputTokens = cachedInputTokens,
            cacheCreationTokens = cacheCreationTokens
        )
    }

    private fun firstNonNegativeInt(json: JSONObject?, vararg names: String): Int {
        if (json == null) return 0
        val name = names.firstOrNull(json::has) ?: return 0
        return nonNegativeInt(json, name)
    }

    private fun nonNegativeInt(json: JSONObject?, name: String): Int {
        val value = json?.opt(name) as? Number ?: return 0
        return value.toLong().coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
    }

    private fun saturatedSum(vararg values: Int): Int = values
        .fold(0L) { total, value -> total + value.coerceAtLeast(0).toLong() }
        .coerceAtMost(Int.MAX_VALUE.toLong())
        .toInt()
}
