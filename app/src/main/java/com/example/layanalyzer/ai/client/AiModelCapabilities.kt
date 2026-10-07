// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

/** Where the host learned the token ceilings for a model. */
enum class TokenLimitSource {
    /** A provider/gateway capability handshake supplied the value. */
    Negotiated,
    /** The model id matched a maintained, documented family. */
    KnownModel,
    /** The user explicitly supplied an advanced limit. */
    UserConfigured,
    /** The adapter supplied a conservative default; it is not provider data. */
    AdapterFallback,
    /** No usable token ceiling was available. */
    Unknown
}

/**
 * What a model client can actually do, declared by the client itself.
 *
 * The Agent loop reads this before building a request so it never asks for a
 * feature the adapter cannot honour.  Every value describes the *boundary*, not
 * a vendor: there is no field here that a provider SDK would have to fill in.
 *
 * The constructor defaults are the most conservative useful shape — tool calling, one call
 * at a time, structured output, no streaming — because a client that forgets to
 * declare a capability should degrade rather than have the loop assume more
 * than the adapter supports.
 */
data class AiModelCapabilities(
    /** The client can be given tool definitions and return ToolCalls. */
    val toolCalling: Boolean = true,
    /**
     * The client may return more than one tool call per response.
     *
     * This controls both what the host announces and whether different tool
     * names may be dispatched concurrently. Same-name calls stay ordered.
     */
    val parallelToolCalls: Boolean = false,
    /** The client honours AgentModelRequest.responseSchema for its Final. */
    val structuredOutput: Boolean = true,
    /** The client can emit incremental provider-neutral output. */
    val streaming: Boolean = false,
    /** Total context budget in tokens, or 0 when the client does not report one. */
    val maxContextTokens: Int = 0,
    /** Output ceiling in tokens, or 0 when the client does not report one. */
    val maxOutputTokens: Int = 0,
    /** Provenance of [maxContextTokens] and [maxOutputTokens]. */
    val tokenLimitSource: TokenLimitSource = TokenLimitSource.Unknown
) {
    init {
        require(maxContextTokens >= 0) { "maxContextTokens must not be negative." }
        require(maxOutputTokens >= 0) { "maxOutputTokens must not be negative." }
        require(!parallelToolCalls || toolCalling) {
            "parallelToolCalls requires toolCalling."
        }
    }

    /** True when the client reports a usable context ceiling. */
    val hasContextLimit: Boolean
        get() = maxContextTokens > 0

    /**
     * Output ceiling for one request: a caller may only ask for less than the
     * client supports, never more.  A request value of 0 means "client default".
     */
    fun clampOutputTokens(requested: Int): Int = when {
        requested <= 0 -> maxOutputTokens
        maxOutputTokens <= 0 -> requested
        else -> minOf(requested, maxOutputTokens)
    }

    companion object {
        /**
         * The shape Phase 0 is built against: sequential tool calling plus a
         * structured final report, which is exactly what MockAiModelClient and
         * the AgentLoop need.
         */
        val PHASE0: AiModelCapabilities = AiModelCapabilities()

        /**
         * Default shape for a direct BYOK call to a modern OpenAI-compatible
         * endpoint.
         *
         * [PHASE0] reports 0/0 for clients that do not advertise limits. A
         * caller that knows its model's real limits should still pass them
         * explicitly; these values are only the default for the direct
         * OpenAI-compatible adapter.
        */
        val OPENAI_COMPATIBLE_DEFAULT: AiModelCapabilities = AiModelCapabilities(
            streaming = true,
            maxContextTokens = 128_000,
            maxOutputTokens = 8_192,
            tokenLimitSource = TokenLimitSource.AdapterFallback
        )

        /** The Responses API has the same structured/tool boundary as Chat Completions. */
        val OPENAI_RESPONSES_DEFAULT: AiModelCapabilities = AiModelCapabilities(
            streaming = true,
            maxContextTokens = 128_000,
            maxOutputTokens = 8_192,
            tokenLimitSource = TokenLimitSource.AdapterFallback
        )

        /** Conservative defaults for direct Anthropic Messages API calls. */
        val ANTHROPIC_DEFAULT: AiModelCapabilities = AiModelCapabilities(
            streaming = true,
            maxContextTokens = 200_000,
            maxOutputTokens = 64_000,
            tokenLimitSource = TokenLimitSource.AdapterFallback
        )

        /**
         * A client that can only answer in prose.  Useful for asserting that the
         * loop refuses to start a tool-driven run rather than silently sending
         * tool definitions no one will read.
         */
        val TEXT_ONLY: AiModelCapabilities = AiModelCapabilities(
            toolCalling = false,
            parallelToolCalls = false,
            structuredOutput = false
        )
    }
}
