// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AiModelCapabilitiesResolverTest {
    @Test
    fun knownOpenAiFamiliesUseDocumentedTokenLimits() {
        val defaults = AiModelCapabilities.OPENAI_RESPONSES_DEFAULT.copy(
            parallelToolCalls = true
        )

        val latest = AiModelCapabilitiesResolver.resolve("gpt-5.6-terra", defaults)
        val longContext = AiModelCapabilitiesResolver.resolve(
            "gpt-4.1-mini-2025-04-14",
            defaults
        )
        val reasoning = AiModelCapabilitiesResolver.resolve("o4-mini-2025-04-16", defaults)

        assertEquals(1_050_000, latest.maxContextTokens)
        assertEquals(128_000, latest.maxOutputTokens)
        assertEquals(1_047_576, longContext.maxContextTokens)
        assertEquals(32_768, longContext.maxOutputTokens)
        assertEquals(200_000, reasoning.maxContextTokens)
        assertEquals(100_000, reasoning.maxOutputTokens)
        assertTrue(latest.streaming)
        assertTrue(latest.parallelToolCalls)
    }

    @Test
    fun knownAnthropicFamiliesCoverCurrentAndLegacyLongContextModels() {
        val defaults = AiModelCapabilities.ANTHROPIC_DEFAULT

        val opus = AiModelCapabilitiesResolver.resolve("claude-opus-5", defaults)
        val sonnet = AiModelCapabilitiesResolver.resolve("claude-sonnet-4-6", defaults)
        val haiku = AiModelCapabilitiesResolver.resolve(
            "claude-haiku-4-5-20251001",
            defaults
        )

        assertEquals(1_000_000, opus.maxContextTokens)
        assertEquals(128_000, opus.maxOutputTokens)
        assertEquals(1_000_000, sonnet.maxContextTokens)
        assertEquals(128_000, sonnet.maxOutputTokens)
        assertEquals(200_000, haiku.maxContextTokens)
        assertEquals(64_000, haiku.maxOutputTokens)
        assertTrue(opus.streaming)
    }

    @Test
    fun unknownModelReturnsTheAdapterDefaultsWithoutGuessing() {
        val defaults = AiModelCapabilities(
            toolCalling = false,
            structuredOutput = false,
            streaming = true,
            maxContextTokens = 73_000,
            maxOutputTokens = 9_000
        )

        val resolved = AiModelCapabilitiesResolver.resolve("private-model-v7", defaults)

        assertEquals(73_000, resolved.maxContextTokens)
        assertEquals(9_000, resolved.maxOutputTokens)
        assertEquals(TokenLimitSource.AdapterFallback, resolved.tokenLimitSource)
        assertFalse(resolved.toolCalling)
        assertFalse(resolved.structuredOutput)
        assertTrue(resolved.streaming)
    }

    @Test
    fun providerQualifiedGlmModelDoesNotMatchTheGptFamily() {
        val resolved = AiModelCapabilitiesResolver.resolve(
            "z-ai/glm-5.2",
            AiModelCapabilities.OPENAI_COMPATIBLE_DEFAULT
        )

        assertEquals(128_000, resolved.maxContextTokens)
        assertEquals(8_192, resolved.maxOutputTokens)
        assertEquals(TokenLimitSource.AdapterFallback, resolved.tokenLimitSource)
    }

    @Test
    fun deepSeekV4FlashUsesItsDeclaredWideOutputWindow() {
        val resolved = AiModelCapabilitiesResolver.resolve(
            "deepseek-v4-flash-0731",
            AiModelCapabilities.OPENAI_COMPATIBLE_DEFAULT
        )

        assertEquals(128_000, resolved.maxContextTokens)
        assertEquals(328_000, resolved.maxOutputTokens)
        assertEquals(TokenLimitSource.KnownModel, resolved.tokenLimitSource)
        assertTrue(resolved.streaming)
    }

    @Test
    fun userConfiguredLimitsOverrideKnownModelAndAreMarkedAsSuch() {
        val resolved = AiModelCapabilitiesResolver.resolve(
            modelId = "gpt-5.6-terra",
            adapterDefaults = AiModelCapabilities.OPENAI_COMPATIBLE_DEFAULT,
            userContextLimitTokens = 96_000,
            userOutputLimitTokens = 12_000
        )

        assertEquals(96_000, resolved.maxContextTokens)
        assertEquals(12_000, resolved.maxOutputTokens)
        assertEquals(TokenLimitSource.UserConfigured, resolved.tokenLimitSource)
    }

    @Test(expected = IllegalArgumentException::class)
    fun userConfiguredOutputLimitIsRangeChecked() {
        AiModelCapabilitiesResolver.resolve(
            modelId = "private-model",
            adapterDefaults = AiModelCapabilities.OPENAI_COMPATIBLE_DEFAULT,
            userOutputLimitTokens = 1
        )
    }
}
