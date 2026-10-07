// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentPolicyTest {
    @Test
    fun defaultBudgetMatchesDesignDocument() {
        val policy = AgentPolicy()

        assertEquals(48, policy.maxSteps)
        assertEquals(
            AgentPolicy.DEFAULT_MAX_MODEL_REQUEST_TIMEOUT_MILLIS,
            policy.maxModelRequestTimeoutMillis
        )
        assertEquals(100, policy.maxSummaryFramesPerCall)
        assertEquals(16, policy.maxDetailFramesPerCall)
        assertEquals(48, policy.maxDetailFramesPerSession)
        assertEquals(32 * 1024, policy.maxToolResultBytes)
        assertEquals(1, policy.maxConcurrentSessions)
        assertFalse(policy.allowPayload)
        assertEquals(3, policy.maxInvalidArgumentRetries)
        assertEquals(AgentPolicy.DEFAULT_MAX_MODEL_RETRIES, policy.maxModelRetries)
        assertEquals(3, policy.maxConsecutiveIdenticalToolCalls)
        assertEquals(0L, policy.maxCumulativeInputTokens)
        assertEquals(0L, policy.maxCumulativeOutputTokens)
        assertEquals(policy.maxSteps * 2 + 2, policy.maxTurns)
    }

    @Test
    fun perStepTimeoutDoesNotScaleWithCaptureSize() {
        val defaultPolicy = AgentPolicy()

        assertEquals(defaultPolicy, defaultPolicy.adaptiveForCapture(1_999))
        assertEquals(defaultPolicy, defaultPolicy.adaptiveForCapture(13_702))
        assertEquals(
            AgentPolicy.DEFAULT_MAX_MODEL_REQUEST_TIMEOUT_MILLIS,
            defaultPolicy.maxModelRequestTimeoutMillis
        )
        // Tool steps stay on the tighter step ceiling.
        assertEquals(120_000L, defaultPolicy.maxToolTimeoutMillis)
    }

    @Test
    fun adaptiveBudgetDoesNotWidenAStrictCallerBudget() {
        val strict = AgentPolicy(
            maxModelRequestTimeoutMillis = 60_000L,
            maxToolTimeoutMillis = 60_000L
        )

        assertEquals(strict, strict.adaptiveForCapture(13_702))
    }

    @Test
    fun clampNeverWidensTheHostLimit() {
        assertEquals(100, AgentPolicy.clamp(null, 100))
        assertEquals(100, AgentPolicy.clamp(5_000, 100))
        assertEquals(20, AgentPolicy.clamp(20, 100))
        assertEquals(1, AgentPolicy.clamp(0, 100))
        assertEquals(1, AgentPolicy.clamp(-40, 100))
    }

    @Test
    fun narrowedToTakesTheStricterValueOfEachLimit() {
        val base = AgentPolicy()
        val narrowed = base.narrowedTo(
            AgentPolicy(maxSteps = 4, maxSummaryFramesPerCall = 1_000, allowPayload = true)
        )

        assertEquals(4, narrowed.maxSteps)
        assertEquals(100, narrowed.maxSummaryFramesPerCall)
        assertFalse(narrowed.allowPayload)
        assertEquals(
            2,
            base.narrowedTo(AgentPolicy(maxConsecutiveIdenticalToolCalls = 2))
                .maxConsecutiveIdenticalToolCalls
        )
        assertEquals(
            1_000L,
            AgentPolicy(maxCumulativeInputTokens = 1_000L)
                .narrowedTo(AgentPolicy())
                .maxCumulativeInputTokens
        )
        assertEquals(
            500L,
            AgentPolicy(maxCumulativeInputTokens = 1_000L)
                .narrowedTo(AgentPolicy(maxCumulativeInputTokens = 500L))
                .maxCumulativeInputTokens
        )
    }

    @Test
    fun narrowedToCannotEnablePayloadFromOneSideOnly() {
        val permissive = AgentPolicy(allowPayload = true)

        assertFalse(permissive.narrowedTo(AgentPolicy()).allowPayload)
        assertTrue(permissive.narrowedTo(AgentPolicy(allowPayload = true)).allowPayload)
    }

    @Test
    fun aggregateAndMetadataAreAllowedInRedactedMode() {
        val policy = AgentPolicy()

        assertNull(
            AgentSensitivityPolicy.check(
                AgentDataSensitivity.Aggregate,
                AgentPrivacyMode.RedactedMetadata,
                policy
            )
        )
        assertNull(
            AgentSensitivityPolicy.check(
                AgentDataSensitivity.Metadata,
                AgentPrivacyMode.RedactedMetadata,
                policy
            )
        )
    }

    @Test
    fun unknownSensitivityAndUnknownModeFailClosed() {
        val policy = AgentPolicy()

        assertEquals(
            AgentErrorCode.PRIVACY_BLOCKED,
            AgentSensitivityPolicy.check(
                AgentDataSensitivity.Unknown,
                AgentPrivacyMode.RedactedMetadata,
                policy
            )?.code
        )
        assertEquals(
            AgentErrorCode.PRIVACY_BLOCKED,
            AgentSensitivityPolicy.check(
                AgentDataSensitivity.Aggregate,
                AgentPrivacyMode.Unknown,
                policy
            )?.code
        )
    }

    @Test
    fun credentialIsBlockedEvenWithPayloadEnabled() {
        val error = AgentSensitivityPolicy.check(
            AgentDataSensitivity.Credential,
            AgentPrivacyMode.SelectedPayload,
            AgentPolicy(allowPayload = true)
        )

        assertEquals(AgentErrorCode.PRIVACY_BLOCKED, error?.code)
        assertEquals("credential_never_shared", error?.details?.get("reason"))
    }

    @Test
    fun invalidPolicyValuesAreRejected() {
        assertTrue(runCatching { AgentPolicy(maxSteps = 0) }.isFailure)
        assertTrue(runCatching { AgentPolicy(maxModelRequestTimeoutMillis = 0L) }.isFailure)
        assertTrue(
            runCatching {
                AgentPolicy(maxModelRequestTimeoutMillis = AgentPolicy.MAX_MODEL_REQUEST_TIMEOUT_MILLIS + 1L)
            }.isFailure
        )
        assertTrue(runCatching { AgentPolicy(maxToolTimeoutMillis = 0L) }.isFailure)
        assertTrue(runCatching { AgentPolicy(maxToolTimeoutMillis = 120_001L) }.isFailure)
        assertTrue(runCatching { AgentPolicy(maxToolResultBytes = 8) }.isFailure)
        assertTrue(runCatching { AgentPolicy(maxInvalidArgumentRetries = 0) }.isFailure)
        assertTrue(runCatching { AgentPolicy(maxModelRetries = -1) }.isFailure)
        assertTrue(runCatching { AgentPolicy(maxModelRetries = AgentPolicy.MAX_MODEL_RETRIES + 1) }.isFailure)
        assertTrue(runCatching { AgentPolicy(maxConsecutiveIdenticalToolCalls = 0) }.isFailure)
        assertTrue(runCatching { AgentPolicy(maxCumulativeInputTokens = -1L) }.isFailure)
        assertTrue(runCatching { AgentPolicy(maxCumulativeOutputTokens = -1L) }.isFailure)
        assertTrue(runCatching { AgentPolicy(maxTurns = 0) }.isFailure)
    }

    @Test
    fun narrowedToTakesTheStricterTurnAndRetryCeilings() {
        val narrowed = AgentPolicy().narrowedTo(
            AgentPolicy(
                maxInvalidArgumentRetries = 1,
                maxModelRetries = 1,
                maxTurns = 4
            )
        )

        assertEquals(1, narrowed.maxInvalidArgumentRetries)
        assertEquals(1, narrowed.maxModelRetries)
        assertEquals(4, narrowed.maxTurns)
    }

    @Test
    @Suppress("DEPRECATION")
    fun modelRetryDelayUsesExponentialBackoffWithAFourSecondCap() {
        assertEquals(500L, AgentPolicy.modelRetryDelayMillis(1))
        assertEquals(1_000L, AgentPolicy.modelRetryDelayMillis(2))
        assertEquals(2_000L, AgentPolicy.modelRetryDelayMillis(3))
        assertEquals(4_000L, AgentPolicy.modelRetryDelayMillis(4))
        assertEquals(4_000L, AgentPolicy.modelRetryDelayMillis(8))
    }

    @Test
    fun classifiedRetryDelayHonorsProviderGuidanceAndErrorType() {
        val rateLimited = AgentError(
            code = AgentErrorCode.MODEL_RATE_LIMITED,
            userMessage = "limited",
            retryable = true,
            details = mapOf("retryAfterMillis" to 12_345L)
        )
        val unavailable = AgentError(
            code = AgentErrorCode.MODEL_UNAVAILABLE,
            userMessage = "unavailable",
            retryable = true
        )
        val timeout = unavailable.copy(details = mapOf("reason" to "timeout"))

        assertEquals(12_345L, AgentPolicy.retryDelayMillis(1, rateLimited, 0.2))
        assertEquals(2_000L, AgentPolicy.retryDelayMillis(1, rateLimited.copy(details = emptyMap()), 0.0))
        assertEquals(1_200L, AgentPolicy.retryDelayMillis(2, unavailable, 0.2))
        assertEquals(200L, AgentPolicy.retryDelayMillis(1, timeout, 0.0))
    }
}
