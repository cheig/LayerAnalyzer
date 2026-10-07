// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.client.AiModelErrors
import com.example.layanalyzer.ai.client.AgentTruncationTarget
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentRunPhase

enum class ModelRetryDecisionKind {
    Stop,
    RetrySame,
    RetryWithOutputLimit,
    ForceSummary
}

data class ModelRetryDecision(
    val kind: ModelRetryDecisionKind,
    val outputTokens: Int? = null,
    val requiresInputCompaction: Boolean = false,
    val retryLimit: Int = 0
)

/** Pure, provider-neutral retry classification for one logical model request. */
object ModelRetryPolicy {
    fun decide(
        error: AgentError,
        phase: AgentRunPhase,
        requestStage: AgentModelRequestStage = AgentModelRequestStage.FinalReport,
        truncationTarget: AgentTruncationTarget = AgentTruncationTarget.Unknown,
        retriesUsed: Int,
        currentOutputTokens: Int,
        maximumOutputTokens: Int,
        userMaxRetries: Int
    ): ModelRetryDecision {
        val isGatewayTimeout = error.code == AgentErrorCode.MODEL_UNAVAILABLE &&
            error.details["reason"] == AiModelErrors.GATEWAY_TIMEOUT_REASON
        val retryLimit = userMaxRetries
        // Finalizing is the bounded recovery path itself, and its own failures
        // are handled by the caller's degradation ladder (format repair, then a
        // synthesized report). Retrying here would spend the same
        // evidence-preserving escape hatch twice and can turn one terminal
        // failure into a tail of summary requests.
        val canRetry = phase != AgentRunPhase.Finalizing &&
            error.retryable &&
            retriesUsed < retryLimit
        if (canRetry) {
            return when (error.code) {
                AgentErrorCode.MODEL_RESPONSE_TOO_LARGE,
                AgentErrorCode.MODEL_TIMEOUT,
                AgentErrorCode.MODEL_UNAVAILABLE -> {
                    if (error.code == AgentErrorCode.MODEL_UNAVAILABLE && !isGatewayTimeout) {
                        // A provider outage says nothing about the request, so
                        // replaying it unchanged is the right retry.
                        ModelRetryDecision(
                            kind = ModelRetryDecisionKind.RetrySame,
                            retryLimit = retryLimit
                        )
                    } else {
                        val shrunk = smaller(currentOutputTokens)
                        when {
                            shrunk != null -> ModelRetryDecision(
                                kind = ModelRetryDecisionKind.RetryWithOutputLimit,
                                outputTokens = shrunk,
                                retryLimit = retryLimit
                            )
                            // At the floor the allowance can no longer adapt.
                            // Shrinking is the only thing that made these
                            // retries differ from each other: an oversized
                            // response is deterministic, and a gateway deadline
                            // is fixed, so a byte-identical replay cannot pass
                            // either. A host-side timeout is the one case that
                            // may still be a transient blip.
                            error.code == AgentErrorCode.MODEL_TIMEOUT ->
                                ModelRetryDecision(
                                    kind = ModelRetryDecisionKind.RetrySame,
                                    retryLimit = retryLimit
                                )
                            else -> ModelRetryDecision(
                                kind = if (phase != AgentRunPhase.Revising) {
                                    ModelRetryDecisionKind.ForceSummary
                                } else {
                                    ModelRetryDecisionKind.Stop
                                },
                                retryLimit = retryLimit
                            )
                        }
                    }
                }
                AgentErrorCode.MODEL_OUTPUT_TRUNCATED -> {
                    val mayExpand = truncationTarget == AgentTruncationTarget.ToolCalls &&
                        requestStage in setOf(
                            AgentModelRequestStage.PlanDeclaration,
                            AgentModelRequestStage.ToolSelection
                        )
                    val expanded = if (mayExpand) {
                        larger(currentOutputTokens, maximumOutputTokens)
                    } else {
                        null
                    }
                    if (expanded != null) {
                        ModelRetryDecision(
                            kind = ModelRetryDecisionKind.RetryWithOutputLimit,
                            outputTokens = expanded,
                            retryLimit = retryLimit
                        )
                    } else {
                        // Truncation is deterministic: the model filled the
                        // ceiling. With no room left to widen, replaying the
                        // identical request reproduces the identical
                        // truncation, so hand off instead of spending retries.
                        ModelRetryDecision(
                            kind = if (mayExpand &&
                                phase != AgentRunPhase.Finalizing &&
                                phase != AgentRunPhase.Revising) {
                                ModelRetryDecisionKind.ForceSummary
                            } else {
                                ModelRetryDecisionKind.Stop
                            },
                            retryLimit = retryLimit
                        )
                    }
                }
                AgentErrorCode.MODEL_INPUT_CONTEXT_LIMIT ->
                    // Also deterministic: the payload did not fit. Compaction
                    // is the one thing that can change that, and it runs once,
                    // so a second attempt on an unchanged payload would only
                    // replay the overflow.
                    if (retriesUsed == 0) {
                        ModelRetryDecision(
                            kind = ModelRetryDecisionKind.RetrySame,
                            requiresInputCompaction = true,
                            retryLimit = retryLimit
                        )
                    } else {
                        ModelRetryDecision(
                            kind = if (phase != AgentRunPhase.Finalizing &&
                                phase != AgentRunPhase.Revising) {
                                ModelRetryDecisionKind.ForceSummary
                            } else {
                                ModelRetryDecisionKind.Stop
                            },
                            retryLimit = retryLimit
                        )
                    }
                else -> ModelRetryDecision(
                    kind = ModelRetryDecisionKind.RetrySame,
                    retryLimit = retryLimit
                )
            }
        }

        val mayForceSummary = phase != AgentRunPhase.Finalizing &&
            phase != AgentRunPhase.Revising &&
            isRecoverable(error)
        return ModelRetryDecision(
            kind = if (mayForceSummary) ModelRetryDecisionKind.ForceSummary
            else ModelRetryDecisionKind.Stop,
            retryLimit = retryLimit
        )
    }

    /**
     * Floor for the shrinking retry allowance.
     *
     * Response-size and timeout retries halve the output ceiling every attempt,
     * so with a high user retry count an unbounded shrink would reach an
     * allowance too small to hold any report — turning a recoverable failure
     * into a guaranteed truncation. This floor is the smallest allowance that
     * still fits the compact forced summary.
     */
    const val MIN_RETRY_OUTPUT_TOKENS = 1_024

    private fun isRecoverable(error: AgentError): Boolean =
        error.code == AgentErrorCode.MODEL_RATE_LIMITED ||
            error.code == AgentErrorCode.MODEL_UNAVAILABLE ||
            error.code == AgentErrorCode.MODEL_TIMEOUT ||
            error.code == AgentErrorCode.MODEL_RESPONSE_TOO_LARGE ||
            error.code == AgentErrorCode.MODEL_INPUT_CONTEXT_LIMIT ||
            error.code == AgentErrorCode.MODEL_OUTPUT_TRUNCATED ||
            // A report the host could not parse leaves the gathered evidence
            // intact, so the bounded summary path can still answer from it
            // instead of ending the run with nothing.
            error.code == AgentErrorCode.MODEL_RESPONSE_MALFORMED

    /** Halve the allowance, or null once it is already at the floor. */
    private fun smaller(current: Int): Int? {
        if (current <= MIN_RETRY_OUTPUT_TOKENS) return null
        return (current / 2).coerceAtLeast(MIN_RETRY_OUTPUT_TOKENS)
    }

    private fun larger(current: Int, maximum: Int): Int? {
        if (maximum <= current) return null
        return minOf(maximum, (current.toLong() * 2L).coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            .coerceAtLeast(current + 1)
    }
}
