// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse

/**
 * The only way the Agent core talks to a model.
 *
 * The interface is deliberately narrow and vendor-neutral.  An implementation
 * receives an [AgentModelRequest] built purely from AI-01 domain types and
 * answers with the closed [AgentModelResponse] vocabulary; it never hands the
 * caller a provider request/response object, an HTTP body, a `Context`, or an
 * API key.  Whatever authentication, retry, or wire format a real adapter needs
 * stays behind this boundary, which is what lets the loop run against
 * [MockAiModelClient] with no network at all.
 *
 * Implementations must be safe to call from any coroutine and must respect
 * structured concurrency: [respond] suspends until it has an answer and must not
 * launch work into a scope that outlives its caller.
 */
interface AiModelClient {
    /** Stable identifier recorded in AgentReportProvenance.modelId. */
    val id: String

    /** What this client supports; the loop reads it before building a request. */
    val capabilities: AiModelCapabilities

    /**
     * Produce one response for one request.
     *
     * An implementation reports trouble as [AgentModelResponse.Failure] carrying
     * an already-mapped [AgentError] rather than by throwing, so the loop has a
     * single error vocabulary to reason about.  The one exception is
     * cancellation: a cancelled call must let `CancellationException` propagate
     * so structured concurrency still works.
     */
    suspend fun respond(request: AgentModelRequest): AgentModelResponse

    /**
     * Produce one response while exposing provider-neutral incremental output.
     *
     * The default keeps existing local, mock, and normalized gateway clients
     * source-compatible. Clients that advertise [AiModelCapabilities.streaming]
     * override this method and emit deltas as their wire response arrives.
     */
    suspend fun respondStreaming(
        request: AgentModelRequest,
        onChunk: suspend (StreamChunk) -> Unit
    ): AgentModelResponse {
        val response = respond(request)
        onChunk(StreamChunk.Done(response))
        return response
    }

    /**
     * Cancel an in-flight request by [AgentModelRequest.requestId].
     *
     * Must be idempotent, safe to call for an unknown or already-finished id,
     * and must affect only the named request.  It is a non-suspending signal:
     * the cancelled [respond] call is what actually completes.
     */
    fun cancel(requestId: String)
}

/** Incremental model output after provider-specific SSE events are normalized. */
sealed interface StreamChunk {
    data class TextDelta(val text: String) : StreamChunk

    data class ToolCallStart(
        val index: Int,
        val toolCallId: String,
        val toolName: String
    ) : StreamChunk

    data class ToolCallArgumentDelta(
        val index: Int,
        val toolCallId: String?,
        val delta: String
    ) : StreamChunk

    data class Done(val response: AgentModelResponse) : StreamChunk
}

enum class AgentTruncationTarget(val wireName: String) {
    ToolCalls("tool_calls"),
    FinalReport("final_report"),
    Unknown("unknown");

    companion object {
        fun from(value: Any?): AgentTruncationTarget = entries.firstOrNull {
            it.wireName == value?.toString()?.lowercase()
        } ?: Unknown
    }
}

/** Optional capability handshake implemented by gateway-backed clients. */
interface AgentCapabilityNegotiator {
    /** Production gateway clients negotiate before the first model turn. */
    val negotiateBeforeRun: Boolean
        get() = false

    /** A gateway may explicitly permit one final report without tools. */
    val oneShotFallback: Boolean
        get() = false

    /** Returns a normalized error, or null after capabilities were accepted. */
    suspend fun negotiateCapabilities(): AgentError?
}

/** Errors every model client maps to, so the loop never sees a raw exception. */
object AiModelErrors {
    /**
     * An intermediary (proxy, load balancer) gave up waiting for the upstream
     * model — HTTP 408/504 — rather than the model itself failing.
     *
     * This is distinct from an ordinary `timeout` because the deadline belongs
     * to the intermediary, not to the host: retrying a byte-identical request
     * against a fixed proxy ceiling cannot succeed. The agent loop therefore
     * shrinks the output allowance between these attempts, down to a floor
     * that still holds a report.
     */
    const val GATEWAY_TIMEOUT_REASON: String = "gateway_timeout"

    fun inputContextLimit(details: Map<String, Any?> = emptyMap()): AgentError = AgentError(
        code = AgentErrorCode.MODEL_INPUT_CONTEXT_LIMIT,
        userMessage = "The analysis request is larger than the model context window.",
        retryable = true,
        details = mapOf("reason" to "input_context_limit") + details
    )

    fun outputTruncated(
        target: AgentTruncationTarget = AgentTruncationTarget.Unknown,
        details: Map<String, Any?> = emptyMap()
    ): AgentError = AgentError(
        code = AgentErrorCode.MODEL_OUTPUT_TRUNCATED,
        userMessage = "The model stopped at its output limit before completing the report.",
        retryable = true,
        details = mapOf(
            "reason" to "output_truncated",
            "truncationTarget" to target.wireName
        ) + details
    )

    fun responseTooLarge(details: Map<String, Any?> = emptyMap()): AgentError = AgentError(
        code = AgentErrorCode.MODEL_RESPONSE_TOO_LARGE,
        userMessage = "The model response exceeded the app's safe processing limit.",
        // Retryability here means "the policy may attempt one smaller
        // generation"; it never means that the same request may be replayed.
        retryable = true,
        details = mapOf("reason" to "response_too_large") + details
    )

    /**
     * The model returned something the app could not read.
     *
     * Format failures are retryable by default. A dropped delimiter is a
     * sampling accident, not a property of the request: the same prompt
     * regenerated usually parses, and treating it as terminal meant a run could
     * fail with its entire retry budget unspent. Callers that know a particular
     * malformation cannot improve on retry pass `retryable = false`.
     */
    fun malformed(
        reason: String,
        details: Map<String, Any?> = emptyMap(),
        retryable: Boolean = true
    ): AgentError = AgentError(
        code = AgentErrorCode.MODEL_RESPONSE_MALFORMED,
        userMessage = "The analysis model returned a response the app could not understand.",
        retryable = retryable,
        details = mapOf("reason" to reason) + details
    )

    fun timeout(
        stage: String = "unknown",
        networkFailureKind: String = "timeout",
        details: Map<String, Any?> = emptyMap()
    ): AgentError = AgentError(
        code = AgentErrorCode.MODEL_TIMEOUT,
        userMessage = "The analysis model did not respond before the time limit.",
        retryable = true,
        details = mapOf(
            "reason" to "timeout",
            "failureStage" to stage,
            "networkFailureKind" to networkFailureKind
        ) + details
    )

    fun cancelled(requestId: String): AgentError = AgentError(
        code = AgentErrorCode.CANCELLED,
        userMessage = "The analysis was cancelled.",
        retryable = false,
        details = mapOf("requestId" to requestId)
    )

    fun unavailable(reason: String, details: Map<String, Any?> = emptyMap()): AgentError = AgentError(
        code = AgentErrorCode.MODEL_UNAVAILABLE,
        userMessage = "The analysis model is unavailable.",
        retryable = true,
        details = buildMap {
            put("reason", reason)
            putAll(details)
        }
    )

    /**
     * A client-side contract violation — a scripted expectation that did not
     * match, an exhausted script, a response the adapter could not map.  This is
     * a host bug or a test-setup bug, not something a retry would fix.
     */
    fun contract(reason: String, details: Map<String, Any?> = emptyMap()): AgentError = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The analysis model returned an unexpected response.",
        retryable = false,
        details = buildMap {
            put("reason", reason)
            putAll(details)
        }
    )
}
