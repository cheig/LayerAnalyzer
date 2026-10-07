// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.privacy.AgentFieldSensitivity
import com.example.layanalyzer.ai.audit.isAgentFatal
import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

/** Shared safety and transport boundary for direct provider adapters. */
abstract class DirectApiModelClient(
    protected val apiBaseUrl: String,
    protected val transport: AgentHttpTransport,
    protected val providerId: String,
    protected val modelId: String,
    protected val apiKeyProvider: () -> String?,
    override val capabilities: AiModelCapabilities,
    private val allowInsecureHttpForTests: Boolean = false
) : AiModelClient {

    protected abstract fun requestUrl(): String

    protected abstract fun requestHeaders(apiKey: String): Map<String, String>

    abstract fun encodeRequest(request: AgentModelRequest): String

    protected abstract fun parseResponse(body: String): AgentModelResponse

    protected abstract fun createStreamDecoder(): ModelStreamDecoder

    protected open fun encodeStreamingRequest(request: AgentModelRequest): String =
        JSONObject(encodeRequest(request)).put("stream", true).toString()

    final override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
        requestError(request)?.let { return AgentModelResponse.Failure(it) }
        val apiKey = apiKeyProvider()?.trim().orEmpty()

        val response = try {
            transport.execute(
                AgentHttpRequest(
                    requestId = request.requestId,
                    url = requestUrl(),
                    body = encodeRequest(request),
                    headers = requestHeaders(apiKey),
                    timeoutMillis = request.timeoutMillis
                )
            )
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (error: AgentHttpException) {
            return AgentModelResponse.Failure(mapTransportError(error, request.requestId))
        } catch (_: Throwable) {
            return AgentModelResponse.Failure(AiModelErrors.unavailable("network_error"))
        }

        if (response.statusCode !in 200..299) {
            return AgentModelResponse.Failure(mapHttpError(response))
        }
        return parseSafely(response.body)
    }

    final override suspend fun respondStreaming(
        request: AgentModelRequest,
        onChunk: suspend (StreamChunk) -> Unit
    ): AgentModelResponse {
        requestError(request)?.let { error ->
            return AgentModelResponse.Failure(error).also {
                onChunk(StreamChunk.Done(it))
            }
        }
        val apiKey = apiKeyProvider()?.trim().orEmpty()
        val streamDecoder = createStreamDecoder()
        val eventDecoder = ServerSentEventDecoder { data ->
            streamDecoder.accept(data, onChunk)
        }
        val response = try {
            transport.executeStreaming(
                AgentHttpRequest(
                    requestId = request.requestId,
                    url = requestUrl(),
                    body = encodeStreamingRequest(request),
                    headers = requestHeaders(apiKey) + ("Accept" to "text/event-stream"),
                    timeoutMillis = request.timeoutMillis
                )
            ) { rawChunk -> eventDecoder.accept(rawChunk) }
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (error: AgentHttpException) {
            return AgentModelResponse.Failure(mapTransportError(error, request.requestId)).also {
                onChunk(StreamChunk.Done(it))
            }
        } catch (_: Throwable) {
            return AgentModelResponse.Failure(AiModelErrors.unavailable("network_error")).also {
                onChunk(StreamChunk.Done(it))
            }
        }

        val result = try {
            val parsed = when {
                response.statusCode !in 200..299 -> AgentModelResponse.Failure(mapHttpError(response))
                response.body.isNotBlank() -> parseSafely(response.body)
                else -> {
                    eventDecoder.finish()
                    streamDecoder.finish()
                }
            }
            AgentResponseSemanticLimits.validate(parsed)
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (failure: Throwable) {
            if (failure.isAgentFatal()) throw failure
            AgentModelResponse.Failure(AiModelErrors.malformed("stream_decode"))
        }
        onChunk(StreamChunk.Done(result))
        return result
    }

    final override fun cancel(requestId: String) {
        transport.cancel(requestId)
    }

    private fun requestError(request: AgentModelRequest): AgentError? {
        if (request.requestId.isBlank()) return AiModelErrors.contract("blank_request_id")
        if (request.privacyMode == AgentPrivacyMode.LocalOnly) {
            return AgentError(
                code = AgentErrorCode.PRIVACY_BLOCKED,
                userMessage = "Remote model calls are disabled in Local only mode.",
                retryable = false,
                details = mapOf("reason" to "local_only")
            )
        }
        if (modelId.isBlank()) return configurationError("blank_model_id")
        if (!allowInsecureHttpForTests && !isSecureGatewayUrl(apiBaseUrl)) {
            return configurationError("https_required")
        }
        if (apiKeyProvider()?.trim().isNullOrBlank()) {
            return authenticationError("missing_api_key")
        }
        return null
    }

    protected fun mapHttpError(response: AgentHttpResponse): AgentError {
        val providerError = remoteErrorObject(response.body)
        val responseDetails = remoteErrorDetails(
            error = providerError,
            httpStatus = response.statusCode,
            responseBody = response.body
        ) + mapOf(
            "bytesReceived" to response.bytesReceived,
            "responseLimitBytes" to response.responseLimitBytes
        )
        val retryAfterDetails = retryAfterMillis(response.headers)
            ?.let { mapOf("retryAfterMillis" to it) }
            .orEmpty()
        return when (response.statusCode) {
            401, 403 -> authenticationError("http_${response.statusCode}", responseDetails)
            429 -> AgentError(
                code = AgentErrorCode.MODEL_RATE_LIMITED,
                userMessage = "The analysis model is rate limited. Try again later.",
                retryable = true,
                details = mapOf("providerId" to providerId) +
                    responseDetails + retryAfterDetails
            )
            408, 504 -> AiModelErrors.timeout(
                stage = "headers",
                details = mapOf("reason" to AiModelErrors.GATEWAY_TIMEOUT_REASON) + responseDetails
            )
            else -> providerError?.let {
                mapProviderError(it, response.statusCode, response.body)
            }
                ?: AiModelErrors.unavailable("http_${response.statusCode}", responseDetails)
        }
    }

    protected fun mapProviderError(
        error: JSONObject,
        httpStatus: Int? = null,
        responseBody: String? = null
    ): AgentError {
        val code = error.optString("code").lowercase(Locale.ROOT)
        val type = error.optString("type").lowercase(Locale.ROOT)
        val message = error.optString("message").lowercase(Locale.ROOT)
        val details = remoteErrorDetails(error, httpStatus, responseBody)
        return when {
            code.contains("context_length") || code.contains("input_too_large") ||
                code.contains("prompt_too_large") || type.contains("context_length") ||
                message.contains("context length") || message.contains("input is too large") ->
                AiModelErrors.inputContextLimit(details)
            code.contains("max_tokens") || code.contains("output_limit") ||
                type.contains("max_tokens") || message.contains("maximum output") ->
                AiModelErrors.outputTruncated(details = details)
            code.contains("timeout") || type.contains("timeout") || message.contains("timed out") ->
                AiModelErrors.timeout(stage = "decode", details = details)
            code.contains("auth") || code.contains("key") || type.contains("auth") ->
                authenticationError("provider_authentication", details)
            code.contains("rate") || code.contains("quota") ||
                type.contains("rate") || type.contains("quota") -> AgentError(
                    code = AgentErrorCode.MODEL_RATE_LIMITED,
                    userMessage = "The analysis model is rate limited. Try again later.",
                    retryable = true,
                    details = mapOf("providerId" to providerId) + details
                )
            // An unrecognized 4xx means the provider rejected this request.
            // Replaying the same body cannot recover, while 408 and 429 have
            // already been classified into their dedicated retryable errors.
            else -> AiModelErrors.unavailable("provider_error", details).copy(
                retryable = httpStatus == null || httpStatus !in 400..499
            )
        }
    }

    protected fun mapTransportError(error: AgentHttpException, requestId: String): AgentError =
        when (error.kind) {
            AgentHttpFailureKind.Cancelled -> AiModelErrors.cancelled(requestId)
            AgentHttpFailureKind.Timeout -> AiModelErrors.timeout(
                stage = error.failureStage,
                networkFailureKind = error.networkFailureKind,
                details = transportDetails(error)
            )
            AgentHttpFailureKind.Network -> AiModelErrors.unavailable(
                "network_error",
                transportDetails(error)
            )
            AgentHttpFailureKind.ResponseTooLarge -> AiModelErrors.responseTooLarge(
                transportDetails(error)
            )
            AgentHttpFailureKind.InsecureEndpoint -> configurationError("https_required")
        }

    private fun transportDetails(error: AgentHttpException): Map<String, Any?> = mapOf(
        "failureStage" to error.failureStage,
        "networkFailureKind" to error.networkFailureKind,
        "bytesReceived" to error.bytesReceived,
        "responseLimitBytes" to error.responseLimitBytes
    )

    protected fun authenticationError(
        reason: String,
        additionalDetails: Map<String, Any?> = emptyMap()
    ) = AgentError(
        code = AgentErrorCode.MODEL_AUTH_FAILED,
        userMessage = "The configured model API key is missing or was rejected.",
        retryable = false,
        details = mapOf("providerId" to providerId, "reason" to reason) + additionalDetails
    )

    protected fun configurationError(reason: String) = AgentError(
        code = AgentErrorCode.MODEL_UNAVAILABLE,
        userMessage = "The remote model configuration is incomplete or invalid.",
        retryable = false,
        details = mapOf("providerId" to providerId, "reason" to reason)
    )

    protected fun outputTruncatedError(
        target: AgentTruncationTarget = AgentTruncationTarget.Unknown,
        finishReason: String = "length"
    ) = AgentError(
        code = AgentErrorCode.MODEL_OUTPUT_TRUNCATED,
        userMessage = "The model ran out of output space before it finished the report. " +
            "The host will try a smaller report once.",
        retryable = true,
        details = mapOf(
            "providerId" to providerId,
            "reason" to "finish_reason_length",
            "providerFinishReason" to finishReason,
            "truncationTarget" to target.wireName
        )
    )

    /** Adapters must never turn a decoder bug into a generic network error. */
    private fun parseSafely(body: String): AgentModelResponse = try {
        AgentResponseSemanticLimits.validate(parseResponse(body))
    } catch (cancelled: kotlinx.coroutines.CancellationException) {
        throw cancelled
    } catch (failure: Throwable) {
        if (failure.isAgentFatal()) throw failure
        AgentModelResponse.Failure(AiModelErrors.malformed("adapter_decode"))
    }

    protected fun sanitizeToolData(data: AgentJsonObject): AgentJsonObject = data
        .entries
        .associate { (key, value) -> key to sanitizeValue(value, key) }

    /** Defense in depth for callers that bypass the normal redacting tool runner. */
    private fun sanitizeValue(value: Any?, fieldName: String): Any? {
        if (value == null) return null
        if (value is Map<*, *> &&
            (fieldName.equals("data", true) ||
                fieldName.equals("fields", true) ||
                fieldName.equals("metrics", true))
        ) {
            return value.entries.associate { (key, nested) ->
                key.toString() to sanitizeValue(nested, key.toString())
            }
        }
        return when (AgentFieldSensitivity.handling(fieldName)) {
            AgentFieldSensitivity.Handling.Credential -> mapOf("present" to true)
            AgentFieldSensitivity.Handling.Payload -> "PRIVACY_BLOCKED"
            else -> when (value) {
                is Map<*, *> -> value.entries.associate { (key, nested) ->
                    key.toString() to sanitizeValue(nested, key.toString())
                }
                is Iterable<*> -> value.map { sanitizeValue(it, fieldName) }
                is Array<*> -> value.map { sanitizeValue(it, fieldName) }
                else -> value
            }
        }
    }

    protected fun toolMessageContent(message: AgentModelMessage): String {
        val structured = message.structuredContent
        if (structured != null) return toJsonValue(sanitizeToolData(structured)).toString()
        return message.content
    }

    protected fun messageContent(value: Any?): String = when (value) {
        is String -> value
        is JSONArray -> buildString {
            for (index in 0 until value.length()) {
                val part = value.optJSONObject(index) ?: continue
                if (part.optString("type") in setOf("text", "output_text")) {
                    append(part.optString("text"))
                }
            }
        }
        else -> ""
    }

    protected fun extractJsonObject(content: String): String? {
        val trimmed = content.trim()
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) return trimmed
        val withoutFence = trimmed
            .removePrefix("```json")
            .removePrefix("```JSON")
            .removePrefix("```")
            .removeSuffix("```")
            .trim()
        if (withoutFence.startsWith("{") && withoutFence.endsWith("}")) return withoutFence
        val start = trimmed.indexOf('{')
        val end = trimmed.lastIndexOf('}')
        return if (start >= 0 && end > start) trimmed.substring(start, end + 1) else null
    }

    /** Decode a final report while retaining only safe structural diagnostics. */
    protected fun decodeFinalReportContent(
        content: String,
        providerFinishReason: String?
    ): FinalReportDecodeResult {
        val reportJson = extractJsonObject(content)
            ?: return FinalReportDecodeResult(
                error = malformedFinalError("no_json_object", content, providerFinishReason)
            )
        // A report that fails to parse gets one structural repair attempt before
        // it is discarded. The repair only inserts delimiters JSON grammar
        // requires, so a successfully repaired document carries exactly the data
        // the model emitted — a dropped quote in a few thousand characters no
        // longer costs the user a complete analysis.
        val usableJson = if (runCatching { JSONObject(reportJson) }.isSuccess) {
            reportJson
        } else {
            AgentJsonRepair.repair(reportJson)
                ?.takeIf { runCatching { JSONObject(it.json) }.isSuccess }
                ?.json
                ?: return FinalReportDecodeResult(
                    error = malformedFinalError("invalid_json", content, providerFinishReason)
                )
        }
        val report = AgentJsonCodec.decodeReport(usableJson).getOrNull()
            ?: return FinalReportDecodeResult(
                error = malformedFinalError(
                    "invalid_report_envelope",
                    content,
                    providerFinishReason
                )
            )
        return FinalReportDecodeResult(report = report)
    }

    protected data class FinalReportDecodeResult(
        val report: AgentReport? = null,
        val error: AgentError? = null
    )

    private fun malformedFinalError(
        reason: String,
        content: String,
        providerFinishReason: String?
    ): AgentError = AiModelErrors.malformed(
        reason = reason,
        details = mapOf(
            "contentChars" to content.length,
            "providerFinishReason" to providerFinishReason
                ?.takeIf { it.isNotBlank() }
                ?.take(MAX_FINISH_REASON_CHARS)
                .orEmpty()
        )
    )

    protected fun toJsonValue(value: Any?): Any = when (value) {
        null, JSONObject.NULL -> JSONObject.NULL
        is JSONObject, is JSONArray, is String, is Number, is Boolean -> value
        is Map<*, *> -> JSONObject().apply {
            value.forEach { (key, nested) -> if (key is String) put(key, toJsonValue(nested)) }
        }
        is Iterable<*> -> JSONArray().apply { value.forEach { put(toJsonValue(it)) } }
        is Array<*> -> JSONArray().apply { value.forEach { put(toJsonValue(it)) } }
        else -> value.toString()
    }

    protected fun jsonObjectToMap(json: JSONObject): AgentJsonObject = buildMap {
        val keys = json.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            put(key, fromJsonValue(json.opt(key)))
        }
    }

    private fun fromJsonValue(value: Any?): Any? = when (value) {
        null, JSONObject.NULL -> null
        is JSONObject -> jsonObjectToMap(value)
        is JSONArray -> buildList {
            for (index in 0 until value.length()) add(fromJsonValue(value.opt(index)))
        }
        else -> value
    }

    private companion object {
        const val MAX_FINISH_REASON_CHARS = 80
    }
}
