// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.ai.privacy.AgentFieldSensitivity
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolDefinition
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/** Configuration for the provider-neutral Android gateway. */
data class CloudModelConfiguration(
    val providerId: String,
    val modelId: String,
    val gatewayBaseUrl: String
)

/**
 * Adapter for the normalized gateway contract.
 *
 * The only wire vocabulary here is the gateway vocabulary from AI-23:
 * `requestId`, `modelId`, `messages`, `tools`, `responseSchema`,
 * `maxOutputTokens`, `timeout`, `privacyMode` and `clientSchemaVersion`.
 * Provider SDK classes and provider response fields never leave this file.
 */
class CloudAiModelClient(
    private val gatewayBaseUrl: String,
    private val transport: AgentHttpTransport,
    private val providerId: String = "gateway",
    private val modelId: String = "default",
    private val authTokenProvider: () -> String? = { null },
    private val byokSecretProvider: () -> String? = { null },
    initialCapabilities: AiModelCapabilities = AiModelCapabilities.PHASE0,
    override val negotiateBeforeRun: Boolean = false,
    private val responseEndpointPath: String = "v1/agent/respond",
    private val modelsEndpointPath: String = "v1/models",
    private val cancelEndpointPath: String = "v1/agent/cancel",
    internal val clientSchemaVersion: String = CLIENT_SCHEMA_VERSION,
    private val allowInsecureHttpForTests: Boolean = false
) : AiModelClient, AgentCapabilityNegotiator {

    constructor(
        configuration: CloudModelConfiguration,
        transport: AgentHttpTransport,
        authTokenProvider: () -> String? = { null },
        byokSecretProvider: () -> String? = { null },
        initialCapabilities: AiModelCapabilities = AiModelCapabilities.PHASE0,
        negotiateBeforeRun: Boolean = false
    ) : this(
        gatewayBaseUrl = configuration.gatewayBaseUrl,
        transport = transport,
        providerId = configuration.providerId,
        modelId = configuration.modelId,
        authTokenProvider = authTokenProvider,
        byokSecretProvider = byokSecretProvider,
        initialCapabilities = initialCapabilities,
        negotiateBeforeRun = negotiateBeforeRun
    )

    override val id: String = "cloud:$providerId:$modelId"

    @Volatile
    private var negotiatedCapabilities: AiModelCapabilities = initialCapabilities

    @Volatile
    private var capabilitiesNegotiated: Boolean = false

    /** True after a gateway reports that the selected model cannot call tools. */
    @Volatile
    override var oneShotFallback: Boolean = !initialCapabilities.toolCalling
        private set

    override val capabilities: AiModelCapabilities
        get() = negotiatedCapabilities

    override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
        if (request.requestId.isBlank()) {
            return AgentModelResponse.Failure(
                AiModelErrors.contract("blank_request_id")
            )
        }
        if (request.privacyMode == AgentPrivacyMode.LocalOnly) {
            // This guard is intentionally before URL validation and transport
            // creation: LocalOnly must be provably network-free.
            return AgentModelResponse.Failure(
                AgentError(
                    code = AgentErrorCode.PRIVACY_BLOCKED,
                    userMessage = "Cloud analysis is disabled in Local only mode.",
                    retryable = false,
                    details = mapOf("reason" to "local_only")
                )
            )
        }
        if (!allowInsecureHttpForTests && !isSecureGatewayUrl(gatewayBaseUrl)) {
            return AgentModelResponse.Failure(AiModelErrors.unavailable("https_required"))
        }

        if (negotiateBeforeRun && !capabilitiesNegotiated) {
            negotiateCapabilities()?.let { return AgentModelResponse.Failure(it) }
        }

        val httpRequest = AgentHttpRequest(
            requestId = request.requestId,
            url = endpointUrl(responseEndpointPath),
            body = encodeRequest(request),
            headers = authorizationHeaders(),
            timeoutMillis = request.timeoutMillis
        )
        val response = try {
            transport.execute(httpRequest)
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (error: AgentHttpException) {
            return AgentModelResponse.Failure(mapTransportError(error, request.requestId))
        } catch (_: Throwable) {
            return AgentModelResponse.Failure(
                AiModelErrors.unavailable("network_error")
            )
        }

        if (response.statusCode !in 200..299) {
            return AgentModelResponse.Failure(mapHttpStatus(response).error)
        }

        return AgentResponseSemanticLimits.validate(parseGatewayResponse(response.body))
    }

    override fun cancel(requestId: String) {
        transport.cancel(requestId)
        if (requestId.isBlank()) return
        transport.cancelRemote(
            AgentHttpRequest(
                requestId = "cancel-$requestId",
                url = endpointUrl(cancelEndpointPath),
                body = JSONObject().put("requestId", requestId).toString(),
                headers = authorizationHeaders(),
                timeoutMillis = REMOTE_CANCEL_TIMEOUT_MILLIS
            )
        )
    }

    /**
     * Fetch `/v1/models` and retain only the normalized capability fields for
     * [modelId]. The response body is discarded after parsing.
     */
    override suspend fun negotiateCapabilities(): AgentError? {
        if (capabilitiesNegotiated) return null
        if (!allowInsecureHttpForTests && !isSecureGatewayUrl(gatewayBaseUrl)) {
            return AiModelErrors.unavailable("https_required")
        }
        val response = try {
            transport.execute(
                AgentHttpRequest(
                    requestId = "capabilities-$modelId",
                    url = endpointUrl(modelsEndpointPath),
                    headers = authorizationHeaders(),
                    timeoutMillis = CAPABILITY_TIMEOUT_MILLIS
                )
            )
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (error: AgentHttpException) {
            return mapTransportError(error, "capabilities-$modelId")
        } catch (_: Throwable) {
            return AiModelErrors.unavailable("capability_network_error")
        }
        if (response.statusCode !in 200..299) return mapHttpStatus(response).error

        val parsed = runCatching { parseCapabilitiesResponse(response.body) }.getOrNull()
            ?: return AiModelErrors.unavailable("malformed_capabilities")
        negotiatedCapabilities = parsed
        oneShotFallback = !parsed.toolCalling
        capabilitiesNegotiated = true
        return null
    }

    /** Build the exact normalized request body used by [respond]. */
    fun encodeRequest(request: AgentModelRequest): String = JSONObject().apply {
        put("requestId", request.requestId)
        put("modelId", modelId)
        put("messages", messagesToJson(request.messages))
        put("tools", toolsToJson(request.toolDefinitions))
        request.responseSchema?.let { put("responseSchema", toJsonValue(it)) }
        put("maxOutputTokens", capabilities.clampOutputTokens(request.maxOutputTokens))
        put("timeout", request.timeoutMillis)
        put("privacyMode", request.privacyMode.name)
        put("clientSchemaVersion", clientSchemaVersion)
    }.toString()

    private fun parseGatewayResponse(body: String): AgentModelResponse {
        val root = try {
            JSONObject(body)
        } catch (_: Throwable) {
            return AgentModelResponse.Failure(AiModelErrors.malformed("malformed_json"))
        }

        updateCapabilities(root.optJSONObject("capabilities"))
        val envelope = root.optJSONObject("response") ?: root
        updateCapabilities(envelope.optJSONObject("capabilities"))
        val usage = AgentTokenUsageParser.normalized(root, envelope)

        val type = normalized(
            envelope.optString("type")
                .ifBlank { envelope.optString("kind") }
                .ifBlank { envelope.optString("responseType") }
        )
        val errorObject = envelope.optJSONObject("error")
        if (type == "error" || errorObject != null) {
            return AgentModelResponse.Failure(mapGatewayError(errorObject ?: envelope), usage)
        }

        if (type in REFUSAL_TYPES) {
            return AgentModelResponse.Refusal(
                reason = "gateway_refusal",
                error = AgentError(
                    code = AgentErrorCode.MODEL_UNAVAILABLE,
                    userMessage = "The analysis model declined to answer.",
                    retryable = false,
                    details = mapOf("reason" to "gateway_refusal")
                ),
                usage = usage
            )
        }

        val toolArray = firstArray(envelope, "toolCalls", "tool_calls", "calls")
        if (type in TOOL_CALL_TYPES || toolArray != null) {
            val calls = toolArray?.let(::toolCallsFromJson)
                ?: return AgentModelResponse.Failure(
                    AiModelErrors.malformed("malformed_tool_calls"),
                    usage
                )
            if (calls.isEmpty()) {
                return AgentModelResponse.Failure(AiModelErrors.malformed("empty_tool_calls"), usage)
            }
            if (!capabilities.toolCalling) {
                return AgentModelResponse.Failure(
                    AiModelErrors.malformed("model_cannot_call_tools"),
                    usage
                )
            }
            return AgentModelResponse.ToolCalls(
                calls = calls,
                usage = usage,
                assistantContent = firstString(
                    envelope,
                    "assistantContent",
                    "assistant_content"
                ).orEmpty(),
                reasoningContent = firstString(
                    envelope,
                    "reasoningContent",
                    "reasoning_content"
                )
            )
        }

        val reportJson = finalReportJson(envelope)
        if (type in FINAL_TYPES || reportJson != null) {
            if (reportJson == null) {
                return AgentModelResponse.Failure(AiModelErrors.malformed("malformed_final"), usage)
            }
            val report = AgentJsonCodec.decodeReport(reportJson).getOrNull()
                ?: return AgentModelResponse.Failure(AiModelErrors.malformed("malformed_final"), usage)
            return AgentModelResponse.Final(
                report = report,
                usage = usage,
                reasoningContent = firstString(
                    envelope,
                    "reasoningContent",
                    "reasoning_content"
                )
            )
        }

        return AgentModelResponse.Failure(AiModelErrors.malformed("unknown_response_type"), usage)
    }

    private fun finalReportJson(envelope: JSONObject): String? {
        val report = envelope.optJSONObject("report")
            ?: envelope.optJSONObject("final")?.optJSONObject("report")
            ?: envelope.optJSONObject("data")?.optJSONObject("report")
        if (report != null) return report.toString()

        val finalValue = envelope.opt("final")
        if (finalValue is JSONObject) return finalValue.toString()
        if (finalValue is String && finalValue.isNotBlank()) return finalValue
        val content = envelope.optString("content")
        return content.takeIf { it.trimStart().startsWith("{") }
    }

    private fun toolCallsFromJson(array: JSONArray): List<AgentToolCall> = buildList {
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index) ?: continue
            val function = item.optJSONObject("function")
            val id = item.optString("id").ifBlank { item.optString("toolCallId") }
            val name = item.optString("name").ifBlank { function?.optString("name").orEmpty() }
            val argumentValue = item.opt("arguments").takeUnless { it == JSONObject.NULL }
                ?: function?.opt("arguments")
            val arguments = when (argumentValue) {
                is JSONObject -> jsonObjectToMap(argumentValue)
                is String -> runCatching { jsonObjectToMap(JSONObject(argumentValue)) }.getOrNull()
                else -> null
            }
            if (id.isNotBlank() && name.isNotBlank() && arguments != null) {
                add(AgentToolCall(id, name, arguments))
            }
        }
    }

    private fun updateCapabilities(json: JSONObject?) {
        if (json == null) return
        val next = parseCapabilities(json) ?: return
        negotiatedCapabilities = next
        oneShotFallback = !next.toolCalling
        capabilitiesNegotiated = true
    }

    private fun parseCapabilitiesResponse(body: String): AiModelCapabilities {
        val root = JSONObject(body)
        val models = root.optJSONArray("models")
        val model = if (models == null) {
            root.optJSONObject("capabilities") ?: root
        } else {
            (0 until models.length())
                .mapNotNull { models.optJSONObject(it) }
                .firstOrNull { it.optString("modelId") == modelId || it.optString("id") == modelId }
                ?.optJSONObject("capabilities")
                ?: throw IllegalArgumentException("model_not_found")
        }
        return parseCapabilities(model) ?: throw IllegalArgumentException("missing_capabilities")
    }

    private fun parseCapabilities(json: JSONObject): AiModelCapabilities? {
        if (!json.has("toolCalling") && !json.has("tool_calling") &&
            !json.has("structuredOutput") && !json.has("structured_output")
        ) return null
        return AiModelCapabilities(
            toolCalling = boolean(json, "toolCalling", "tool_calling", true),
            parallelToolCalls = boolean(json, "parallelToolCalls", "parallel_tool_calls", false),
            structuredOutput = boolean(json, "structuredOutput", "structured_output", true),
            streaming = boolean(json, "streaming", "streaming", false),
            maxContextTokens = positiveInt(json, "maxContextTokens", "max_context_tokens"),
            maxOutputTokens = positiveInt(json, "maxOutputTokens", "max_output_tokens"),
            tokenLimitSource = TokenLimitSource.Negotiated
        )
    }

    private fun mapGatewayError(
        error: JSONObject?,
        httpStatus: Int? = null,
        responseBody: String? = null
    ): AgentError {
        val code = normalized(error?.optString("code").orEmpty())
        val type = normalized(error?.optString("type").orEmpty())
        val message = normalized(error?.optString("message").orEmpty())
        val responseDetails = remoteErrorDetails(error, httpStatus, responseBody)
        return when {
            code.contains("context") || code.contains("input_too_large") ||
                type.contains("context") || message.contains("context length") ->
                AiModelErrors.inputContextLimit(responseDetails)
            code.contains("max_token") || code.contains("output_limit") ||
                type.contains("max_token") || message.contains("output limit") ->
                AiModelErrors.outputTruncated(details = responseDetails)
            code.contains("privacy") || code.contains("payload") || code.contains("credential") ->
                AgentError(
                    code = AgentErrorCode.PRIVACY_BLOCKED,
                    userMessage = "The gateway rejected data outside the allowed privacy policy.",
                    retryable = false,
                    details = mapOf("reason" to "gateway_privacy_policy") + responseDetails
                )
            code.contains("unauthor") || code.contains("forbidden") || code.contains("auth") ->
                authError(responseDetails)
            code.contains("rate") || code.contains("quota") || code == "429" ->
                rateLimitError(
                    retryAfterMillis = retryAfterSecondsMillis(
                        error?.opt("retryAfter") ?: error?.opt("retry_after")
                    ),
                    quotaType = error?.optString("quotaType")
                        ?.ifBlank { error.optString("quota_type") }
                        ?.let(::safeGatewayQuotaType),
                    additionalDetails = responseDetails
                )
            code.contains("timeout") -> AiModelErrors.timeout("decode", details = responseDetails)
            else -> AiModelErrors.unavailable("gateway_error", responseDetails)
        }
    }

    private fun mapHttpStatus(response: AgentHttpResponse): StatusError {
        val headerRetryAfterMillis = retryAfterMillis(response.headers)
        val bodyError = remoteErrorObject(response.body)
        val responseDetails = remoteErrorDetails(
            error = bodyError,
            httpStatus = response.statusCode,
            responseBody = response.body
        ) + mapOf(
            "bytesReceived" to response.bytesReceived,
            "responseLimitBytes" to response.responseLimitBytes
        )
        if (response.statusCode == 402 || response.statusCode == 451) {
            return StatusError(accountActionRequiredError(responseDetails))
        }
        bodyError?.let { error ->
            val mapped = mapGatewayError(error, response.statusCode, response.body)
            if (mapped.code == AgentErrorCode.MODEL_RATE_LIMITED) {
                val headerDetails = headerRetryAfterMillis?.let {
                    mapOf(
                        "retryAfterSeconds" to it / 1_000L,
                        "retryAfterMillis" to it
                    )
                }.orEmpty()
                return StatusError(mapped.copy(details = mapped.details + headerDetails))
            }
            if (mapped.code != AgentErrorCode.MODEL_UNAVAILABLE || response.statusCode == 400) {
                return StatusError(mapped)
            }
        }
        val bodyRetryAfterMillis = retryAfterSecondsMillis(
            bodyError?.opt("retryAfter") ?: bodyError?.opt("retry_after")
        )
        val bodyQuotaType = bodyError?.optString("quotaType")
            ?.ifBlank { bodyError.optString("quota_type") }
            ?.let(::safeGatewayQuotaType)
        return when (response.statusCode) {
            401, 403 -> StatusError(authError(responseDetails))
            429 -> StatusError(
                rateLimitError(
                    headerRetryAfterMillis ?: bodyRetryAfterMillis,
                    bodyQuotaType,
                    responseDetails
                )
            )
            // An intermediary that gave up waiting for the upstream model, not a
            // model that failed. Retrying an identical request against a fixed
            // proxy deadline cannot succeed, so the reason is distinguishable
            // and the loop caps these attempts separately.
            408, 504 -> StatusError(
                AiModelErrors.timeout(
                    stage = "headers",
                    details = mapOf("reason" to AiModelErrors.GATEWAY_TIMEOUT_REASON) + responseDetails
                )
            )
            in 500..599 -> StatusError(
                AiModelErrors.unavailable("service_unavailable", responseDetails)
            )
            else -> StatusError(
                AiModelErrors.unavailable("http_${response.statusCode}", responseDetails)
            )
        }
    }

    private fun mapTransportError(error: AgentHttpException, requestId: String): AgentError = when (error.kind) {
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
        AgentHttpFailureKind.InsecureEndpoint -> AiModelErrors.unavailable("https_required")
    }

    private fun transportDetails(error: AgentHttpException): Map<String, Any?> = mapOf(
        "failureStage" to error.failureStage,
        "networkFailureKind" to error.networkFailureKind,
        "bytesReceived" to error.bytesReceived,
        "responseLimitBytes" to error.responseLimitBytes
    )

    private fun authError(additionalDetails: Map<String, Any?> = emptyMap()) = AgentError(
        code = AgentErrorCode.MODEL_AUTH_FAILED,
        userMessage = "The model gateway rejected authentication.",
        retryable = false,
        details = mapOf("providerId" to providerId) + additionalDetails
    )

    private fun accountActionRequiredError(
        additionalDetails: Map<String, Any?> = emptyMap()
    ) = AgentError(
        code = AgentErrorCode.MODEL_AUTH_FAILED,
        userMessage = "The model account requires attention before analysis can continue.",
        retryable = false,
        details = mapOf("providerId" to providerId, "reason" to "account_action_required") + additionalDetails
    )

    private fun rateLimitError(
        retryAfterMillis: Long?,
        quotaType: String? = null,
        additionalDetails: Map<String, Any?> = emptyMap()
    ) = AgentError(
        code = AgentErrorCode.MODEL_RATE_LIMITED,
        userMessage = "The model gateway is rate limited. Try again later.",
        retryable = true,
        details = mapOf(
            "providerId" to providerId,
            "quotaType" to quotaType?.takeIf { it.isNotBlank() },
            "retryAfterSeconds" to retryAfterMillis?.div(1_000L),
            "retryAfterMillis" to retryAfterMillis
        ) + additionalDetails
    )

    private fun authorizationHeaders(): Map<String, String> {
        val token = authTokenProvider()?.trim().orEmpty()
        val byok = byokSecretProvider()?.trim().orEmpty()
        val credential = token.ifBlank { byok }
        return buildMap {
            put("Accept", "application/json")
            if (credential.isNotBlank()) put("Authorization", "Bearer $credential")
        }
    }

    private fun endpointUrl(path: String): String {
        val base = gatewayBaseUrl.trim().removeSuffix("/")
        return "$base/${path.trimStart('/')}"
    }

    private fun messagesToJson(messages: List<AgentModelMessage>): JSONArray = JSONArray().apply {
        messages.forEach { message ->
            put(JSONObject().apply {
                put("role", message.role.name.lowercase(Locale.ROOT))
                val toolPayload = message.toolResult != null || message.structuredContent != null
                put(
                    "content",
                    if (message.role == com.example.layanalyzer.model.AgentModelMessageRole.Tool && toolPayload) {
                        ""
                    } else {
                        message.content
                    }
                )
                message.toolCallId?.let { put("toolCallId", it) }
                message.toolName?.let { put("toolName", it) }
                if (message.role == AgentModelMessageRole.Assistant) {
                    message.reasoningContent?.let { put("reasoningContent", it) }
                }
                if (message.toolCalls.isNotEmpty()) {
                    put("toolCalls", toolCallsToJson(message.toolCalls))
                }
                if (message.untrustedCaptureData) put("untrustedCaptureData", true)
                message.toolResult?.let { result ->
                    put("toolResult", toJsonValue(result.toGatewayMap()))
                } ?: message.structuredContent?.let { content ->
                    put("structuredContent", toJsonValue(sanitizeToolData(content)))
                }
            })
        }
    }

    private fun toolsToJson(tools: List<AgentToolDefinition>): JSONArray = JSONArray().apply {
        tools.forEach { tool ->
            put(JSONObject().apply {
                put("name", tool.name)
                put("description", tool.description)
                put("inputSchema", toJsonValue(tool.inputSchema))
            })
        }
    }

    private fun toolCallsToJson(calls: List<AgentToolCall>): JSONArray = JSONArray().apply {
        calls.forEach { call ->
            put(JSONObject().apply {
                put("id", call.toolCallId)
                put("name", call.toolName)
                put("arguments", toJsonValue(call.arguments))
            })
        }
    }

    private fun com.example.layanalyzer.model.AgentToolResult.toGatewayMap(): AgentJsonObject = mapOf(
        "toolCallId" to toolCallId,
        "toolName" to toolName,
        "success" to success,
        // `data` here is the envelope's structured result, not a packet-payload
        // field. Start classification at its children so aggregate and metadata
        // values remain available while nested payload keys are still blocked.
        "data" to data?.let(::sanitizeToolData),
        "error" to error?.let { mapOf("code" to it.code.name, "retryable" to it.retryable) },
        "truncated" to truncated,
        "sensitivity" to sensitivity.name,
        "returnedCount" to returnedCount,
        "totalCount" to totalCount
    )

    private fun sanitizeToolData(data: AgentJsonObject): AgentJsonObject = data
        .entries
        .associate { (key, value) -> key to sanitizeGatewayValue(value, key) }

    /** Last-resort structural guard for callers that bypass the normal ToolRunner. */
    private fun sanitizeGatewayValue(value: Any?, fieldName: String = "data"): Any? {
        if (value == null) return null
        if (value is Map<*, *> && (
                fieldName.equals("data", ignoreCase = true) ||
                    fieldName.equals("fields", ignoreCase = true) ||
                    fieldName.equals("metrics", ignoreCase = true)
            )
        ) {
            return value.entries.associate { (key, nested) ->
                key.toString() to sanitizeGatewayValue(nested, key.toString())
            }
        }
        return when (AgentFieldSensitivity.handling(fieldName)) {
            AgentFieldSensitivity.Handling.Credential -> sanitizeCredentialValue(value)
            AgentFieldSensitivity.Handling.Payload -> "PRIVACY_BLOCKED"
            else -> when (value) {
                is Map<*, *> -> value.entries.associate { (key, nested) ->
                    key.toString() to sanitizeGatewayValue(nested, key.toString())
                }
                is Iterable<*> -> value.map { sanitizeGatewayValue(it, fieldName) }
                is Array<*> -> value.map { sanitizeGatewayValue(it, fieldName) }
                else -> value
            }
        }
    }

    private fun sanitizeCredentialValue(value: Any?): Any? = when (value) {
        is Iterable<*> -> value.map(::sanitizeCredentialValue)
        is Array<*> -> value.map(::sanitizeCredentialValue)
        is Map<*, *> -> buildMap {
            put("credential", true)
            put("present", (value["present"] as? Boolean) ?: true)
            knownScheme(value["scheme"] ?: value["displayValue"] ?: value["filterValue"])
                ?.let { put("scheme", it) }
        }
        else -> buildMap {
            put("present", true)
            knownScheme(value)?.let { put("scheme", it) }
        }
    }

    private fun knownScheme(value: Any?): String? {
        val text = (value as? String)?.trim()?.lowercase(Locale.ROOT) ?: return null
        return KNOWN_AUTH_SCHEMES.firstOrNull { scheme ->
            text == scheme || text.startsWith("$scheme ")
        }
    }

    private fun toJsonValue(value: Any?): Any = when (value) {
        null -> JSONObject.NULL
        JSONObject.NULL -> JSONObject.NULL
        is JSONObject, is JSONArray, is String, is Number, is Boolean -> value
        is Map<*, *> -> JSONObject().apply {
            value.forEach { (key, nested) ->
                if (key is String) put(key, toJsonValue(nested))
            }
        }
        is Iterable<*> -> JSONArray().apply { value.forEach { put(toJsonValue(it)) } }
        else -> value.toString()
    }

    private fun jsonObjectToMap(json: JSONObject): AgentJsonObject = buildMap {
        val keys = json.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            put(key, fromJsonValue(json.opt(key)))
        }
    }

    private fun fromJsonValue(value: Any?): Any? = when (value) {
        null, JSONObject.NULL -> null
        is JSONObject -> jsonObjectToMap(value)
        is JSONArray -> buildList { for (index in 0 until value.length()) add(fromJsonValue(value.opt(index))) }
        else -> value
    }

    private fun firstArray(json: JSONObject, vararg names: String): JSONArray? =
        names.firstNotNullOfOrNull { name -> json.optJSONArray(name) }

    /** Preserve an explicitly empty continuation marker as well as non-empty reasoning. */
    private fun firstString(json: JSONObject, vararg names: String): String? {
        names.forEach { name ->
            if (json.has(name) && !json.isNull(name)) {
                return json.opt(name) as? String
            }
        }
        return null
    }

    private fun normalized(value: String): String = value
        .trim()
        .lowercase(Locale.ROOT)
        .filter(Char::isLetterOrDigit)

    private fun boolean(json: JSONObject, first: String, second: String, default: Boolean): Boolean =
        when {
            json.has(first) -> json.optBoolean(first, default)
            json.has(second) -> json.optBoolean(second, default)
            else -> default
        }

    private fun positiveInt(json: JSONObject, first: String, second: String): Int =
        when {
            json.has(first) -> json.optInt(first, 0).coerceAtLeast(0)
            json.has(second) -> json.optInt(second, 0).coerceAtLeast(0)
            else -> 0
        }

    private data class StatusError(val error: AgentError)

    private companion object {
        const val CLIENT_SCHEMA_VERSION = "ai-12-gateway-v2"
        const val CAPABILITY_TIMEOUT_MILLIS = 15_000L
        const val REMOTE_CANCEL_TIMEOUT_MILLIS = 5_000L
        val KNOWN_AUTH_SCHEMES = setOf(
            "digest", "basic", "bearer", "negotiate", "ntlm", "akav1-md5", "akav2-md5", "aka"
        )
        val TOOL_CALL_TYPES = setOf("toolcalls", "toolcall", "tools")
        val FINAL_TYPES = setOf("final", "report", "answer")
        val REFUSAL_TYPES = setOf("refusal", "refused", "blocked")
    }
}
