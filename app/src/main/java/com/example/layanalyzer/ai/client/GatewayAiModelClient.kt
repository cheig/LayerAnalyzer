// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import org.json.JSONArray
import org.json.JSONObject

/** Configuration for the production account-backed gateway. */
data class GatewayModelConfiguration(
    val providerId: String = "gateway",
    val modelId: String,
    val gatewayBaseUrl: String
)

/** Alias used by applications that call the endpoint simply a gateway. */
typealias GatewayConfiguration = GatewayModelConfiguration

/**
 * Production Android adapter for the provider-neutral Agent gateway.
 *
 * This class deliberately has no BYOK parameter. The only credential source is
 * a short-lived access token supplied by the host application. The existing
 * [CloudAiModelClient] remains available for the AI-12 debug/BYOK path, while
 * Release wiring uses this class exclusively.
 */
class GatewayAiModelClient(
    private val gatewayBaseUrl: String,
    private val transport: AgentHttpTransport,
    private val providerId: String = "gateway",
    private val modelId: String = "default",
    private val accessTokenProvider: (() -> String?)? = null,
    /** Compatibility name for callers that already use the HTTP auth term. */
    private val authTokenProvider: (() -> String?)? = null,
    initialCapabilities: AiModelCapabilities = AiModelCapabilities.PHASE0,
    override val negotiateBeforeRun: Boolean = true,
    private val onAuthenticationRejected: () -> Unit = {},
    private val responseEndpointPath: String = "v1/agent/respond",
    private val modelsEndpointPath: String = "v1/models",
    private val usageEndpointPath: String = "v1/usage",
    private val cancelEndpointPath: String = "v1/agent/cancel",
    private val allowInsecureHttpForTests: Boolean = false
) : AiModelClient, AgentCapabilityNegotiator, GatewayAccountApi {

    constructor(
        configuration: GatewayModelConfiguration,
        transport: AgentHttpTransport,
        accessTokenProvider: (() -> String?)? = null,
        authTokenProvider: (() -> String?)? = null,
        initialCapabilities: AiModelCapabilities = AiModelCapabilities.PHASE0,
        negotiateBeforeRun: Boolean = true,
        onAuthenticationRejected: () -> Unit = {},
        allowInsecureHttpForTests: Boolean = false
    ) : this(
        gatewayBaseUrl = configuration.gatewayBaseUrl,
        transport = transport,
        providerId = configuration.providerId,
        modelId = configuration.modelId,
        accessTokenProvider = accessTokenProvider,
        authTokenProvider = authTokenProvider,
        initialCapabilities = initialCapabilities,
        negotiateBeforeRun = negotiateBeforeRun,
        onAuthenticationRejected = onAuthenticationRejected,
        allowInsecureHttpForTests = allowInsecureHttpForTests
    )

    private val delegate = CloudAiModelClient(
        gatewayBaseUrl = gatewayBaseUrl,
        transport = transport,
        providerId = providerId,
        modelId = modelId,
        authTokenProvider = ::accessToken,
        byokSecretProvider = { null },
        initialCapabilities = initialCapabilities,
        negotiateBeforeRun = negotiateBeforeRun,
        responseEndpointPath = responseEndpointPath,
        modelsEndpointPath = modelsEndpointPath,
        cancelEndpointPath = cancelEndpointPath,
        clientSchemaVersion = CLIENT_SCHEMA_VERSION,
        allowInsecureHttpForTests = allowInsecureHttpForTests
    )

    override val id: String = "gateway:$providerId:$modelId"

    override val capabilities: AiModelCapabilities
        get() = delegate.capabilities

    override val oneShotFallback: Boolean
        get() = delegate.oneShotFallback

    /** Last non-secret account identity returned by a models or usage call. */
    @Volatile
    var account: GatewayAccount? = null
        private set

    override suspend fun respond(request: AgentModelRequest): AgentModelResponse =
        delegate.respond(request).also(::handleAuthenticationFailure)

    override fun cancel(requestId: String) {
        delegate.cancel(requestId)
    }

    override suspend fun negotiateCapabilities(): AgentError? =
        delegate.negotiateCapabilities().also { error ->
            if (error?.code == AgentErrorCode.MODEL_AUTH_FAILED) {
                onAuthenticationRejected()
            }
        }

    /** Exposes the exact request body for contract tests without exposing a key. */
    fun encodeRequest(request: AgentModelRequest): String = delegate.encodeRequest(request)

    override suspend fun getModels(): GatewayModelsResult {
        val response = executeAccountRequest(
            requestId = "models-$modelId",
            path = modelsEndpointPath
        ) ?: return GatewayResult.Failure(lastAccountError ?: unavailable("models_request_failed"))
        if (response.statusCode !in 200..299) {
            return GatewayResult.Failure(mapHttpError(response))
        }

        return runCatching {
            val root = JSONObject(response.body)
            parseAccount(root.optJSONObject("account"))?.let { account = it }
            val models = parseModels(root)
            GatewayResult.Success(models)
        }.getOrElse {
            GatewayResult.Failure(unavailable("malformed_models"))
        }
    }

    /** Naming aliases keep the account surface easy to discover in callers. */
    suspend fun fetchModels(): GatewayModelsResult = getModels()

    suspend fun models(): GatewayModelsResult = getModels()

    override suspend fun getUsage(): GatewayUsageResult {
        val response = executeAccountRequest(
            requestId = "usage-$modelId",
            path = usageEndpointPath
        ) ?: return GatewayResult.Failure(lastAccountError ?: unavailable("usage_request_failed"))
        if (response.statusCode !in 200..299) {
            return GatewayResult.Failure(mapHttpError(response))
        }

        return runCatching {
            val root = JSONObject(response.body)
            val parsedAccount = parseAccount(root.optJSONObject("account"))
            if (parsedAccount != null) account = parsedAccount
            GatewayResult.Success(parseUsage(root, parsedAccount))
        }.getOrElse {
            GatewayResult.Failure(unavailable("malformed_usage"))
        }
    }

    suspend fun fetchUsage(): GatewayUsageResult = getUsage()

    suspend fun usage(): GatewayUsageResult = getUsage()

    private var lastAccountError: AgentError? = null

    private suspend fun executeAccountRequest(
        requestId: String,
        path: String
    ): AgentHttpResponse? {
        if (!allowInsecureHttpForTests && !isSecureGatewayUrl(gatewayBaseUrl)) {
            lastAccountError = unavailable("https_required")
            return null
        }
        return try {
            transport.execute(
                AgentHttpRequest(
                    requestId = requestId,
                    url = endpointUrl(path),
                    headers = authorizationHeaders(),
                    timeoutMillis = ACCOUNT_TIMEOUT_MILLIS
                )
            )
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (error: AgentHttpException) {
            lastAccountError = mapTransportError(error, requestId)
            null
        } catch (_: Throwable) {
            lastAccountError = unavailable("network_error")
            null
        }
    }

    private fun parseModels(root: JSONObject): List<GatewayModel> {
        val models = root.optJSONArray("models")
            ?: throw IllegalArgumentException("models_missing")
        return buildList {
            for (index in 0 until models.length()) {
                val item = models.optJSONObject(index) ?: continue
                val id = item.optString("modelId").ifBlank { item.optString("id") }
                if (id.isBlank()) continue
                val capabilities = parseCapabilities(
                    item.optJSONObject("capabilities") ?: item
                )
                add(
                    GatewayModel(
                        id = id,
                        displayName = item.optString("displayName").ifBlank { id },
                        capabilities = capabilities,
                        allowed = item.optBoolean("allowed", true),
                        region = item.optString("region").ifBlank { null },
                        dataPolicy = item.optString("dataPolicy")
                            .ifBlank { item.optString("data_policy") }
                            .ifBlank { null }
                    )
                )
            }
        }.also { parsed ->
            if (parsed.isEmpty()) throw IllegalArgumentException("models_empty")
        }
    }

    private fun parseCapabilities(json: JSONObject): AiModelCapabilities {
        return AiModelCapabilities(
            toolCalling = boolean(json, "toolCalling", "tool_calling", false),
            parallelToolCalls = boolean(json, "parallelToolCalls", "parallel_tool_calls", false),
            structuredOutput = boolean(json, "structuredOutput", "structured_output", false),
            streaming = boolean(json, "streaming", "streaming", false),
            maxContextTokens = nonNegativeInt(json, "maxContextTokens", "max_context_tokens"),
            maxOutputTokens = nonNegativeInt(json, "maxOutputTokens", "max_output_tokens"),
            tokenLimitSource = TokenLimitSource.Negotiated
        )
    }

    private fun parseUsage(root: JSONObject, parsedAccount: GatewayAccount?): GatewayUsage {
        val usage = root.optJSONObject("usage") ?: root
        val quota = root.optJSONObject("quota")
            ?: root.optJSONObject("limits")
            ?: usage.optJSONObject("quota")
            ?: usage.optJSONObject("limits")
            ?: JSONObject()
        val allowedModels = firstArray(root, "allowedModels", "allowed_model_ids")
            ?: firstArray(usage, "allowedModels", "allowed_model_ids")

        return GatewayUsage(
            account = parsedAccount,
            quota = GatewayQuota(
                requestsPerMinute = nonNegativeLong(quota, "requestsPerMinute", "requests_per_minute"),
                concurrentSessions = nonNegativeLong(quota, "concurrentSessions", "concurrent_sessions"),
                tokensPerDay = nonNegativeLong(quota, "tokensPerDay", "tokens_per_day"),
                tokensPerMonth = nonNegativeLong(quota, "tokensPerMonth", "tokens_per_month"),
                costMicrosPerMonth = nonNegativeLong(quota, "costMicrosPerMonth", "cost_micros_per_month"),
                maxContextTokens = nonNegativeLong(quota, "maxContextTokens", "max_context_tokens"),
                maxOutputTokens = nonNegativeLong(quota, "maxOutputTokens", "max_output_tokens")
            ),
            requestsThisMinute = nonNegativeLong(usage, "requestsThisMinute", "requests_this_minute") ?: 0L,
            activeSessions = nonNegativeLong(usage, "activeSessions", "active_sessions") ?: 0L,
            tokensToday = nonNegativeLong(usage, "tokensToday", "tokens_today") ?: 0L,
            tokensThisMonth = nonNegativeLong(usage, "tokensThisMonth", "tokens_this_month") ?: 0L,
            costMicrosThisMonth = nonNegativeLong(usage, "costMicrosThisMonth", "cost_micros_this_month") ?: 0L,
            allowedModelIds = strings(allowedModels),
            windowStartMillis = nonNegativeLong(usage, "windowStartMillis", "window_start_millis"),
            windowEndMillis = nonNegativeLong(usage, "windowEndMillis", "window_end_millis"),
            refreshedAtMillis = nonNegativeLong(root, "refreshedAtMillis", "refreshed_at_millis")
                ?: System.currentTimeMillis()
        )
    }

    private fun parseAccount(json: JSONObject?): GatewayAccount? {
        if (json == null) return null
        val userId = json.optString("userId").ifBlank { json.optString("user_id") }
        if (userId.isBlank()) return null
        return GatewayAccount(
            userId = userId,
            organizationId = json.optString("organizationId")
                .ifBlank { json.optString("organization_id") }
                .ifBlank { null },
            planId = json.optString("planId").ifBlank { json.optString("plan_id") }.ifBlank { null },
            tokenExpiresAtMillis = nonNegativeLong(json, "tokenExpiresAtMillis", "token_expires_at_millis")
        )
    }

    private fun mapHttpError(response: AgentHttpResponse): AgentError {
        val error = remoteErrorObject(response.body)
        val code = normalize(error?.optString("code").orEmpty())
        val type = normalize(error?.optString("type").orEmpty())
        val message = normalize(error?.optString("message").orEmpty())
        val responseDetails = remoteErrorDetails(
            error = error,
            httpStatus = response.statusCode,
            responseBody = response.body
        ) + mapOf(
            "bytesReceived" to response.bytesReceived,
            "responseLimitBytes" to response.responseLimitBytes
        )
        val retryAfter = retryAfterMillis(response.headers)
            ?: retryAfterSecondsMillis(error?.let {
                it.opt("retryAfter") ?: it.opt("retry_after")
            })
        val quotaType = error?.optString("quotaType")
            ?.ifBlank { error.optString("quota_type") }
            ?.ifBlank { null }
            ?.let(::safeGatewayQuotaType)
        return when {
            response.statusCode == 402 || response.statusCode == 451 ->
                accountActionRequiredError(responseDetails)
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
            response.statusCode == 401 || response.statusCode == 403 ||
                code.contains("auth") || code.contains("unauthor") || code.contains("forbidden") -> {
                onAuthenticationRejected()
                AgentError(
                    code = AgentErrorCode.MODEL_AUTH_FAILED,
                    userMessage = "The model gateway rejected authentication.",
                    retryable = false,
                    details = mapOf("providerId" to providerId) + responseDetails
                )
            }
            response.statusCode == 429 || code.contains("rate") || code.contains("quota") ->
                rateLimitError(retryAfter, quotaType, responseDetails)
            response.statusCode == 408 || response.statusCode == 504 || code.contains("timeout") ->
                AiModelErrors.timeout(
                    stage = "headers",
                    details = mapOf("reason" to AiModelErrors.GATEWAY_TIMEOUT_REASON) + responseDetails
                )
            response.statusCode in 500..599 -> unavailable("service_unavailable", responseDetails)
            else -> unavailable("http_${response.statusCode}", responseDetails)
        }
    }

    private fun mapTransportError(error: AgentHttpException, requestId: String): AgentError = when (error.kind) {
        AgentHttpFailureKind.Cancelled -> AiModelErrors.cancelled(requestId)
        AgentHttpFailureKind.Timeout -> AiModelErrors.timeout(
            stage = error.failureStage,
            networkFailureKind = error.networkFailureKind,
            details = transportDetails(error)
        )
        AgentHttpFailureKind.Network -> unavailable("network_error", transportDetails(error))
        AgentHttpFailureKind.ResponseTooLarge -> AiModelErrors.responseTooLarge(
            transportDetails(error)
        )
        AgentHttpFailureKind.InsecureEndpoint -> unavailable("https_required")
    }

    private fun transportDetails(error: AgentHttpException): Map<String, Any?> = mapOf(
        "failureStage" to error.failureStage,
        "networkFailureKind" to error.networkFailureKind,
        "bytesReceived" to error.bytesReceived,
        "responseLimitBytes" to error.responseLimitBytes
    )

    private fun handleAuthenticationFailure(response: AgentModelResponse) {
        if (response is AgentModelResponse.Failure &&
            response.error.code == AgentErrorCode.MODEL_AUTH_FAILED
        ) {
            onAuthenticationRejected()
        }
    }

    private fun rateLimitError(
        retryAfterMillis: Long?,
        quotaType: String?,
        additionalDetails: Map<String, Any?> = emptyMap()
    ) = AgentError(
        code = AgentErrorCode.MODEL_RATE_LIMITED,
        userMessage = "The model gateway is rate limited. Try again later.",
        retryable = true,
        details = mapOf(
            "providerId" to providerId,
            "quotaType" to quotaType,
            "retryAfterSeconds" to retryAfterMillis?.div(1_000L),
            "retryAfterMillis" to retryAfterMillis
        ) + additionalDetails
    )

    private fun unavailable(
        reason: String,
        additionalDetails: Map<String, Any?> = emptyMap()
    ) = AgentError(
        code = AgentErrorCode.MODEL_UNAVAILABLE,
        userMessage = "The model gateway is unavailable.",
        retryable = true,
        details = mapOf("reason" to reason) + additionalDetails
    )

    private fun accountActionRequiredError(
        additionalDetails: Map<String, Any?> = emptyMap()
    ) = AgentError(
        code = AgentErrorCode.MODEL_AUTH_FAILED,
        userMessage = "The model account requires attention before analysis can continue.",
        retryable = false,
        details = mapOf("providerId" to providerId, "reason" to "account_action_required") + additionalDetails
    )

    private fun accessToken(): String? =
        accessTokenProvider?.invoke()?.trim()?.takeIf { it.isNotBlank() }
            ?: authTokenProvider?.invoke()?.trim()?.takeIf { it.isNotBlank() }

    private fun authorizationHeaders(): Map<String, String> = buildMap {
        put("Accept", "application/json")
        accessToken()?.let { put("Authorization", "Bearer $it") }
    }

    private fun endpointUrl(path: String): String =
        "${gatewayBaseUrl.trim().removeSuffix("/")}/${path.trimStart('/')}"

    private fun boolean(json: JSONObject, first: String, second: String, default: Boolean): Boolean =
        when {
            json.has(first) -> json.optBoolean(first, default)
            json.has(second) -> json.optBoolean(second, default)
            else -> default
        }

    private fun nonNegativeInt(json: JSONObject, first: String, second: String): Int =
        when {
            json.has(first) -> json.optInt(first, 0).coerceAtLeast(0)
            json.has(second) -> json.optInt(second, 0).coerceAtLeast(0)
            else -> 0
        }

    private fun nonNegativeLong(json: JSONObject, first: String, second: String): Long? =
        when {
            json.has(first) -> json.optLong(first, 0L).coerceAtLeast(0L)
            json.has(second) -> json.optLong(second, 0L).coerceAtLeast(0L)
            else -> null
        }

    private fun firstArray(json: JSONObject, vararg names: String): JSONArray? =
        names.firstNotNullOfOrNull { json.optJSONArray(it) }

    private fun strings(array: JSONArray?): Set<String> = buildSet {
        if (array == null) return@buildSet
        for (index in 0 until array.length()) {
            val value = array.opt(index)
            when (value) {
                is String -> value.trim().takeIf { it.isNotBlank() }?.let(::add)
                is JSONObject -> value.optString("modelId").ifBlank { value.optString("id") }
                    .trim().takeIf { it.isNotBlank() }?.let(::add)
            }
        }
    }

    private fun normalize(value: String): String = value.trim().lowercase()
        .filter(Char::isLetterOrDigit)

    private companion object {
        const val CLIENT_SCHEMA_VERSION = "ai-23-gateway-v2"
        const val ACCOUNT_TIMEOUT_MILLIS = 15_000L
    }
}
