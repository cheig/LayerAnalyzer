// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentError
import java.util.Locale

/** A model advertised by the gateway after account and policy filtering. */
data class GatewayModel(
    val id: String,
    val displayName: String = id,
    val capabilities: AiModelCapabilities = AiModelCapabilities.TEXT_ONLY,
    val allowed: Boolean = true,
    val region: String? = null,
    val dataPolicy: String? = null
)

/** Non-secret account identity returned by the gateway. */
data class GatewayAccount(
    val userId: String,
    val organizationId: String? = null,
    val planId: String? = null,
    val tokenExpiresAtMillis: Long? = null
)

/** Account limits. A null limit means that the gateway did not publish one. */
data class GatewayQuota(
    val requestsPerMinute: Long? = null,
    val concurrentSessions: Long? = null,
    val tokensPerDay: Long? = null,
    val tokensPerMonth: Long? = null,
    val costMicrosPerMonth: Long? = null,
    val maxContextTokens: Long? = null,
    val maxOutputTokens: Long? = null
)

/** Safe usage counters returned by GET /v1/usage. */
data class GatewayUsage(
    val account: GatewayAccount? = null,
    val quota: GatewayQuota = GatewayQuota(),
    val requestsThisMinute: Long = 0L,
    val activeSessions: Long = 0L,
    val tokensToday: Long = 0L,
    val tokensThisMonth: Long = 0L,
    val costMicrosThisMonth: Long = 0L,
    val allowedModelIds: Set<String> = emptySet(),
    val windowStartMillis: Long? = null,
    val windowEndMillis: Long? = null,
    val refreshedAtMillis: Long = 0L
)

/** A typed result for non-model gateway endpoints. */
sealed interface GatewayResult<out T> {
    data class Success<T>(val value: T) : GatewayResult<T>

    data class Failure(val error: AgentError) : GatewayResult<Nothing>
}

typealias GatewayModelsResult = GatewayResult<List<GatewayModel>>
typealias GatewayUsageResult = GatewayResult<GatewayUsage>

/** State rendered by the Agent page; it contains no access token or response body. */
data class GatewayAccountUiState(
    val isLoading: Boolean = false,
    val account: GatewayAccount? = null,
    val models: List<GatewayModel> = emptyList(),
    val usage: GatewayUsage? = null,
    val error: AgentError? = null,
    val lastUpdatedAtMillis: Long? = null
) {
    val isAvailable: Boolean
        get() = account != null || models.isNotEmpty() || usage != null
}

/** Optional account surface implemented by the production gateway client. */
interface GatewayAccountApi {
    suspend fun getModels(): GatewayModelsResult

    suspend fun getUsage(): GatewayUsageResult
}

/** Keep gateway-provided quota labels bounded and provider-neutral. */
internal fun safeGatewayQuotaType(value: String?): String? {
    val normalized = value?.trim()?.lowercase(Locale.ROOT) ?: return null
    return when (normalized) {
        "requests_per_minute",
        "concurrent_sessions",
        "tokens_per_day",
        "tokens_per_month",
        "cost_per_month",
        "model_not_allowed",
        "privacy_policy" -> normalized
        else -> null
    }
}
