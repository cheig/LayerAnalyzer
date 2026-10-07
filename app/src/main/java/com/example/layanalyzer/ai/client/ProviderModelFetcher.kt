// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.agent.AgentApiType
import kotlinx.coroutines.CancellationException
import org.json.JSONObject

/** Why a `/models` catalog fetch could not deliver a usable model list. */
enum class ProviderModelFetchFailure {
    MissingBaseUrl,
    MissingApiKey,
    InsecureEndpoint,
    Network,
    Timeout,
    Authentication,
    Server,
    MalformedResponse,
    Empty
}

/** Outcome of a `/models` catalog fetch. The ids are never secrets. */
sealed interface ProviderModelFetchResult {
    data class Success(val modelIds: List<String>) : ProviderModelFetchResult
    data class Failure(val reason: ProviderModelFetchFailure) : ProviderModelFetchResult
}

/**
 * Lists the models a user-configured provider advertises via its `/models`
 * endpoint, so the settings editor can add them instead of requiring hand
 * transcription. Only the id is kept; provider display metadata (if any) is
 * ignored because it does not affect how a model is addressed.
 */
class ProviderModelFetcher(
    private val transport: AgentHttpTransport
) {
    /**
     * Fetch the model catalog for a provider. [apiKey] must already be resolved
     * (typed in the editor or read from the secret store) by the caller.
     */
    suspend fun fetchModels(
        baseUrl: String,
        apiType: AgentApiType,
        apiKey: String
    ): ProviderModelFetchResult {
        val base = baseUrl.trim().trimEnd('/')
        if (base.isBlank()) {
            return ProviderModelFetchResult.Failure(ProviderModelFetchFailure.MissingBaseUrl)
        }
        val key = apiKey.trim()
        if (key.isBlank()) {
            return ProviderModelFetchResult.Failure(ProviderModelFetchFailure.MissingApiKey)
        }
        val response = try {
            transport.execute(
                AgentHttpRequest(
                    requestId = "models-${System.nanoTime()}",
                    url = modelsUrl(base),
                    headers = requestHeaders(apiType, key),
                    timeoutMillis = MODELS_TIMEOUT_MILLIS
                )
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: AgentHttpException) {
            return ProviderModelFetchResult.Failure(
                when (error.kind) {
                    AgentHttpFailureKind.Timeout -> ProviderModelFetchFailure.Timeout
                    AgentHttpFailureKind.InsecureEndpoint -> ProviderModelFetchFailure.InsecureEndpoint
                    else -> ProviderModelFetchFailure.Network
                }
            )
        } catch (_: Throwable) {
            return ProviderModelFetchResult.Failure(ProviderModelFetchFailure.Network)
        }

        return when {
            response.statusCode == 401 || response.statusCode == 403 ->
                ProviderModelFetchResult.Failure(ProviderModelFetchFailure.Authentication)
            response.statusCode !in 200..299 ->
                ProviderModelFetchResult.Failure(ProviderModelFetchFailure.Server)
            else -> parseModels(response.body)
        }
    }

    private fun modelsUrl(base: String): String = when {
        base.endsWith("/models") -> base
        base.endsWith("/v1") -> "$base/models"
        else -> "$base/v1/models"
    }

    private fun requestHeaders(apiType: AgentApiType, apiKey: String): Map<String, String> =
        when (apiType) {
            AgentApiType.ANTHROPIC_API -> mapOf(
                "Accept" to "application/json",
                "x-api-key" to apiKey,
                "anthropic-version" to ANTHROPIC_API_VERSION
            )
            AgentApiType.OPENAI_CHAT_COMPLETIONS,
            AgentApiType.OPENAI_RESPONSES -> mapOf(
                "Accept" to "application/json",
                "Authorization" to "Bearer $apiKey"
            )
        }

    private fun parseModels(body: String): ProviderModelFetchResult = runCatching {
        val data = JSONObject(body).optJSONArray("data")
        if (data == null) {
            ProviderModelFetchResult.Failure(ProviderModelFetchFailure.MalformedResponse)
        } else {
            val ids = buildList {
                for (index in 0 until data.length()) {
                    val item = data.optJSONObject(index) ?: continue
                    val id = item.optString("id").trim()
                    if (id.isNotBlank()) add(id)
                }
            }.distinct()
            if (ids.isEmpty()) {
                ProviderModelFetchResult.Failure(ProviderModelFetchFailure.Empty)
            } else {
                ProviderModelFetchResult.Success(ids)
            }
        }
    }.getOrElse {
        ProviderModelFetchResult.Failure(ProviderModelFetchFailure.MalformedResponse)
    }

    private companion object {
        const val ANTHROPIC_API_VERSION = "2023-06-01"
        const val MODELS_TIMEOUT_MILLIS = 30_000L
    }
}
