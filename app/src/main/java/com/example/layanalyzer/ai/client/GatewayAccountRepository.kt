package com.example.layanalyzer.ai.client

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Loads the account-safe model and usage views without retaining gateway bodies. */
class GatewayAccountRepository(
    private val clientProvider: () -> GatewayAiModelClient?,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    private val _state = MutableStateFlow(GatewayAccountUiState())
    val state: StateFlow<GatewayAccountUiState> = _state.asStateFlow()

    suspend fun refresh() {
        val client = clientProvider()
        if (client == null) {
            _state.value = GatewayAccountUiState()
            return
        }

        _state.value = _state.value.copy(isLoading = true, error = null)
        val modelsResult = client.getModels()
        val models = when (modelsResult) {
            is GatewayResult.Success -> modelsResult.value
            is GatewayResult.Failure -> {
                _state.value = _state.value.copy(
                    isLoading = false,
                    error = modelsResult.error,
                    lastUpdatedAtMillis = clock()
                )
                return
            }
        }

        val usageResult = client.getUsage()
        when (usageResult) {
            is GatewayResult.Success -> {
                _state.value = GatewayAccountUiState(
                    isLoading = false,
                    account = usageResult.value.account ?: client.account,
                    models = models,
                    usage = usageResult.value,
                    lastUpdatedAtMillis = clock()
                )
            }
            is GatewayResult.Failure -> {
                _state.value = _state.value.copy(
                    isLoading = false,
                    account = client.account,
                    models = models,
                    error = usageResult.error,
                    lastUpdatedAtMillis = clock()
                )
            }
        }
    }

    fun clear() {
        _state.value = GatewayAccountUiState()
    }
}
