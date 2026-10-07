// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse

/** Fails explicitly when configuration cannot select a real or named mock model. */
class UnavailableAiModelClient(
    reason: String,
    private val error: AgentError
) : AiModelClient {
    override val id: String = "unavailable:$reason"
    override val capabilities: AiModelCapabilities = AiModelCapabilities.PHASE0

    override suspend fun respond(request: AgentModelRequest): AgentModelResponse =
        AgentModelResponse.Failure(error)

    override fun cancel(requestId: String) = Unit
}
