// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.agent.AgentReasoningEffort
import org.json.JSONObject

/**
 * Encodes [AgentReasoningEffort] in the shape each direct provider API accepts.
 *
 * Unspecified effort leaves the body unchanged so models that do not support
 * reasoning keep working. `none` is an explicit disable, not a missing setting.
 */
internal fun AgentReasoningEffort.applyToChatCompletions(body: JSONObject) {
    if (!isConfigured) return
    // Official Chat Completions field for o-series / GPT-5 reasoning models.
    body.put("reasoning_effort", wireValue)
    // OpenAI-compatible and newer Chat Completions gateways accept the object
    // form; `context=all_turns` keeps prior-turn reasoning available.
    body.put(
        "reasoning",
        JSONObject()
            .put("effort", wireValue)
            .put("context", AgentReasoningEffort.REASONING_CONTEXT_ALL_TURNS)
    )
}

internal fun AgentReasoningEffort.applyToResponses(body: JSONObject) {
    if (!isConfigured) return
    body.put("reasoning", JSONObject().put("effort", wireValue))
}

/**
 * Writes Anthropic `thinking` and returns the `max_tokens` the request should
 * send. Thinking tokens are charged against `max_tokens`, so an enabled budget
 * is added on top of the requested visible output.
 */
internal fun AgentReasoningEffort.applyToAnthropic(body: JSONObject, outputTokens: Int): Int {
    if (!isConfigured) return outputTokens
    if (this == AgentReasoningEffort.NONE) {
        body.put("thinking", JSONObject().put("type", "disabled"))
        return outputTokens
    }
    val budget = anthropicBudgetTokens() ?: return outputTokens
    body.put(
        "thinking",
        JSONObject()
            .put("type", "enabled")
            .put("budget_tokens", budget)
    )
    return outputTokens + budget
}
