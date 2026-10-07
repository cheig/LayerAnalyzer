// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.model.AgentModelResponse
import java.nio.charset.StandardCharsets

/** Independent post-transport limits for fields with meaning to the Agent. */
object AgentResponseSemanticLimits {
    const val MAX_FINAL_REPORT_BYTES: Long = 256L * 1024
    const val MAX_REASONING_BYTES: Long = 1L * 1024 * 1024
    const val MAX_SINGLE_TOOL_ARGUMENT_BYTES: Long = 64L * 1024
    const val MAX_TOTAL_TOOL_ARGUMENT_BYTES: Long = 256L * 1024

    /** Return a bounded model failure, or the original response when valid. */
    fun validate(response: AgentModelResponse): AgentModelResponse {
        val violation = when (response) {
            is AgentModelResponse.ToolCalls -> {
                val reasoning = response.reasoningContent?.utf8Size()
                when {
                    reasoning != null && reasoning > MAX_REASONING_BYTES ->
                        Violation("reasoning", MAX_REASONING_BYTES)
                    response.assistantContent.utf8Size() > MAX_FINAL_REPORT_BYTES ->
                        Violation("assistant_content", MAX_FINAL_REPORT_BYTES)
                    else -> {
                        var total = 0L
                        response.calls.forEachIndexed { index, call ->
                            val size = jsonSize(call.arguments, MAX_SINGLE_TOOL_ARGUMENT_BYTES)
                            if (size > MAX_SINGLE_TOOL_ARGUMENT_BYTES) {
                                return responseTooLarge(
                                    Violation("tool_arguments[$index]", MAX_SINGLE_TOOL_ARGUMENT_BYTES)
                                )
                            }
                            total = (total + size).coerceAtMost(MAX_TOTAL_TOOL_ARGUMENT_BYTES + 1L)
                        }
                        if (total > MAX_TOTAL_TOOL_ARGUMENT_BYTES) {
                            Violation("tool_arguments_total", MAX_TOTAL_TOOL_ARGUMENT_BYTES)
                        } else {
                            null
                        }
                    }
                }
            }
            is AgentModelResponse.Final -> {
                val reportSize = response.report?.let {
                    it.let { report ->
                        AgentJsonCodec.encodeReport(report).utf8Size()
                    }
                } ?: response.rawJson?.utf8Size()
                when {
                    reportSize != null && reportSize > MAX_FINAL_REPORT_BYTES ->
                        Violation("final_report", MAX_FINAL_REPORT_BYTES)
                    else -> response.reasoningContent?.utf8Size()
                        ?.takeIf { it > MAX_REASONING_BYTES }
                        ?.let { Violation("reasoning", MAX_REASONING_BYTES) }
                }
            }
            is AgentModelResponse.Refusal,
            is AgentModelResponse.Failure -> null
        }
        return violation?.let(::responseTooLarge) ?: response
    }

    private fun responseTooLarge(violation: Violation): AgentModelResponse.Failure =
        AgentModelResponse.Failure(
            AiModelErrors.responseTooLarge(
                details = mapOf(
                    "reason" to "semantic_limit",
                    "semanticField" to violation.field,
                    "semanticLimitBytes" to violation.limitBytes
                )
            )
        )

    private fun String.utf8Size(): Long =
        toByteArray(StandardCharsets.UTF_8).size.toLong()

    /** Measure only until the field limit is crossed, keeping this check bounded. */
    private fun jsonSize(value: Any?, limit: Long): Long {
        fun measure(current: Any?, remaining: Long): Long {
            if (remaining < 0L) return limit + 1L
            val size = when (current) {
                null -> 4L
                is String -> current.utf8Size() + 2L
                is Number, is Boolean -> current.toString().length.toLong()
                is Map<*, *> -> {
                    var total = 2L
                    current.entries.forEach { (key, nested) ->
                        total += key.toString().utf8Size() + 3L
                        total += measure(nested, limit - total)
                        if (total > limit) return limit + 1L
                    }
                    total
                }
                is Iterable<*> -> {
                    var total = 2L
                    current.forEach { nested ->
                        total += measure(nested, limit - total)
                        if (total > limit) return limit + 1L
                    }
                    total
                }
                is Array<*> -> measure(current.asList(), remaining)
                else -> current.toString().utf8Size() + 2L
            }
            return if (size > limit) limit + 1L else size
        }
        return measure(value, limit)
    }

    private data class Violation(val field: String, val limitBytes: Long)
}
