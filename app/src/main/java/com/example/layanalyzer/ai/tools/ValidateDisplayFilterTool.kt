// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult

/**
 * validate_display_filter — compile a display filter without applying it.
 *
 * The tool only ever calls the repository's validation path, so a model can
 * probe filter syntax without disturbing what the user is looking at.  A blank
 * filter is legal and means "no filter"; that is the value the rest of the tool
 * layer uses to request an unfiltered read.
 *
 * An invalid filter is a failed validation attempt, not evidence. Returning a
 * structured INVALID_DISPLAY_FILTER failure lets the loop apply its bounded
 * correction policy and prevents the bad expression from becoming a success
 * citation.
 */
class ValidateDisplayFilterTool : AgentTool {

    override val definition = AgentToolDefinition(
        name = "validate_display_filter",
        description = "Check whether a Wireshark display filter compiles, without applying it. " +
            "An empty filter is valid and means no filter. IP literals are not quoted " +
            "(for example ip.addr == 192.0.2.1); string values use double quotes.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "required" to listOf("filter"),
            "properties" to mapOf(
                "filter" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_FILTER_LENGTH
                )
            )
        ),
        sensitivity = AgentDataSensitivity.Aggregate,
        defaultTimeoutMillis = 10_000L
    )

    /**
     * This tool reports on a filter rather than reading through one, so the
     * runner's pre-execution compile must not intercept it.  Otherwise an
     * invalid filter would be rejected before the tool could answer the very
     * question it was asked. Validation itself is orchestration and does not
     * consume an evidence step.
     */
    override val filterArgumentNames: Set<String> = emptySet()

    override val consumesEvidenceStep: Boolean = false

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val requested = arguments["filter"] as? String ?: ""
        val normalized = requested.trim()

        // An empty filter clears the filter rather than compiling one, so there
        // is nothing for the engine to reject.
        if (normalized.isEmpty()) {
            return context.validationResult(valid = true, normalizedFilter = "")
        }

        return when (val result = context.repository.validateDisplayFilter(context.snapshot, normalized)) {
            is AgentAnalysisResult.Success -> context.validationResult(
                valid = true,
                normalizedFilter = normalized
            )

            is AgentAnalysisResult.Failure -> {
                // Only a genuine syntax rejection is reported as valid=false.
                // A session change or cancellation must surface as an error, or
                // the model would record a perfectly good filter as broken.
                if (result.error.code == AgentErrorCode.INVALID_DISPLAY_FILTER) {
                    context.failure(
                        result.error.copy(
                            retryable = true,
                            details = result.error.details + mapOf(
                                "stage" to "validation"
                            )
                        )
                    )
                } else {
                    throw AgentToolException(result.error)
                }
            }
        }
    }

    /**
     * Validation touches no frames, so the counts describe filters checked
     * rather than packets read.
     */
    private fun AgentToolContext.validationResult(
        valid: Boolean,
        normalizedFilter: String,
        errorMessage: String? = null
    ): AgentToolResult = success(
        data = mapOf(
            "valid" to valid,
            "normalizedFilter" to normalizedFilter,
            "errorMessage" to errorMessage
        ),
        returnedCount = 1L,
        totalCount = 1L
    )

    private companion object {
        const val MAX_FILTER_LENGTH = 2048
    }
}
