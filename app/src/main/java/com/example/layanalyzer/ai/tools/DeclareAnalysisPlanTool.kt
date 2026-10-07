// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult

/** Host-only plan declaration. It reads no capture data. */
class DeclareAnalysisPlanTool : AgentTool {
    override val consumesEvidenceStep: Boolean = false

    override val definition = AgentToolDefinition(
        name = NAME,
        description = "After reviewing host-provided baseline evidence, declare the bounded analysis goal " +
            "and ordered targeted-analysis tool steps before further capture investigation.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "required" to listOf("goal", "steps"),
            "properties" to mapOf(
                "goal" to mapOf("type" to "string", "minLength" to 1, "maxLength" to 500),
                "steps" to mapOf(
                    "type" to "array",
                    "minItems" to 1,
                    "maxItems" to MAX_PLAN_STEPS,
                    "items" to mapOf(
                        "type" to "object",
                        "additionalProperties" to false,
                        "required" to listOf("tool", "purpose"),
                        "properties" to mapOf(
                            "tool" to mapOf("type" to "string", "minLength" to 1, "maxLength" to 120),
                            "purpose" to mapOf("type" to "string", "minLength" to 1, "maxLength" to 500),
                            // Optional (OPT-VAL-01-02): plans without it still parse and behave
                            // exactly as before; a step that names a playbook check id promises
                            // that check, and the host gates report acceptance on it.
                            "checkId" to mapOf(
                                "type" to "string",
                                "minLength" to 1,
                                "maxLength" to 120,
                                "description" to "Optional id of the playbook check this step " +
                                    "covers; the step must actually run for the check to count."
                            )
                        )
                    )
                )
            )
        ),
        sensitivity = AgentDataSensitivity.Aggregate,
        defaultTimeoutMillis = 1_000L,
        version = "2"
    )

    override val filterArgumentNames: Set<String> = emptySet()

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val steps = (arguments["steps"] as? List<*>).orEmpty()
        val data: AgentJsonObject = mapOf(
            "goal" to arguments["goal"].toString(),
            "steps" to steps,
            "declared" to true
        )
        return context.success(data, returnedCount = steps.size.toLong(), totalCount = steps.size.toLong())
    }

    companion object {
        const val NAME = "declare_analysis_plan"
        const val MAX_PLAN_STEPS = 12
    }
}
