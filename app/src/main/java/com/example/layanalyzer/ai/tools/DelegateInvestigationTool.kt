package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult

/** Runs a bounded, transcript-isolated investigation through the owning loop. */
class DelegateInvestigationTool : AgentTool {
    override val consumesEvidenceStep: Boolean = false

    override val definition = AgentToolDefinition(
        name = NAME,
        description = "Delegate a focused investigation and return only its compact validated summary.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "required" to listOf("goal"),
            "properties" to mapOf(
                "goal" to mapOf(
                    "type" to "string",
                    "minLength" to 1,
                    "maxLength" to SCHEMA_GOAL_MAX_CHARS,
                    HOST_TRUNCATE_SCHEMA_KEY to MAX_GOAL_CHARS
                ),
                "maxTurns" to mapOf("type" to "integer", "minimum" to 1, "maximum" to MAX_TURNS)
            )
        ),
        sensitivity = AgentDataSensitivity.Metadata,
        defaultTimeoutMillis = AgentPolicy.DEFAULT_MAX_DELEGATED_TIMEOUT_MILLIS,
        version = "1"
    )

    override val filterArgumentNames: Set<String> = emptySet()

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val goal = arguments["goal"].toString().trim()
        val turns = (arguments["maxTurns"] as? Number)?.toInt()?.coerceIn(1, MAX_TURNS)
            ?: DEFAULT_TURNS
        val data = context.delegateInvestigation(goal, turns)
        val findings = (data["findings"] as? Collection<*>)?.size?.toLong() ?: 0L
        return context.success(
            data = data,
            returnedCount = findings,
            totalCount = findings,
            truncated = data["delegateIncomplete"] == true
        )
    }

    companion object {
        const val NAME = "delegate_investigation"
        const val DEFAULT_TURNS = 6
        const val MAX_TURNS = 12
        /**
         * Semantic cap on the delegated goal. The provider-visible schema
         * remains bounded, while the host validator applies this internal cap
         * before the tool executes.
         */
        const val MAX_GOAL_CHARS = 1_000
        const val SCHEMA_GOAL_MAX_CHARS = 8_000
    }
}
