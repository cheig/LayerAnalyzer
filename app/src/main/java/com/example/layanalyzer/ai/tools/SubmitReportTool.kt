// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentPrompt
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult

/**
 * Terminal handoff for the final report.  It reads no capture data.
 *
 * The report used to arrive as free text that happened to contain JSON, which
 * put two mutually exclusive contracts on one request: the same response had to
 * be either a tool call or a whole report, and the model had to guess which.  A
 * model that guessed "report" during a tool-selection turn produced prose with
 * an embedded object, and a single missing quote in several thousand characters
 * discarded an otherwise complete analysis.
 *
 * Routing the report through the tool channel removes the guess.  Every turn
 * now has exactly one shape — a tool call — and the arguments are generated
 * against [AgentPrompt.REPORT_SCHEMA] by the provider, so a malformed report is
 * rejected before it reaches the host instead of after.
 */
class SubmitReportTool : AgentTool {
    /** The report is the conclusion of evidence gathering, not evidence itself. */
    override val consumesEvidenceStep: Boolean = false

    override val definition = AgentToolDefinition(
        name = NAME,
        description = "Submit the final analysis report. Call this exactly once, only after the " +
            "evidence you need has been gathered, instead of writing the report as prose. " +
            "This ends the analysis.",
        inputSchema = AgentPrompt.REPORT_SCHEMA,
        sensitivity = AgentDataSensitivity.Aggregate,
        defaultTimeoutMillis = 1_000L,
        version = "1"
    )

    /** No argument here is a display filter; nothing must be compiled. */
    override val filterArgumentNames: Set<String> = emptySet()

    /**
     * Echo the schema-validated arguments back as the result payload.
     *
     * The loop, not the tool, decides that the run is over: it reads these
     * arguments as the report envelope and runs them through the same evidence
     * validator a free-text report went through.
     */
    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val findings = (arguments["findings"] as? List<*>).orEmpty()
        val data: AgentJsonObject = arguments.mapValues { (_, value) -> value } +
            mapOf("submitted" to true)
        return context.success(
            data = data,
            returnedCount = findings.size.toLong(),
            totalCount = findings.size.toLong()
        )
    }

    companion object {
        const val NAME = "submit_report"
    }
}
