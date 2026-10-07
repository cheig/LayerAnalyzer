// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import com.example.layanalyzer.ai.tools.DeclareAnalysisPlanTool
import com.example.layanalyzer.model.AgentJsonObject

/**
 * Where a playbook came from.
 *
 * [origin] is never decoded from or serialized to JSON: package decoding and
 * the user-layer file format both omit it, and the owning store assigns it
 * when it builds playbooks.  Keeping it out of the serialization surface means
 * stored content can never mislabel itself as built-in, and scenario-package
 * content can never pose as user-authored (or vice versa).
 */
enum class ScenarioOrigin {
    /** Shipped in assets or a verified downloaded scenario package. */
    BuiltIn,

    /** Created or copied by the user and stored under filesDir. */
    User
}

/** A versioned, trusted recommendation for how to investigate one intent. */
data class AgentPlaybook(
    val id: String,
    val version: Int,
    val title: String,
    val intentHints: List<String>,
    val protocols: List<String>,
    val initialTools: List<String>,
    val requiredFields: List<String>,
    val checks: List<AgentPlaybookCheck>,
    val successPath: List<String>,
    val failureBranches: List<AgentPlaybookFailureBranch>,
    val requiredLimitations: List<String>,
    val outputSections: List<String>,
    /** Operator/device-layer review thresholds; additive only, never conclusions. */
    val thresholds: List<ScenarioThreshold> = emptyList(),
    /** Operator/device-layer recommended display filters; additive candidates. */
    val recommendedFilters: List<String> = emptyList(),
    /**
     * Assigned by the owning store, never read from JSON; the default keeps
     * every existing constructor call site a built-in playbook.
     */
    val origin: ScenarioOrigin = ScenarioOrigin.BuiltIn
) {
    val versionedId: String
        get() = "$id@$version"

    /** Trusted prompt text. It contains playbook data only, never capture data. */
    fun promptSection(): String = buildString {
        appendLine("Playbook: $id (version $version) - $title")
        appendLine("Initial tools: ${initialTools.joinToString()}")
        if (requiredFields.isNotEmpty()) appendLine("Required fields when drilling down: ${requiredFields.joinToString()}")
        checks.forEach { check ->
            appendLine("Check ${check.id}: ${check.description}. Recommended tools: ${check.recommendedTools.joinToString()}")
        }
        if (successPath.isNotEmpty()) appendLine("Success path: ${successPath.joinToString("; ")}")
        failureBranches.forEach { branch ->
            appendLine("Failure branch: ${branch.condition}. Recommended tools: ${branch.recommendedTools.joinToString()}. Limitation: ${branch.limitation}")
        }
        if (requiredLimitations.isNotEmpty()) appendLine("Required limitations: ${requiredLimitations.joinToString("; ")}")
        if (thresholds.isNotEmpty()) {
            appendLine("Review thresholds (signals worth a closer look, never conclusions on their own):")
            thresholds.forEach { threshold ->
                appendLine("- ${threshold.id}: ${threshold.value} ${threshold.unit}. ${threshold.notes}")
            }
        }
        if (recommendedFilters.isNotEmpty()) {
            appendLine("Candidate display filters to validate before use: ${recommendedFilters.joinToString()}")
        }
        append("Report sections: ${outputSections.joinToString()}")
    }

    fun recommendedToolsForOverview(overview: AgentJsonObject): List<String> =
        if (id == GENERAL_CAPTURE_HEALTH_ID) {
            GeneralCaptureHealthPlanner.recommendedTools(overview)
        } else {
            emptyList()
        }

    /**
     * The first bootstrap version intentionally recognises only the bounded
     * capture overview. Other initial tools may require question-specific
     * arguments and remain model-selected targeted analysis.
     */
    internal fun bootstrapTools(availableTools: Set<String>): List<String> =
        listOf(CAPTURE_OVERVIEW_TOOL).filter { tool ->
            tool in initialTools && tool in availableTools
        }

    fun matchesIntent(question: String): Boolean {
        val normalized = question.lowercase()
        return intentHints.any { hint -> hint.isNotBlank() && normalized.contains(hint.lowercase()) }
    }

    companion object {
        const val GENERAL_CAPTURE_HEALTH_ID = "general-capture-health"
        const val CAPTURE_OVERVIEW_TOOL = "get_capture_overview"

        /** Safe built-in fallback for JVM callers that do not have Android assets. */
        fun generalCaptureHealth(): AgentPlaybook = AgentPlaybook(
            id = GENERAL_CAPTURE_HEALTH_ID,
            version = 1,
            title = "General capture health",
            intentHints = listOf(
                "main problem", "capture health", "what is wrong", "analyze capture",
                "主要问题", "分析这份抓包", "抓包分析"
            ),
            protocols = listOf("any"),
            initialTools = listOf(DeclareAnalysisPlanTool.NAME, CAPTURE_OVERVIEW_TOOL),
            requiredFields = emptyList(),
            checks = listOf(
                AgentPlaybookCheck(
                    id = "health",
                    description = "Use health and Expert counts to choose the next aggregate query",
                    recommendedTools = listOf("get_statistics", "get_expert_info", "get_communication_analysis")
                )
            ),
            successPath = listOf(
                "Read the overview first",
                "Query aggregate evidence before packet detail",
                "For a large candidate set use query_packet_field_aggregate with a validated filter",
                "Use packet summaries and fields only to locate and explain evidence",
                "Treat sampled frame numbers as candidates, not proof that omitted frames are absent"
            ),
            failureBranches = listOf(
                AgentPlaybookFailureBranch(
                    condition = "A source is truncated or a query fails",
                    recommendedTools = emptyList(),
                    limitation = "State the incomplete coverage, omitted frames or sample scope and do not infer an absence."
                )
            ),
            requiredLimitations = listOf(
                "Conclusions require tool evidence.",
                "Truncated or failed sources limit negative conclusions."
            ),
            outputSections = listOf(
                "summary",
                "major_anomalies",
                "excluded_causes",
                "limitations",
                "recommended_next_steps"
            )
        )
    }
}

data class AgentPlaybookCheck(
    val id: String,
    val description: String,
    val recommendedTools: List<String>
)

data class AgentPlaybookFailureBranch(
    val condition: String,
    val recommendedTools: List<String>,
    val limitation: String
)

/**
 * The operator/device overlay for one package: additive-only rule content.
 *
 * An overlay can *add* field aliases (alternate spellings the host resolves to
 * the canonical supported field), review thresholds and recommended display
 * filters.  By construction it cannot:
 *
 *  - register or remove tools (AgentToolRegistry has no runtime registration);
 *  - change AgentPolicy budgets or AgentPayloadRedactor sensitivity levels;
 *  - raise EvidenceValidator's confidence cap;
 *  - weaken the "no evidence, no definite conclusion" rule;
 *  - rename or reprioritize playbook intent matching.
 *
 * Everything in it is validated declarative data, and it can only come from a
 * package that passed signature verification — never from model output or
 * capture text.
 */
data class ScenarioRulesOverlay(
    val aliases: List<ScenarioFieldAlias> = emptyList(),
    val thresholds: List<ScenarioThreshold> = emptyList(),
    val recommendedFilters: Map<String, List<String>> = emptyMap()
) {
    companion object {
        val EMPTY = ScenarioRulesOverlay()
    }
}

/**
 * Deterministic recommendation for the first general-health follow-up.
 *
 * This narrows the model's next choices but is never evidence itself and never
 * writes a report conclusion. The model still has to call the selected tool and
 * EvidenceValidator still checks every later citation.
 */
object GeneralCaptureHealthPlanner {
    fun recommendedTools(overview: AgentJsonObject): List<String> {
        val selected = LinkedHashSet<String>()
        val expertErrors = (overview["expertErrorCount"] as? Number)?.toLong() ?: 0L
        val expertWarnings = (overview["expertWarningCount"] as? Number)?.toLong() ?: 0L
        if (expertErrors > 0L || expertWarnings > 0L) selected += "get_expert_info"

        val health = overview["health"] as? Map<*, *> ?: emptyMap<Any?, Any?>()
        val hasHealthProblem = health.values.any { entry ->
            val item = entry as? Map<*, *> ?: return@any false
            val problems = (item["problems"] as? Number)?.toLong() ?: 0L
            val severity = item["severity"]?.toString()?.lowercase().orEmpty()
            problems > 0L || severity in setOf("warning", "error", "critical")
        }
        if (hasHealthProblem) selected += "get_statistics"

        val hierarchy = overview["protocolHierarchy"] as? Iterable<*> ?: emptyList<Any?>()
        val hasCommunicationProtocol = hierarchy.any { entry ->
            val name = (entry as? Map<*, *>)?.get("name")?.toString()?.lowercase().orEmpty()
            name in COMMUNICATION_PROTOCOLS
        }
        if (hasCommunicationProtocol) selected += "get_communication_analysis"

        // A clean overview still benefits from one aggregate baseline, rather
        // than jumping straight to packet rows with no investigation target.
        if (selected.isEmpty()) selected += "get_statistics"
        return selected.toList()
    }

    private val COMMUNICATION_PROTOCOLS = setOf(
        "sip", "sdp", "rtp", "rtcp", "diameter", "pfcp", "gtp", "gtpv2", "ngap", "s1ap", "nas",
        "radio", "rrc", "lte-rrc", "nr-rrc"
    )
}
