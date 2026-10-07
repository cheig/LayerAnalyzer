package com.example.layanalyzer.ai.evaluation

import com.example.layanalyzer.ai.playbook.ScenarioPackageManifest
import com.example.layanalyzer.ai.playbook.ScenarioPackageSource
import com.example.layanalyzer.ai.playbook.ScenarioReleaseIssue
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale

/**
 * Everything one release is pinned to.
 *
 * A report is only reproducible if the app, the native engine, the model, the
 * prompt and the rule package are all recorded together — a Golden result from
 * a different native build or rule package version says nothing about this one.
 */
data class AgentReleaseMatrix(
    val appVersion: String,
    val nativeBuildMarker: String,
    val abi: String,
    val modelId: String,
    val modelCapabilities: List<String>,
    val promptVersion: String,
    val playbookPackageId: String,
    val playbookPackageVersion: Int,
    val playbookPackageSource: ScenarioPackageSource,
    val playbookVersion: String
) {
    fun toJsonObject(): JSONObject = JSONObject()
        .put("appVersion", appVersion)
        .put("nativeBuildMarker", nativeBuildMarker)
        .put("abi", abi)
        .put("modelId", modelId)
        .put("modelCapabilities", JSONArray(modelCapabilities))
        .put("promptVersion", promptVersion)
        .put("playbookPackageId", playbookPackageId)
        .put("playbookPackageVersion", playbookPackageVersion)
        .put("playbookPackageSource", playbookPackageSource.name)
        .put("playbookVersion", playbookVersion)

    companion object {
        /** Build the matrix from an evaluation run's metadata plus package identity. */
        fun from(
            metadata: AgentEvaluationMetadata,
            manifest: ScenarioPackageManifest,
            source: ScenarioPackageSource,
            abi: String,
            modelCapabilities: List<String> = emptyList()
        ): AgentReleaseMatrix = AgentReleaseMatrix(
            appVersion = metadata.appVersion,
            nativeBuildMarker = metadata.nativeBuildMarker,
            abi = abi,
            modelId = metadata.modelId,
            modelCapabilities = modelCapabilities,
            promptVersion = metadata.promptVersion,
            playbookPackageId = manifest.packageId,
            playbookPackageVersion = manifest.version,
            playbookPackageSource = source,
            playbookVersion = metadata.playbookVersion
        )
    }
}

/** Budgets a release must stay inside; defaults are the AI-19 recommendations. */
data class AgentReleaseBudget(
    val maxAverageToolCalls: Double = 12.0,
    val maxAverageDurationMillis: Double = 120_000.0,
    val maxInvalidFilterRate: Double = 0.05,
    val maxAverageInputTokens: Double? = null,
    val maxAverageCost: Double? = null
)

data class AgentReleaseCheck(
    val id: String,
    val passed: Boolean,
    val detail: String
)

data class AgentReleaseGateReport(
    val matrix: AgentReleaseMatrix,
    val checks: List<AgentReleaseCheck>
) {
    val passed: Boolean
        get() = checks.all { it.passed }

    fun toJson(): String = JSONObject()
        .put("schema", "AgentReleaseGateReport")
        .put("schemaVersion", AgentReleaseGate.SCHEMA_VERSION)
        .put("passed", passed)
        .put("matrix", matrix.toJsonObject())
        .put("checks", JSONArray().apply {
            checks.forEach { check ->
                put(
                    JSONObject()
                        .put("id", check.id)
                        .put("passed", check.passed)
                        .put("detail", check.detail)
                )
            }
        })
        .toString(2)

    fun toMarkdown(): String = buildString {
        appendLine("# Agent Release Matrix")
        appendLine()
        appendLine("| Dimension | Pinned value |")
        appendLine("|---|---|")
        appendLine("| App version | `${matrix.appVersion}` |")
        appendLine("| Native build | `${matrix.nativeBuildMarker}` |")
        appendLine("| ABI | `${matrix.abi}` |")
        appendLine("| Model | `${matrix.modelId}` |")
        appendLine("| Model capabilities | `${matrix.modelCapabilities.joinToString().ifBlank { "n/a" }}` |")
        appendLine("| Prompt version | `${matrix.promptVersion}` |")
        appendLine(
            "| Scenario package | `${matrix.playbookPackageId}@${matrix.playbookPackageVersion}` " +
                "(${matrix.playbookPackageSource.name}) |"
        )
        appendLine("| Playbook | `${matrix.playbookVersion}` |")
        appendLine()
        appendLine("## Release gates")
        appendLine()
        appendLine("| Gate | Result | Detail |")
        appendLine("|---|---|---|")
        checks.forEach { check ->
            appendLine("| ${check.id} | ${if (check.passed) "pass" else "FAIL" } | ${check.detail} |")
        }
        appendLine()
        appendLine("Release ${if (passed) "allowed" else "blocked"} by ${checks.count { !it.passed }} failing gate(s).")
    }
}

/**
 * The hard release gate over an AI-19 evaluation report.
 *
 * These are the checks that block a release rather than merely inform it: an
 * unverifiable citation, an unsupported High-Confidence claim or a forbidden
 * conclusion is a correctness failure, and a scenario without a Golden
 * expectation cannot be regression-tested at all.  All of them are computed
 * from aggregate metrics; no model text is read here.
 */
object AgentReleaseGate {
    const val SCHEMA_VERSION = 1

    fun evaluate(
        matrix: AgentReleaseMatrix,
        evaluation: AgentEvaluationReport,
        packageReleaseIssues: List<ScenarioReleaseIssue>,
        budget: AgentReleaseBudget = AgentReleaseBudget()
    ): AgentReleaseGateReport {
        val summary = evaluation.summary
        val checks = mutableListOf<AgentReleaseCheck>()

        checks += AgentReleaseCheck(
            id = "deterministic-regression",
            passed = summary.scenarioCount > 0 && summary.passedScenarioCount == summary.scenarioCount,
            detail = "${summary.passedScenarioCount}/${summary.scenarioCount} Golden scenarios passed."
        )
        checks += AgentReleaseCheck(
            id = "evidence-citation-validity",
            passed = summary.evidenceFramePrecision >= 1.0,
            detail = "Evidence citation validity is ${summary.evidenceFramePrecision.percent()}; 100% is required."
        )
        checks += AgentReleaseCheck(
            id = "no-unsupported-high-confidence",
            passed = summary.unsupportedHighConfidenceFindings == 0,
            detail = "${summary.unsupportedHighConfidenceFindings} High-Confidence findings lack tool evidence."
        )
        checks += AgentReleaseCheck(
            id = "no-forbidden-conclusions",
            passed = summary.forbiddenConclusionHits == 0,
            detail = "${summary.forbiddenConclusionHits} forbidden conclusions were produced."
        )
        checks += AgentReleaseCheck(
            id = "budgets",
            passed = summary.averageToolCalls <= budget.maxAverageToolCalls &&
                summary.averageDurationMillis <= budget.maxAverageDurationMillis &&
                summary.invalidFilterRate <= budget.maxInvalidFilterRate &&
                summary.filterLeaseRestoreFailures == 0 &&
                withinBudget(summary.averageInputTokens, budget.maxAverageInputTokens) &&
                withinBudget(summary.averageCost, budget.maxAverageCost),
            detail = "Average ${summary.averageToolCalls.decimal()} tool calls, " +
                "${summary.averageDurationMillis.decimal()} ms, " +
                "invalid filter rate ${summary.invalidFilterRate.percent()}, " +
                "${summary.filterLeaseRestoreFailures} filter lease restore failures."
        )
        checks += AgentReleaseCheck(
            id = "scenario-golden-coverage",
            passed = packageReleaseIssues.isEmpty(),
            detail = if (packageReleaseIssues.isEmpty()) {
                "Every scenario in the rule package is pinned by a Golden or synthetic expectation."
            } else {
                packageReleaseIssues.joinToString("; ") { "${it.playbookId}: ${it.reason}" }
            }
        )
        checks += AgentReleaseCheck(
            id = "matrix-reproducible",
            passed = matrix.appVersion.isNotBlank() &&
                matrix.nativeBuildMarker.isNotBlank() &&
                matrix.abi.isNotBlank() &&
                matrix.modelId.isNotBlank() &&
                matrix.promptVersion.isNotBlank() &&
                matrix.playbookPackageId.isNotBlank() &&
                matrix.playbookPackageVersion > 0 &&
                matrix.appVersion == evaluation.metadata.appVersion &&
                matrix.nativeBuildMarker == evaluation.metadata.nativeBuildMarker &&
                matrix.modelId == evaluation.metadata.modelId &&
                matrix.promptVersion == evaluation.metadata.promptVersion,
            detail = "Matrix pins app, native build, ABI, model, prompt and rule package " +
                "and matches the evaluated run's metadata."
        )
        return AgentReleaseGateReport(matrix, checks)
    }

    fun write(report: AgentReleaseGateReport, jsonFile: File, markdownFile: File) {
        jsonFile.parentFile?.mkdirs()
        markdownFile.parentFile?.mkdirs()
        jsonFile.writeText(report.toJson())
        markdownFile.writeText(report.toMarkdown())
    }

    private fun withinBudget(value: Double?, limit: Double?): Boolean =
        limit == null || value == null || value <= limit

    private fun Double.percent(): String = String.format(Locale.US, "%.1f%%", this * 100.0)

    private fun Double.decimal(): String = String.format(Locale.US, "%.1f", this)
}
