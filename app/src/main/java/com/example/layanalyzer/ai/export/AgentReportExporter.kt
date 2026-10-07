// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.export

import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.ai.audit.AgentToolRunRecord
import com.example.layanalyzer.ai.markdown.ReportMarkdown
import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.data.MetadataRedactor
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentQuestionAlignment
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.EvidenceExportMode
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

data class AgentReportExport(
    val reportJson: String,
    val reportMarkdown: String,
    val runJson: String
) {
    val entries: Map<String, String>
        get() = mapOf(
            "agent-report.json" to reportJson,
            "agent-report.md" to reportMarkdown,
            "agent-run.json" to runJson
        )
}

/** Produces the three reviewable, privacy-safe Agent entries in an evidence ZIP. */
class AgentReportExporter {
    /** Privacy-safe Markdown suitable for the system clipboard. */
    fun markdown(report: AgentReport): String = export(report).reportMarkdown

    fun export(
        report: AgentReport,
        runRecord: AgentRunRecord? = null,
        mode: EvidenceExportMode = EvidenceExportMode.Redacted
    ): AgentReportExport {
        // Agent report prose must stay safe even when the surrounding evidence
        // package also contains the original capture. Original mode controls
        // the capture attachment, never disclosure of model/tool content.
        // Exported prose and provenance use a fresh salt. The capture
        // fingerprint is a local cache key and must never be the salt for
        // aliases that leave the device.
        val redactor = MetadataRedactor(randomExportSalt())
        val safeReport = report.redactedForExport(redactor)
        val safeRun = runRecord?.copy(
            captureFingerprint = redactFingerprint(runRecord.captureFingerprint, redactor),
            modelId = redactValue(runRecord.modelId, redactor),
            toolCalls = runRecord.toolCalls.map { it.copy(toolName = redactValue(it.toolName, redactor)) }
        )
        return AgentReportExport(
            reportJson = reportJson(safeReport, safeRun, mode),
            reportMarkdown = reportMarkdown(safeReport),
            runJson = runJson(safeRun, safeReport)
        )
    }

    private fun reportJson(
        report: AgentReport,
        runRecord: AgentRunRecord?,
        mode: EvidenceExportMode
    ): String = JSONObject()
        .put("schema", "AgentReportExport")
        .put("schemaVersion", SCHEMA_VERSION)
        .put("exportMode", mode.name)
        .put("agentReport", JSONObject(AgentJsonCodec.encodeReport(report)))
        .put("modelId", report.provenance.modelId)
        .put("promptVersion", report.provenance.promptVersion)
        .put("playbookVersion", report.provenance.playbookVersion ?: JSONObject.NULL)
        .put("analysisScope", report.provenance.scope.name)
        .put("captureFingerprint", report.provenance.captureFingerprint)
        .put("toolCalls", JSONArray().apply {
            runRecord?.toolCalls.orEmpty().forEach { put(toolCallJson(it)) }
        })
        .put("resultTruncated", runRecord?.toolCalls?.any { it.truncated } ?: false)
        .put("completeness", report.completeness.name)
        .toString(2)

    private fun runJson(runRecord: AgentRunRecord?, report: AgentReport): String {
        val record = runRecord ?: AgentRunRecord(
            sessionId = "",
            captureFingerprint = report.provenance.captureFingerprint,
            modelId = report.provenance.modelId,
            promptVersion = report.provenance.promptVersion,
            playbookVersion = report.provenance.playbookVersion,
            analysisScope = report.provenance.scope.name,
            displayFilterApplied = report.provenance.displayFilter.isNotBlank(),
            startedAtMillis = report.provenance.startedAtMillis ?: 0L,
            completedAtMillis = report.provenance.completedAtMillis ?: report.provenance.generatedAtMillis,
            evidenceCount = report.findings.sumOf { it.evidence.size },
            completeness = report.completeness.name
        )
        return JSONObject()
            .put("schema", "AgentRunRecord")
            .put("schemaVersion", SCHEMA_VERSION)
            .put("sessionId", record.sessionId)
            .put("captureFingerprint", record.captureFingerprint)
            .put("modelId", record.modelId)
            .put("promptVersion", record.promptVersion)
            .put("playbookVersion", record.playbookVersion ?: JSONObject.NULL)
            .put("analysisScope", record.analysisScope)
            .put("displayFilterApplied", record.displayFilterApplied)
            .put("startedAtMillis", record.startedAtMillis)
            .put("completedAtMillis", record.completedAtMillis)
            .put("toolCalls", JSONArray().apply { record.toolCalls.forEach { put(toolCallJson(it)) } })
            .put("totalSteps", record.totalSteps)
            .put("totalDurationMillis", record.totalDurationMillis)
            .put("cancelReason", record.cancelReason ?: JSONObject.NULL)
            .put("evidenceCount", record.evidenceCount)
            .put("completeness", record.completeness ?: JSONObject.NULL)
            .toString(2)
    }

    private fun toolCallJson(call: AgentToolRunRecord): JSONObject = JSONObject()
        .put("toolName", call.toolName)
        .put("normalizedArgumentsHash", call.normalizedArgumentsHash)
        .put("durationMillis", call.durationMillis)
        .put("returned", call.returned)
        .put("total", call.total)
        .put("errorCode", call.errorCode?.name ?: JSONObject.NULL)
        .put("truncated", call.truncated)
        .put("resultBytes", call.resultBytes)
        .put("queryMode", call.queryMode ?: JSONObject.NULL)
        .put("sampled", call.sampled)

    private fun reportMarkdown(report: AgentReport): String = buildString {
        appendLine("# Agent Report")
        appendLine()
        appendLine("## Summary")
        appendLine()
        appendLine(report.summary.ifBlank { "None." })
        appendLine()
        appendLine("## Findings")
        appendLine()
        if (report.findings.isEmpty()) appendLine("No findings were saved by the Agent.")
        report.findings.forEach { finding -> findingMarkdown(finding) }
        section("Limitations", report.limitations)
        section("Next Steps", report.recommendedNextSteps)
        // agent-report-2: rendered only when declared, matching the codec's
        // emit-only-when-non-default rule.
        if (report.questionAlignment.isNotEmpty()) {
            appendLine("## Question Alignment")
            appendLine()
            report.questionAlignment.forEach { entry -> appendLine(questionAlignmentLine(entry)) }
            appendLine()
        }
    }

    private fun StringBuilder.findingMarkdown(finding: AgentFinding) {
        appendLine()
        appendLine("### ${finding.title}")
        appendLine()
        appendLine("- Severity: ${finding.severity.name}")
        appendLine("- Confidence: ${finding.confidence.name}")
        appendLine()
        if (finding.conclusion.isNotBlank()) {
            appendLine(finding.conclusion)
            appendLine()
        }
        if (finding.evidence.isNotEmpty()) {
            appendLine("- Evidence:")
            finding.evidence.forEach { evidence ->
                appendLine(ReportMarkdown.listItem(evidenceLabel(evidence), "  - "))
            }
        }
        if (finding.alternatives.isNotEmpty()) {
            appendLine("- Alternatives:")
            finding.alternatives.forEach { appendLine(ReportMarkdown.listItem(it, "  - ")) }
        }
        if (finding.recommendations.isNotEmpty()) {
            appendLine("- Recommendations:")
            finding.recommendations.forEach { appendLine(ReportMarkdown.listItem(it, "  - ")) }
        }
        // agent-report-2 fields: emitted only when non-default so legacy
        // reports keep the same Markdown layout.
        if (finding.polarity != AgentFindingPolarity.Unknown) {
            appendLine("- Polarity: ${finding.polarity.name}")
        }
        finding.hypothesisId?.let { appendLine("- Hypothesis: $it") }
        if (finding.relatedSignals.isNotEmpty()) {
            appendLine("- Related signals: ${finding.relatedSignals.joinToString(", ")}")
        }
        if (finding.counterEvidenceChecked.isNotEmpty()) {
            appendLine("- Falsification checks: ${finding.counterEvidenceChecked.joinToString(", ")}")
        }
        appendLine()
    }

    private fun StringBuilder.section(title: String, values: List<String>) {
        appendLine("## $title")
        appendLine()
        if (values.none { it.isNotBlank() }) appendLine("None.")
        values.filter { it.isNotBlank() }.forEach { appendLine(ReportMarkdown.listItem(it)) }
        appendLine()
    }

    private fun questionAlignmentLine(entry: AgentQuestionAlignment): String {
        val status = if (entry.addressed) "addressed" else "unaddressed"
        val findings = entry.findingIds.joinToString(", ")
        return if (entry.findingIds.isEmpty()) {
            ReportMarkdown.listItem("${entry.questionPart} — $status")
        } else {
            ReportMarkdown.listItem("${entry.questionPart} — $status (findings: $findings)")
        }
    }

    private fun evidenceLabel(evidence: AgentEvidence): String = when {
        evidence.frameNumber != null -> "Frame ${evidence.frameNumber}: ${evidence.observation}"
        !evidence.displayFilter.isNullOrBlank() -> "Filter ${evidence.displayFilter}: ${evidence.observation}"
        else -> evidence.observation
    }

    private fun AgentReport.redactedForExport(redactor: MetadataRedactor?): AgentReport = copy(
        summary = redactValue(summary, redactor),
        limitations = limitations.map { redactValue(it, redactor) },
        recommendedNextSteps = recommendedNextSteps.map { redactValue(it, redactor) },
        provenance = provenance.copy(
            captureFingerprint = redactFingerprint(provenance.captureFingerprint, redactor),
            displayFilter = redactValue(provenance.displayFilter, redactor),
            modelId = redactValue(provenance.modelId, redactor)
        ),
        findings = findings.map { finding ->
            finding.copy(
                title = redactValue(finding.title, redactor),
                conclusion = redactValue(finding.conclusion, redactor),
                alternatives = finding.alternatives.map { redactValue(it, redactor) },
                recommendations = finding.recommendations.map { redactValue(it, redactor) },
                evidence = finding.evidence.map { evidence ->
                    evidence.copy(
                        displayFilter = evidence.displayFilter?.let { redactValue(it, redactor) },
                        field = evidence.field?.let { redactValue(it, redactor) },
                        observation = redactValue(evidence.observation, redactor),
                        observedValue = evidence.observedValue?.let { redactValue(it, redactor) }
                    )
                }
            )
        }
    )

    private fun redactValue(value: String, redactor: MetadataRedactor?): String {
        if (redactor == null) return value
        return SECRET_VALUE.replace(redactor.redact(value)) { match ->
            "${match.groupValues[1]}=[redacted]"
        }
    }

    private fun redactFingerprint(value: String, redactor: MetadataRedactor?): String {
        if (value.isBlank() || redactor == null) return value
        return redactor.redactValue(MetadataRedactor.IdentifierKind.Opaque, value)
    }

    private companion object {
        const val SCHEMA_VERSION = 1
        fun randomExportSalt(): String {
            val random = ByteArray(32).also { SecureRandom().nextBytes(it) }
            return buildString(random.size * 2 + 16) {
                random.forEach { append("%02x".format(it.toInt() and 0xff)) }
                append("|export")
            }
        }
        val SECRET_VALUE = Regex(
            "(?i)\\b(payload|api[ _-]?key|secret|token|credential|authorization|password)\\s*[:=]\\s*[^\\s,;]+"
        )
    }
}
