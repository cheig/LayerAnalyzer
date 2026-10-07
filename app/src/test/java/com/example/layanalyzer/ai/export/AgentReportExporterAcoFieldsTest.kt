// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.export

import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentQuestionAlignment
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.EvidenceExportMode
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * agent-report-2 fields (OPT-ARCH-04): the exporter renders polarity,
 * hypothesis reference, related signals and falsification checks only when
 * they are set, and keeps them verbatim through redaction.
 */
class AgentReportExporterAcoFieldsTest {

    private val exporter = AgentReportExporter()

    private fun fullFieldFinding() = AgentFinding(
        id = "f-1",
        title = "Finding",
        polarity = AgentFindingPolarity.Positive,
        counterEvidenceChecked = listOf("call-1", "call-2"),
        hypothesisId = "h-1",
        relatedSignals = listOf("sig-1", "sig-2")
    )

    @Test
    fun `finding markdown adds the four agent-report-2 lines when set`() {
        val markdown = exporter.markdown(
            AgentReport(summary = "Summary", findings = listOf(fullFieldFinding()))
        )

        assertTrue(markdown.contains("- Polarity: Positive"))
        assertTrue(markdown.contains("- Hypothesis: h-1"))
        assertTrue(markdown.contains("- Related signals: sig-1, sig-2"))
        assertTrue(markdown.contains("- Falsification checks: call-1, call-2"))

        // The lines follow the model declaration order.
        val polarity = markdown.indexOf("- Polarity: Positive")
        val hypothesis = markdown.indexOf("- Hypothesis: h-1")
        val signals = markdown.indexOf("- Related signals: sig-1, sig-2")
        val checks = markdown.indexOf("- Falsification checks: call-1, call-2")
        assertTrue(polarity in 0 until hypothesis)
        assertTrue(hypothesis in 0 until signals)
        assertTrue(signals in 0 until checks)
    }

    @Test
    fun `default finding markdown omits the agent-report-2 lines`() {
        val markdown = exporter.markdown(
            AgentReport(summary = "Summary", findings = listOf(AgentFinding(title = "Finding")))
        )

        assertFalse(markdown.contains("Polarity"))
        assertFalse(markdown.contains("- Hypothesis:"))
        assertFalse(markdown.contains("Related signals"))
        assertFalse(markdown.contains("Falsification checks"))
    }

    @Test
    fun `question alignment section renders after next steps with finding references`() {
        val markdown = exporter.markdown(
            AgentReport(
                summary = "Summary",
                questionAlignment = listOf(
                    AgentQuestionAlignment(
                        questionPart = "Why does registration fail?",
                        addressed = true,
                        findingIds = listOf("f-1", "f-2")
                    ),
                    AgentQuestionAlignment(questionPart = "TLS handshake", addressed = false)
                )
            )
        )

        assertTrue(markdown.contains("## Question Alignment"))
        assertTrue(markdown.contains("- Why does registration fail? — addressed (findings: f-1, f-2)"))
        assertTrue(markdown.contains("- TLS handshake — unaddressed"))
        assertTrue(markdown.indexOf("## Question Alignment") > markdown.indexOf("## Next Steps"))
    }

    @Test
    fun `empty question alignment renders no section`() {
        val markdown = exporter.markdown(AgentReport(summary = "Summary"))

        assertFalse(markdown.contains("Question Alignment"))
    }

    @Test
    fun `report json keeps the new keys when set and drops them when default`() {
        val full = JSONObject(
            exporter.export(
                AgentReport(
                    summary = "Summary",
                    findings = listOf(fullFieldFinding()),
                    questionAlignment = listOf(
                        AgentQuestionAlignment(
                            questionPart = "part",
                            addressed = true,
                            findingIds = listOf("f-1")
                        )
                    )
                ),
                mode = EvidenceExportMode.Redacted
            ).reportJson
        ).getJSONObject("agentReport")

        val fullFinding = full.getJSONArray("findings").getJSONObject(0)
        assertEquals("Positive", fullFinding.getString("polarity"))
        assertEquals("h-1", fullFinding.getString("hypothesisId"))
        assertTrue(fullFinding.getJSONArray("relatedSignals").toString().contains("sig-1"))
        assertTrue(fullFinding.getJSONArray("counterEvidenceChecked").toString().contains("call-2"))
        assertTrue(full.has("questionAlignment"))

        val defaultReport = JSONObject(
            exporter.export(
                AgentReport(summary = "Summary", findings = listOf(AgentFinding(title = "Finding"))),
                mode = EvidenceExportMode.Redacted
            ).reportJson
        ).getJSONObject("agentReport")
        val defaultFinding = defaultReport.getJSONArray("findings").getJSONObject(0)

        assertFalse(defaultFinding.has("polarity"))
        assertFalse(defaultFinding.has("hypothesisId"))
        assertFalse(defaultFinding.has("relatedSignals"))
        assertFalse(defaultFinding.has("counterEvidenceChecked"))
        assertFalse(defaultReport.has("questionAlignment"))
    }

    @Test
    fun `redacted export retains the new fields verbatim`() {
        val finding = fullFieldFinding().copy(
            title = "Call-ID: secret-call-id",
            conclusion = "Payload=rawbody"
        )
        val markdown = exporter.markdown(AgentReport(summary = "Summary", findings = listOf(finding)))

        // The agent-report-2 values are host-generated ids and never redacted.
        assertTrue(markdown.contains("- Polarity: Positive"))
        assertTrue(markdown.contains("- Hypothesis: h-1"))
        assertTrue(markdown.contains("- Related signals: sig-1, sig-2"))
        assertTrue(markdown.contains("- Falsification checks: call-1, call-2"))
        // Redaction itself still applies to the capture-derived text.
        assertFalse(markdown.contains("rawbody"))
        assertFalse(markdown.contains("secret-call-id"))
    }
}
