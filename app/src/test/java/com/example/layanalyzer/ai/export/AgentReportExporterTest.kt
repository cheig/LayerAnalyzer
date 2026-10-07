// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.export

import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.ai.markdown.ReportMarkdown
import com.example.layanalyzer.ai.markdown.children
import org.commonmark.node.Heading
import org.commonmark.node.Paragraph
import org.commonmark.node.BulletList
import org.junit.Assert.assertEquals
import com.example.layanalyzer.ai.audit.AgentToolRunRecord
import com.example.layanalyzer.data.MetadataRedactor
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportProvenance
import com.example.layanalyzer.model.EvidenceExportMode
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentReportExporterTest {
    @Test
    fun markdownBodyParagraphsDoNotMergeWithMetadataOrEscapeLists() {
        val markdown = AgentReportExporter().markdown(AgentReport(
            summary = "**注册失败**。\n\n服务端拒绝请求。",
            findings = listOf(AgentFinding(
                title = "响应异常",
                conclusion = "观察到拒绝响应。\n\n原因需要进一步确认。",
                recommendations = listOf("检查配置。\n\n先核对服务端策略。")
            )),
            recommendedNextSteps = listOf("重新抓包。\n\n覆盖完整流程。")
        ))
        val blocks = ReportMarkdown.parse(markdown).children().toList()
        val summary = blocks.indexOfFirst { it is Heading && ReportMarkdown.plainText(it) == "Summary" }
        assertTrue(blocks[summary + 1] is Paragraph)
        assertTrue(blocks[summary + 2] is Paragraph)
        assertTrue(blocks.any { it is Paragraph && ReportMarkdown.plainText(it) == "观察到拒绝响应。" })
        val steps = blocks.indexOfFirst { it is Heading && ReportMarkdown.plainText(it) == "Next Steps" }
        val list = blocks[steps + 1] as BulletList
        assertEquals(1, list.children().count())
        assertEquals(2, list.firstChild.children().count())
        assertTrue(markdown.contains("    先核对服务端策略。"))
    }

    @Test
    fun `redacted export omits identifiers payload and credentials while retaining audit hashes`() {
        val report = AgentReport(
            summary = "IMSI: 460001234567890 Call-ID: secret-call-id Payload=rawbody API key=sk-live",
            findings = listOf(
                AgentFinding(
                    id = "finding-1",
                    title = "Call-ID: secret-call-id",
                    severity = AgentFindingSeverity.Warning,
                    conclusion = "Payload=rawbody",
                    evidence = listOf(
                        AgentEvidence(
                            type = AgentEvidenceType.Frame,
                            frameNumber = 7,
                            observation = "IMSI: 460001234567890",
                            sourceToolCallId = "tool-1"
                        )
                    )
                )
            ),
            provenance = AgentReportProvenance(
                captureFingerprint = "fingerprint",
                modelId = "mock-model",
                promptVersion = "prompt-v1",
                toolCallIds = listOf("tool-1")
            )
        )
        val run = AgentRunRecord(
            sessionId = "session-1",
            captureFingerprint = "fingerprint",
            modelId = "mock-model",
            promptVersion = "prompt-v1",
            analysisScope = "CompleteFile",
            displayFilterApplied = false,
            startedAtMillis = 1L,
            completedAtMillis = 2L,
            toolCalls = listOf(
                AgentToolRunRecord(
                    toolName = "packet_search",
                    normalizedArgumentsHash = "hash-only-value",
                    durationMillis = 1L,
                    returned = 3L,
                    total = 5L
                )
            )
        )

        val export = AgentReportExporter().export(report, run, EvidenceExportMode.Redacted)
        val contents = export.entries.values.joinToString("\n")

        listOf("460001234567890", "secret-call-id", "rawbody", "sk-live").forEach { raw ->
            assertFalse("export leaked $raw", contents.contains(raw))
        }
        assertTrue(export.runJson.contains("hash-only-value"))
        assertFalse(export.runJson.contains("arguments"))
    }

    @Test
    fun `export does not expose the capture fingerprint or aliases derived from it`() {
        val fingerprint = "0123456789abcdef".repeat(4)
        val legacyAlias = MetadataRedactor(fingerprint).redact("source 192.0.2.10")
        val report = AgentReport(
            summary = "source 192.0.2.10",
            provenance = AgentReportProvenance(
                captureFingerprint = fingerprint,
                modelId = "mock-model",
                promptVersion = "prompt-v1"
            )
        )

        val export = AgentReportExporter().export(report, mode = EvidenceExportMode.Redacted)
        val contents = export.entries.values.joinToString("\n")

        assertFalse("raw capture fingerprint leaked", contents.contains(fingerprint))
        assertFalse("export reused the capture fingerprint as its salt", contents.contains(legacyAlias))
    }

    @Test
    fun `clipboard markdown reuses the privacy safe report rendering`() {
        val markdown = AgentReportExporter().markdown(
            AgentReport(
                summary = "Payload=rawbody",
                findings = listOf(AgentFinding(title = "Finding", conclusion = "Conclusion"))
            )
        )

        assertTrue(markdown.contains("# Agent Report"))
        assertTrue(markdown.contains("### Finding"))
        assertFalse(markdown.contains("rawbody"))
    }
}
