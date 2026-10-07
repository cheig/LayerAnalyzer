package com.example.layanalyzer.ai

import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.ai.serialization.AgentJsonDecodeResult
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentQuestionAlignment
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * OPT-ARCH-02 contracts for the agent-report-2 fields on the report codec.
 *
 * Pins the degradation contract: missing or malformed new fields must decode
 * successfully into their defaults (they become host limitations later, never
 * a parse failure), and encoding a report whose new fields are all defaults
 * must not emit the new keys, keeping the version-1 byte layout intact.
 */
class AgentJsonCodecAcoFieldsTest {

    @Test
    fun oldReportWithoutNewFieldsDecodesToDefaults() {
        val json = """
            {
              "schema":"AgentReport",
              "schemaVersion":1,
              "summary":"legacy",
              "findings":[
                {
                  "id":"f-1",
                  "title":"Legacy finding",
                  "severity":"Warning",
                  "confidence":"Medium",
                  "conclusion":"Old conclusion",
                  "evidence":[{"type":"Observation","observation":"obs","sourceToolCallId":"call-1"}],
                  "alternatives":["alt"],
                  "recommendations":["rec"],
                  "timeline":[{"stage":"s","detail":"d"}]
                }
              ],
              "limitations":["lim"],
              "recommendedNextSteps":["next"]
            }
        """.trimIndent()

        val decoded = AgentJsonCodec.decodeReport(json)
        assertTrue("legacy report must decode", decoded is AgentJsonDecodeResult.Success)
        val report = decoded.getOrThrow()
        assertEquals("legacy", report.summary)
        val finding = report.findings.single()
        assertEquals("f-1", finding.id)
        assertEquals(AgentFindingPolarity.Unknown, finding.polarity)
        assertEquals(emptyList<String>(), finding.counterEvidenceChecked)
        assertNull(finding.hypothesisId)
        assertEquals(emptyList<String>(), finding.relatedSignals)
        assertEquals(emptyList<AgentQuestionAlignment>(), report.questionAlignment)
    }

    @Test
    fun newFieldsDecode() {
        val json = """
            {
              "schema":"AgentReport",
              "schemaVersion":1,
              "summary":"new fields",
              "findings":[
                {
                  "id":"f-1",
                  "title":"t",
                  "severity":"Error",
                  "confidence":"High",
                  "conclusion":"c",
                  "polarity":"Negative",
                  "counterEvidenceChecked":["call-2","call-3"],
                  "hypothesisId":"H1",
                  "relatedSignals":["sig-1"]
                }
              ],
              "questionAlignment":[
                {"questionPart":"part A","addressed":true,"findingIds":["f-1"]},
                {"questionPart":"part B","addressed":false}
              ]
            }
        """.trimIndent()

        val report = AgentJsonCodec.decodeReport(json).getOrThrow()
        val finding = report.findings.single()
        assertEquals(AgentFindingPolarity.Negative, finding.polarity)
        assertEquals(listOf("call-2", "call-3"), finding.counterEvidenceChecked)
        assertEquals("H1", finding.hypothesisId)
        assertEquals(listOf("sig-1"), finding.relatedSignals)
        assertEquals(
            listOf(
                AgentQuestionAlignment("part A", true, listOf("f-1")),
                AgentQuestionAlignment("part B", false, emptyList())
            ),
            report.questionAlignment
        )
    }

    @Test
    fun invalidNewFieldValuesFallBackToDefaults() {
        val json = """
            {
              "schema":"AgentReport",
              "schemaVersion":1,
              "summary":"s",
              "findings":[
                {
                  "id":"f-1",
                  "title":"t",
                  "severity":"Info",
                  "confidence":"Low",
                  "conclusion":"c",
                  "polarity":"banana",
                  "counterEvidenceChecked":"not-an-array",
                  "hypothesisId":42,
                  "relatedSignals":[{"not":"a-string"}]
                }
              ],
              "questionAlignment":[
                {"addressed":"yes"},
                "not-an-object",
                {"questionPart":"ok part"}
              ]
            }
        """.trimIndent()

        val decoded = AgentJsonCodec.decodeReport(json)
        assertTrue("malformed new fields must not fail decoding", decoded is AgentJsonDecodeResult.Success)
        val report = decoded.getOrThrow()
        val finding = report.findings.single()
        assertEquals(AgentFindingPolarity.Unknown, finding.polarity)
        assertEquals(emptyList<String>(), finding.counterEvidenceChecked)
        assertNull(finding.hypothesisId)
        assertEquals(emptyList<String>(), finding.relatedSignals)
        assertEquals(
            listOf(
                AgentQuestionAlignment("", false, emptyList()),
                AgentQuestionAlignment("ok part", false, emptyList())
            ),
            report.questionAlignment
        )
    }

    @Test
    fun filledNewFieldsRoundTrip() {
        val report = AgentReport(
            summary = "round trip",
            findings = listOf(
                AgentFinding(
                    id = "f-1",
                    title = "t",
                    severity = AgentFindingSeverity.Error,
                    confidence = AgentConfidence.High,
                    conclusion = "c",
                    polarity = AgentFindingPolarity.Positive,
                    counterEvidenceChecked = listOf("call-9"),
                    hypothesisId = "H7",
                    relatedSignals = listOf("sig-a", "sig-b")
                )
            ),
            limitations = listOf("lim"),
            recommendedNextSteps = listOf("next"),
            completeness = AgentReportCompleteness.Complete,
            questionAlignment = listOf(
                AgentQuestionAlignment("Is auth failing?", true, listOf("f-1")),
                AgentQuestionAlignment("Why?", false, emptyList())
            )
        )

        val decoded = AgentJsonCodec.decodeReport(AgentJsonCodec.encodeReport(report))
        assertTrue(decoded is AgentJsonDecodeResult.Success)
        val restored = decoded.getOrThrow()
        assertEquals(report, restored)
        val finding = restored.findings.single()
        assertEquals(AgentFindingPolarity.Positive, finding.polarity)
        assertEquals(listOf("call-9"), finding.counterEvidenceChecked)
        assertEquals("H7", finding.hypothesisId)
        assertEquals(listOf("sig-a", "sig-b"), finding.relatedSignals)
        assertEquals(
            listOf(
                AgentQuestionAlignment("Is auth failing?", true, listOf("f-1")),
                AgentQuestionAlignment("Why?", false, emptyList())
            ),
            restored.questionAlignment
        )
    }

    @Test
    fun defaultReportEncodingOmitsNewKeys() {
        val report = AgentReport(
            summary = "defaults",
            findings = listOf(
                AgentFinding(
                    id = "f-1",
                    title = "t",
                    severity = AgentFindingSeverity.Info,
                    confidence = AgentConfidence.Low,
                    conclusion = "c",
                    evidence = listOf(
                        AgentEvidence(observation = "obs", sourceToolCallId = "call-1")
                    )
                )
            )
        )

        val root = JSONObject(AgentJsonCodec.encodeReport(report))
        assertEquals(
            setOf(
                "schema",
                "schemaVersion",
                "summary",
                "findings",
                "limitations",
                "recommendedNextSteps",
                "provenance",
                "completeness"
            ),
            root.keys().asSequence().toSet()
        )
        val finding = root.getJSONArray("findings").getJSONObject(0)
        assertEquals(
            setOf(
                "id",
                "title",
                "severity",
                "confidence",
                "conclusion",
                "evidence",
                "alternatives",
                "recommendations",
                "timeline"
            ),
            finding.keys().asSequence().toSet()
        )
    }

    @Test
    fun revisedFindingsDecodeNewFieldsLaxly() {
        val json = """
            {
              "findings":[
                {
                  "id":"f-1",
                  "title":"t",
                  "severity":"Info",
                  "confidence":"Low",
                  "conclusion":"c",
                  "polarity":"Neutral",
                  "hypothesisId":"H2",
                  "relatedSignals":["sig-9"]
                },
                {
                  "id":"f-2",
                  "title":"t2",
                  "severity":"Info",
                  "confidence":"Low",
                  "conclusion":"c2",
                  "polarity":"bogus"
                }
              ]
            }
        """.trimIndent()

        val decoded = AgentJsonCodec.decodeRevisedFindings(json)
        assertTrue("revision payload must decode", decoded is AgentJsonDecodeResult.Success)
        val findings = decoded.getOrThrow()
        assertEquals(2, findings.size)
        assertEquals(AgentFindingPolarity.Neutral, findings[0].polarity)
        assertEquals("H2", findings[0].hypothesisId)
        assertEquals(listOf("sig-9"), findings[0].relatedSignals)
        assertEquals(emptyList<String>(), findings[0].counterEvidenceChecked)
        assertEquals(AgentFindingPolarity.Unknown, findings[1].polarity)
        assertNull(findings[1].hypothesisId)
    }
}
