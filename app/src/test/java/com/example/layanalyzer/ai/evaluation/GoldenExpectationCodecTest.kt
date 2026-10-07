// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.evaluation

import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentReport
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * OPT-EVAL-02-01: pins the `attributionRubric` contract of
 * [GoldenExpectationCodec].  The rubric is an additive optional extension of
 * schema v1: documents without it must decode exactly as they did before the
 * field existed, documents with a malformed one must fail closed, and the
 * deterministic runner verdict must be byte-for-byte indifferent to it (the
 * scoring consumer arrives with OPT-EVAL-02-02).
 */
class GoldenExpectationCodecTest {

    // ------------------------------------------------------------- fixtures

    private fun baseExpectationJson(): JSONObject = JSONObject()
        .put("schemaVersion", 1)
        .put("id", "fixture")
        .put("captureFile", "fixture.pcap")
        .put("captureSha256", "a".repeat(64))
        .put("captureFrameCount", 3)
        .put("question", "What happened?")
        .put("scope", "complete_file")
        .put("privacyMode", "redacted_metadata")
        .put(
            "expectedFindings",
            JSONArray().put(
                JSONObject()
                    .put("id", "finding")
                    .put("kind", "ObservedFailure")
                    .put("severity", "Error")
                    .put("minimumConfidence", "Medium")
                    .put("requiredEvidenceFrames", JSONArray().put(2))
            )
        )
        .put("requiredEvidenceFrames", JSONArray().put(2))
        .put("allowedAlternativeConclusions", JSONArray().put("A failure was observed."))
        .put("forbiddenConclusions", JSONArray().put("the root cause is known"))
        .put("expectedLimitations", JSONArray().put("the capture boundary is visible"))
        .put("maximumToolCalls", 2)

    private fun fixtureExpectation(rubric: GoldenAttributionRubric? = null) = GoldenCaptureExpectation(
        schemaVersion = 1,
        id = "fixture",
        captureFile = "fixture.pcap",
        captureSha256 = "a".repeat(64),
        captureFrameCount = 3,
        question = "What happened?",
        scope = "complete_file",
        privacyMode = "redacted_metadata",
        expectedFindings = listOf(
            GoldenExpectedFinding("finding", "ObservedFailure", "Error", "Medium", listOf(2L))
        ),
        requiredEvidenceFrames = listOf(2L),
        allowedAlternativeConclusions = listOf("A failure was observed."),
        forbiddenConclusions = listOf("the root cause is known"),
        expectedLimitations = listOf("the capture boundary is visible"),
        maximumToolCalls = 2,
        attributionRubric = rubric
    )

    // --------------------------------------------------- absence degradation

    @Test
    fun `a v1 document without a rubric decodes to no attribution requirement`() {
        val decoded = GoldenExpectationCodec.decode(baseExpectationJson().toString())

        assertNull(decoded.attributionRubric)
        // Every other field keeps the exact pre-rubric value; the data-class
        // equality below fails if any decoded field changed shape.
        assertEquals(fixtureExpectation(), decoded)
    }

    @Test
    fun `an explicit null rubric also decodes to no attribution requirement`() {
        val document = baseExpectationJson().put("attributionRubric", JSONObject.NULL)

        val decoded = GoldenExpectationCodec.decode(document.toString())

        assertNull(decoded.attributionRubric)
        assertEquals(fixtureExpectation(), decoded)
    }

    // -------------------------------------------------------- valid rubrics

    @Test
    fun `a valid rubric decodes every field verbatim`() {
        val document = baseExpectationJson().put(
            "attributionRubric",
            JSONObject()
                .put("requiredRootCause", "the server application returned HTTP 5xx responses")
                .put(
                    "disallowedRootCauses",
                    JSONArray()
                        .put("a network path failure caused the outage")
                        .put("requests were never delivered")
                )
        )

        val decoded = GoldenExpectationCodec.decode(document.toString())

        assertEquals(
            fixtureExpectation(
                GoldenAttributionRubric(
                    requiredRootCause = "the server application returned HTTP 5xx responses",
                    // Stored raw, marker-style; normalization is the consumer's job.
                    disallowedRootCauses = listOf(
                        "a network path failure caused the outage",
                        "requests were never delivered"
                    )
                )
            ),
            decoded
        )
    }

    @Test
    fun `an omitted disallowedRootCauses list defaults to empty`() {
        val document = baseExpectationJson().put(
            "attributionRubric",
            JSONObject().put("requiredRootCause", "the observed failure sat in the application")
        )

        val decoded = GoldenExpectationCodec.decode(document.toString())

        assertEquals(GoldenAttributionRubric("the observed failure sat in the application", emptyList()), decoded.attributionRubric)
    }

    // ------------------------------------------------------ fail-closed format

    @Test
    fun `a rubric that is not an object is rejected`() {
        listOf("a string", 7, true, JSONArray().put("requiredRootCause")).forEach { value ->
            val document = baseExpectationJson().put("attributionRubric", value)
            expectDecodeFailure(document, "attributionRubric must be an object.")
        }
    }

    @Test
    fun `a missing or blank requiredRootCause is rejected`() {
        val missing = baseExpectationJson().put("attributionRubric", JSONObject())
        val blank = baseExpectationJson().put(
            "attributionRubric",
            JSONObject().put("requiredRootCause", "   ")
        )
        val nullValue = baseExpectationJson().put(
            "attributionRubric",
            JSONObject().put("requiredRootCause", JSONObject.NULL)
        )
        listOf(missing, blank, nullValue).forEach { document ->
            expectDecodeFailure(
                document,
                "attributionRubric.requiredRootCause must be a non-blank string."
            )
        }
    }

    @Test
    fun `a disallowedRootCauses list that is not an array is rejected`() {
        val document = baseExpectationJson().put(
            "attributionRubric",
            JSONObject()
                .put("requiredRootCause", "the application failed")
                .put("disallowedRootCauses", "a network path failure")
        )
        expectDecodeFailure(
            document,
            "attributionRubric.disallowedRootCauses must be an array."
        )
    }

    @Test
    fun `a blank disallowed root cause entry is rejected`() {
        val document = baseExpectationJson().put(
            "attributionRubric",
            JSONObject()
                .put("requiredRootCause", "the application failed")
                .put("disallowedRootCauses", JSONArray().put("a network path failure").put("  "))
        )
        expectDecodeFailure(
            document,
            "attributionRubric.disallowedRootCauses[1] must be a non-blank string."
        )
    }

    @Test
    fun `a disallowed root cause repeating the required root cause is rejected`() {
        val document = baseExpectationJson().put(
            "attributionRubric",
            JSONObject()
                .put("requiredRootCause", "The Service Failed At The Application")
                // Same string under normalizeForMatch (case and spacing differ only).
                .put("disallowedRootCauses", JSONArray().put("the   service failed at the application"))
        )
        expectDecodeFailure(
            document,
            "attributionRubric.disallowedRootCauses must not repeat attributionRubric.requiredRootCause."
        )
    }

    @Test
    fun `duplicate disallowed root causes are rejected`() {
        val document = baseExpectationJson().put(
            "attributionRubric",
            JSONObject()
                .put("requiredRootCause", "the application failed")
                .put(
                    "disallowedRootCauses",
                    JSONArray().put("a network path failure").put("A Network  Path Failure")
                )
        )
        expectDecodeFailure(
            document,
            "attributionRubric.disallowedRootCauses must not contain duplicates."
        )
    }

    // --------------------------------------------- runner verdict is untouched

    @Test
    fun `the rubric never changes the deterministic evaluation verdict`() {
        val metadata = AgentEvaluationMetadata(
            modelId = "mock:golden",
            appVersion = "1.0",
            nativeBuildMarker = "test-native",
            promptVersion = "phase1-1",
            playbookVersion = "general-capture-health@1"
        )
        val finding = AgentFinding(
            id = "finding",
            title = "ObservedFailure",
            severity = AgentFindingSeverity.Error,
            confidence = AgentConfidence.Medium,
            conclusion = "A failure was observed.",
            evidence = listOf(
                AgentEvidence(
                    type = AgentEvidenceType.Frame,
                    frameNumber = 2L,
                    observation = "Frame 2 supports the failure.",
                    sourceToolCallId = "analysis"
                )
            )
        )
        val passingReport = AgentReport(
            summary = "A failure was observed.",
            findings = listOf(finding),
            limitations = listOf("The capture boundary is visible.")
        )
        val failingReport = AgentReport(
            summary = "A failure was observed.",
            findings = listOf(
                AgentFinding(
                    id = "finding",
                    title = "ObservedFailure",
                    severity = AgentFindingSeverity.Error,
                    confidence = AgentConfidence.High,
                    conclusion = "A failure was observed.",
                    evidence = listOf(
                        AgentEvidence(
                            type = AgentEvidenceType.Frame,
                            frameNumber = 3L,
                            observation = "Frame 3.",
                            sourceToolCallId = "analysis"
                        )
                    )
                )
            ),
            limitations = listOf("The capture boundary is visible.")
        )
        val rubric = GoldenAttributionRubric(
            requiredRootCause = "the observed failure sat in the application layer",
            disallowedRootCauses = listOf("a network path failure caused it")
        )

        listOf(passingReport to true, failingReport to false).forEach { (report, expectPass) ->
            val withoutRubric = AgentEvaluationRunner.evaluate(
                expectations = listOf(fixtureExpectation()),
                samples = listOf(
                    GoldenRunSample(
                        scenarioId = "fixture",
                        report = report,
                        toolCallCount = 1,
                        durationMillis = 12,
                        toolResultFramesByCall = mapOf("analysis" to setOf(2L))
                    )
                ),
                metadata = metadata
            )
            val withRubric = AgentEvaluationRunner.evaluate(
                expectations = listOf(fixtureExpectation(rubric)),
                samples = listOf(
                    GoldenRunSample(
                        scenarioId = "fixture",
                        report = report,
                        toolCallCount = 1,
                        durationMillis = 12,
                        toolResultFramesByCall = mapOf("analysis" to setOf(2L))
                    )
                ),
                metadata = metadata
            )

            assertEquals("Scenarios must be identical with and without a rubric.", withoutRubric.scenarios, withRubric.scenarios)
            assertEquals("Summary must be identical with and without a rubric.", withoutRubric.summary, withRubric.summary)
            assertEquals("JSON must be identical with and without a rubric.", withoutRubric.toJson(), withRubric.toJson())
            assertEquals("Markdown must be identical with and without a rubric.", withoutRubric.toMarkdown(), withRubric.toMarkdown())
            assertEquals(expectPass, withRubric.scenarios.single().passed)
        }
    }

    // ------------------------------------------------- repository inventory

    @Test
    fun `the golden set pins exactly the five rubric families and eleven without`() {
        val files = expectationFiles()
        assertEquals(16, files.size)

        val expectations = GoldenExpectationCodec.decodeAll(files.map(File::readText))
        val byId = expectations.associateBy { it.id }
        val rubricFamilies = setOf(
            "tcp_out_of_order",
            "dns_timeout",
            "tls_handshake_failure",
            "http_5xx_storm",
            "sip_register_storm"
        )

        assertEquals(
            "Exactly the five discriminating families carry an attributionRubric.",
            rubricFamilies,
            expectations.filter { it.attributionRubric != null }.map { it.id }.toSet()
        )
        rubricFamilies.forEach { id ->
            val rubric = byId.getValue(id).attributionRubric
            assertTrue("$id must expose a non-blank required root cause.", rubric?.requiredRootCause?.isNotBlank() == true)
            assertTrue("$id must pin at least one disallowed root cause.", rubric?.disallowedRootCauses?.isNotEmpty() == true)
        }
        // The nine §11-frozen baseline families and the other two non-
        // discriminating families must stay rubric-free.
        expectations.forEach { expectation ->
            if (expectation.id !in rubricFamilies) {
                assertNull("${expectation.id} must not carry an attributionRubric.", expectation.attributionRubric)
            }
        }
    }

    // ------------------------------------------------------------- plumbing

    private fun expectDecodeFailure(document: JSONObject, expectedMessage: String) {
        val outcome = runCatching { GoldenExpectationCodec.decode(document.toString()) }
        val failure = outcome.exceptionOrNull()
        assertTrue("Expected decoding to fail: $document", failure != null)
        assertEquals(expectedMessage, failure!!.message)
    }

    private fun expectationFiles(): List<File> {
        val candidates = listOf(
            File("app/src/androidTest/assets/agent_golden/expectations"),
            File("src/androidTest/assets/agent_golden/expectations")
        )
        val directory = candidates.firstOrNull(File::isDirectory)
            ?: error("Golden expectation directory is missing.")
        return directory.listFiles { file -> file.extension == "json" }
            ?.sortedBy(File::getName)
            .orEmpty()
    }
}
