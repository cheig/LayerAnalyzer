package com.example.layanalyzer.ai.evaluation

import com.example.layanalyzer.ai.client.MockModelScriptCodec
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentReport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AgentEvaluationRunnerTest {

    @Test
    fun `all generated expectations pin a capture hash and evidence range`() {
        val files = expectationFiles()
        // 9 IMS/SIP + 4 transport families (OPT-EVAL-01-01)
        // + 3 application-layer families (OPT-EVAL-01-03)
        assertEquals(16, files.size)

        val expectations = GoldenExpectationCodec.decodeAll(files.map(File::readText))
        assertEquals(16, expectations.map { it.id }.distinct().size)
        expectations.forEach { expectation ->
            assertEquals("${expectation.id}.pcap", expectation.captureFile)
            assertTrue(expectation.captureSha256.matches(Regex("[0-9a-f]{64}")))
            assertTrue(expectation.requiredEvidenceFrames.all { it <= expectation.captureFrameCount })
            assertTrue(expectation.maximumToolCalls > 0)
        }
    }

    @Test
    fun `all generated offline transcripts decode`() {
        val files = transcriptFiles()
        // Matches the 16-scenario golden set (OPT-EVAL-01-01/03).
        assertEquals(16, files.size)

        val scripts = files.map { MockModelScriptCodec.decode(it.readText()) }
        assertEquals(16, scripts.map { it.id }.distinct().size)
        assertTrue(scripts.all { it.turnCount == 3 })
    }

    @Test
    fun `a report only passes when evidence came from the cited tool result`() {
        val expectation = GoldenCaptureExpectation(
            schemaVersion = 1,
            id = "fixture",
            captureFile = "fixture.pcap",
            captureSha256 = "a".repeat(64),
            captureFrameCount = 3,
            question = "What happened?",
            scope = "complete_file",
            privacyMode = "redacted_metadata",
            expectedFindings = listOf(
                GoldenExpectedFinding(
                    id = "observed-failure",
                    kind = "ObservedFailure",
                    severity = "Error",
                    minimumConfidence = "Medium",
                    requiredEvidenceFrames = listOf(2L)
                )
            ),
            requiredEvidenceFrames = listOf(2L),
            allowedAlternativeConclusions = listOf("A failure was observed."),
            forbiddenConclusions = listOf("the root cause is known"),
            expectedLimitations = listOf("the capture boundary is visible"),
            maximumToolCalls = 2
        )
        val report = AgentReport(
            summary = "A failure was observed.",
            findings = listOf(
                AgentFinding(
                    id = "observed-failure",
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
            ),
            limitations = listOf("The capture boundary is visible.")
        )

        val result = AgentEvaluationRunner.evaluate(
            expectations = listOf(expectation),
            samples = listOf(
                GoldenRunSample(
                    scenarioId = "fixture",
                    report = report,
                    toolCallCount = 1,
                    durationMillis = 12,
                    toolResultFramesByCall = mapOf("analysis" to setOf(2L))
                )
            ),
            metadata = metadata()
        )

        assertEquals(1, result.summary.passedScenarioCount)
        assertEquals(1.0, result.summary.evidenceFramePrecision, 0.0)
        assertEquals(1.0, result.summary.evidenceFrameRecall, 0.0)
        assertTrue(result.toJson().contains("nativeBuildMarker"))
        assertTrue(result.toMarkdown().contains("Evidence precision"))
    }

    @Test
    fun `an invented frame is not valid evidence`() {
        val expectation = simpleExpectation()
        val report = AgentReport(
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
        val result = AgentEvaluationRunner.evaluate(
            listOf(expectation),
            listOf(
                GoldenRunSample(
                    scenarioId = expectation.id,
                    report = report,
                    toolCallCount = 1,
                    durationMillis = 1,
                    toolResultFramesByCall = mapOf("analysis" to setOf(2L))
                )
            ),
            metadata()
        )

        assertEquals(0.0, result.summary.evidenceFramePrecision, 0.0)
        assertEquals(1, result.summary.unsupportedHighConfidenceFindings)
        assertEquals(0, result.summary.passedScenarioCount)
    }

    @Test
    fun `external evaluation requires both opt in and a credential`() {
        val disabled = runCatching {
            AgentEvaluationRunner.requireExternalEvaluationEnabled(emptyMap())
        }
        assertTrue(disabled.isFailure)

        val enabled = mapOf(
            AgentEvaluationRunner.EXTERNAL_EVALUATION_FLAG to "true",
            AgentEvaluationRunner.EXTERNAL_CREDENTIAL to "test-only"
        )
        assertTrue(runCatching {
            AgentEvaluationRunner.requireExternalEvaluationEnabled(enabled)
        }.isSuccess)
    }

    /**
     * The continuation feature must stay invisible to the evaluation contract:
     * a follow-up run that carried the prior round's transcript scores like any
     * other run, and replays history without shifting validated conclusions.
     */
    @Test
    fun `a follow-up run that replays history stays consistent with its first round`() {
        val expectation = simpleExpectation()
        val failedFinding = { conclusion: String ->
            AgentFinding(
                id = "observed-failure",
                title = "ObservedFailure",
                severity = AgentFindingSeverity.Error,
                confidence = AgentConfidence.Medium,
                conclusion = conclusion,
                evidence = listOf(
                    AgentEvidence(
                        type = AgentEvidenceType.Frame,
                        frameNumber = 2L,
                        observation = "Frame 2 supports the failure.",
                        sourceToolCallId = "analysis"
                    )
                )
            )
        }
        val toolFrames = mapOf("analysis" to setOf(2L))
        val firstRound = AgentReport(
            summary = "A failure was observed.",
            findings = listOf(failedFinding("A failure was observed.")),
            limitations = listOf("The capture boundary is visible.")
        )
        val followUpWithHistory = AgentReport(
            summary = "Following up on the earlier answer: the failure stands.",
            findings = listOf(
                failedFinding("Reconfirmed against this round's own tool call.")
            ),
            limitations = listOf(
                "The capture boundary is visible.",
                "Prior-round facts were reconfirmed before citation."
            )
        )

        val result = AgentEvaluationRunner.evaluate(
            listOf(expectation),
            listOf(
                GoldenRunSample(
                    scenarioId = "fixture",
                    report = firstRound,
                    toolCallCount = 1,
                    durationMillis = 12,
                    toolResultFramesByCall = toolFrames
                ),
                GoldenRunSample(
                    scenarioId = "fixture",
                    report = followUpWithHistory,
                    toolCallCount = 2,
                    durationMillis = 20,
                    toolResultFramesByCall = mapOf(
                        "analysis" to setOf(2L),
                        "recheck" to setOf(2L)
                    )
                )
            ),
            metadata()
        )

        assertEquals(2, result.scenarios.single().runs)
        assertTrue(result.scenarios.single().passed)
        assertEquals(1.0, result.summary.consistencyRate, 0.0)
        assertEquals(1, result.summary.passedScenarioCount)
    }

    private fun simpleExpectation() = GoldenCaptureExpectation(
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
        maximumToolCalls = 2
    )

    private fun metadata() = AgentEvaluationMetadata(
        modelId = "mock:golden",
        appVersion = "1.0",
        nativeBuildMarker = "test-native",
        promptVersion = "phase1-1",
        playbookVersion = "general-capture-health@1"
    )

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

    private fun transcriptFiles(): List<File> {
        val candidates = listOf(
            File("app/src/test/resources/agent/transcripts"),
            File("src/test/resources/agent/transcripts")
        )
        val directory = candidates.firstOrNull(File::isDirectory)
            ?: error("Golden transcript directory is missing.")
        return directory.listFiles { file -> file.extension == "json" }
            ?.sortedBy(File::getName)
            .orEmpty()
    }
}
