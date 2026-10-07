// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.evaluation

import com.example.layanalyzer.ai.client.MockModelScriptCodec
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentReport
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * OPT-EVAL-02-02: pins the LLM-as-judge pass of [AgentEvaluationRunner].
 *
 * The center of gravity is the §9.3 gate "the judge only scores and never
 * re-judges": for every attached verdict the deterministic scenarios,
 * summary, `passed`, and both serializations must stay exactly as they were,
 * judge numbers may only appear on live rubric-bearing samples, malformed
 * verdict data (hallucinated labels, blank judge ids) must fail closed, and
 * a judge that throws or abstains must be skipped without blocking the
 * evaluation.  A companion red line — enforced structurally, asserted where
 * observable here: the runner has no API that writes expectations, so the
 * annotation set stays human-owned.
 */
class AgentJudgePassTest {

    // ------------------------------------------------------------- fixtures

    private val rubric = GoldenAttributionRubric(
        requiredRootCause = "the observed failure sat in the application layer",
        disallowedRootCauses = listOf(
            "a network path failure caused it",
            "requests were never delivered",
            "the client aborted the connection"
        )
    )

    private fun fixtureExpectation(
        id: String = "fixture",
        withRubric: GoldenAttributionRubric? = rubric
    ) = GoldenCaptureExpectation(
        schemaVersion = 1,
        id = id,
        captureFile = "$id.pcap",
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
        attributionRubric = withRubric
    )

    private fun passingReport() = AgentReport(
        summary = "A failure was observed.",
        findings = listOf(
            AgentFinding(
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
        ),
        limitations = listOf("The capture boundary is visible.")
    )

    private fun sample(
        scenarioId: String,
        isLive: Boolean,
        verdict: GoldenJudgeVerdict? = null
    ) = GoldenRunSample(
        scenarioId = scenarioId,
        report = passingReport(),
        toolCallCount = 1,
        durationMillis = 12,
        toolResultFramesByCall = mapOf("analysis" to setOf(2L)),
        isLive = isLive,
        judgeVerdict = verdict
    )

    /**
     * Pinned clock so byte-for-byte JSON/Markdown comparisons are stable.
     * The modelId deliberately avoids the substring "judge" so the
     * "no judge keys in a judge-free artifact" scans stay meaningful.
     */
    private fun metadata() = AgentEvaluationMetadata(
        modelId = "mock:fixture",
        appVersion = "1.0",
        nativeBuildMarker = "test-native",
        promptVersion = "phase1-1",
        playbookVersion = "general-capture-health@1",
        generatedAtMillis = 1_757_000_000_000L
    )

    /** The hostile verdict for pins (a)/(c): every disallowed label plus a missed required attribution. */
    private fun hostileVerdict() = GoldenJudgeVerdict(
        requiredRootCauseAttributed = false,
        disallowedRootCausesAttributed = rubric.disallowedRootCauses,
        judgeId = "attribution-judge-v1"
    )

    private fun evaluate(
        expectation: GoldenCaptureExpectation,
        verdict: GoldenJudgeVerdict?,
        live: Boolean
    ): AgentEvaluationReport {
        val sharedMetadata = metadata()
        return AgentEvaluationRunner.evaluate(
            expectations = listOf(expectation),
            samples = listOf(sample(expectation.id, isLive = live, verdict = verdict)),
            metadata = sharedMetadata
        )
    }

    /**
     * Compares two reports that may only differ in the additive judge
     * counters: the deterministic metrics, `passed`, the group aggregates and
     * the full serializations must be identical after stripping judge fields.
     */
    private fun assertJudgeIsPureReporting(
        baseline: AgentEvaluationReport,
        judged: AgentEvaluationReport
    ) {
        assertEquals(
            "Deterministic scenario metrics must not move when a judge verdict is attached.",
            baseline.scenarios.map { it.stripJudge() },
            judged.scenarios.map { it.stripJudge() }
        )
        assertEquals(
            "The summary's deterministic half must not move when a judge verdict is attached.",
            baseline.summary.stripJudge(),
            judged.summary.stripJudge()
        )
        assertEquals(
            "The §9.2 gate 8 group aggregates must never grow a judge dimension.",
            baseline.summary.scenarioGroups,
            judged.summary.scenarioGroups
        )
        assertEquals(
            "Per-scenario pass verdicts must be identical.",
            baseline.scenarios.map { it.passed },
            judged.scenarios.map { it.passed }
        )
        assertEquals(
            "The forbidden-conclusion counter is deterministic and judge-independent.",
            baseline.summary.forbiddenConclusionHits,
            judged.summary.forbiddenConclusionHits
        )
    }

    private fun GoldenScenarioMetrics.stripJudge() = copy(
        judgeRuns = 0,
        judgeDisallowedRootCauseHits = 0,
        judgeRequiredAttributionMisses = 0,
        judgeApplicable = false
    )

    private fun GoldenEvaluationSummary.stripJudge() = copy(
        judgeRuns = 0,
        judgeDisallowedRootCauseHits = 0,
        judgeRequiredAttributionMisses = 0,
        judgeApplicable = false
    )

    // (a) judge on a non-live sample is ignored end to end

    @Test
    fun `a verdict attached to an offline mock sample is ignored end to end`() {
        val expectation = fixtureExpectation()
        val baseline = evaluate(expectation, verdict = null, live = false)
        val judged = evaluate(expectation, verdict = hostileVerdict(), live = false)

        assertJudgeIsPureReporting(baseline, judged)
        assertEquals(baseline.summary, judged.summary)
        assertEquals(
            "A judge verdict on a non-live sample must leave the scenario metrics byte-equal.",
            baseline.scenarios,
            judged.scenarios
        )
        assertEquals(baseline.toJson(), judged.toJson())
        assertEquals(baseline.toMarkdown(), judged.toMarkdown())
        assertFalse(
            "Mock artifacts must serialize no judge keys at all.",
            judged.toJson().contains("judge")
        )
        assertFalse(judged.toMarkdown().contains("## Judge pass"))
    }

    // (b) live + rubric + clean verdict scores without touching anything else

    @Test
    fun `a clean live verdict adds judge metrics without touching deterministic numbers`() {
        val expectation = fixtureExpectation()
        val baseline = evaluate(expectation, verdict = null, live = true)
        val judged = evaluate(
            expectation,
            verdict = GoldenJudgeVerdict(
                requiredRootCauseAttributed = true,
                disallowedRootCausesAttributed = emptyList(),
                judgeId = "attribution-judge-v1"
            ),
            live = true
        )

        assertJudgeIsPureReporting(baseline, judged)
        val scenario = judged.scenarios.single()
        assertTrue("The deterministic verdict of a passing live run stays passing.", scenario.passed)
        assertTrue(scenario.judgeApplicable)
        assertEquals(1, scenario.judgeRuns)
        assertEquals(0, scenario.judgeDisallowedRootCauseHits)
        assertEquals(0, scenario.judgeRequiredAttributionMisses)

        assertEquals(1, judged.summary.judgeRuns)
        assertEquals(0, judged.summary.judgeDisallowedRootCauseHits)
        assertEquals(0, judged.summary.judgeRequiredAttributionMisses)
        assertTrue(judged.summary.judgeApplicable)

        val json = judged.toJson()
        assertTrue(json.contains("\"judgeRuns\": 1"))
        assertTrue(json.contains("\"judgeApplicable\": true"))
        val markdown = judged.toMarkdown()
        assertTrue(markdown.contains("## Judge pass"))
        assertTrue(markdown.contains("| fixture | 1 | 0 | 0 |"))
    }

    // (c) hostile verdict scores hard, changes nothing deterministic

    @Test
    fun `a hostile live verdict scores without changing the pass verdict or the forbidden counter`() {
        val expectation = fixtureExpectation()
        val baseline = evaluate(expectation, verdict = null, live = true)
        val judged = evaluate(expectation, verdict = hostileVerdict(), live = true)

        assertJudgeIsPureReporting(baseline, judged)
        assertEquals(
            "A worst-case judge verdict must not flip the delivery verdict.",
            baseline.scenarios.single().passed,
            judged.scenarios.single().passed
        )
        val scenario = judged.scenarios.single()
        assertEquals(1, scenario.judgeRuns)
        assertEquals(
            "Every rubric label may be matched at most once per run, judge-side duplicates included.",
            rubric.disallowedRootCauses.size,
            scenario.judgeDisallowedRootCauseHits
        )
        assertEquals(1, scenario.judgeRequiredAttributionMisses)
        assertEquals(0, scenario.forbiddenConclusionHits)
        assertEquals(0, judged.summary.forbiddenConclusionHits)
        assertEquals(3, judged.summary.judgeDisallowedRootCauseHits)
        assertEquals(1, judged.summary.judgeRequiredAttributionMisses)
    }

    @Test
    fun `disallowed labels match the rubric under normalizeForMatch equivalence`() {
        val expectation = fixtureExpectation()
        val judged = evaluate(
            expectation,
            verdict = GoldenJudgeVerdict(
                requiredRootCauseAttributed = true,
                // Same string under normalizeForMatch: case and spacing differ only.
                disallowedRootCausesAttributed = listOf("A  Network  Path  FAILURE  caused  IT"),
                judgeId = "attribution-judge-v1"
            ),
            live = true
        )
        assertEquals(1, judged.scenarios.single().judgeDisallowedRootCauseHits)
    }

    // (e) hallucinated labels are dropped

    @Test
    fun `a hallucinated label outside the rubric is dropped and never widens the metric`() {
        val expectation = fixtureExpectation()
        val judged = evaluate(
            expectation,
            verdict = GoldenJudgeVerdict(
                requiredRootCauseAttributed = true,
                disallowedRootCausesAttributed = listOf("requests were never delivered", "the moon caused it"),
                judgeId = "attribution-judge-v1"
            ),
            live = true
        )
        val scenario = judged.scenarios.single()
        assertEquals(1, scenario.judgeRuns)
        assertEquals(
            "Only the one rubric-grounded label counts; the hallucinated label contributes nothing.",
            1,
            scenario.judgeDisallowedRootCauseHits
        )
    }

    // fail-closed provenance: a verdict without a stable judge id is dropped

    @Test
    fun `a verdict with a blank judge id is dropped rather than counted`() {
        val expectation = fixtureExpectation()
        val judged = evaluate(
            expectation,
            verdict = GoldenJudgeVerdict(
                requiredRootCauseAttributed = false,
                disallowedRootCausesAttributed = rubric.disallowedRootCauses,
                judgeId = "   "
            ),
            live = true
        )
        val scenario = judged.scenarios.single()
        assertTrue(scenario.judgeApplicable)
        assertEquals(0, scenario.judgeRuns)
        assertEquals(0, scenario.judgeDisallowedRootCauseHits)
        assertEquals(0, scenario.judgeRequiredAttributionMisses)
    }

    // coverage gap stays visible: live + rubric but no verdict yet

    @Test
    fun `a live run without a verdict reports applicability with an empty score`() {
        val expectation = fixtureExpectation()
        val judged = evaluate(expectation, verdict = null, live = true)
        val scenario = judged.scenarios.single()

        assertTrue(scenario.judgeApplicable)
        assertEquals(0, scenario.judgeRuns)
        // The applicability keys are serialized so the gap is report-visible...
        assertTrue(judged.toJson().contains("\"judgeApplicable\": true"))
        assertTrue(judged.toJson().contains("\"judgeRuns\": 0"))
        // ...while the Markdown section gate is judgeRuns > 0.
        assertFalse(judged.toMarkdown().contains("## Judge pass"))
    }

    // (f) no rubric means not applicable, even live with a verdict

    @Test
    fun `a live verdict on a rubric-free scenario is never scored`() {
        val expectation = fixtureExpectation(withRubric = null)
        val baseline = evaluate(expectation, verdict = null, live = true)
        val judged = evaluate(expectation, verdict = hostileVerdict(), live = true)

        assertJudgeIsPureReporting(baseline, judged)
        assertFalse(judged.scenarios.single().judgeApplicable)
        assertEquals(0, judged.scenarios.single().judgeRuns)
        assertFalse(judged.summary.judgeApplicable)
        assertFalse(judged.toJson().contains("judge"))
        assertFalse(judged.toMarkdown().contains("## Judge pass"))
        assertEquals(baseline.toJson(), judged.toJson())
        assertEquals(baseline.toMarkdown(), judged.toMarkdown())
    }

    // (g) judgeRequests selection and red lines

    @Test
    fun `judgeRequests are generated only for live samples of rubric-bearing expectations`() {
        val withRubric = fixtureExpectation(id = "rubric_family")
        val withoutRubric = fixtureExpectation(id = "plain_family", withRubric = null)
        val samples = listOf(
            sample("rubric_family", isLive = true),
            sample("rubric_family", isLive = false, verdict = hostileVerdict()),
            sample("plain_family", isLive = true),
            sample("plain_family", isLive = false)
        )

        val requests = AgentEvaluationRunner.judgeRequests(listOf(withRubric, withoutRubric), samples)

        val request = requests.single()
        assertEquals("rubric_family", request.scenarioId)
        assertEquals("rubric_family", request.expectationId)
        assertEquals("What happened?", request.question)
        assertEquals(rubric.requiredRootCause, request.requiredRootCause)
        assertEquals(rubric.disallowedRootCauses, request.disallowedRootCauses)
        // The request carries only the report's conclusion-text domain:
        // normalized summary/limitation prose is present, capture-file
        // identity (raw capture data surface) is not.
        assertTrue(request.reportText.contains("a failure was observed"))
        assertTrue(request.reportText.contains("the capture boundary is visible"))
        assertFalse(request.reportText.contains("rubric_family.pcap"))
        assertFalse(request.reportText.contains("captureSha256"))
    }

    @Test
    fun `withJudgeVerdicts calls the judge only for applicable samples and leaves the rest untouched`() {
        val withRubric = fixtureExpectation(id = "rubric_family")
        val withoutRubric = fixtureExpectation(id = "plain_family", withRubric = null)
        val samples = listOf(
            sample("rubric_family", isLive = true),
            sample("rubric_family", isLive = false),
            sample("plain_family", isLive = true),
            sample("plain_family", isLive = false)
        )
        val seen = mutableListOf<String>()

        val scored = AgentEvaluationRunner.withJudgeVerdicts(
            expectations = listOf(withRubric, withoutRubric),
            samples = samples
        ) { request ->
            seen += request.scenarioId
            GoldenJudgeVerdict(true, emptyList(), "attribution-judge-v1")
        }

        assertEquals(listOf("rubric_family"), seen)
        assertNotNull(scored[0].judgeVerdict)
        assertTrue(scored[0].isLive)
        // Non-applicable samples come back as the identical untouched instances.
        assertSame(samples[1], scored[1])
        assertSame(samples[2], scored[2])
        assertSame(samples[3], scored[3])
        assertNull(scored[1].judgeVerdict)
    }

    // (d) judge failures never block the evaluation

    @Test
    fun `a throwing or abstaining judge is skipped without blocking the evaluation`() {
        val ok = fixtureExpectation(id = "judge_ok")
        val thrower = fixtureExpectation(id = "judge_throw")
        val abstainer = fixtureExpectation(id = "judge_null")
        val samples = listOf(
            sample("judge_ok", isLive = true),
            sample("judge_throw", isLive = true),
            sample("judge_null", isLive = true)
        )

        val scored = AgentEvaluationRunner.withJudgeVerdicts(
            expectations = listOf(ok, thrower, abstainer),
            samples = samples
        ) { request ->
            when (request.scenarioId) {
                "judge_throw" -> error("judge client exploded")
                "judge_null" -> null
                else -> GoldenJudgeVerdict(false, request.disallowedRootCauses.take(1), "attribution-judge-v1")
            }
        }

        assertNotNull(scored[0].judgeVerdict)
        assertNull("A throwing judge must leave the sample unjudged.", scored[1].judgeVerdict)
        assertNull("An abstaining judge must leave the sample unjudged.", scored[2].judgeVerdict)

        val expectations = listOf(ok, thrower, abstainer)
        val judged = AgentEvaluationRunner.evaluate(expectations, scored, metadata())
        val byId = judged.scenarios.associateBy { it.scenarioId }
        assertEquals(1, byId.getValue("judge_ok").judgeRuns)
        assertEquals(0, byId.getValue("judge_throw").judgeRuns)
        assertEquals(0, byId.getValue("judge_null").judgeRuns)
        assertTrue("Skipped runs keep the scenario applicable so the gap is visible.",
            byId.getValue("judge_throw").judgeApplicable)
        // All three live runs are still evaluated and still pass exactly as
        // without any judge pass: three successes, three passes.
        val baseline = AgentEvaluationRunner.evaluate(
            expectations,
            listOf(
                sample("judge_ok", isLive = true),
                sample("judge_throw", isLive = true),
                sample("judge_null", isLive = true)
            ),
            metadata()
        )
        assertJudgeIsPureReporting(baseline, judged)
        assertEquals(3, judged.summary.passedScenarioCount)
    }

    // (h) offline artifacts keep the exact pre-judge serialization shape

    @Test
    fun `the sixteen family offline replay stays free of judge data and keeps its pre-judge key sets`() {
        val expectations = GoldenExpectationCodec.decodeAll(expectationFiles().map(File::readText))
        assertEquals(16, expectations.size)
        val report = AgentEvaluationRunner.evaluate(
            expectations = expectations,
            samples = expectations.map { offlineSample(it) },
            metadata = AgentEvaluationMetadata(
                modelId = "mock:offline-golden",
                appVersion = "1.0",
                nativeBuildMarker = "test-native",
                promptVersion = "phase1-1",
                playbookVersion = "general-capture-health@1"
            )
        )

        // No scenario has a live sample, so nothing may be judge-applicable.
        assertTrue(report.scenarios.none { it.judgeApplicable })
        assertEquals(0, report.summary.judgeRuns)
        val json = report.toJson()
        assertFalse("The offline golden JSON must not gain any judge key.", json.contains("judge"))
        val markdown = report.toMarkdown()
        assertFalse(markdown.contains("## Judge pass"))

        // The serialized object shapes are exactly the HEAD field sets.
        assertEquals(
            HEAD_REPORT_KEYS,
            JSONObject(json).keys().asSequence().toSet()
        )
        assertEquals(
            HEAD_SUMMARY_KEYS,
            JSONObject(json).getJSONObject("summary").keys().asSequence().toSet()
        )
        val scenarioKeys = JSONObject(json).getJSONArray("scenarios")
        for (index in 0 until scenarioKeys.length()) {
            assertEquals(
                "scenarios[$index] must keep the pre-judge key set.",
                HEAD_SCENARIO_KEYS,
                scenarioKeys.getJSONObject(index).keys().asSequence().toSet()
            )
        }
    }

    // -------------------------------------------------- offline replay copy

    /** Mirrors [AgentGoldenOfflineMockTest]'s crediting: the last tool call returned the pinned frames. */
    private fun offlineSample(expectation: GoldenCaptureExpectation): GoldenRunSample {
        val script = MockModelScriptCodec.decode(transcriptText(expectation.id))
        val toolCallIds = script.responses.flatMap { response ->
            (response.response as? AgentModelResponse.ToolCalls)?.calls.orEmpty().map { it.toolCallId }
        }
        val report = (script.responses.last().response as? AgentModelResponse.Final)?.report
            ?: error("${expectation.id} has no decoded final report.")
        val creditedFrames = (
            expectation.requiredEvidenceFrames +
                expectation.expectedFindings.flatMap { it.requiredEvidenceFrames }
            ).toSet()
        val framesByCall = toolCallIds.mapIndexed { index, id ->
            id to if (index == toolCallIds.lastIndex) creditedFrames else emptySet()
        }.toMap()
        return GoldenRunSample(
            scenarioId = expectation.id,
            report = report,
            toolCallCount = toolCallIds.size,
            durationMillis = 13L,
            toolResultFramesByCall = framesByCall
        )
    }

    private fun transcriptText(id: String): String {
        val candidates = listOf(
            File("app/src/test/resources/agent/transcripts/$id.json"),
            File("src/test/resources/agent/transcripts/$id.json")
        )
        return candidates.firstOrNull(File::isFile)
            ?.readText()
            ?: error("Golden transcript $id is missing from the test resources.")
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

    private companion object {
        // Exact HEAD (pre-judge, post-OPT-EVAL-02-01) serialization field
        // sets; a judge key leaking into a judge-free artifact, or any other
        // new key appearing there, fails these pins.
        val HEAD_REPORT_KEYS = setOf(
            "schema",
            "schemaVersion",
            "modelId",
            "appVersion",
            "nativeBuildMarker",
            "promptVersion",
            "playbookVersion",
            "generatedAtMillis",
            "summary",
            "scenarios"
        )

        val HEAD_SUMMARY_KEYS = setOf(
            "scenarioCount",
            "passedScenarioCount",
            "findingHitRate",
            "evidenceFramePrecision",
            "evidenceFrameRecall",
            "unsupportedHighConfidenceFindings",
            "forbiddenConclusionHits",
            "boundaryDeclarationRate",
            "invalidFilterRate",
            "filterLeaseRestoreFailures",
            "averageToolCalls",
            "averageDurationMillis",
            "averageInputTokens",
            "averageOutputTokens",
            "averageCost",
            "consistencyRate",
            "scenarioGroups"
        )

        val HEAD_SCENARIO_KEYS = setOf(
            "scenarioId",
            "groupId",
            "runs",
            "expectedFindingCount",
            "findingHits",
            "evidenceFrameCitations",
            "validEvidenceFrameCitations",
            "requiredEvidenceFrames",
            "citedRequiredEvidenceFrames",
            "unsupportedHighConfidenceFindings",
            "forbiddenConclusionHits",
            "boundaryDeclarations",
            "invalidFilterCalls",
            "filterLeaseRestoreFailures",
            "averageToolCalls",
            "averageDurationMillis",
            "averageInputTokens",
            "averageOutputTokens",
            "averageCost",
            "consistencyRate",
            "passed"
        )
    }
}
