package com.example.layanalyzer.ai.evaluation

import com.example.layanalyzer.ai.playbook.ScenarioPackageManifest
import com.example.layanalyzer.ai.playbook.ScenarioPackageSource
import com.example.layanalyzer.ai.playbook.ScenarioReleaseIssue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentReleaseGateTest {

    @Test
    fun aCleanEvaluationPassesEveryGate() {
        val report = AgentReleaseGate.evaluate(
            matrix = matrix(),
            evaluation = evaluation(metadata = metadata()),
            packageReleaseIssues = emptyList()
        )

        assertTrue(report.passed)
        assertTrue(report.toJson().contains("playbookPackageId"))
        assertTrue(report.toMarkdown().contains("Release Matrix"))
    }

    @Test
    fun aSingleInvalidCitationBlocksTheRelease() {
        val report = AgentReleaseGate.evaluate(
            matrix = matrix(),
            evaluation = evaluation(metadata = metadata(), evidencePrecision = 0.9),
            packageReleaseIssues = emptyList()
        )

        assertFalse(report.passed)
        assertFalse(report.checks.first { it.id == "evidence-citation-validity" }.passed)
    }

    @Test
    fun anUnsupportedHighConfidenceFindingBlocksTheRelease() {
        val report = AgentReleaseGate.evaluate(
            matrix = matrix(),
            evaluation = evaluation(metadata = metadata(), unsupportedHighConfidence = 1),
            packageReleaseIssues = emptyList()
        )

        assertFalse(report.passed)
        assertFalse(report.checks.first { it.id == "no-unsupported-high-confidence" }.passed)
    }

    @Test
    fun aForbiddenConclusionBlocksTheRelease() {
        val report = AgentReleaseGate.evaluate(
            matrix = matrix(),
            evaluation = evaluation(metadata = metadata(), forbiddenHits = 1),
            packageReleaseIssues = emptyList()
        )

        assertFalse(report.passed)
        assertFalse(report.checks.first { it.id == "no-forbidden-conclusions" }.passed)
    }

    @Test
    fun aScenarioWithoutAGoldenExpectationBlocksTheRelease() {
        val report = AgentReleaseGate.evaluate(
            matrix = matrix(),
            evaluation = evaluation(metadata = metadata()),
            packageReleaseIssues = listOf(
                ScenarioReleaseIssue(
                    "eps-fallback",
                    "No Golden capture is pinned and the scenario is not marked synthetic-only."
                )
            )
        )

        assertFalse(report.passed)
        val gate = report.checks.first { it.id == "scenario-golden-coverage" }
        assertFalse(gate.passed)
        assertTrue(gate.detail.contains("eps-fallback"))
    }

    @Test
    fun aMatrixThatDoesNotMatchTheEvaluatedRunBlocksTheRelease() {
        val report = AgentReleaseGate.evaluate(
            matrix = matrix(),
            evaluation = evaluation(metadata = metadata().copy(nativeBuildMarker = "wireshark-9.9.9")),
            packageReleaseIssues = emptyList()
        )

        assertFalse(report.passed)
        assertFalse(report.checks.first { it.id == "matrix-reproducible" }.passed)
    }

    @Test
    fun budgetsAreEnforcedAsGates() {
        val report = AgentReleaseGate.evaluate(
            matrix = matrix(),
            evaluation = evaluation(metadata = metadata(), averageToolCalls = 40.0),
            packageReleaseIssues = emptyList()
        )

        assertFalse(report.passed)
        assertFalse(report.checks.first { it.id == "budgets" }.passed)
    }

    @Test
    fun theReleaseMatrixPinsEveryDimension() {
        val matrix = matrix()

        assertEquals("1.0", matrix.appVersion)
        assertEquals("wireshark-4.0.10", matrix.nativeBuildMarker)
        assertEquals("arm64-v8a", matrix.abi)
        assertEquals("mock:agent-golden", matrix.modelId)
        assertEquals("phase1-1", matrix.promptVersion)
        assertEquals("com.layanalyzer.scenarios.core", matrix.playbookPackageId)
        assertEquals(1, matrix.playbookPackageVersion)
        assertEquals(ScenarioPackageSource.BuiltIn, matrix.playbookPackageSource)
        assertEquals("general-capture-health@1", matrix.playbookVersion)
    }

    private fun metadata() = AgentEvaluationMetadata(
        modelId = "mock:agent-golden",
        appVersion = "1.0",
        nativeBuildMarker = "wireshark-4.0.10",
        promptVersion = "phase1-1",
        playbookVersion = "general-capture-health@1"
    )

    private fun matrix() = AgentReleaseMatrix.from(
        metadata = metadata(),
        manifest = manifest(),
        source = ScenarioPackageSource.BuiltIn,
        abi = "arm64-v8a"
    )

    private fun manifest(): ScenarioPackageManifest = ScenarioPackageManifest.decode(
        com.example.layanalyzer.ai.playbook.TestScenarioPackages.builtInAsset(
            com.example.layanalyzer.ai.playbook.VersionedScenarioPackageStore.MANIFEST_FILE
        )
    )

    private fun evaluation(
        metadata: AgentEvaluationMetadata,
        evidencePrecision: Double = 1.0,
        unsupportedHighConfidence: Int = 0,
        forbiddenHits: Int = 0,
        averageToolCalls: Double = 3.0
    ): AgentEvaluationReport {
        val scenarioMetrics = GoldenScenarioMetrics(
            scenarioId = "ims_call_success",
            runs = 2,
            expectedFindingCount = 2,
            findingHits = 4,
            evidenceFrameCitations = 10,
            validEvidenceFrameCitations = (10 * evidencePrecision).toInt(),
            requiredEvidenceFrames = 4,
            citedRequiredEvidenceFrames = 4,
            unsupportedHighConfidenceFindings = unsupportedHighConfidence,
            forbiddenConclusionHits = forbiddenHits,
            boundaryDeclarations = 2,
            invalidFilterCalls = 0,
            filterLeaseRestoreFailures = 0,
            averageToolCalls = averageToolCalls,
            averageDurationMillis = 5_000.0,
            averageInputTokens = 1_000.0,
            averageOutputTokens = 300.0,
            averageCost = 0.01,
            consistencyRate = 1.0,
            passed = unsupportedHighConfidence == 0 && forbiddenHits == 0
        )
        return AgentEvaluationReport(
            schemaVersion = AgentEvaluationRunner.SCHEMA_VERSION,
            metadata = metadata,
            scenarios = listOf(scenarioMetrics),
            summary = GoldenEvaluationSummary(
                scenarioCount = 1,
                passedScenarioCount = if (scenarioMetrics.passed) 1 else 0,
                findingHitRate = 1.0,
                evidenceFramePrecision = evidencePrecision,
                evidenceFrameRecall = 1.0,
                unsupportedHighConfidenceFindings = unsupportedHighConfidence,
                forbiddenConclusionHits = forbiddenHits,
                boundaryDeclarationRate = 1.0,
                invalidFilterRate = 0.0,
                filterLeaseRestoreFailures = 0,
                averageToolCalls = averageToolCalls,
                averageDurationMillis = 5_000.0,
                averageInputTokens = 1_000.0,
                averageOutputTokens = 300.0,
                averageCost = 0.01,
                consistencyRate = 1.0
            )
        )
    }
}
