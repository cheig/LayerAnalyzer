// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentReport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * EVL-COVERAGE-01: set bookkeeping between the flagged evidence frames and
 * the frame numbers the report's citations carry. Pure-function tests only —
 * the fact verification behind citations stays with [EvidenceValidator] and
 * is deliberately not exercised here.
 */
class EvidenceCoverageEvaluatorTest {

    private fun reportWithFindings(vararg findings: AgentFinding): AgentReport =
        AgentReport(findings = findings.toList())

    private fun findingWithFrames(vararg frames: Long?): AgentFinding = AgentFinding(
        id = "f-${frames.contentToString()}",
        evidence = frames.map { frame ->
            AgentEvidence(
                type = AgentEvidenceType.Frame,
                frameNumber = frame,
                sourceToolCallId = "call-1"
            )
        }
    )

    @Test
    fun `every flagged frame cited by the report is a full hit`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = listOf(1L, 2L, 3L),
            report = reportWithFindings(findingWithFrames(1L, 2L), findingWithFrames(3L))
        )

        assertEquals(setOf(1L, 2L, 3L), coverage.citedFrames)
        assertEquals(emptySet<Long>(), coverage.uncitedFrames)
        assertEquals(emptySet<Long>(), coverage.citationOutsideFlagged)
        assertTrue(coverage.clean)
    }

    @Test
    fun `no citation touching the evidence set leaves every frame uncited`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = listOf(1L, 2L),
            report = reportWithFindings(findingWithFrames(9L, 10L))
        )

        assertEquals(emptySet<Long>(), coverage.citedFrames)
        assertEquals(setOf(1L, 2L), coverage.uncitedFrames)
        assertEquals(setOf(9L, 10L), coverage.citationOutsideFlagged)
        assertFalse(coverage.clean)
    }

    @Test
    fun `partial hit splits flagged frames and outside citations`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = listOf(1L, 2L, 3L),
            report = reportWithFindings(findingWithFrames(2L, 7L))
        )

        assertEquals(setOf(2L), coverage.citedFrames)
        assertEquals(setOf(1L, 3L), coverage.uncitedFrames)
        assertEquals(setOf(7L), coverage.citationOutsideFlagged)
        assertFalse(coverage.clean)
    }

    @Test
    fun `a report without findings cites nothing`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = listOf(1L, 2L),
            report = AgentReport()
        )

        assertEquals(emptySet<Long>(), coverage.citedFrames)
        assertEquals(setOf(1L, 2L), coverage.uncitedFrames)
        assertEquals(emptySet<Long>(), coverage.citationOutsideFlagged)
        assertFalse(coverage.clean)
    }

    @Test
    fun `an empty flagged evidence set makes everything a citation outside`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = emptyList(),
            report = reportWithFindings(findingWithFrames(1L, 2L))
        )

        assertEquals(emptySet<Long>(), coverage.citedFrames)
        assertEquals(emptySet<Long>(), coverage.uncitedFrames)
        assertEquals(setOf(1L, 2L), coverage.citationOutsideFlagged)
        assertFalse(coverage.clean)
    }

    @Test
    fun `duplicate flagged frames collapse into one frame`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = listOf(5L, 5L, 5L, 6L),
            report = reportWithFindings(findingWithFrames(5L, 6L))
        )

        assertEquals(setOf(5L, 6L), coverage.citedFrames)
        assertEquals(emptySet<Long>(), coverage.uncitedFrames)
        assertEquals(emptySet<Long>(), coverage.citationOutsideFlagged)
        assertTrue(coverage.clean)
    }

    @Test
    fun `citations without a frame number never enter the accounting`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = listOf(1L),
            report = reportWithFindings(findingWithFrames(null), findingWithFrames(1L))
        )

        assertEquals(setOf(1L), coverage.citedFrames)
        assertEquals(emptySet<Long>(), coverage.uncitedFrames)
        assertEquals(emptySet<Long>(), coverage.citationOutsideFlagged)
        assertTrue(coverage.clean)
    }
}
