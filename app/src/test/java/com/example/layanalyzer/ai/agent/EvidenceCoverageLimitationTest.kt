// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentReport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * EVL-COVERAGE-02: the host-authored uncited-frame limitation appended to a
 * report after it was accepted, and the `AgentRunTrace.evidenceCoverage`
 * receipt that carries the accounting. Pure-function tests only — the loop
 * appends the line after validation on the same host-bookkeeping channel as
 * the ledger reconciliation note, never through a model-writable field.
 */
class EvidenceCoverageLimitationTest {

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
    fun `uncited frames produce a host limitation naming the frame numbers`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = listOf(3L, 7L, 12L),
            report = reportWithFindings(findingWithFrames(3L))
        )

        val limitation = coverage.uncitedFramesLimitation()

        assertTrue(limitation != null)
        limitation!!
        assertTrue(
            limitation.startsWith(EvidenceCoverage.UNCITED_FRAMES_LIMITATION_MARKER)
        )
        // The uncited frames are named as stable ids; the cited one is not.
        assertTrue(limitation.contains("7"))
        assertTrue(limitation.contains("12"))
        assertTrue(limitation.contains("were returned by this run's tools but cited by no finding"))
    }

    @Test
    fun `uncited frames beyond the cap are truncated with a declared remainder`() {
        val flagged = (1L..15L).toList()
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = flagged,
            report = reportWithFindings(findingWithFrames())
        )

        val limitation = coverage.uncitedFramesLimitation()

        assertTrue(limitation != null)
        limitation!!
        // Exactly the first ten sorted frames are listed, then the truncation
        // marker, and the remainder is declared as a count — never listed.
        assertEquals(
            "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, ...",
            limitation.removePrefix(EvidenceCoverage.UNCITED_FRAMES_LIMITATION_MARKER)
                .substringBefore(" were returned")
        )
        assertTrue(limitation.contains("5 more uncited frames not listed"))
        // The overflow frames stay out of the listed part entirely.
        assertTrue(!limitation.substringBefore(" were returned").contains("11"))
    }

    @Test
    fun `a full hit appends nothing so the report bytes stay unchanged`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = listOf(3L, 7L),
            report = reportWithFindings(findingWithFrames(3L, 7L))
        )

        assertTrue(coverage.clean)
        assertNull(coverage.uncitedFramesLimitation())
    }

    @Test
    fun `an empty evidence set appends nothing`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = emptyList(),
            report = reportWithFindings(findingWithFrames(1L, 2L))
        )

        assertEquals(emptySet<Long>(), coverage.uncitedFrames)
        assertNull(coverage.uncitedFramesLimitation())
    }

    @Test
    fun `a single overflow frame is declared with singular wording`() {
        val coverage = EvidenceCoverageEvaluator.evaluate(
            flagged = (1L..11L).toList(),
            report = reportWithFindings(findingWithFrames())
        )

        val limitation = coverage.uncitedFramesLimitation()

        assertTrue(limitation != null)
        limitation!!
        assertTrue(limitation.contains("1 more uncited frame not listed"))
    }

    @Test
    fun `trace evidenceCoverage defaults to null for existing constructions`() {
        val trace = AgentRunTrace(
            snapshot = AgentCaptureSnapshot(),
            ledger = EvidenceLedger()
        )

        assertNull(trace.evidenceCoverage)
    }
}
