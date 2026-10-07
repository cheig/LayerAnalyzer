package com.example.layanalyzer.ui.components

import com.example.layanalyzer.ai.agent.EvidenceCoverage
import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportProvenance
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * EVL-UI-07: the report evidence-coverage badge.
 *
 * The badge pairs a run record's coverage counters (EVL-COVERAGE-03) with the
 * host-authored uncited-frame limitation (EVL-COVERAGE-02). It is fail-closed:
 * when the two cannot be reconciled it returns null and the UI renders nothing,
 * so it can never print a number that contradicts the limitation below it.
 *
 * The round-trip cases build the limitation with the real producer
 * ([EvidenceCoverage.uncitedFramesLimitation]) so the parser is pinned against
 * the exact bytes the host writes, not a hand-copied sample.
 */
class ReportCoverageBadgeTest {

    private fun run(
        flagged: Int,
        cited: Int,
        fingerprint: String = ""
    ) = AgentRunRecord(
        sessionId = "session-1",
        captureFingerprint = fingerprint,
        modelId = "model-x",
        promptVersion = "prompt-1",
        analysisScope = "CurrentFilter",
        displayFilterApplied = false,
        startedAtMillis = 0L,
        completedAtMillis = 0L,
        evidenceFlaggedCount = flagged,
        evidenceCitedCount = cited
    )

    private fun report(
        limitations: List<String> = emptyList(),
        fingerprint: String = ""
    ) = AgentReport(
        limitations = limitations,
        provenance = AgentReportProvenance(captureFingerprint = fingerprint)
    )

    /** The host limitation exactly as the loop mints it, or null for a clean run. */
    private fun hostLine(cited: Set<Long>, uncited: Set<Long>): String? =
        EvidenceCoverage(
            citedFrames = cited,
            uncitedFrames = uncited,
            citationOutsideFlagged = emptySet()
        ).uncitedFramesLimitation()

    // ------------------------------------------------------------- round-trip

    @Test
    fun `a clean run with no uncited frames reads back as complete`() {
        // A full-hit run appends no host line: the badge must still show N / N.
        assertNull(hostLine(cited = setOf(1L, 2L), uncited = emptySet()))

        val model = ReportCoverageBadge.from(
            run = run(flagged = 2, cited = 2),
            report = report()
        )!!

        assertEquals(2, model.citedCount)
        assertEquals(2, model.flaggedCount)
        assertTrue(model.uncitedFrames.isEmpty())
        assertEquals(0, model.uncitedOverflow)
        assertTrue(model.complete)
    }

    @Test
    fun `one uncited frame round-trips from the real host limitation`() {
        val line = hostLine(cited = setOf(3L), uncited = setOf(5L))!!

        val model = ReportCoverageBadge.from(
            run = run(flagged = 2, cited = 1),
            report = report(limitations = listOf(line))
        )!!

        assertEquals(listOf(5L), model.uncitedFrames)
        assertEquals(0, model.uncitedOverflow)
        assertEquals(1, model.totalUncited)
        assertFalse(model.complete)
    }

    @Test
    fun `five uncited frames round-trip in sorted order`() {
        val uncited = setOf(12L, 3L, 7L, 20L, 5L)
        val line = hostLine(cited = setOf(1L), uncited = uncited)!!

        val model = ReportCoverageBadge.from(
            run = run(flagged = 6, cited = 1),
            report = report(limitations = listOf(line))
        )!!

        assertEquals(listOf(3L, 5L, 7L, 12L, 20L), model.uncitedFrames)
        assertEquals(5, model.totalUncited)
    }

    @Test
    fun `exactly ten uncited frames are all listed with no overflow`() {
        val line = hostLine(cited = emptySet(), uncited = (1L..10L).toSet())!!

        val model = ReportCoverageBadge.from(
            run = run(flagged = 10, cited = 0),
            report = report(limitations = listOf(line))
        )!!

        assertEquals((1L..10L).toList(), model.uncitedFrames)
        assertEquals(10, model.uncitedFrames.size)
        assertEquals(0, model.uncitedOverflow)
        assertEquals(10, model.totalUncited)
    }

    @Test
    fun `eleven uncited frames list ten and declare the overflow`() {
        val line = hostLine(cited = emptySet(), uncited = (1L..11L).toSet())!!

        val model = ReportCoverageBadge.from(
            run = run(flagged = 11, cited = 0),
            report = report(limitations = listOf(line))
        )!!

        assertEquals(11, model.flaggedCount)
        assertEquals(10, model.uncitedFrames.size)
        assertEquals(1, model.uncitedOverflow)
        assertEquals(11, model.totalUncited)
    }

    // ------------------------------------------------------------- fail-closed

    @Test
    fun `no run record yields no badge`() {
        assertNull(ReportCoverageBadge.from(run = null, report = report()))
    }

    @Test
    fun `a zero flagged set yields no badge`() {
        assertNull(ReportCoverageBadge.from(run = run(flagged = 0, cited = 0), report = report()))
    }

    @Test
    fun `a cited count above the flagged set yields no badge`() {
        assertNull(ReportCoverageBadge.from(run = run(flagged = 3, cited = 4), report = report()))
    }

    @Test
    fun `a negative cited count yields no badge`() {
        assertNull(ReportCoverageBadge.from(run = run(flagged = 3, cited = -1), report = report()))
    }

    @Test
    fun `a fingerprint mismatch between run and report yields no badge`() {
        val line = hostLine(cited = setOf(1L), uncited = setOf(2L))!!

        assertNull(
            ReportCoverageBadge.from(
                run = run(flagged = 2, cited = 1, fingerprint = "capture-a"),
                report = report(limitations = listOf(line), fingerprint = "capture-b")
            )
        )
    }

    @Test
    fun `a blank report fingerprint does not by itself suppress the badge`() {
        val line = hostLine(cited = setOf(1L), uncited = setOf(2L))!!

        assertNotNull(
            ReportCoverageBadge.from(
                run = run(flagged = 2, cited = 1, fingerprint = "capture-a"),
                report = report(limitations = listOf(line), fingerprint = "")
            )
        )
    }

    @Test
    fun `a blank run fingerprint does not by itself suppress the badge`() {
        val line = hostLine(cited = setOf(1L), uncited = setOf(2L))!!

        assertNotNull(
            ReportCoverageBadge.from(
                run = run(flagged = 2, cited = 1, fingerprint = ""),
                report = report(limitations = listOf(line), fingerprint = "capture-b")
            )
        )
    }

    @Test
    fun `a host line that undercounts the run's uncited frames yields no badge`() {
        // The run says 5 flagged / 3 cited: two uncited frames are unaccounted
        // for, but the host line names only one and declares no remainder. The
        // numbers disagree, so nothing is shown.
        val line = hostLine(cited = setOf(1L, 2L, 3L, 4L), uncited = setOf(7L))!!

        assertNull(
            ReportCoverageBadge.from(
                run = run(flagged = 5, cited = 3),
                report = report(limitations = listOf(line))
            )
        )
    }

    @Test
    fun `a host line that overcounts the run's uncited frames yields no badge`() {
        val line = hostLine(cited = setOf(1L), uncited = setOf(7L, 8L, 9L))!!

        assertNull(
            ReportCoverageBadge.from(
                run = run(flagged = 2, cited = 1),
                report = report(limitations = listOf(line))
            )
        )
    }

    @Test
    fun `a host line present when the run reports no uncited frames yields no badge`() {
        val line = hostLine(cited = setOf(1L), uncited = setOf(9L))!!

        assertNull(
            ReportCoverageBadge.from(
                run = run(flagged = 2, cited = 2),
                report = report(limitations = listOf(line))
            )
        )
    }

    @Test
    fun `a host line whose listed frames and remainder match the run shows the badge`() {
        // Listed one frame plus a declared remainder of one matches the run's
        // flagged(5) - cited(3) = 2 uncited frames.
        val line = EvidenceCoverage.UNCITED_FRAMES_LIMITATION_MARKER +
            "7, ... were returned by this run's tools but cited by no finding; " +
            "1 more uncited frame not listed."

        val model = ReportCoverageBadge.from(
            run = run(flagged = 5, cited = 3),
            report = report(limitations = listOf(line))
        )!!

        assertEquals(listOf(7L), model.uncitedFrames)
        assertEquals(1, model.uncitedOverflow)
        assertEquals(2, model.totalUncited)
    }

    // --------------------------------------------------------- parse robustness

    @Test
    fun `unrelated limitations are ignored and the host line is found anywhere in the list`() {
        val line = hostLine(cited = setOf(1L), uncited = setOf(4L, 6L))!!

        val model = ReportCoverageBadge.from(
            run = run(flagged = 3, cited = 1),
            report = report(
                limitations = listOf(
                    "The model could not confirm the capture start time.",
                    "A second model-authored limitation.",
                    line
                )
            )
        )!!

        assertEquals(listOf(4L, 6L), model.uncitedFrames)
    }

    @Test
    fun `a malformed host line is skipped rather than guessed`() {
        val malformed = EvidenceCoverage.UNCITED_FRAMES_LIMITATION_MARKER +
            "not frames were returned by this run's tools but cited by no finding."

        assertNull(
            ReportCoverageBadge.from(
                run = run(flagged = 1, cited = 0),
                report = report(limitations = listOf(malformed))
            )
        )
    }

    @Test
    fun `a host line without its terminating period is skipped`() {
        val noPeriod = hostLine(cited = emptySet(), uncited = setOf(2L))!!.removeSuffix(".")

        assertNull(
            ReportCoverageBadge.from(
                run = run(flagged = 1, cited = 0),
                report = report(limitations = listOf(noPeriod))
            )
        )
    }

    // ------------------------------------------------------------ derived state

    @Test
    fun `total uncited and complete derive from the listed frames and the overflow`() {
        val line = hostLine(cited = setOf(1L), uncited = setOf(2L, 3L))!!
        val partial = ReportCoverageBadge.from(
            run = run(flagged = 3, cited = 1),
            report = report(limitations = listOf(line))
        )!!
        assertEquals(2, partial.totalUncited)
        assertFalse(partial.complete)

        val clean = ReportCoverageBadge.from(
            run = run(flagged = 2, cited = 2),
            report = report()
        )!!
        assertEquals(0, clean.totalUncited)
        assertTrue(clean.complete)
    }
}
