package com.example.layanalyzer.data

import com.example.layanalyzer.model.EvidenceExportMode
import com.example.layanalyzer.model.EvidenceExportMode.MetadataOnly
import com.example.layanalyzer.model.EvidenceExportMode.Original
import com.example.layanalyzer.model.EvidenceExportMode.Redacted
import com.example.layanalyzer.model.EvidenceExportScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-logic coverage for the evidence-frame export flow (EVL-EXPORT-02). The
 * ViewModel that consumes these decisions depends on Android, so the branching
 * rules live here instead: the plan matrix, the frame-count guard, and the
 * compile-driven fail-closed combination.
 */
class EvidenceExportPlanTest {

    // --- plan: 3 modes x 2 scopes = 6 combinations ---

    @Test
    fun `Original with CurrentView attaches a pcap built from the current view`() {
        val plan = EvidenceExportPlanner.planFor(Original, EvidenceExportScope.CurrentView)

        assertTrue(plan.attachCapture)
        assertFalse(plan.applyEvidenceTemporaryFilter)
        assertFalse(plan.verifyEvidenceFrameCount)
        assertFalse(plan.pcapIncludesEvidenceFramesOnly)
    }

    @Test
    fun `Original with EvidenceFrames attaches an evidence-only pcap under the lease`() {
        val plan = EvidenceExportPlanner.planFor(Original, EvidenceExportScope.EvidenceFrames)

        assertTrue(plan.attachCapture)
        assertTrue(plan.applyEvidenceTemporaryFilter)
        assertTrue(plan.verifyEvidenceFrameCount)
        assertTrue(plan.pcapIncludesEvidenceFramesOnly)
    }

    @Test
    fun `Redacted with CurrentView keeps today's behaviour exactly`() {
        val plan = EvidenceExportPlanner.planFor(Redacted, EvidenceExportScope.CurrentView)

        assertFalse(plan.attachCapture)
        assertFalse(plan.applyEvidenceTemporaryFilter)
        assertFalse(plan.verifyEvidenceFrameCount)
        assertFalse(plan.pcapIncludesEvidenceFramesOnly)
    }

    @Test
    fun `Redacted with EvidenceFrames verifies the count without attaching a pcap`() {
        val plan = EvidenceExportPlanner.planFor(Redacted, EvidenceExportScope.EvidenceFrames)

        assertFalse(plan.attachCapture)
        assertTrue(plan.applyEvidenceTemporaryFilter)
        assertTrue(plan.verifyEvidenceFrameCount)
        assertFalse(plan.pcapIncludesEvidenceFramesOnly)
    }

    @Test
    fun `MetadataOnly with CurrentView keeps today's behaviour exactly`() {
        val plan = EvidenceExportPlanner.planFor(MetadataOnly, EvidenceExportScope.CurrentView)

        assertFalse(plan.attachCapture)
        assertFalse(plan.applyEvidenceTemporaryFilter)
        assertFalse(plan.verifyEvidenceFrameCount)
        assertFalse(plan.pcapIncludesEvidenceFramesOnly)
    }

    @Test
    fun `MetadataOnly with EvidenceFrames verifies the count without attaching a pcap`() {
        val plan = EvidenceExportPlanner.planFor(MetadataOnly, EvidenceExportScope.EvidenceFrames)

        assertFalse(plan.attachCapture)
        assertTrue(plan.applyEvidenceTemporaryFilter)
        assertTrue(plan.verifyEvidenceFrameCount)
        assertFalse(plan.pcapIncludesEvidenceFramesOnly)
    }

    @Test
    fun `every mode and scope pair is classified by the same rules`() {
        EvidenceExportMode.values().forEach { mode ->
            EvidenceExportScope.values().forEach { scope ->
                val plan = EvidenceExportPlanner.planFor(mode, scope)

                assertEquals(
                    "attachCapture tracks Original for $mode/$scope",
                    mode == Original,
                    plan.attachCapture
                )
                assertEquals(
                    "the temporary filter is applied for EvidenceFrames only",
                    scope == EvidenceExportScope.EvidenceFrames,
                    plan.applyEvidenceTemporaryFilter
                )
                assertEquals(
                    "the count is verified for EvidenceFrames only",
                    scope == EvidenceExportScope.EvidenceFrames,
                    plan.verifyEvidenceFrameCount
                )
                assertEquals(
                    "an evidence-only pcap needs both inputs",
                    mode == Original && scope == EvidenceExportScope.EvidenceFrames,
                    plan.pcapIncludesEvidenceFramesOnly
                )
            }
        }
    }

    // --- frame-count verification ---

    @Test
    fun `equal counts pass`() {
        val verification = EvidenceFrameCountGuard.verify(expected = 12, actual = 12)

        assertEquals(EvidenceFrameCountVerification.Match, verification)
    }

    @Test
    fun `fewer frames than expected fail and carry both counts`() {
        val verification = EvidenceFrameCountGuard.verify(expected = 12, actual = 11) as
            EvidenceFrameCountVerification.Mismatch

        assertEquals(12, verification.expected)
        assertEquals(11, verification.actual)
    }

    @Test
    fun `more frames than expected fail and carry both counts`() {
        val verification = EvidenceFrameCountGuard.verify(expected = 12, actual = 13) as
            EvidenceFrameCountVerification.Mismatch

        assertEquals(12, verification.expected)
        assertEquals(13, verification.actual)
    }

    @Test
    fun `a zero expectation is refused even when the actual is also zero`() {
        // Unreachable in production: an empty evidence set is refused before the
        // lease is entered. The guard still fails closed rather than treating a
        // degenerate "export nothing" request as a pass.
        val verification = EvidenceFrameCountGuard.verify(expected = 0, actual = 0) as
            EvidenceFrameCountVerification.Mismatch

        assertEquals(0, verification.expected)
        assertEquals(0, verification.actual)
    }

    // --- compile-driven fail-closed ---

    @Test
    fun `an empty evidence set never yields an exportable scope`() {
        assertScopeRefused(EvidenceFrameFilter.compileOrNull(emptyList()))
    }

    @Test
    fun `a TooManyFrames rejection never yields an exportable scope`() {
        val frames = (1..EvidenceFrameFilter.MAX_FRAMES + 1).map { it.toLong() }

        assertScopeRefused(EvidenceFrameFilter.compileOrNull(frames))
    }

    @Test
    fun `a TooManyRanges rejection never yields an exportable scope`() {
        val frames = (1..EvidenceFrameFilter.MAX_RANGES + 1).map { it * 2L }

        assertScopeRefused(EvidenceFrameFilter.compileOrNull(frames))
    }

    @Test
    fun `an invalid filter rejection never yields an exportable scope`() {
        assertScopeRefused(EvidenceFrameFilter.compileOrNull(listOf(0L, 12L)))
    }

    @Test
    fun `only a compiled evidence set yields an exportable scope`() {
        val compiled = EvidenceFrameFilter.compileOrNull(listOf(3L, 7L, 8L))
        assertTrue(compiled is EvidenceFrameFilter.CompileResult.Compiled)

        val availability = EvidenceExportScopePolicy.evaluate(
            EvidenceExportScope.EvidenceFrames,
            compiled
        )

        assertTrue(availability.available)
    }

    private fun assertScopeRefused(result: EvidenceFrameFilter.CompileResult) {
        val availability = EvidenceExportScopePolicy.evaluate(
            EvidenceExportScope.EvidenceFrames,
            result
        )

        assertFalse(
            "the execution side must refuse an evidence set that is not Compiled: $result",
            availability.available
        )
        assertNotNull(
            "a refused evidence scope must explain itself: $result",
            availability.reasonCode
        )
    }
}
