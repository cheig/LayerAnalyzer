// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.data.EvidenceFrameViewDecision.Apply
import com.example.layanalyzer.data.EvidenceFrameViewDecision.Reject
import com.example.layanalyzer.data.EvidenceFrameViewRejection.EmptySet
import com.example.layanalyzer.data.EvidenceFrameViewRejection.InvalidFilter
import com.example.layanalyzer.data.EvidenceFrameViewRejection.TooManyFrames
import com.example.layanalyzer.data.EvidenceFrameViewRejection.TooManyRanges
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceFrameViewPolicyTest {
    // --- Direct CompileResult mapping (no compiler involved) ---

    @Test
    fun `Empty becomes Reject EmptySet`() {
        val decision = EvidenceFrameViewPolicy.decide(EvidenceFrameFilter.CompileResult.Empty)

        assertTrue(decision is Reject)
        assertEquals(EmptySet, (decision as Reject).reason)
        assertNull(decision.actual)
        assertNull(decision.limit)
    }

    @Test
    fun `Compiled single frame is applied verbatim`() {
        val decision = EvidenceFrameViewPolicy.decide(
            EvidenceFrameFilter.CompileResult.Compiled("frame.number==5", rangeCount = 1, frameCount = 1)
        )

        assertTrue(decision is Apply)
        assertEquals("frame.number==5", (decision as Apply).filter)
        assertEquals(1, decision.frameCount)
    }

    @Test
    fun `Compiled multi-segment filter passes through unchanged`() {
        val filter = "frame.number==5 || (frame.number>=10 && frame.number<=14)"
        val decision = EvidenceFrameViewPolicy.decide(
            EvidenceFrameFilter.CompileResult.Compiled(filter, rangeCount = 2, frameCount = 6)
        )

        assertTrue(decision is Apply)
        // Fail-closed: the policy must never rewrite or re-join the expression.
        assertEquals(filter, (decision as Apply).filter)
        assertEquals(6, decision.frameCount)
    }

    @Test
    fun `Rejected TooManyFrames carries actual and limit through`() {
        val decision = EvidenceFrameViewPolicy.decide(
            EvidenceFrameFilter.CompileResult.Rejected(
                reason = EvidenceFrameFilter.RejectReason.TooManyFrames,
                message = "too many frames",
                actual = EvidenceFrameFilter.MAX_FRAMES + 1,
                limit = EvidenceFrameFilter.MAX_FRAMES
            )
        )

        assertTrue(decision is Reject)
        assertEquals(TooManyFrames, (decision as Reject).reason)
        assertEquals(EvidenceFrameFilter.MAX_FRAMES + 1, decision.actual)
        assertEquals(EvidenceFrameFilter.MAX_FRAMES, decision.limit)
    }

    @Test
    fun `Rejected TooManyRanges carries actual and limit through`() {
        val decision = EvidenceFrameViewPolicy.decide(
            EvidenceFrameFilter.CompileResult.Rejected(
                reason = EvidenceFrameFilter.RejectReason.TooManyRanges,
                message = "too many ranges",
                actual = EvidenceFrameFilter.MAX_RANGES + 1,
                limit = EvidenceFrameFilter.MAX_RANGES
            )
        )

        assertTrue(decision is Reject)
        assertEquals(TooManyRanges, (decision as Reject).reason)
        assertEquals(EvidenceFrameFilter.MAX_RANGES + 1, decision.actual)
        assertEquals(EvidenceFrameFilter.MAX_RANGES, decision.limit)
    }

    @Test
    fun `Rejected InvalidFilter keeps null counts`() {
        val decision = EvidenceFrameViewPolicy.decide(
            EvidenceFrameFilter.CompileResult.Rejected(
                reason = EvidenceFrameFilter.RejectReason.InvalidFilter,
                message = "invalid"
            )
        )

        assertTrue(decision is Reject)
        assertEquals(InvalidFilter, (decision as Reject).reason)
        assertNull(decision.actual)
        assertNull(decision.limit)
    }

    // --- End-to-end invariants driven by the real compiler ---

    @Test
    fun `empty evidence set is rejected, never applied`() {
        val decision = EvidenceFrameViewPolicy.decide(EvidenceFrameFilter.compileOrNull(emptyList()))

        assertTrue("an empty evidence set must not become an Apply", decision is Reject)
        assertEquals(EmptySet, (decision as Reject).reason)
    }

    @Test
    fun `non-positive frame number is rejected as invalid, never applied`() {
        listOf(listOf(0L), listOf(-3L), listOf(0L, 12L)).forEach { frames ->
            val decision = EvidenceFrameViewPolicy.decide(EvidenceFrameFilter.compileOrNull(frames))

            assertFalse(
                "a non-positive frame must not become an Apply: $frames",
                decision is Apply
            )
            assertEquals(InvalidFilter, (decision as Reject).reason)
        }
    }

    @Test
    fun `over MAX_FRAMES is rejected and never silently truncated into an Apply`() {
        val frames = (1..EvidenceFrameFilter.MAX_FRAMES + 1).map { it.toLong() }
        val decision = EvidenceFrameViewPolicy.decide(EvidenceFrameFilter.compileOrNull(frames))

        assertFalse(
            "an over-limit evidence set must not be silently truncated into an Apply",
            decision is Apply
        )
        assertEquals(TooManyFrames, (decision as Reject).reason)
        assertEquals(EvidenceFrameFilter.MAX_FRAMES + 1, decision.actual)
        assertEquals(EvidenceFrameFilter.MAX_FRAMES, decision.limit)
    }

    @Test
    fun `over MAX_RANGES is rejected and never silently truncated into an Apply`() {
        // MAX_RANGES + 1 mutually disjoint frames -> MAX_RANGES + 1 merged ranges.
        val frames = (1..EvidenceFrameFilter.MAX_RANGES + 1).map { it * 2L }
        val decision = EvidenceFrameViewPolicy.decide(EvidenceFrameFilter.compileOrNull(frames))

        assertFalse(
            "an over-range evidence set must not be silently truncated into an Apply",
            decision is Apply
        )
        assertEquals(TooManyRanges, (decision as Reject).reason)
        assertEquals(EvidenceFrameFilter.MAX_RANGES + 1, decision.actual)
        assertEquals(EvidenceFrameFilter.MAX_RANGES, decision.limit)
    }

    @Test
    fun `normal evidence set is applied with the compiler's exact filter`() {
        val frames = listOf(1L, 2L, 3L, 4L, 5L)
        val compiled = EvidenceFrameFilter.compileOrNull(frames) as EvidenceFrameFilter.CompileResult.Compiled
        val decision = EvidenceFrameViewPolicy.decide(compiled)

        assertTrue(decision is Apply)
        assertEquals(compiled.filter, (decision as Apply).filter)
        assertEquals(5, decision.frameCount)
    }
}
