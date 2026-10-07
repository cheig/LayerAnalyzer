// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.data.EvidenceExportScopePolicy.ReasonCode
import com.example.layanalyzer.data.EvidenceExportScopePolicy.ScopeAvailability
import com.example.layanalyzer.model.EvidenceExportScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceExportScopePolicyTest {
    private fun evaluate(
        scope: EvidenceExportScope,
        result: EvidenceFrameFilter.CompileResult
    ): ScopeAvailability = EvidenceExportScopePolicy.evaluate(scope, result)

    // --- CurrentView is unconditional ---

    @Test
    fun `CurrentView is available for an empty evidence set`() {
        val availability = evaluate(
            EvidenceExportScope.CurrentView,
            EvidenceFrameFilter.CompileResult.Empty
        )

        assertTrue(availability.available)
        assertNull(availability.reasonCode)
    }

    @Test
    fun `CurrentView is available even when the evidence filter was rejected`() {
        val availability = evaluate(
            EvidenceExportScope.CurrentView,
            EvidenceFrameFilter.CompileResult.Rejected(
                reason = EvidenceFrameFilter.RejectReason.TooManyFrames,
                message = "too many",
                actual = EvidenceFrameFilter.MAX_FRAMES + 1,
                limit = EvidenceFrameFilter.MAX_FRAMES
            )
        )

        assertTrue(availability.available)
        assertNull(availability.reasonCode)
    }

    @Test
    fun `CurrentView is available when the evidence filter compiled`() {
        val availability = evaluate(
            EvidenceExportScope.CurrentView,
            EvidenceFrameFilter.CompileResult.Compiled(
                filter = "frame.number==1",
                rangeCount = 1,
                frameCount = 1
            )
        )

        assertTrue(availability.available)
        assertNull(availability.reasonCode)
    }

    // --- EvidenceFrames + Empty ---

    @Test
    fun `EvidenceFrames is unavailable for an empty evidence set`() {
        val availability = evaluate(
            EvidenceExportScope.EvidenceFrames,
            EvidenceFrameFilter.CompileResult.Empty
        )

        assertFalse(availability.available)
        assertEquals(ReasonCode.NoEvidenceFrames, availability.reasonCode)
        assertNull(availability.actual)
        assertNull(availability.limit)
        assertNull(availability.rejectReason)
    }

    @Test
    fun `EvidenceFrames does not fall back to CurrentView when empty`() {
        // Fail-closed: an empty set must never become available.
        val availability = evaluate(
            EvidenceExportScope.EvidenceFrames,
            EvidenceFrameFilter.compileOrNull(emptyList())
        )

        assertFalse("an empty evidence set must not be exported", availability.available)
        assertEquals(ReasonCode.NoEvidenceFrames, availability.reasonCode)
    }

    // --- EvidenceFrames + Rejected ---

    @Test
    fun `EvidenceFrames rejects TooManyFrames and passes actual and limit through`() {
        val frames = (1..EvidenceFrameFilter.MAX_FRAMES + 1).map { it.toLong() }
        val rejected = EvidenceFrameFilter.compileOrNull(frames) as
            EvidenceFrameFilter.CompileResult.Rejected

        val availability = evaluate(EvidenceExportScope.EvidenceFrames, rejected)

        assertFalse(availability.available)
        assertEquals(ReasonCode.FilterRejected, availability.reasonCode)
        assertEquals(EvidenceFrameFilter.RejectReason.TooManyFrames, availability.rejectReason)
        assertEquals(EvidenceFrameFilter.MAX_FRAMES + 1, availability.actual)
        assertEquals(EvidenceFrameFilter.MAX_FRAMES, availability.limit)
        assertNotNull(availability.detail)
    }

    @Test
    fun `EvidenceFrames rejects TooManyRanges and passes actual and limit through`() {
        val frames = (1..EvidenceFrameFilter.MAX_RANGES + 1).map { it * 2L }
        val rejected = EvidenceFrameFilter.compileOrNull(frames) as
            EvidenceFrameFilter.CompileResult.Rejected

        val availability = evaluate(EvidenceExportScope.EvidenceFrames, rejected)

        assertFalse(availability.available)
        assertEquals(ReasonCode.FilterRejected, availability.reasonCode)
        assertEquals(EvidenceFrameFilter.RejectReason.TooManyRanges, availability.rejectReason)
        assertEquals(EvidenceFrameFilter.MAX_RANGES + 1, availability.actual)
        assertEquals(EvidenceFrameFilter.MAX_RANGES, availability.limit)
    }

    @Test
    fun `EvidenceFrames rejects InvalidFilter with null counts`() {
        val rejected = EvidenceFrameFilter.compileOrNull(listOf(0L, 12L)) as
            EvidenceFrameFilter.CompileResult.Rejected

        val availability = evaluate(EvidenceExportScope.EvidenceFrames, rejected)

        assertFalse(availability.available)
        assertEquals(ReasonCode.FilterRejected, availability.reasonCode)
        assertEquals(EvidenceFrameFilter.RejectReason.InvalidFilter, availability.rejectReason)
        assertNull(availability.actual)
        assertNull(availability.limit)
    }

    // --- EvidenceFrames + Compiled ---

    @Test
    fun `EvidenceFrames is available when the evidence filter compiled`() {
        val compiled = EvidenceFrameFilter.compileOrNull(listOf(3L, 7L, 10L, 11L, 12L)) as
            EvidenceFrameFilter.CompileResult.Compiled

        val availability = evaluate(EvidenceExportScope.EvidenceFrames, compiled)

        assertTrue(availability.available)
        assertNull(availability.reasonCode)
        assertNull(availability.actual)
        assertNull(availability.limit)
    }

    // --- No silent fallback: the verdict is exhaustive and mutually exclusive ---

    @Test
    fun `availability is true exactly for Compiled and false otherwise`() {
        val corpus = listOf(
            EvidenceFrameFilter.CompileResult.Empty,
            EvidenceFrameFilter.CompileResult.Compiled("frame.number==1", rangeCount = 1, frameCount = 1),
            EvidenceFrameFilter.CompileResult.Rejected(
                EvidenceFrameFilter.RejectReason.TooManyFrames,
                "too many frames",
                actual = 2,
                limit = 1
            ),
            EvidenceFrameFilter.CompileResult.Rejected(
                EvidenceFrameFilter.RejectReason.InvalidFilter,
                "invalid"
            )
        )

        corpus.forEach { result ->
            val availability = evaluate(EvidenceExportScope.EvidenceFrames, result)

            assertEquals(
                "availability must mirror the Compiled state for $result",
                result is EvidenceFrameFilter.CompileResult.Compiled,
                availability.available
            )
            if (availability.available) {
                assertNull(
                    "an available scope must not carry a reason code",
                    availability.reasonCode
                )
            } else {
                assertNotNull(
                    "an unavailable scope must explain itself",
                    availability.reasonCode
                )
            }
        }
    }
}
