// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import kotlinx.coroutines.runBlocking

class EvidenceFrameFilterTest {
    @Test
    fun `empty collection compiles to null`() {
        assertNull(EvidenceFrameFilter.compile(emptyList()))
    }

    @Test
    fun `single frame uses an equality expression`() {
        assertEquals("frame.number==12", EvidenceFrameFilter.compile(listOf(12L)))
    }

    @Test
    fun `single minimum frame uses an equality expression`() {
        assertEquals("frame.number==1", EvidenceFrameFilter.compile(listOf(1L)))
    }

    @Test
    fun `two non-consecutive frames are joined with or`() {
        assertEquals("frame.number==3 || frame.number==7", EvidenceFrameFilter.compile(listOf(3L, 7L)))
    }

    @Test
    fun `two consecutive frames collapse into a range`() {
        assertEquals(
            "(frame.number>=10 && frame.number<=11)",
            EvidenceFrameFilter.compile(listOf(10L, 11L))
        )
    }

    @Test
    fun `longer consecutive runs collapse into one range`() {
        assertEquals(
            "(frame.number>=10 && frame.number<=14)",
            EvidenceFrameFilter.compile(listOf(10L, 11L, 12L, 13L, 14L))
        )
    }

    @Test
    fun `mixed singles and ranges are joined with or`() {
        val compiled = EvidenceFrameFilter.compile(listOf(5L, 10L, 11L, 12L, 13L, 14L, 20L))

        assertEquals(
            "frame.number==5 || (frame.number>=10 && frame.number<=14) || frame.number==20",
            compiled
        )
    }

    @Test
    fun `unsorted input is compiled in ascending order`() {
        assertEquals(
            "frame.number==5 || (frame.number>=10 && frame.number<=14) || frame.number==20",
            EvidenceFrameFilter.compile(listOf(20L, 11L, 5L, 14L, 10L, 13L, 12L))
        )
    }

    @Test
    fun `duplicate frames are de-duplicated`() {
        assertEquals(
            "(frame.number>=10 && frame.number<=12)",
            EvidenceFrameFilter.compile(listOf(10L, 10L, 11L, 12L, 12L, 11L))
        )
    }

    @Test
    fun `duplicates alone do not invent a range`() {
        assertEquals("frame.number==4", EvidenceFrameFilter.compile(listOf(4L, 4L, 4L)))
    }

    @Test
    fun `consecutive frames at the long boundary collapse`() {
        val frames = listOf(Long.MAX_VALUE - 1L, Long.MAX_VALUE)

        assertEquals(
            "(frame.number>=9223372036854775806 && frame.number<=9223372036854775807)",
            EvidenceFrameFilter.compile(frames)
        )
    }

    @Test
    fun `large non-consecutive frames stay single expressions`() {
        val frames = listOf(1_000_000_000_000L, Long.MAX_VALUE)

        assertEquals(
            "frame.number==1000000000000 || frame.number==9223372036854775807",
            EvidenceFrameFilter.compile(frames)
        )
    }

    @Test
    fun `a zero frame number is rejected rather than dropped`() {
        assertThrows(IllegalArgumentException::class.java) {
            EvidenceFrameFilter.compile(listOf(0L, 12L))
        }
    }

    @Test
    fun `a negative frame number is rejected rather than dropped`() {
        assertThrows(IllegalArgumentException::class.java) {
            EvidenceFrameFilter.compile(listOf(-3L))
        }
    }

    // --- EVL-FILTER-02: bounds and reject-not-truncate semantics ---

    /** [count] frames each two apart: every frame becomes its own range. */
    private fun isolatedFrames(count: Int): List<Long> = (1..count).map { it * 2L }

    @Test
    fun `compileOrNull returns Empty for an empty collection`() {
        assertEquals(
            EvidenceFrameFilter.CompileResult.Empty,
            EvidenceFrameFilter.compileOrNull(emptyList())
        )
    }

    @Test
    fun `compileOrNull reports the filter and both counts`() {
        val result = EvidenceFrameFilter.compileOrNull(listOf(3L, 7L, 10L, 11L, 12L))

        val compiled = result as EvidenceFrameFilter.CompileResult.Compiled
        assertEquals(
            "frame.number==3 || frame.number==7 || (frame.number>=10 && frame.number<=12)",
            compiled.filter
        )
        assertEquals(3, compiled.rangeCount)
        assertEquals(5, compiled.frameCount)
    }

    @Test
    fun `compileOrNull accepts exactly MAX_FRAMES`() {
        val frames = (1..EvidenceFrameFilter.MAX_FRAMES).map { it.toLong() }

        val compiled = EvidenceFrameFilter.compileOrNull(frames) as
            EvidenceFrameFilter.CompileResult.Compiled
        assertEquals(EvidenceFrameFilter.MAX_FRAMES, compiled.frameCount)
        assertEquals(1, compiled.rangeCount)
    }

    @Test
    fun `compileOrNull rejects MAX_FRAMES plus one`() {
        val frames = (1..EvidenceFrameFilter.MAX_FRAMES + 1).map { it.toLong() }

        val rejected = EvidenceFrameFilter.compileOrNull(frames) as
            EvidenceFrameFilter.CompileResult.Rejected
        assertEquals(EvidenceFrameFilter.RejectReason.TooManyFrames, rejected.reason)
        assertEquals(EvidenceFrameFilter.MAX_FRAMES + 1, rejected.actual)
        assertEquals(EvidenceFrameFilter.MAX_FRAMES, rejected.limit)
        assertTrue(rejected.message.contains("${EvidenceFrameFilter.MAX_FRAMES + 1}"))
        assertTrue(rejected.message.contains("${EvidenceFrameFilter.MAX_FRAMES}"))
    }

    @Test
    fun `compileOrNull accepts exactly MAX_RANGES`() {
        val frames = isolatedFrames(EvidenceFrameFilter.MAX_RANGES)

        val compiled = EvidenceFrameFilter.compileOrNull(frames) as
            EvidenceFrameFilter.CompileResult.Compiled
        assertEquals(EvidenceFrameFilter.MAX_RANGES, compiled.rangeCount)
        assertEquals(EvidenceFrameFilter.MAX_RANGES, compiled.frameCount)
    }

    @Test
    fun `compileOrNull rejects MAX_RANGES plus one`() {
        val frames = isolatedFrames(EvidenceFrameFilter.MAX_RANGES + 1)

        val rejected = EvidenceFrameFilter.compileOrNull(frames) as
            EvidenceFrameFilter.CompileResult.Rejected
        assertEquals(EvidenceFrameFilter.RejectReason.TooManyRanges, rejected.reason)
        assertEquals(EvidenceFrameFilter.MAX_RANGES + 1, rejected.actual)
        assertEquals(EvidenceFrameFilter.MAX_RANGES, rejected.limit)
        assertTrue(rejected.message.contains("${EvidenceFrameFilter.MAX_RANGES + 1}"))
        assertTrue(rejected.message.contains("${EvidenceFrameFilter.MAX_RANGES}"))
    }

    @Test
    fun `a rejection never exposes a truncated compiled result`() {
        val tooManyFrames = (1..EvidenceFrameFilter.MAX_FRAMES + 1).map { it.toLong() }
        val tooManyRanges = isolatedFrames(EvidenceFrameFilter.MAX_RANGES + 1)

        for (result in listOf(
            EvidenceFrameFilter.compileOrNull(tooManyFrames),
            EvidenceFrameFilter.compileOrNull(tooManyRanges)
        )) {
            // Exhaustive: a truncated Compiled could not be silently consumed.
            when (result) {
                is EvidenceFrameFilter.CompileResult.Compiled ->
                    fail("a rejected compilation produced a truncated filter: ${result.filter}")
                is EvidenceFrameFilter.CompileResult.Rejected -> {
                    assertTrue("actual must be populated", result.actual != null)
                    assertTrue("limit must be populated", result.limit != null)
                    assertTrue(
                        "message must name both the actual and the limit",
                        result.message.contains("${result.actual}") &&
                            result.message.contains("${result.limit}")
                    )
                }
                EvidenceFrameFilter.CompileResult.Empty ->
                    fail("a rejected compilation must not look empty")
            }
        }
    }

    @Test
    fun `compileOrNull checks MAX_FRAMES before MAX_RANGES`() {
        // Exceeds both limits: the documented order reports the frame limit.
        val frames = isolatedFrames(EvidenceFrameFilter.MAX_FRAMES + 1)

        val rejected = EvidenceFrameFilter.compileOrNull(frames) as
            EvidenceFrameFilter.CompileResult.Rejected
        assertEquals(EvidenceFrameFilter.RejectReason.TooManyFrames, rejected.reason)
    }

    @Test
    fun `compileOrNull turns a non-positive frame into a rejection instead of throwing`() {
        val zero = EvidenceFrameFilter.compileOrNull(listOf(0L, 12L))
        val negative = EvidenceFrameFilter.compileOrNull(listOf(-3L))

        assertEquals(
            EvidenceFrameFilter.RejectReason.InvalidFilter,
            (zero as EvidenceFrameFilter.CompileResult.Rejected).reason
        )
        assertEquals(
            EvidenceFrameFilter.RejectReason.InvalidFilter,
            (negative as EvidenceFrameFilter.CompileResult.Rejected).reason
        )
    }

    @Test
    fun `compileValidated returns the compiled filter when validation succeeds`() = runBlocking {
        var calls = 0
        val result = EvidenceFrameFilter.compileValidated(listOf(10L, 11L)) {
            calls += 1
            Result.success(Unit)
        }

        assertEquals(1, calls)
        assertEquals(
            "(frame.number>=10 && frame.number<=11)",
            (result as EvidenceFrameFilter.CompileResult.Compiled).filter
        )
    }

    @Test
    fun `compileValidated rejects when validation fails`() = runBlocking {
        val result = EvidenceFrameFilter.compileValidated(listOf(10L, 11L)) {
            Result.failure(IllegalArgumentException("bad filter"))
        }

        val rejected = result as EvidenceFrameFilter.CompileResult.Rejected
        assertEquals(EvidenceFrameFilter.RejectReason.InvalidFilter, rejected.reason)
    }

    @Test
    fun `compileValidated rejects when the validator throws`() = runBlocking {
        val result = EvidenceFrameFilter.compileValidated(listOf(10L, 11L)) {
            error("validator exploded")
        }

        val rejected = result as EvidenceFrameFilter.CompileResult.Rejected
        assertEquals(EvidenceFrameFilter.RejectReason.InvalidFilter, rejected.reason)
        assertTrue(rejected.message.isNotEmpty())
    }

    @Test
    fun `compileValidated does not call the validator for an empty set`() = runBlocking {
        var calls = 0
        val result = EvidenceFrameFilter.compileValidated(emptyList()) {
            calls += 1
            Result.success(Unit)
        }

        assertEquals(EvidenceFrameFilter.CompileResult.Empty, result)
        assertEquals(0, calls)
    }

    @Test
    fun `compileValidated does not call the validator for a rejected set`() = runBlocking {
        var calls = 0
        val result = EvidenceFrameFilter.compileValidated(
            isolatedFrames(EvidenceFrameFilter.MAX_RANGES + 1)
        ) {
            calls += 1
            Result.success(Unit)
        }

        assertEquals(
            EvidenceFrameFilter.RejectReason.TooManyRanges,
            (result as EvidenceFrameFilter.CompileResult.Rejected).reason
        )
        assertEquals(0, calls)
    }

    @Test
    fun `a long consecutive run collapses to a single range`() {
        val frames = (1L..2000L).toList()

        val compiled = EvidenceFrameFilter.compileOrNull(frames) as
            EvidenceFrameFilter.CompileResult.Compiled
        assertEquals(1, compiled.rangeCount)
        assertEquals(2000, compiled.frameCount)
        assertEquals("(frame.number>=1 && frame.number<=2000)", compiled.filter)

        val perFrame = frames.sumOf { "frame.number==$it".length } + (frames.size - 1) * " || ".length
        assertTrue(
            "merged expression (${compiled.filter.length}) must be far shorter than $perFrame",
            compiled.filter.length * 10 < perFrame
        )
    }
}
