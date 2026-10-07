// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentTruncationTest {
    @Test
    fun byteTrimContinuationStartsAfterTheActuallyRetainedPage() {
        val original = mapOf(
            "packets" to (1..500).map { mapOf("frameNumber" to it, "info" to "x".repeat(100)) },
            "offset" to 40,
            "limit" to 100,
            "returned" to 500,
            "total" to 1_000
        )
        val outcome = AgentResultTruncator.truncate(original, 2_048)
        val returned = (outcome.data["returned"] as Number).toLong()
        val info = AgentTruncation.fromData(
            data = outcome.data,
            returned = returned,
            total = 1_000,
            fallbackTruncated = outcome.truncated
        )

        assertTrue(info.payloadTruncated)
        assertEquals(40L + returned, (info.continuation?.get("offset") as Number).toLong())
        assertTrue(info.omittedPaths.isNotEmpty())
    }

    @Test
    fun omittedDetailFramesProduceAnExplicitTargetedRead() {
        val info = AgentTruncation.fromData(
            data = mapOf(
                "fields" to listOf("sip.Call-ID"),
                "includeDisplayValue" to false,
                "omittedFrames" to listOf(17L, 18L),
                "omittedByBudget" to true
            ),
            returned = 1,
            total = 3,
            fallbackTruncated = true
        )

        assertTrue(info.quotaTruncated)
        assertNotNull(info.continuation)
        assertEquals("get_packet_fields", info.continuation?.get("tool"))
        assertEquals(listOf(17L, 18L), info.continuation?.get("frames"))
    }

    @Test
    fun payloadTrimWithoutSafePagingHasExplicitUnavailableContinuation() {
        val info = AgentTruncation.fromData(
            data = mapOf(
                "payloadTruncated" to true,
                "omittedPaths" to listOf("summary")
            ),
            returned = 1,
            total = 1,
            fallbackTruncated = true
        )

        assertEquals(false, info.continuation?.get("available"))
        assertEquals("no_safe_continuation", info.continuation?.get("reason"))
    }

    /**
     * The device-observed communication-analysis shape: 4 of 4 returned, bytes
     * cut from *inside* the entries.
     *
     * Re-reading with a smaller limit cannot help here — the list was already
     * complete, so a halved limit returns fewer of the same partial entries. The
     * continuation must say the projection needs narrowing instead.
     */
    @Test
    fun payloadTruncatedCompleteListAsksForANarrowerProjection() {
        val info = AgentTruncation.fromData(
            data = mapOf(
                "offset" to 0,
                "limit" to 20,
                "returned" to 4,
                "total" to 4,
                "payloadTruncated" to true,
                "truncated" to true
            ),
            returned = 4,
            total = 4,
            fallbackTruncated = true
        )

        assertTrue(info.payloadTruncated)
        assertEquals(false, info.continuation?.get("available"))
        assertEquals("narrow_projection_required", info.continuation?.get("reason"))
    }

    /**
     * When whole items were dropped by the byte trim, re-reading the page really
     * does help.
     *
     * The counts here are the ones the *trim* produced: `returned` already equals
     * `total`, so ordinary paging has nothing left to advance to and the
     * payload-retry path is what must answer. The `callsReturned`/`callsTotal`
     * pair is AgentResultTruncator's own record that four of ten entries survived.
     */
    @Test
    fun payloadTruncatedDroppedItemsRetrySameOffsetWithSmallerLimit() {
        val info = AgentTruncation.fromData(
            data = mapOf(
                "offset" to 0,
                "limit" to 20,
                "returned" to 4,
                "total" to 4,
                "callsTruncated" to true,
                "callsTotal" to 10,
                "callsReturned" to 4,
                "payloadTruncated" to true,
                "truncated" to true
            ),
            returned = 4,
            total = 4,
            fallbackTruncated = true
        )

        assertTrue(info.payloadTruncated)
        assertEquals(0L, (info.continuation?.get("offset") as Number).toLong())
        assertEquals(2L, (info.continuation?.get("limit") as Number).toLong())
        assertEquals("retry_with_smaller_limit", info.continuation?.get("reason"))
    }

    @Test
    fun payloadTruncatedSingleItemPageStaysUnrecoverable() {
        val info = AgentTruncation.fromData(
            data = mapOf(
                "offset" to 3,
                "limit" to 1,
                "returned" to 1,
                "total" to 1,
                "itemsTruncated" to true,
                "itemsTotal" to 4,
                "itemsReturned" to 1,
                "payloadTruncated" to true
            ),
            returned = 1,
            total = 1,
            fallbackTruncated = true
        )

        // Items were dropped, so this is the retry path — but the limit is
        // already a single item, and a halved limit would just repeat the
        // identical call.
        assertEquals(false, info.continuation?.get("available"))
        assertEquals("no_safe_continuation", info.continuation?.get("reason"))
    }
}
