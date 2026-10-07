// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.data.ScopedPacketSummaryQuery
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.PacketSummary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketSummaryQueryToolTest {

    @Test
    fun nativeScopedCapabilityIsPreferredOverTheFilterLease() = runBlocking {
        AgentToolTestHarness.create(frameCount = 4) {
            summaries = (1..4).map { summary(it.toLong()) }
            scopedQuery = ScopedPacketSummaryQuery(
                success = true,
                items = listOf(summary(3L, time = "102.000000")),
                offset = 2,
                returned = 1,
                total = 1,
                truncated = false,
                queryVersion = "native-scoped-v1"
            )
        }.use { harness ->
            val result = harness.runSummaries(mapOf("filter" to "udp", "offset" to 2))

            assertTrue(result.success)
            assertEquals("native_scoped", result.provenance.queryMode)
            assertTrue(harness.source.appliedFilters.isEmpty())
            assertEquals(3L, requireNotNull(result.data)["packets"]
                .let { it as List<Map<String, Any?>> }
                .single()["frameNumber"])
        }
    }

    @Test
    fun aPageCarriesTheColumnsTheModelNeedsToChooseCandidateFrames() = runBlocking {
        AgentToolTestHarness.create(frameCount = 3) {
            summaries = listOf(
                summary(1L, time = "100.000000", protocol = "SIP", info = "INVITE sip:bob@example.com"),
                summary(2L, time = "100.250000", protocol = "SIP", info = "100 Trying"),
                summary(3L, time = "101.000000", protocol = "RTP", info = "PT=PCMU")
            )
        }.use { harness ->
            val result = harness.runSummaries()

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val packets = data["packets"] as List<Map<String, Any?>>
            assertEquals(3, packets.size)
            assertEquals(3, data["returned"])
            assertEquals(3, data["total"])
            assertEquals(false, data["truncated"])

            val first = packets.first()
            assertEquals(1L, first["frameNumber"])
            assertEquals("SIP", first["protocol"])
            assertNotNull(first["length"])
            assertNotNull(first["sourcePort"])
            // Both clocks: absolute for external correlation, relative for the
            // position the user sees in the packet list.
            assertEquals(100.0, first["absoluteTime"] as Double, 1e-9)
            assertEquals(0.0, first["relativeTime"] as Double, 1e-9)
            assertEquals(1.0, packets[2]["relativeTime"] as Double, 1e-9)
        }
    }

    @Test
    fun pagingUsesOffsetAndLimitAndFlagsRemainingFrames() = runBlocking {
        AgentToolTestHarness.create(frameCount = 10) {
            summaries = (1..10).map { summary(it.toLong()) }
        }.use { harness ->
            val firstPage = harness.runSummaries(mapOf("limit" to 4))
            val firstData = requireNotNull(firstPage.data)
            assertEquals(4, firstData["returned"])
            assertEquals(10, firstData["total"])
            assertEquals(true, firstData["truncated"])

            val lastPage = harness.runSummaries(mapOf("offset" to 8, "limit" to 4))
            val lastData = requireNotNull(lastPage.data)
            assertEquals(2, lastData["returned"])
            assertEquals(false, lastData["truncated"])

            @Suppress("UNCHECKED_CAST")
            val packets = lastData["packets"] as List<Map<String, Any?>>
            assertEquals(9L, packets.first()["frameNumber"])
        }
    }

    @Test
    fun anOffsetPastTheEndIsAnEmptyPageRatherThanAnError() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5) {
            summaries = (1..5).map { summary(it.toLong()) }
        }.use { harness ->
            val result = harness.runSummaries(mapOf("offset" to 500))

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertTrue((data["packets"] as List<*>).isEmpty())
            assertEquals(0, data["returned"])
            assertEquals(5, data["total"])
            // Nothing was withheld — the model simply paged past the end.
            assertEquals(false, data["truncated"])
        }
    }

    @Test
    fun limitIsCappedAtOneHundred() = runBlocking {
        AgentToolTestHarness.create(frameCount = 150) {
            summaries = (1..150).map { summary(it.toLong()) }
        }.use { harness ->
            val rejected = harness.runSummaries(mapOf("limit" to 500))
            assertFalse(rejected.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, rejected.error?.code)

            val atMax = harness.runSummaries(mapOf("limit" to 100))
            assertEquals(100, requireNotNull(atMax.data)["returned"])
        }
    }

    @Test
    fun anUnsupportedSortOrderIsRejectedBySchema() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val result = harness.runSummaries(mapOf("sort" to "time_descending"))

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
        }
    }

    @Test
    fun filterIsAppliedThroughTheLeaseAndTheUserFilterIsRestored() = runBlocking {
        AgentToolTestHarness.create(frameCount = 10) {
            summaries = (1..10).map { summary(it.toLong()) }
            filteredVisibleCount = 4
        }.use { harness ->
            harness.coordinator.applyUserFilter("ip", harness.token)
            harness.source.appliedFilters.clear()

            val result = harness.runSummaries(mapOf("filter" to "sip"))

            assertTrue(result.success)
            assertEquals(4, requireNotNull(result.data)["total"])
            assertEquals("filter_lease", result.provenance.queryMode)
            assertEquals(listOf("sip", "ip"), harness.source.appliedFilters)
            assertEquals("ip", harness.source.getAppliedDisplayFilter())
        }
    }

    @Test
    fun invalidFilterFailsWithoutChangingUserFilterState() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            harness.coordinator.applyUserFilter("ip", harness.token)
            harness.source.invalidFilters = setOf("sip.Method ===")
            harness.source.appliedFilters.clear()

            val result = harness.runSummaries(mapOf("filter" to "sip.Method ==="))

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_DISPLAY_FILTER, result.error?.code)
            assertTrue(harness.source.appliedFilters.isEmpty())
            assertEquals("ip", harness.source.getAppliedDisplayFilter())
        }
    }

    @Test
    fun neitherPacketBytesNorProtocolTreesAppearInTheResult() = runBlocking {
        AgentToolTestHarness.create(frameCount = 2) {
            summaries = listOf(summary(1L), summary(2L))
        }.use { harness ->
            val encoded = AgentResultTruncator.encode(requireNotNull(harness.runSummaries().data))

            listOf("bytes", "hex", "payload", "children", "localPath", "\"start\"").forEach { forbidden ->
                assertFalse(forbidden, encoded.contains(forbidden))
            }
            // No frame was dissected to build a summary page.
            assertTrue(harness.source.readDetailFrames.isEmpty())
        }
    }

    @Test
    fun sessionChangeIsRejectedWithAStructuredError() = runBlocking {
        AgentToolTestHarness.create(frameCount = 2) {
            summaries = listOf(summary(1L), summary(2L))
        }.use { harness ->
            val snapshot = harness.snapshot
            harness.coordinator.invalidateSession()

            val result = harness.runSummaries(snapshot = snapshot)

            assertFalse(result.success)
            assertNull(result.data)
            assertNotNull(result.error)
        }
    }

    private suspend fun AgentToolTestHarness.runSummaries(
        arguments: Map<String, Any?> = emptyMap(),
        snapshot: AgentCaptureSnapshot = this.snapshot
    ) = AgentToolRunner(
        registry = AgentToolRegistry(PacketSummaryQueryTool(Dispatchers.Unconfined)),
        repository = repository
    ).execute(
        AgentToolCall("call-1", "query_packet_summaries", arguments),
        snapshot,
        // LocalOnly keeps addresses unredacted so the assertions read the values
        // the engine actually produced; redaction has its own test.
        AgentPrivacyMode.LocalOnly
    )

    private fun summary(
        frame: Long,
        time: String = "100.$frame",
        protocol: String = "TCP",
        info: String = "Frame $frame"
    ) = PacketSummary(
        frameNumber = frame,
        time = time,
        source = "10.0.0.1",
        destination = "10.0.0.2",
        protocol = protocol,
        length = 100 + frame.toInt(),
        sourcePort = 5060,
        destinationPort = 5060,
        info = info
    )
}
