package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentBudgetTracker
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.ProtocolNode
import com.example.layanalyzer.model.PacketSummary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketFieldAggregateToolTest {

    @Test
    fun aggregatesPresenceOccurrencesAndBoundaryFrames() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5) {
            summaries = (1L..5L).map(::summary)
            details = mapOf(
                1L to frame(
                    field("sip.Method", "INVITE"),
                    field("sip.Via", "proxy-1"),
                    field("sip.Via", "proxy-2")
                ),
                2L to frame(
                    field("sip.Method", "ACK"),
                    field("sip.Via", "proxy-3")
                ),
                3L to frame(field("sip.Method", "BYE")),
                4L to frame(field("sip.Status-Code", "200")),
                5L to frame(field("sip.Status-Code", "486"))
            )
        }.use { harness ->
            val result = harness.runAggregate(
                mapOf(
                    "fields" to listOf("sip.Method", "sip.Via"),
                    "sampleLimit" to 2,
                    "sampleMode" to "first_last"
                )
            )

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertEquals(5, data["matchedPackets"])
            assertEquals(5, data["scannedPackets"])
            assertEquals(true, data["coverageComplete"])
            assertEquals(true, data["sampled"])
            assertEquals(false, data["truncated"])
            assertEquals(listOf(1L, 5L), data["sampleFrames"])
            assertEquals(2, data["returned"])
            assertEquals(5, data["total"])
            assertEquals("filter_lease", data["queryMode"])
            assertEquals("filter_lease", result.provenance.queryMode)

            @Suppress("UNCHECKED_CAST")
            val fields = data["fields"] as Map<String, Map<String, Any?>>
            val method = requireNotNull(fields["sip.Method"])
            assertEquals(3, method["presentFrames"])
            assertEquals(3, method["occurrenceCount"])
            assertEquals(1L, method["firstFrame"])
            assertEquals(3L, method["lastFrame"])

            val via = requireNotNull(fields["sip.Via"])
            assertEquals(2, via["presentFrames"])
            assertEquals(3, via["occurrenceCount"])
        }
    }

    @Test
    fun credentialAggregateContainsOnlyPresenceAndSafeScheme() = runBlocking {
        val secret = "Digest username=alice, response=c0ffee"
        AgentToolTestHarness.create(frameCount = 2) {
            summaries = (1L..2L).map(::summary)
            details = mapOf(
                1L to frame(field("sip.Authorization", secret)),
                2L to frame(field("sip.Method", "INVITE"))
            )
        }.use { harness ->
            val result = harness.runAggregate(
                mapOf("fields" to listOf("sip.Authorization"))
            )

            assertTrue(result.success)
            val encoded = AgentResultTruncator.encode(requireNotNull(result.data))
            assertTrue(encoded.contains("\"credential\":true"))
            assertTrue(encoded.contains("\"digest\""))
            assertFalse(encoded.contains("alice"))
            assertFalse(encoded.contains("c0ffee"))
        }
    }

    @Test
    fun payloadAggregateContainsCountsButNeverTheBody() = runBlocking {
        val payload = "raw-body-that-must-not-escape"
        AgentToolTestHarness.create(frameCount = 1) {
            summaries = listOf(summary(1L))
            details = mapOf(1L to frame(field("tcp.payload", payload)))
        }.use { harness ->
            val result = harness.runAggregate(
                mapOf("fields" to listOf("tcp.payload"))
            )

            assertTrue(result.success)
            val encoded = AgentResultTruncator.encode(requireNotNull(result.data))
            assertTrue(encoded.contains("\"payload\":true"))
            assertFalse(encoded.contains(payload))
        }
    }

    @Test
    fun filterIsAppliedForTheScanAndRestoredAfterwards() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5) {
            summaries = (1L..5L).map(::summary)
            filteredVisibleCount = 2
            details = mapOf(
                1L to frame(field("sip.Method", "INVITE")),
                2L to frame(field("sip.Method", "ACK"))
            )
        }.use { harness ->
            val filter = "sip.Method == INVITE"
            val result = harness.runAggregate(
                mapOf(
                    "filter" to filter,
                    "fields" to listOf("sip.Method"),
                    "sampleMode" to "first_last"
                )
            )

            assertTrue(result.success)
            assertEquals(2, requireNotNull(result.data)["matchedPackets"])
            assertEquals(listOf(filter, ""), harness.source.appliedFilters)
            assertEquals("", harness.source.getAppliedDisplayFilter())
        }
    }

    @Test
    fun emptyAndLargeMatchesStayBoundedAndReportCoverage() = runBlocking {
        AgentToolTestHarness.create(frameCount = 0) {
            filteredVisibleCount = 0
        }.use { emptyHarness ->
            val empty = emptyHarness.runAggregate(
                mapOf("fields" to listOf("sip.Method"))
            )
            assertTrue(empty.success)
            val data = requireNotNull(empty.data)
            assertEquals(0, data["matchedPackets"])
            assertEquals(0, data["scannedPackets"])
            assertEquals(emptyList<Long>(), data["sampleFrames"])
            assertEquals(false, data["sampled"])
            assertEquals(true, data["coverageComplete"])
            assertEquals(false, data["truncated"])
        }

        AgentToolTestHarness.create(frameCount = 1_001) {
            summaries = (1L..1_001L).map(::summary)
        }.use { largeHarness ->
            val large = largeHarness.runAggregate(
                mapOf(
                    "fields" to listOf("sip.Method"),
                    "sampleLimit" to 4,
                    "sampleMode" to "uniform"
                )
            )
            assertTrue(large.success)
            val data = requireNotNull(large.data)
            assertEquals(1_001, data["matchedPackets"])
            assertEquals(1_001, data["scannedPackets"])
            assertEquals(true, data["coverageComplete"])
            assertEquals(true, data["sampled"])
            assertEquals(false, data["truncated"])
            @Suppress("UNCHECKED_CAST")
            val samples = data["sampleFrames"] as List<Long>
            assertTrue(samples.size <= 4)
            assertEquals(1L, samples.first())
            assertEquals(1_001L, samples.last())
        }
    }

    @Test
    fun phase3RegistryExposesTheAggregateTool() {
        assertNotNull(
            AgentToolRegistry.phase3(Dispatchers.Unconfined)
                .find("query_packet_field_aggregate")
        )
    }

    private suspend fun AgentToolTestHarness.runAggregate(
        arguments: Map<String, Any?>,
        snapshot: AgentCaptureSnapshot = this.snapshot
    ) = AgentToolRunner(
        registry = AgentToolRegistry(PacketFieldAggregateTool(Dispatchers.Unconfined)),
        repository = repository,
        policy = AgentPolicy(),
        budget = AgentBudgetTracker(AgentPolicy())
    ).execute(
        AgentToolCall("aggregate-call", "query_packet_field_aggregate", arguments),
        snapshot,
        AgentPrivacyMode.LocalOnly
    )

    private fun frame(vararg fields: ProtocolNode) = ProtocolNode(
        label = "Frame",
        children = fields.toList()
    )

    private fun field(name: String, value: String) = ProtocolNode(
        label = "$name: $value",
        value = value,
        filter = name,
        filterValue = value
    )

    private fun summary(frame: Long) = PacketSummary(
        frameNumber = frame,
        time = frame.toString(),
        source = "10.0.0.1",
        destination = "10.0.0.2",
        protocol = "TCP",
        length = 100,
        sourcePort = 5060,
        destinationPort = 5060,
        info = "Frame $frame"
    )
}
