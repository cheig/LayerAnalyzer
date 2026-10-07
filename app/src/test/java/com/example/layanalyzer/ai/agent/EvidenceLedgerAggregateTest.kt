package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentProvenance
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceLedgerAggregateTest {

    @Test
    fun aCompleteAggregateCanBeSampledAndStillSupportsEvidence() {
        val ledger = EvidenceLedger()
        val entry = ledger.record(
            call = AgentToolCall(
                toolCallId = "aggregate-1",
                toolName = "query_packet_field_aggregate",
                arguments = mapOf(
                    "filter" to "tcp.analysis.retransmission",
                    "fields" to listOf("tcp.analysis.retransmission")
                )
            ),
            result = aggregateResult(
                coverageComplete = true,
                truncated = false,
                returned = 2,
                total = 100
            ),
            stepIndex = 1
        )

        assertTrue(entry.complete)
        assertTrue(entry.sampled)
        assertEquals(setOf(12L, 8120L), entry.frameNumbers)
        assertTrue(entry.fields.contains("tcp.analysis.retransmission"))
        assertTrue(entry.metrics.contains("matchedPackets"))
        assertTrue(entry.leafMetrics.contains("matchedPackets"))
        assertEquals("100", entry.metricValues["matchedPackets"])
        assertEquals(100L, entry.executedFilterMatches["tcp.analysis.retransmission"])
        assertEquals("filter_lease", entry.queryMode)
        assertEquals(321, entry.resultBytes)
        assertTrue(entry.validatedFilters.contains("tcp.analysis.retransmission"))
        assertTrue(entry.describe().contains("sample frame(s)"))
    }

    @Test
    fun onlyScalarLeavesBecomeMetricValues() {
        val entry = EvidenceLedger().record(
            call = AgentToolCall("metric-1", "get_statistics"),
            result = AgentToolResult(
                toolCallId = "metric-1",
                toolName = "get_statistics",
                success = true,
                data = mapOf(
                    "health" to mapOf(
                        "retransmissions" to 3,
                        "details" to mapOf("count" to 7)
                    )
                ),
                returnedCount = 1L,
                totalCount = 1L,
                provenance = AgentProvenance(returnedCount = 1L, totalCount = 1L)
            ),
            stepIndex = 1
        )

        assertTrue(entry.metrics.contains("health"))
        assertFalse(entry.leafMetrics.contains("health"))
        assertEquals("3", entry.metricValues["health.retransmissions"])
        assertEquals("7", entry.metricValues["health.details.count"])
        assertFalse(entry.metricValues.containsKey("health"))
    }

    @Test
    fun provenanceFilterIsValidatedAndPayloadTotalCountTracksExecution() {
        val filter = "tcp.analysis.retransmission"
        val entry = EvidenceLedger().record(
            call = AgentToolCall("filter-lease", "get_expert_info"),
            result = AgentToolResult(
                toolCallId = "filter-lease",
                toolName = "get_expert_info",
                success = true,
                data = mapOf("totalCount" to 4L),
                returnedCount = 0L,
                totalCount = 0L,
                provenance = AgentProvenance(
                    displayFilter = filter,
                    returnedCount = 0L,
                    totalCount = 0L
                )
            ),
            stepIndex = 1
        )

        assertTrue(entry.validatedFilters.contains(filter))
        assertEquals(4L, entry.executedFilterMatches[filter])
    }

    @Test
    fun anIncompleteAggregateCannotSupportACompleteFinding() {
        val ledger = EvidenceLedger()
        val entry = ledger.record(
            call = AgentToolCall(
                toolCallId = "aggregate-2",
                toolName = "query_packet_field_aggregate"
            ),
            result = aggregateResult(
                coverageComplete = false,
                truncated = true,
                returned = 2,
                total = 100
            ),
            stepIndex = 1
        )

        assertFalse(entry.complete)
        assertTrue(entry.truncated)
        assertTrue(ledger.anyTruncated())
    }

    private fun aggregateResult(
        coverageComplete: Boolean,
        truncated: Boolean,
        returned: Int,
        total: Int
    ) = AgentToolResult(
        toolCallId = "aggregate-result",
        toolName = "query_packet_field_aggregate",
        success = true,
        data = mapOf(
            "filter" to "tcp.analysis.retransmission",
            "queryMode" to "filter_lease",
            "matchedPackets" to total,
            "scannedPackets" to if (coverageComplete) total else 40,
            "fields" to mapOf(
                "tcp.analysis.retransmission" to mapOf(
                    "presentFrames" to 40,
                    "occurrenceCount" to 40,
                    "firstFrame" to 12L,
                    "lastFrame" to 8120L
                )
            ),
            "sampleFrames" to listOf(12L, 8120L),
            "sampled" to true,
            "coverageComplete" to coverageComplete,
            "returned" to returned,
            "total" to total,
            "truncated" to truncated
        ),
        truncated = truncated,
        returnedCount = returned.toLong(),
        totalCount = total.toLong(),
        queryMode = "filter_lease",
        resultBytes = 321,
        provenance = AgentProvenance(queryMode = "filter_lease")
    )
}
