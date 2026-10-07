// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ExpertInfoItem
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.ProtocolStat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureOverviewToolTest {
    @Test
    fun emptyCaptureReportsZeroedIndicatorsWithoutFailing() = runBlocking {
        AgentToolTestHarness.create(frameCount = 0).use { harness ->
            val result = harness.runOverview()

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertEquals(0, data["frameCount"])
            assertEquals(0, data["expertErrorCount"])
            assertEquals(0, data["expertWarningCount"])
            assertEquals(0.0, data["durationSeconds"] as Double, 0.0001)
            assertTrue((data["protocolHierarchy"] as List<*>).isEmpty())
        }
    }

    @Test
    fun healthIndicatorsAndTruncationFlagsAreReported() = runBlocking {
        AgentToolTestHarness.create(frameCount = 40) {
            statisticsByFilter = mapOf("" to richStatistics())
            expert = ExpertInfoSummary(
                errorPackets = 3,
                warningPackets = 5,
                items = listOf(expertItem(7L, "error")),
                totalItems = 9,
                truncated = true
            )
        }.use { harness ->
            val result = harness.runOverview()

            assertTrue(result.success)
            val data = requireNotNull(result.data)

            assertEquals(3, data["expertErrorCount"])
            assertEquals(5, data["expertWarningCount"])
            assertEquals(1_024L, data["capturedByteCount"])
            assertEquals(2, data["truncatedPacketCount"])

            @Suppress("UNCHECKED_CAST")
            val health = data["health"] as Map<String, Map<String, Any?>>
            assertEquals(setOf("dns", "tcp", "tls", "http"), health.keys)

            val dns = requireNotNull(health["dns"])
            assertEquals(4, dns["events"])
            assertEquals(2, dns["problems"])
            assertEquals("error", dns["severity"])
            assertEquals(11L, dns["firstProblemFrame"])

            val tcp = requireNotNull(health["tcp"])
            // 6 retransmissions + 2 dup ACKs + 1 reset + 0 zero windows.
            assertEquals(9, tcp["problems"])
            assertEquals(6, tcp["retransmissions"])

            val http = requireNotNull(health["http"])
            assertEquals("error", http["severity"])
            assertEquals(21L, http["firstProblemFrame"])

            // A capped Expert list must surface as truncated on the overview.
            assertTrue(result.truncated)
        }
    }

    @Test
    fun protocolHierarchyIsCappedAtTwentyEntriesAndReportsTheTotal() = runBlocking {
        val stats = CaptureStatistics(
            packetCount = 100,
            protocolHierarchy = (1..35).map { index ->
                ProtocolStat("proto-$index", index, index.toLong(), 1.0, 1.0)
            }
        )
        AgentToolTestHarness.create(frameCount = 100) {
            statisticsByFilter = mapOf("" to stats)
        }.use { harness ->
            val result = harness.runOverview()

            val data = requireNotNull(result.data)
            assertEquals(20, (data["protocolHierarchy"] as List<*>).size)
            assertEquals(35, data["protocolHierarchyTotal"])
            assertTrue(result.truncated)
        }
    }

    @Test
    fun completeFileScopeClearsTheUserFilterAndRestoresIt() = runBlocking {
        AgentToolTestHarness.create(frameCount = 30).use { harness ->
            harness.coordinator.applyUserFilter("tcp.port == 443", harness.token)
            val snapshot = requireNotNull(
                harness.repository.createSnapshot(AnalysisScope.CompleteFile).getOrNull()
            )
            harness.source.appliedFilters.clear()

            val result = harness.runOverview(snapshot = snapshot)

            assertTrue(result.success)
            assertEquals("complete_file", requireNotNull(result.data)["scope"])
            // The lease clears the filter for the read, then puts it back.
            assertEquals(listOf("", "tcp.port == 443"), harness.source.appliedFilters)
            assertEquals("tcp.port == 443", harness.source.getAppliedDisplayFilter())
        }
    }

    @Test
    fun currentFilterScopeReadsThroughTheSnapshotFilter() = runBlocking {
        AgentToolTestHarness.create(frameCount = 30) {
            filteredVisibleCount = 12
            statisticsByFilter = mapOf(
                "" to CaptureStatistics(packetCount = 30),
                "udp" to CaptureStatistics(packetCount = 12)
            )
        }.use { harness ->
            harness.coordinator.applyUserFilter("udp", harness.token)
            val snapshot = requireNotNull(
                harness.repository.createSnapshot(AnalysisScope.CurrentFilter).getOrNull()
            )

            val result = harness.runOverview(snapshot = snapshot)

            val data = requireNotNull(result.data)
            assertEquals("current_filter", data["scope"])
            assertEquals("udp", data["displayFilter"])
            assertEquals(12, data["visibleFrameCount"])
            // Frame count stays the whole file even in a filtered scope.
            assertEquals(30, data["frameCount"])
            assertEquals(12, data["returned"])
        }
    }

    @Test
    fun scopeArgumentOverridesTheSnapshotScope() = runBlocking {
        AgentToolTestHarness.create(frameCount = 30, scope = AnalysisScope.CurrentFilter) {
            filteredVisibleCount = 5
        }.use { harness ->
            harness.coordinator.applyUserFilter("dns", harness.token)
            val snapshot = requireNotNull(
                harness.repository.createSnapshot(AnalysisScope.CurrentFilter).getOrNull()
            )

            val result = harness.runOverview(
                arguments = mapOf("scope" to "complete_file"),
                snapshot = snapshot
            )

            assertEquals("complete_file", requireNotNull(result.data)["scope"])
            assertEquals("dns", harness.source.getAppliedDisplayFilter())
        }
    }

    @Test
    fun bucketSecondsIsClampedToTheDocumentedRange() = runBlocking {
        AgentToolTestHarness.create(frameCount = 10).use { harness ->
            harness.runOverview(arguments = mapOf("statisticsBucketSeconds" to 30.0))
            assertEquals(30.0, harness.source.requestedBuckets.last(), 0.0001)

            // Out-of-range values are rejected by the schema before the tool runs.
            val tooLarge = harness.runOverview(arguments = mapOf("statisticsBucketSeconds" to 600.0))
            assertFalse(tooLarge.success)
        }
    }

    @Test
    fun defaultBucketIsOneSecond() = runBlocking {
        AgentToolTestHarness.create(frameCount = 10).use { harness ->
            harness.runOverview()
            assertEquals(1.0, harness.source.requestedBuckets.last(), 0.0001)
        }
    }

    @Test
    fun overviewNeverExposesLocalPathOrPayload() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            statisticsByFilter = mapOf("" to richStatistics())
        }.use { harness ->
            val result = harness.runOverview()
            val encoded = AgentResultTruncator.encode(requireNotNull(result.data))

            assertFalse(encoded.contains("localPath"))
            assertFalse(encoded.contains(".pcap"))
            assertFalse(encoded.contains("payload"))
            val tempDir = System.getProperty("java.io.tmpdir").orEmpty()
            if (tempDir.isNotBlank()) {
                assertFalse(encoded.contains(tempDir))
            }
            // fileType must stay a type name, not a path.
            assertEquals("pcap", requireNotNull(result.data)["fileType"])
        }
    }

    @Test
    fun closedSessionIsRejectedWithoutPartialData() = runBlocking {
        AgentToolTestHarness.create(frameCount = 10).use { harness ->
            val snapshot = harness.snapshot
            harness.coordinator.invalidateSession()

            val result = harness.runOverview(snapshot = snapshot)

            assertFalse(result.success)
            assertNotNull(result.error)
            assertEquals(null, result.data)
        }
    }

    private suspend fun AgentToolTestHarness.runOverview(
        arguments: Map<String, Any?> = emptyMap(),
        snapshot: com.example.layanalyzer.model.AgentCaptureSnapshot = this.snapshot
    ) = AgentToolRunner(
        registry = AgentToolRegistry(CaptureOverviewTool(Dispatchers.Unconfined)),
        repository = repository
    ).execute(
        AgentToolCall("call-1", "get_capture_overview", arguments),
        snapshot,
        AgentPrivacyMode.RedactedMetadata
    )

    private fun expertItem(frame: Long, severity: String) = ExpertInfoItem(
        frameNumber = frame,
        label = "Expert $severity",
        filter = "frame.number == $frame",
        severity = severity,
        start = 0,
        length = 4
    )

    private fun richStatistics() = CaptureStatistics(
        packetCount = 40,
        byteCount = 4_096L,
        capturedByteCount = 1_024L,
        truncatedPacketCount = 2,
        startTime = 10.0,
        endTime = 25.5,
        protocolHierarchy = listOf(
            ProtocolStat("eth", 40, 4_096L, 100.0, 100.0),
            ProtocolStat("ip", 38, 3_800L, 95.0, 92.0)
        ),
        dnsSummaryTotal = 4,
        dnsQueries = 2,
        dnsResponses = 2,
        dnsAverageResponseMs = 12.5,
        dnsFailureTotal = 2,
        dnsFirstFailureFrame = 11L,
        tcpSummaryTotal = 9,
        tcpSyn = 4,
        tcpSynAck = 3,
        tcpRetransmissions = 6,
        tcpDuplicateAcks = 2,
        tcpResets = 1,
        tcpZeroWindows = 0,
        tcpAverageRttMs = 40.0,
        tcpRttSamples = 5,
        tlsSummaryTotal = 3,
        tlsAlertTotal = 1,
        tlsFirstAlertFrame = 17L,
        tlsVersions = mapOf("TLS 1.3" to 3),
        tlsSni = mapOf("example.com" to 2),
        httpSummaryTotal = 6,
        httpErrorTotal = 2,
        httpFirstErrorFrame = 21L,
        httpStatusCodes = mapOf("200" to 4, "500" to 2),
        httpHosts = mapOf("example.com" to 6)
    )
}
