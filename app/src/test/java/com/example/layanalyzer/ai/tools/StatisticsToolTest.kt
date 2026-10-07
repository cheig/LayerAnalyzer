package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ConversationStat
import com.example.layanalyzer.model.EndpointStat
import com.example.layanalyzer.model.IoBucket
import com.example.layanalyzer.model.PacketLengthBucket
import com.example.layanalyzer.model.PacketLengthStats
import com.example.layanalyzer.model.ProtocolSummaryItem
import com.example.layanalyzer.model.ProtocolStat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class StatisticsToolTest {

    @Test
    fun aBareCallReturnsTheProtocolMixAndTheFourHealthBlocks() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf("" to statistics())
        }.use { harness ->
            val result = harness.runStatistics()

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertNotNull(data["protocolHierarchy"])
            assertNotNull(data["tcp"])
            assertNotNull(data["dns"])
            assertNotNull(data["tls"])
            assertNotNull(data["http"])
            // The two largest tables stay out until asked for by name.
            assertNull(data["conversations"])
            assertNull(data["endpoints"])
            assertNull(data["ioGraph"])
        }
    }

    @Test
    fun eachSectionSelectionReturnsOnlyTheFieldsItNames() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf("" to statistics())
        }.use { harness ->
            val result = harness.runStatistics(mapOf("sections" to listOf("tcp")))

            val data = requireNotNull(result.data)
            assertNotNull(data["tcp"])
            assertNull(data["dns"])
            assertNull(data["tls"])
            assertNull(data["http"])
            assertNull(data["protocolHierarchy"])
            assertEquals(listOf("tcp"), data["sections"])
        }
    }

    @Test
    fun tcpMetricsCarryEveryIndicatorTheDesignAsksFor() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf("" to statistics())
        }.use { harness ->
            val result = harness.runStatistics(mapOf("sections" to listOf("tcp")))

            @Suppress("UNCHECKED_CAST")
            val tcp = requireNotNull(result.data)["tcp"] as Map<String, Any?>
            assertEquals(9, tcp["syn"])
            assertEquals(8, tcp["synAck"])
            assertEquals(4, tcp["retransmissions"])
            assertEquals(3, tcp["duplicateAcks"])
            assertEquals(2, tcp["resets"])
            assertEquals(1, tcp["zeroWindows"])
            assertEquals(12.5, tcp["averageRttMs"] as Double, 1e-9)
            // The native per-protocol list total, so a capped summary stays visible.
            assertEquals(40, tcp["summaryTotal"])
        }
    }

    @Test
    fun protocolMetricsExposeFrameAddressableEventsWithoutEndpointIdentifiers() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf("" to statistics())
        }.use { harness ->
            val result = harness.runStatistics(
                mapOf(
                    "sections" to listOf("tcp", "dns", "tls", "http"),
                    "topN" to 1
                )
            )

            val data = requireNotNull(result.data)
            listOf("tcp", "dns", "tls", "http").forEach { section ->
                @Suppress("UNCHECKED_CAST")
                val metrics = data[section] as Map<String, Any?>
                @Suppress("UNCHECKED_CAST")
                val events = metrics["events"] as List<Map<String, Any?>>
                assertEquals(1, events.size)
                assertNotNull(events.single()["frameNumber"])
                assertNotNull(events.single()["time"])
                assertNotNull(events.single()["summary"])
                assertFalse(events.single().containsKey("source"))
                assertFalse(events.single().containsKey("destination"))
                assertFalse(events.single().containsKey("protocol"))
            }
            assertEquals(true, data["truncated"])
        }
    }

    @Test
    fun packetLengthSectionCarriesDistributionMetricsAndBuckets() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf("" to statistics())
        }.use { harness ->
            val result = harness.runStatistics(mapOf("sections" to listOf("packet_lengths")))

            @Suppress("UNCHECKED_CAST")
            val lengths = requireNotNull(result.data)["packetLengths"] as Map<String, Any?>
            assertEquals(60, lengths["min"])
            assertEquals(1514, lengths["max"])
            assertEquals(512.5, lengths["average"] as Double, 1e-9)
            assertEquals(50_000L, lengths["totalBytes"])
            @Suppress("UNCHECKED_CAST")
            val buckets = lengths["buckets"] as List<Map<String, Any?>>
            assertEquals("0-63", buckets.first()["label"])
            assertEquals(4, buckets.first()["packets"])
        }
    }

    @Test
    fun conversationsAndEndpointsAreRankedByBytesAndCappedAtTopN() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf(
                "" to statistics(
                    conversations = (1..10).map { index ->
                        conversation(bytes = index * 100L, endpointB = "10.0.0.$index")
                    },
                    endpoints = (1..10).map { index ->
                        endpoint(bytes = index * 50L, address = "10.0.0.$index")
                    }
                )
            )
        }.use { harness ->
            val result = harness.runStatistics(
                mapOf("sections" to listOf("conversations", "endpoints"), "topN" to 3)
            )

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val conversations = data["conversations"] as List<Map<String, Any?>>
            assertEquals(3, conversations.size)
            // Heaviest first.
            assertEquals(1000L, conversations.first()["bytes"])
            assertEquals(800L, conversations[2]["bytes"])
            assertEquals(10, data["conversationsTotal"])

            @Suppress("UNCHECKED_CAST")
            val endpoints = data["endpoints"] as List<Map<String, Any?>>
            assertEquals(3, endpoints.size)
            assertEquals(500L, endpoints.first()["bytes"])
            assertEquals(10, data["endpointsTotal"])

            // 3 of 10 returned in both tables, so the result is truncated.
            assertEquals(true, data["truncated"])
        }
    }

    @Test
    fun theIoGraphMergesAdjacentBucketsRatherThanCuttingTheTimeTail() = runBlocking {
        val bucketCount = 500
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf(
                "" to statistics(
                    ioGraph = (0 until bucketCount).map { index ->
                        IoBucket(
                            startTime = index.toDouble(),
                            endTime = index + 1.0,
                            packets = 2,
                            bytes = 10L
                        )
                    }
                )
            )
        }.use { harness ->
            val result = harness.runStatistics(mapOf("sections" to listOf("io_graph")))

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val buckets = data["ioGraph"] as List<Map<String, Any?>>
            assertTrue("at most 120 buckets", buckets.size <= 120)
            assertEquals(true, data["ioGraphMerged"])
            assertEquals(bucketCount, data["ioGraphTotal"])

            // The merged series still spans the whole capture: nothing was cut
            // off the end, only resolution was lowered.
            assertEquals(0.0, buckets.first()["startTime"] as Double, 1e-9)
            assertEquals(bucketCount.toDouble(), buckets.last()["endTime"] as Double, 1e-9)
            // And every packet is still accounted for.
            assertEquals(bucketCount * 2, buckets.sumOf { it["packets"] as Int })
            assertEquals(bucketCount * 10L, buckets.sumOf { it["bytes"] as Long })
        }
    }

    @Test
    fun aShortIoGraphIsReturnedUnmerged() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf(
                "" to statistics(
                    ioGraph = (0 until 5).map { index ->
                        IoBucket(index.toDouble(), index + 1.0, packets = 1, bytes = 5L)
                    }
                )
            )
        }.use { harness ->
            val result = harness.runStatistics(mapOf("sections" to listOf("io_graph")))

            val data = requireNotNull(result.data)
            assertEquals(5, (data["ioGraph"] as List<*>).size)
            assertEquals(false, data["ioGraphMerged"])
        }
    }

    @Test
    fun nativeTruncationCountsAreNotHiddenByAResultThatFitsOnOnePage() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf(
                "" to statistics().copy(truncatedPacketCount = 17)
            )
        }.use { harness ->
            val result = harness.runStatistics(mapOf("sections" to listOf("tcp")))

            val data = requireNotNull(result.data)
            // Frames the capture itself cut short; the model needs this to avoid
            // reading a snaplen artefact as a protocol-level absence.
            assertEquals(17, data["truncatedPacketCount"])
        }
    }

    @Test
    fun bucketSecondsIsForwardedToTheNativeTraversalAndClamped() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf("" to statistics())
        }.use { harness ->
            harness.runStatistics(mapOf("bucketSeconds" to 5.0))
            assertEquals(5.0, harness.source.requestedBuckets.last(), 1e-9)

            // Out-of-range values are rejected by the schema, not silently used.
            val rejected = harness.runStatistics(mapOf("bucketSeconds" to 600.0))
            assertFalse(rejected.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, rejected.error?.code)
        }
    }

    @Test
    fun topNIsRejectedAboveFiftyBySchema() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf("" to statistics())
        }.use { harness ->
            val result = harness.runStatistics(mapOf("topN" to 500))

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
        }
    }

    @Test
    fun filterIsAppliedThroughTheLeaseAndTheUserFilterIsRestored() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf(
                "" to statistics(),
                "sip" to statistics().copy(packetCount = 7)
            )
        }.use { harness ->
            harness.coordinator.applyUserFilter("ip", harness.token)
            harness.source.appliedFilters.clear()

            val result = harness.runStatistics(mapOf("filter" to "sip"))

            assertTrue(result.success)
            assertEquals(7, requireNotNull(result.data)["packetCount"])
            assertEquals(listOf("sip", "ip"), harness.source.appliedFilters)
            assertEquals("ip", harness.source.getAppliedDisplayFilter())
        }
    }

    @Test
    fun anInvalidFilterFailsBeforeAnyNativeTraversalRuns() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf("" to statistics())
        }.use { harness ->
            harness.source.invalidFilters = setOf("tcp.port ===")
            harness.source.requestedBuckets.clear()

            val result = harness.runStatistics(mapOf("filter" to "tcp.port ==="))

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_DISPLAY_FILTER, result.error?.code)
            assertTrue(harness.source.requestedBuckets.isEmpty())
        }
    }

    @Test
    fun noPayloadOrPacketSummaryTextReachesTheResult() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf(
                "" to statistics(
                    conversations = listOf(conversation()),
                    endpoints = listOf(endpoint()),
                    ioGraph = listOf(IoBucket(0.0, 1.0, 1, 10L))
                )
            )
        }.use { harness ->
            val result = harness.runStatistics(
                mapOf(
                    "sections" to listOf(
                        "protocol_hierarchy", "conversations", "endpoints",
                        "io_graph", "tcp", "dns", "tls", "http"
                    )
                )
            )
            val encoded = AgentResultTruncator.encode(requireNotNull(result.data))

            listOf("payload", "ascii", "\"hex\"", "localPath", "summaries").forEach { forbidden ->
                assertFalse(forbidden, encoded.contains(forbidden))
            }
            // Statistics are an aggregate: no frame was dissected individually.
            assertTrue(harness.source.readDetailFrames.isEmpty())
        }
    }

    @Test
    fun aSessionChangeIsRejectedWithAStructuredError() = runBlocking {
        AgentToolTestHarness.create {
            statisticsByFilter = mapOf("" to statistics())
        }.use { harness ->
            val snapshot = harness.snapshot
            harness.coordinator.invalidateSession()

            val result = harness.runStatistics(snapshot = snapshot)

            assertFalse(result.success)
            assertNull(result.data)
            assertNotNull(result.error)
        }
    }

    private suspend fun AgentToolTestHarness.runStatistics(
        arguments: Map<String, Any?> = emptyMap(),
        snapshot: AgentCaptureSnapshot = this.snapshot
    ) = AgentToolRunner(
        registry = AgentToolRegistry(StatisticsTool(Dispatchers.Unconfined)),
        repository = repository
    ).execute(
        AgentToolCall("call-1", "get_statistics", arguments),
        snapshot,
        AgentPrivacyMode.LocalOnly
    )

    private fun statistics(
        conversations: List<ConversationStat> = emptyList(),
        endpoints: List<EndpointStat> = emptyList(),
        ioGraph: List<IoBucket> = emptyList()
    ) = CaptureStatistics(
        packetCount = 100,
        byteCount = 50_000L,
        capturedByteCount = 49_000L,
        startTime = 100.0,
        endTime = 160.0,
        protocolHierarchy = listOf(
            ProtocolStat("tcp", 60, 30_000L, 60.0, 60.0),
            ProtocolStat("udp", 40, 20_000L, 40.0, 40.0)
        ),
        conversations = conversations,
        endpoints = endpoints,
        ioGraph = ioGraph,
        packetLengths = PacketLengthStats(
            min = 60,
            max = 1514,
            average = 512.5,
            totalBytes = 50_000L,
            buckets = listOf(PacketLengthBucket("0-63", packets = 4, bytes = 240L))
        ),
        tcpSummaries = protocolEvents("TCP"),
        tcpSyn = 9,
        tcpSynAck = 8,
        tcpRetransmissions = 4,
        tcpDuplicateAcks = 3,
        tcpResets = 2,
        tcpZeroWindows = 1,
        tcpAverageRttMs = 12.5,
        tcpRttSamples = 30,
        tcpSummaryTotal = 40,
        dnsQueries = 5,
        dnsResponses = 4,
        dnsFailureTotal = 1,
        dnsAverageResponseMs = 22.0,
        dnsFirstFailureFrame = 12L,
        dnsSummaryTotal = 9,
        dnsSummaries = protocolEvents("DNS"),
        tlsVersions = mapOf("TLS 1.3" to 3),
        tlsAlertTotal = 1,
        tlsFirstAlertFrame = 44L,
        tlsSummaryTotal = 6,
        tlsSummaries = protocolEvents("TLS"),
        httpStatusCodes = mapOf("200" to 4, "500" to 1),
        httpErrorTotal = 1,
        httpFirstErrorFrame = 55L,
        httpSummaryTotal = 5,
        httpSummaries = protocolEvents("HTTP")
    )

    private fun protocolEvents(protocol: String) = (1L..2L).map { frame ->
        ProtocolSummaryItem(
            frameNumber = frame,
            time = frame / 10.0,
            source = "192.0.2.1",
            destination = "198.51.100.2",
            protocol = protocol,
            summary = "$protocol event $frame"
        )
    }

    private fun conversation(
        bytes: Long = 1_000L,
        endpointB: String = "10.0.0.2"
    ) = ConversationStat(
        type = "TCP",
        endpointA = "10.0.0.1",
        endpointB = endpointB,
        portA = 12345,
        portB = 443,
        packets = 10,
        bytes = bytes,
        startTime = 100.0,
        duration = 5.0,
        aToBPackets = 6,
        bToAPackets = 4
    )

    private fun endpoint(
        bytes: Long = 500L,
        address: String = "10.0.0.1"
    ) = EndpointStat(
        type = "IPv4",
        address = address,
        port = null,
        packets = 10,
        bytes = bytes,
        sentPackets = 6,
        receivedPackets = 4
    )
}
