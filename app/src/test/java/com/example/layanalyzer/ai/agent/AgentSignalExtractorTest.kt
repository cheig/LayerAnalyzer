package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentToolResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * OPT-VAL-02-01: the pure signal extractor. Payload shapes are copied from
 * their producers — `AgentCaptureOverview.toAgentJson` in BaseToolDtos.kt and
 * the item/summary results of ExpertInfoTool.kt — so the extractor is pinned
 * against what the host actually emits, not an invented variant.
 */
class AgentSignalExtractorTest {

    private val extractor = AgentSignalExtractor()

    // ------------------------------------------------------------- payloads

    /** Mirrors `AgentCaptureOverview.toAgentJson()`. */
    private fun overviewPayload(
        health: Map<String, Any?>?,
        protocolHierarchy: List<Map<String, Any?>>?,
        expertErrorCount: Int = 0,
        expertWarningCount: Int = 0
    ): Map<String, Any?> = buildMap {
        put("fileType", "pcapng")
        put("encapsulation", "EN10MB")
        put("frameCount", 188)
        put("visibleFrameCount", 188)
        put("startTime", 1.0)
        put("endTime", 12.5)
        put("durationSeconds", 11.5)
        put("scope", "complete")
        put("displayFilter", "")
        protocolHierarchy?.let { put("protocolHierarchy", it) }
        put("protocolHierarchyTotal", protocolHierarchy?.size ?: 0)
        health?.let { put("health", it) }
        put("expertErrorCount", expertErrorCount)
        put("expertWarningCount", expertWarningCount)
        put("capturedByteCount", 40960L)
        put("truncatedPacketCount", 0)
        put("returned", 20)
        put("total", 24)
        put("truncated", true)
    }

    /** One `AgentProtocolHealth.toAgentJson()` entry. */
    private fun healthEntry(
        events: Int,
        problems: Int?,
        severity: String,
        firstProblemFrame: Long? = 42L
    ): Map<String, Any?> = buildMap {
        put("events", events)
        problems?.let { put("problems", it) }
        put("severity", severity)
        put("firstProblemFrame", firstProblemFrame)
        put("displayFilter", "tcp.analysis.flags")
        put("truncated", false)
        put("averageRttMs", 51.0)
    }

    /** One `AgentProtocolHierarchyEntry.toAgentJson()`. */
    private fun protocolEntry(name: String, packetPercent: Any?): Map<String, Any?> = mapOf(
        "name" to name,
        "packets" to 100,
        "bytes" to 50000L,
        "packetPercent" to packetPercent,
        "bytePercent" to 62.5
    )

    /** Mirrors ExpertInfoTool.summaryResult(). */
    private fun expertSummaryPayload(groups: List<Map<String, Any?>>): Map<String, Any?> = mapOf(
        "mode" to "summary",
        "filter" to "",
        "severities" to listOf("error", "warning"),
        "groups" to groups,
        "groupsTotal" to groups.size,
        "groupsReturned" to groups.size,
        "matchedItems" to groups.sumOf { (it["count"] as? Number)?.toInt() ?: 0 },
        "errorPackets" to 12,
        "warningPackets" to 3,
        "totalItems" to 15,
        "coverageComplete" to true,
        "sampled" to true,
        "sourceTruncated" to false,
        "returned" to groups.size,
        "total" to groups.size,
        "truncated" to false,
        "continuation" to mapOf(
            "tool" to "get_expert_info",
            "mode" to "items",
            "hint" to "Pass groupKey to read the entries of one group.",
            "availableGroupKeys" to groups.map { it["groupKey"] }
        )
    )

    /** One `AgentExpertGroup.toAgentJson()`. */
    private fun expertGroup(
        groupKey: String,
        severity: String,
        summary: String,
        count: Any?
    ): Map<String, Any?> = mapOf(
        "groupKey" to groupKey,
        "severity" to severity,
        "summary" to summary,
        "count" to count,
        "firstFrame" to 12L,
        "lastFrame" to 87L,
        "sampleFrames" to listOf(12L, 45L, 87L),
        "displayFilter" to groupKey.substringAfter('/')
    )

    /** Mirrors ExpertInfoTool item-mode result. */
    private fun expertItemsPayload(
        items: List<Map<String, Any?>>,
        groupKey: String? = null,
        total: Int = items.size
    ): Map<String, Any?> = mapOf(
        "mode" to "items",
        "groupKey" to groupKey,
        "items" to items,
        "severities" to listOf("error", "warning"),
        "offset" to 0,
        "limit" to 20,
        "returned" to items.size,
        "total" to total,
        "truncated" to false,
        "sourceTruncated" to false,
        "errorPackets" to 3,
        "warningPackets" to 1,
        "totalItems" to 4
    )

    /** One `AgentExpertInfoEntry.toAgentJson()`. */
    private fun expertItem(
        frameNumber: Long,
        severity: String,
        label: String,
        displayFilter: String?
    ): Map<String, Any?> = mapOf(
        "frameNumber" to frameNumber,
        "severity" to severity,
        "label" to label,
        "displayFilter" to displayFilter
    )

    private fun overviewCall(
        data: Map<String, Any?>?,
        success: Boolean = true,
        toolCallId: String = "host-bootstrap-overview-1"
    ) = HostCallPayload(toolCallId, AgentSignalExtractor.TOOL_CAPTURE_OVERVIEW, success, data)

    private fun expertCall(
        data: Map<String, Any?>?,
        success: Boolean = true,
        toolCallId: String = "host-bootstrap-expert-2"
    ) = HostCallPayload(toolCallId, AgentSignalExtractor.TOOL_EXPERT_INFO, success, data)

    // ------------------------------------------------------------ health

    @Test
    fun overviewHealthProducesSignalsForProblemFamiliesOnly() {
        val set = extractor.extract(
            listOf(
                overviewCall(
                    overviewPayload(
                        health = mapOf(
                            "tcp" to healthEntry(events = 90, problems = 5, severity = "error"),
                            "dns" to healthEntry(events = 10, problems = 0, severity = "healthy"),
                            "tls" to healthEntry(events = 4, problems = 0, severity = "notice"),
                            "http" to healthEntry(events = 8, problems = 1, severity = "notice")
                        ),
                        protocolHierarchy = null
                    )
                )
            )
        )
        assertEquals(
            listOf(
                AgentSignal(set.signalIds[0], "health_problems", "5", "problems"),
                AgentSignal(set.signalIds[1], "health_problems", "1", "problems")
            ),
            set.signals
        )
        assertEquals(0, set.droppedSignalCount)
    }

    @Test
    fun healthAtWarningSeverityWithoutProblemsStillSignals() {
        val set = extractor.extract(
            listOf(
                overviewCall(
                    overviewPayload(
                        health = mapOf(
                            "tls" to healthEntry(events = 20, problems = 0, severity = "warning"),
                            "dns" to healthEntry(events = 3, problems = null, severity = "healthy")
                        ),
                        protocolHierarchy = null
                    )
                )
            )
        )
        // tls qualifies on severity alone (value "0"); dns has neither
        // problems nor severity and is skipped, as is the missing-problems
        // family at healthy severity.
        assertEquals(1, set.signals.size)
        assertEquals("health_problems", set.signals.single().kind)
        assertEquals("0", set.signals.single().value)
        assertEquals("problems", set.signals.single().unit)
    }

    @Test
    fun healthSeverityIsPartOfSignalIdentity() {
        fun idFor(severity: String, problems: Int): String = extractor.extract(
            listOf(
                overviewCall(
                    overviewPayload(
                        health = mapOf("tcp" to healthEntry(events = 9, problems, severity)),
                        protocolHierarchy = null
                    )
                )
            )
        ).signals.single().signalId
        assertTrue(idFor("notice", 1) != idFor("warning", 1))
        assertTrue(idFor("warning", 1) != idFor("warning", 2))
    }

    // ------------------------------------------------------------ expert

    @Test
    fun expertSummaryGroupsYieldOnlyNonzeroIdentifiableGroups() {
        val set = extractor.extract(
            listOf(
                expertCall(
                    expertSummaryPayload(
                        listOf(
                            expertGroup(
                                "error/tcp.analysis.retransmission", "error",
                                "TCP fast retransmission", 47
                            ),
                            expertGroup(
                                "warning/tcp.analysis.zero_window", "warning",
                                "Zero window", 0
                            ),
                            expertGroup("error/bogus.checksum", "error", "Bad", "abc"),
                            expertGroup("", "warning", "Splits the map", 3),
                            expertGroup("", "", "", 3)
                        )
                    )
                )
            )
        )
        // count 0 and unparseable counts are skipped; a group without a
        // key falls back to "severity/summary"; with neither it is noise.
        assertEquals(listOf("47", "3"), set.signals.map { it.value })
        assertEquals(listOf("expert_group", "expert_group"), set.signals.map { it.kind })
        assertEquals(listOf("items", "items"), set.signals.map { it.unit })
    }

    @Test
    fun expertItemPageAggregatesReturnedItemsPerGroup() {
        val set = extractor.extract(
            listOf(
                expertCall(
                    expertItemsPayload(
                        listOf(
                            expertItem(3, "error", "TCP fast retransmission", "tcp.analysis.retransmission"),
                            expertItem(9, "error", "TCP fast retransmission", "tcp.analysis.retransmission"),
                            expertItem(11, "error", "TCP fast retransmission", "tcp.analysis.retransmission"),
                            expertItem(12, "warn", "Zero window", "tcp.analysis.zero_window"),
                            expertItem(13, "error", "Bad checksum [0x1234]", null),
                            expertItem(14, "error", "Bad checksum [0xbeef]", null)
                        )
                    )
                )
            )
        )
        // 3 retransmissions, 1 zero-window (native "warn" normalizes to the
        // "warning" wire name), and the two checksum labels collapse to one
        // normalized-label group, exactly as AgentExpertGrouper would.
        // Order: error groups (by key: "bad checksum #" before
        // "tcp.analysis.retransmission"), then the warning group.
        assertEquals(3, set.signals.size)
        assertEquals(listOf("2", "3", "1"), set.signals.map { it.value })
        assertTrue(set.signals.all { it.kind == "expert_group" && it.unit == "items" })
    }

    @Test
    fun expertDrilldownReportsTheGroupsTotalNotItsPage() {
        val set = extractor.extract(
            listOf(
                expertCall(
                    expertItemsPayload(
                        listOf(
                            expertItem(3, "error", "TCP fast retransmission", "tcp.analysis.retransmission"),
                            expertItem(9, "error", "TCP fast retransmission", "tcp.analysis.retransmission")
                        ),
                        groupKey = "error/tcp.analysis.retransmission",
                        total = 47
                    )
                )
            )
        )
        assertEquals(1, set.signals.size)
        assertEquals("47", set.signals.single().value)
    }

    @Test
    fun sameGroupAndCountDedupeAcrossItemAndSummaryShapes() {
        val items = (1..3).map {
            expertItem(it.toLong(), "error", "TCP fast retransmission", "tcp.analysis.retransmission")
        }
        val set = extractor.extract(
            listOf(
                expertCall(expertItemsPayload(items)),
                expertCall(
                    expertSummaryPayload(
                        listOf(
                            expertGroup(
                                "error/tcp.analysis.retransmission", "error",
                                "TCP fast retransmission", 3
                            )
                        )
                    )
                )
            )
        )
        // Same category, same count: one signal, no matter that the two
        // calls spelled it in different shapes.
        assertEquals(1, set.signals.size)
    }

    // ---------------------------------------------------------- protocol

    @Test
    fun protocolShareFlagsAtThresholdAndNotBelow() {
        val set = extractor.extract(
            listOf(
                overviewCall(
                    overviewPayload(
                        health = null,
                        protocolHierarchy = listOf(
                            protocolEntry("TCP", 50.0),
                            protocolEntry("UDP", 49.999),
                            protocolEntry("HTTP", 73.25),
                            protocolEntry("", 99.0),
                            protocolEntry("DNS", "not-a-number"),
                            protocolEntry("TLS", null),
                            protocolEntry("IP", "61.5")
                        )
                    )
                )
            )
        )
        // 50.0 inclusive, 49.999 below; blank name and non-numeric percent
        // are skipped; a numeric string is tolerated. Ordering is by percent
        // descending.
        assertEquals(listOf("73.250", "61.500", "50.000"), set.signals.map { it.value })
        assertTrue(set.signals.all { it.kind == "protocol_share" && it.unit == "percent" })
    }

    @Test
    fun overviewExpertScalarsAloneProduceNoExpertSignals() {
        val set = extractor.extract(
            listOf(
                overviewCall(
                    overviewPayload(
                        health = null,
                        protocolHierarchy = null,
                        expertErrorCount = 7,
                        expertWarningCount = 2
                    )
                )
            )
        )
        // The scalars name no group; per-group facts come from get_expert_info.
        assertTrue(set.isEmpty)
    }

    // -------------------------------------------------- order/dedupe/cap

    @Test
    fun orderingIsExpertBySeverityThenHealthThenProtocol() {
        val set = extractor.extract(
            listOf(
                overviewCall(
                    overviewPayload(
                        health = mapOf(
                            "http" to healthEntry(8, 2, "warning"),
                            "tcp" to healthEntry(90, 3, "error")
                        ),
                        protocolHierarchy = listOf(protocolEntry("TCP", 88.8))
                    )
                ),
                expertCall(
                    expertSummaryPayload(
                        listOf(
                            expertGroup(
                                "warning/tcp.analysis.zero_window", "warning",
                                "Zero window", 4
                            ),
                            expertGroup(
                                "error/tcp.analysis.retransmission", "error",
                                "TCP fast retransmission", 9
                            )
                        )
                    )
                )
            )
        )
        assertEquals(
            listOf(
                Triple("expert_group", "9", "items"),
                Triple("expert_group", "4", "items"),
                Triple("health_problems", "3", "problems"),
                Triple("health_problems", "2", "problems"),
                Triple("protocol_share", "88.800", "percent")
            ),
            set.signals.map { Triple(it.kind, it.value, it.unit) }
        )
    }

    @Test
    fun capFoldsOverflowIntoSignalsCapped() {
        val groups = (0 until 25).map { i ->
            expertGroup("error/cat%02d".format(i), "error", "Group $i", i + 1)
        }
        val set = extractor.extract(listOf(expertCall(expertSummaryPayload(groups))))
        assertEquals(20, set.signals.size)
        assertEquals(6, set.droppedSignalCount)
        // First 19 by (severity, key) order survive; values were 1..25.
        assertEquals("1", set.signals.first().value)
        assertEquals("19", set.signals[18].value)
        val capped = set.signals.last()
        assertEquals("signals_capped", capped.kind)
        assertEquals("6", capped.value)
        assertEquals("signals", capped.unit)
        assertEquals(19, set.signals.take(19).count { it.kind == "expert_group" })
    }

    @Test
    fun dedupeHappensBeforeCapAcrossRepeatedCalls() {
        val groups = (0 until 25).map { i ->
            expertGroup("error/cat%02d".format(i), "error", "Group $i", i + 1)
        }
        val call = expertCall(expertSummaryPayload(groups), toolCallId = "model-call-9")
        // The same 25 groups reported twice: 25 distinct signals, so the
        // drop count is 6, not 31.
        val set = extractor.extract(listOf(call, call))
        assertEquals(20, set.signals.size)
        assertEquals(6, set.droppedSignalCount)
        val single = extractor.extract(listOf(call))
        assertEquals(single.signalIds, set.signalIds)
    }

    // -------------------------------------------------------- tolerance

    @Test
    fun failedAndUnrelatedCallsProduceNothing() {
        val validOverview = overviewPayload(
            health = mapOf("tcp" to healthEntry(90, 5, "error")),
            protocolHierarchy = listOf(protocolEntry("TCP", 90.0))
        )
        val set = extractor.extract(
            listOf(
                overviewCall(validOverview, success = false),
                HostCallPayload("call-1", "search_packets", true, validOverview),
                HostCallPayload("call-2", "get_expert_info", false, expertSummaryPayload(emptyList()))
            )
        )
        assertTrue(set.isEmpty)
        assertEquals(0, set.droppedSignalCount)
    }

    @Test
    fun malformedPayloadsAreToleratedAndNeverThrow() {
        val cases = listOf(
            null,
            emptyMap(),
            mapOf("health" to "not-a-map", "protocolHierarchy" to 42),
            mapOf("health" to mapOf("" to healthEntry(1, 5, "error"))),
            mapOf("health" to mapOf("tcp" to listOf(1, 2))),
            mapOf("protocolHierarchy" to listOf("row", mapOf("name" to "TCP")))
        )
        cases.forEach { data ->
            val set = extractor.extract(listOf(overviewCall(data)))
            assertTrue("expected no signals from $data", set.isEmpty)
        }
        listOf(
            null,
            emptyMap(),
            mapOf("groups" to "not-a-list"),
            mapOf("groups" to listOf("row", 7, mapOf("count" to -3))),
            mapOf("items" to 42),
            mapOf("items" to listOf("row", mapOf("severity" to "", "label" to ""))),
            mapOf("items" to emptyList<Map<String, Any?>>(), "groupKey" to "error/x", "total" to 0)
        ).forEach { data ->
            val set = extractor.extract(listOf(expertCall(data)))
            assertTrue("expected no signals from $data", set.isEmpty)
        }
    }

    @Test
    fun emptyInputProducesEmptySet() {
        val set = extractor.extract(emptyList())
        assertTrue(set.isEmpty)
        assertEquals(emptyList<String>(), set.signalIds)
        assertEquals(0, set.droppedSignalCount)
    }

    // ---------------------------------------------------------- stability

    @Test
    fun signalIdsAreStableWellFormedAndContentKeyed() {
        val payload = overviewPayload(
            health = mapOf("tcp" to healthEntry(90, 5, "error")),
            protocolHierarchy = listOf(protocolEntry("TCP", 66.0))
        ) + mapOf("unused" to true)
        val first = extractor.extract(listOf(overviewCall(payload)))
        val second = extractor.extract(listOf(overviewCall(payload)))
        assertEquals(first.signalIds, second.signalIds)
        first.signalIds.forEach { id ->
            assertTrue("malformed id $id", Regex("sig-[0-9a-f]{12}").matches(id))
        }
        // Different content gives different ids.
        val changed = extractor.extract(
            listOf(
                overviewCall(
                    overviewPayload(
                        health = mapOf("tcp" to healthEntry(90, 6, "error")),
                        protocolHierarchy = listOf(protocolEntry("TCP", 66.0))
                    )
                )
            )
        )
        assertTrue(first.signalIds.toSet() != changed.signalIds.toSet())
        // The id must not leak frame numbers or free text beyond what the
        // hash exposes: same kind/value/unit, different frame content only.
        val withFrames = extractor.extract(
            listOf(
                overviewCall(
                    overviewPayload(
                        health = mapOf("tcp" to healthEntry(90, 5, "error", firstProblemFrame = 999L)),
                        protocolHierarchy = listOf(protocolEntry("TCP", 66.0))
                    )
                )
            )
        )
        assertEquals(first.signalIds, withFrames.signalIds)
    }

    @Test
    fun extractFromResultsMirrorsHostCallPayloadPath() {
        val data = overviewPayload(
            health = mapOf("tcp" to healthEntry(90, 5, "error")),
            protocolHierarchy = null
        )
        val results = listOf(
            AgentToolResult(
                toolCallId = "host-bootstrap-overview-1",
                toolName = "get_capture_overview",
                success = true,
                data = data
            ),
            AgentToolResult(
                toolCallId = "host-bootstrap-expert-2",
                toolName = "get_expert_info",
                success = false,
                data = null
            )
        )
        assertEquals(
            extractor.extract(listOf(overviewCall(data))),
            extractor.extractFromResults(results)
        )
    }
}
