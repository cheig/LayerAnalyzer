// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentBudgetTracker
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.ExpertInfoItem
import com.example.layanalyzer.model.ExpertInfoSummary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExpertInfoToolTest {
    @Test
    fun noExpertInfoReturnsAnEmptyPageWithoutFailing() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val result = harness.runExpert()

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertTrue((data["items"] as List<*>).isEmpty())
            assertEquals(0, data["returned"])
            assertEquals(0, data["total"])
            assertEquals(false, data["truncated"])
        }
    }

    @Test
    fun everyEntryCarriesFrameNumberSeverityAndDrillDownFilter() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(item(4L, "warning"), item(9L, "error"))
        }.use { harness ->
            val result = harness.runExpert()

            @Suppress("UNCHECKED_CAST")
            val items = requireNotNull(result.data)["items"] as List<Map<String, Any?>>
            assertEquals(2, items.size)
            items.forEach { entry ->
                assertTrue((entry["frameNumber"] as Long) > 0L)
                assertNotNull(entry["severity"])
                assertNotNull(entry["displayFilter"])
            }
            assertEquals(4L, items[0]["frameNumber"])
            assertEquals("warning", items[0]["severity"])
            assertEquals("frame.number == 4", items[0]["displayFilter"])
        }
    }

    @Test
    fun onlyWarningsAreReturnedWhenWarningSeverityIsRequested() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(
                item(1L, "warning"),
                item(2L, "error"),
                item(3L, "warning"),
                item(4L, "note")
            )
        }.use { harness ->
            val result = harness.runExpert(mapOf("severities" to listOf("warning")))

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val items = data["items"] as List<Map<String, Any?>>
            assertEquals(2, items.size)
            assertTrue(items.all { it["severity"] == "warning" })
            assertEquals(2, data["total"])
            assertEquals(listOf("warning"), data["severities"])
        }
    }

    @Test
    fun requestedSeverityOrderPrioritizesErrorsInTheBoundedBootstrapPage() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(
                item(1L, "warning"),
                item(2L, "error"),
                item(3L, "warning"),
                item(4L, "error")
            )
        }.use { harness ->
            val result = harness.runExpert(
                mapOf(
                    "severities" to listOf("error", "warning"),
                    "offset" to 0,
                    "limit" to 3
                )
            )

            @Suppress("UNCHECKED_CAST")
            val items = requireNotNull(result.data)["items"] as List<Map<String, Any?>>
            assertEquals(listOf("error", "error", "warning"), items.map { it["severity"] })
            assertEquals(listOf(2L, 4L, 1L), items.map { it["frameNumber"] })
            assertEquals(listOf("error", "warning"), result.data?.get("severities"))
        }
    }

    @Test
    fun pagingUsesOffsetAndLimitAndFlagsRemainingItems() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(*(1..10).map { item(it.toLong(), "note") }.toTypedArray())
        }.use { harness ->
            val firstPage = harness.runExpert(mapOf("limit" to 4))
            val firstData = requireNotNull(firstPage.data)
            assertEquals(4, firstData["returned"])
            assertEquals(10, firstData["total"])
            assertEquals(true, firstData["truncated"])

            val lastPage = harness.runExpert(mapOf("offset" to 8, "limit" to 4))
            val lastData = requireNotNull(lastPage.data)
            assertEquals(2, lastData["returned"])
            // The final page covers the tail, so paging adds no truncation.
            assertEquals(false, lastData["truncated"])

            @Suppress("UNCHECKED_CAST")
            val items = lastData["items"] as List<Map<String, Any?>>
            assertEquals(9L, items.first()["frameNumber"])
        }
    }

    @Test
    fun nativeTruncationIsPropagatedEvenWhenThePageFits() = runBlocking {
        AgentToolTestHarness.create {
            // The engine capped its own list: 2 items reported out of 500.
            expert = ExpertInfoSummary(
                errorPackets = 200,
                warningPackets = 300,
                items = listOf(item(1L, "error"), item(2L, "error")),
                totalItems = 500,
                truncated = true
            )
        }.use { harness ->
            val result = harness.runExpert()

            val data = requireNotNull(result.data)
            assertEquals(2, data["returned"])
            // Paging alone would say "complete"; the source flag must survive.
            assertEquals(true, data["truncated"])
            assertEquals(true, data["sourceTruncated"])
            assertEquals(500, data["totalItems"])
            assertTrue(result.truncated)
            assertEquals(500L, result.totalCount)
        }
    }

    @Test
    fun limitIsCappedAtOneHundred() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(*(1..150).map { item(it.toLong(), "note") }.toTypedArray())
        }.use { harness ->
            // Above the schema maximum the call is rejected outright.
            val rejected = harness.runExpert(mapOf("limit" to 500))
            assertFalse(rejected.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, rejected.error?.code)

            val atMax = harness.runExpert(mapOf("limit" to 100))
            assertEquals(100, requireNotNull(atMax.data)["returned"])
        }
    }

    @Test
    fun filterIsAppliedThroughTheLeaseAndRestoredAfterwards() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(item(3L, "error"))
        }.use { harness ->
            harness.coordinator.applyUserFilter("ip", harness.token)
            harness.source.appliedFilters.clear()

            val result = harness.runExpert(mapOf("filter" to "tcp"))

            assertTrue(result.success)
            assertEquals(listOf("tcp", "ip"), harness.source.appliedFilters)
            assertEquals("ip", harness.source.getAppliedDisplayFilter())
        }
    }

    @Test
    fun invalidFilterFailsWithoutChangingUserFilterState() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            harness.coordinator.applyUserFilter("ip", harness.token)
            harness.source.invalidFilters = setOf("tcp.port ===")
            harness.source.appliedFilters.clear()

            val result = harness.runExpert(mapOf("filter" to "tcp.port ==="))

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_DISPLAY_FILTER, result.error?.code)
            assertTrue(harness.source.appliedFilters.isEmpty())
            assertEquals("ip", harness.source.getAppliedDisplayFilter())
        }
    }

    @Test
    fun byteRangesAreNotSentToTheModel() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(item(5L, "error"))
        }.use { harness ->
            val result = harness.runExpert()
            val encoded = AgentResultTruncator.encode(requireNotNull(result.data))

            assertFalse(encoded.contains("\"start\""))
            assertFalse(encoded.contains("\"length\""))
            assertFalse(encoded.contains("localPath"))
        }
    }

    @Test
    fun sessionChangeIsRejectedWithAStructuredError() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(item(1L, "error"))
        }.use { harness ->
            val snapshot = harness.snapshot
            harness.coordinator.invalidateSession()

            val result = harness.runExpert(snapshot = snapshot)

            assertFalse(result.success)
            assertNull(result.data)
            assertNotNull(result.error)
        }
    }

    @Test
    fun unknownSeverityValueIsRejectedBySchema() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val result = harness.runExpert(mapOf("severities" to listOf("catastrophic")))

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
        }
    }

    /**
     * Native spells a warning "warn"; the tool vocabulary uses "warning". Without
     * the alias a real capture's warnings are invisible to a `severities` filter —
     * including the host's own bootstrap call, which asks for exactly that.
     */
    @Test
    fun nativeWarnSpellingIsMatchedByTheWarningSeverityFilter() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(
                item(1L, "warn"),
                item(2L, "error"),
                item(3L, "warn")
            )
        }.use { harness ->
            val result = harness.runExpert(mapOf("severities" to listOf("warning")))

            val data = requireNotNull(result.data)
            @Suppress("UNCHECKED_CAST")
            val items = data["items"] as List<Map<String, Any?>>
            assertEquals(2, items.size)
            // The model sees the normalized spelling regardless of the engine's.
            assertTrue(items.all { it["severity"] == "warning" })
            assertEquals(listOf(1L, 3L), items.map { it["frameNumber"] })
        }
    }

    /**
     * The real-capture shape: 228 entries over a 188-frame capture.
     *
     * The observed device result was only 10255 bytes yet still payload-trimmed,
     * because by then an earlier 29 KB call had eaten most of the run-wide
     * allowance. That is the condition reproduced here — a narrow remaining
     * budget, not an oversized ceiling — and it is why the decision reads
     * `resultByteAllowance` rather than the per-call maximum.
     */
    @Test
    fun oversizedEntryListReturnsTheDistributionInsteadOfATrimmedPage() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(*retransmissionStorm().toTypedArray())
        }.use { harness ->
            val result = harness.runExpert(
                arguments = mapOf("limit" to 100),
                policy = narrowRemainingBudget()
            )

            val data = requireNotNull(result.data)
            assertEquals("summary", data["mode"])
            assertNull("the entry list must not be returned in summary mode", data["items"])

            @Suppress("UNCHECKED_CAST")
            val groups = data["groups"] as List<Map<String, Any?>>
            assertTrue(groups.isNotEmpty())
            // The distribution covers every matching entry, not just a page.
            assertEquals(228, data["matchedItems"])
            assertEquals(228, groups.sumOf { it["count"] as Int })

            // The byte trim must not have been what shortened this result, and
            // the distribution must be markedly cheaper than the 10255-byte page
            // it replaces.
            assertFalse(result.truncation.payloadTruncated)
            assertTrue(
                "summary was ${result.resultBytes} bytes",
                result.resultBytes < 4_096
            )
        }
    }

    /** Every advertised group key must actually select that group's entries. */
    @Test
    fun groupKeyFromTheSummaryDrillsDownToThatGroupsEntries() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(*retransmissionStorm().toTypedArray())
        }.use { harness ->
            val summary = harness.runExpert(
                arguments = mapOf("limit" to 100),
                policy = narrowRemainingBudget()
            )
            @Suppress("UNCHECKED_CAST")
            val continuation = requireNotNull(summary.data)["continuation"] as Map<String, Any?>
            @Suppress("UNCHECKED_CAST")
            val keys = continuation["availableGroupKeys"] as List<String>
            assertTrue(keys.isNotEmpty())

            keys.forEach { key ->
                val drilled = harness.runExpert(mapOf("groupKey" to key, "limit" to 5))
                val data = requireNotNull(drilled.data)
                assertEquals(
                    "a named group must return entries, not another summary",
                    "items",
                    data["mode"]
                )
                @Suppress("UNCHECKED_CAST")
                val items = data["items"] as List<Map<String, Any?>>
                assertTrue("group $key selected nothing", items.isNotEmpty())
                // Whatever is incomplete about a drill-down is ordinary paging
                // within the group, so the continuation must be a usable next
                // page rather than a dead end.
                if (drilled.truncation.truncated) {
                    assertNotEquals(false, drilled.truncation.continuation?.get("available"))
                }
            }
        }
    }

    /**
     * A drill-down that asks for the whole group must come back complete — this
     * is the payoff of the two-hop flow, so if it were still trimmed the summary
     * would have bought nothing.
     */
    @Test
    fun drillDownSizedToTheGroupReturnsEveryEntryUntrimmed() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(*retransmissionStorm().toTypedArray())
        }.use { harness ->
            val drilled = harness.runExpert(
                mapOf("groupKey" to "error/tcp.checksum_bad", "limit" to 100)
            )

            val data = requireNotNull(drilled.data)
            assertEquals("items", data["mode"])
            assertEquals(12, (data["items"] as List<*>).size)
            assertEquals(12, data["total"])
            assertEquals(false, data["truncated"])
            assertFalse(drilled.truncation.payloadTruncated)
        }
    }

    /** A small capture must behave exactly as it did before summary mode existed. */
    @Test
    fun smallEntryListStillReturnsItemsWithoutSummarizing() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(item(4L, "warning"), item(9L, "error"))
        }.use { harness ->
            val data = requireNotNull(harness.runExpert().data)

            assertEquals("items", data["mode"])
            assertEquals(2, (data["items"] as List<*>).size)
            assertEquals(false, data["truncated"])
        }
    }

    /** An explicit mode overrides the host's estimate in both directions. */
    @Test
    fun explicitModeArgumentOverridesTheByteEstimate() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(item(4L, "warning"), item(9L, "error"))
        }.use { harness ->
            val forcedSummary = harness.runExpert(mapOf("mode" to "summary"))
            assertEquals("summary", requireNotNull(forcedSummary.data)["mode"])

            val forcedItems = harness.runExpert(mapOf("mode" to "items"))
            assertEquals("items", requireNotNull(forcedItems.data)["mode"])
        }
    }

    /** The flag restores the pre-narrowing path for a one-line rollback. */
    @Test
    fun disablingEvidenceNarrowingRestoresTheFullEntryList() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(*retransmissionStorm().toTypedArray())
        }.use { harness ->
            val result = harness.runExpert(
                arguments = mapOf("limit" to 100),
                policy = AgentPolicy(evidenceNarrowingEnabled = false)
            )

            val data = requireNotNull(result.data)
            assertEquals("items", data["mode"])
            assertNotNull(data["items"])
        }
    }

    /**
     * A summary that accounted for every entry saw the whole capture, so it must
     * not be recorded as partial coverage — that would cap the report's
     * completeness for a read that in fact missed nothing.
     */
    @Test
    fun completeDistributionReportsCompleteCoverage() = runBlocking {
        AgentToolTestHarness.create {
            expert = summaryOf(*retransmissionStorm().toTypedArray())
        }.use { harness ->
            val data = requireNotNull(harness.runExpert(mapOf("mode" to "summary")).data)

            assertEquals(true, data["coverageComplete"])
            assertEquals(false, data["truncated"])
        }
    }

    private suspend fun AgentToolTestHarness.runExpert(
        arguments: Map<String, Any?> = emptyMap(),
        snapshot: AgentCaptureSnapshot = this.snapshot,
        policy: AgentPolicy = AgentPolicy()
    ) = AgentToolRunner(
        registry = AgentToolRegistry(ExpertInfoTool(Dispatchers.Unconfined)),
        repository = repository,
        policy = policy,
        budget = AgentBudgetTracker(policy)
    ).execute(
        AgentToolCall("call-1", "get_expert_info", arguments),
        snapshot,
        AgentPrivacyMode.RedactedMetadata
    )

    /**
     * A budget with little room left, as on the observed run where an earlier
     * call had already spent most of it.
     */
    private fun narrowRemainingBudget() = AgentPolicy(
        maxToolResultBytes = 8 * 1024,
        maxDetailResultBytesPerCall = 8 * 1024
    )

    /**
     * The observed device shape: 228 entries over a 188-frame capture, dominated
     * by a few repeating categories.
     */
    private fun retransmissionStorm(): List<ExpertInfoItem> = buildList {
        repeat(96) { index ->
            add(
                ExpertInfoItem(
                    frameNumber = index + 10L,
                    label = "This frame is a (suspected) retransmission of frame $index",
                    filter = "tcp.analysis.retransmission",
                    severity = "warn",
                    start = 0,
                    length = 0
                )
            )
        }
        repeat(80) { index ->
            add(
                ExpertInfoItem(
                    frameNumber = index + 120L,
                    label = "Duplicate ACK (#$index)",
                    filter = "tcp.analysis.duplicate_ack",
                    severity = "note",
                    start = 0,
                    length = 0
                )
            )
        }
        repeat(40) { index ->
            add(
                ExpertInfoItem(
                    frameNumber = index + 5L,
                    label = "This frame is a keep-alive segment",
                    filter = "tcp.analysis.keep_alive",
                    severity = "note",
                    start = 0,
                    length = 0
                )
            )
        }
        repeat(12) { index ->
            add(
                ExpertInfoItem(
                    frameNumber = index + 60L,
                    label = "Bad checksum [0x${index}f2a]",
                    filter = "tcp.checksum_bad",
                    severity = "error",
                    start = 0,
                    length = 0
                )
            )
        }
    }

    private fun item(frame: Long, severity: String) = ExpertInfoItem(
        frameNumber = frame,
        label = "Expert $severity at $frame",
        filter = "frame.number == $frame",
        severity = severity,
        start = 12,
        length = 4
    )

    private fun summaryOf(vararg items: ExpertInfoItem) = ExpertInfoSummary(
        errorPackets = items.count { it.severity == "error" },
        warningPackets = items.count { it.severity == "warning" || it.severity == "warn" },
        items = items.toList(),
        totalItems = items.size,
        truncated = false,
        analyzed = true
    )
}
