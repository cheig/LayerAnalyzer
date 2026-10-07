package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketSearchToolTest {

    @Test
    fun aTextSearchReturnsMatchingFrameNumbersOnly() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            searchResults = mapOf("text:INVITE" to listOf(3L, 7L, 11L))
        }.use { harness ->
            val result = harness.runSearch(mapOf("mode" to "text", "query" to "INVITE"))

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertEquals(listOf(3L, 7L, 11L), data["frameNumbers"])
            assertEquals(3, data["returned"])
            assertEquals(3, data["total"])
            assertEquals(true, data["matched"])
            assertEquals(false, data["truncated"])

            // A search never dissects; reading the hits is a separate decision.
            assertTrue(harness.source.readDetailFrames.isEmpty())
        }
    }

    @Test
    fun noHitsIsASuccessfulResultDistinctFromAFailure() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val result = harness.runSearch(mapOf("mode" to "text", "query" to "nothing-matches"))

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertTrue((data["frameNumbers"] as List<*>).isEmpty())
            assertEquals(0, data["total"])
            // The flag is what separates "searched, found nothing" from "failed".
            assertEquals(false, data["matched"])
            assertEquals(false, data["truncated"])
            assertNull(result.error)
        }
    }

    @Test
    fun aLargeHitSetIsPagedAndTheRemainderIsFlagged() = runBlocking {
        AgentToolTestHarness.create(frameCount = 500) {
            searchResults = mapOf("text:GET" to (1L..300L).toList())
        }.use { harness ->
            val firstPage = harness.runSearch(
                mapOf("mode" to "text", "query" to "GET", "limit" to 10)
            )
            val firstData = requireNotNull(firstPage.data)
            assertEquals(10, firstData["returned"])
            assertEquals(300, firstData["total"])
            assertEquals(true, firstData["truncated"])
            assertEquals(1L, (firstData["frameNumbers"] as List<*>).first())

            val deepPage = harness.runSearch(
                mapOf("mode" to "text", "query" to "GET", "offset" to 295, "limit" to 10)
            )
            val deepData = requireNotNull(deepPage.data)
            assertEquals(5, deepData["returned"])
            assertEquals(false, deepData["truncated"])
            assertEquals(296L, (deepData["frameNumbers"] as List<*>).first())
        }
    }

    @Test
    fun invalidHexInputIsRejectedBeforeTheEngineIsCalled() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            listOf("zz", "0", "48 6x", "0x48").forEach { query ->
                val result = harness.runSearch(mapOf("mode" to "hex", "query" to query))
                assertFalse(query, result.success)
                assertEquals(query, AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
            }
        }
    }

    @Test
    fun wellFormedHexIsAccepted() = runBlocking {
        AgentToolTestHarness.create {
            searchResults = mapOf("hex:48 65 6c" to listOf(2L))
        }.use { harness ->
            val result = harness.runSearch(mapOf("mode" to "hex", "query" to "48 65 6c"))

            assertTrue(result.success)
            assertEquals(listOf(2L), requireNotNull(result.data)["frameNumbers"])
        }
    }

    @Test
    fun fieldModeRejectsAnythingThatIsNotABareFieldName() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            // Field search asks whether a field is present; it is not a filter.
            listOf(
                "sip.Method == INVITE",
                "tcp.port == 443 || udp.port == 53",
                "frame.number > 10",
                "ip.src == \"10.0.0.1\"",
                "sip.Method and sip.Via"
            ).forEach { query ->
                val result = harness.runSearch(mapOf("mode" to "field", "query" to query))
                assertFalse(query, result.success)
                assertEquals(query, AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
            }
        }
    }

    @Test
    fun fieldModeAcceptsABareFieldName() = runBlocking {
        AgentToolTestHarness.create {
            searchResults = mapOf("field:sip.Call-ID" to listOf(4L, 5L))
        }.use { harness ->
            val result = harness.runSearch(mapOf("mode" to "field", "query" to "sip.Call-ID"))

            assertTrue(result.success)
            assertEquals(listOf(4L, 5L), requireNotNull(result.data)["frameNumbers"])
        }
    }

    @Test
    fun numberModeRequiresAPositiveFrameNumber() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            listOf("0", "-3", "abc", "1.5").forEach { query ->
                val result = harness.runSearch(mapOf("mode" to "number", "query" to query))
                assertFalse(query, result.success)
                assertEquals(query, AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
            }

            val ok = harness.runSearch(mapOf("mode" to "number", "query" to "7"))
            assertTrue(ok.success)
        }
    }

    @Test
    fun anUnknownModeIsRejectedBySchema() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val result = harness.runSearch(mapOf("mode" to "regex", "query" to ".*"))

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
        }
    }

    @Test
    fun modeAndQueryAreBothRequired() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            assertFalse(harness.runSearch(mapOf("query" to "INVITE")).success)
            assertFalse(harness.runSearch(mapOf("mode" to "text")).success)
            assertFalse(harness.runSearch(mapOf("mode" to "text", "query" to "")).success)
        }
    }

    @Test
    fun searchRunsUnderTheTemporaryFilterAndRestoresTheUserFilter() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            searchResults = mapOf("text:INVITE" to listOf(3L))
        }.use { harness ->
            harness.coordinator.applyUserFilter("ip", harness.token)
            harness.source.appliedFilters.clear()

            val result = harness.runSearch(
                mapOf("mode" to "text", "query" to "INVITE", "filter" to "sip")
            )

            assertTrue(result.success)
            assertEquals(listOf("sip", "ip"), harness.source.appliedFilters)
            assertEquals("ip", harness.source.getAppliedDisplayFilter())
        }
    }

    @Test
    fun anInvalidFilterIsRejectedWithoutSearching() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            harness.source.invalidFilters = setOf("sip.Method ===")

            val result = harness.runSearch(
                mapOf("mode" to "text", "query" to "INVITE", "filter" to "sip.Method ===")
            )

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_DISPLAY_FILTER, result.error?.code)
        }
    }

    @Test
    fun sessionChangeIsRejectedWithAStructuredError() = runBlocking {
        AgentToolTestHarness.create {
            searchResults = mapOf("text:INVITE" to listOf(1L))
        }.use { harness ->
            val snapshot = harness.snapshot
            harness.coordinator.invalidateSession()

            val result = harness.runSearch(
                mapOf("mode" to "text", "query" to "INVITE"),
                snapshot = snapshot
            )

            assertFalse(result.success)
            assertNull(result.data)
            assertNotNull(result.error)
        }
    }

    private suspend fun AgentToolTestHarness.runSearch(
        arguments: Map<String, Any?> = emptyMap(),
        snapshot: AgentCaptureSnapshot = this.snapshot
    ) = AgentToolRunner(
        registry = AgentToolRegistry(PacketSearchTool(Dispatchers.Unconfined)),
        repository = repository
    ).execute(
        AgentToolCall("call-1", "search_packets", arguments),
        snapshot,
        AgentPrivacyMode.RedactedMetadata
    )
}
