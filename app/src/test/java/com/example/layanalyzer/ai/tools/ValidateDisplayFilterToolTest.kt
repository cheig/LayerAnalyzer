// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ValidateDisplayFilterToolTest {
    @Test
    fun validFilterIsAcceptedAndNormalized() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val result = harness.runValidate("  tcp.port == 443  ")

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertEquals(true, data["valid"])
            assertEquals("tcp.port == 443", data["normalizedFilter"])
            assertNull(data["errorMessage"])
        }
    }

    @Test
    fun emptyFilterIsTreatedAsAValidClearFilter() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val result = harness.runValidate("")

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertEquals(true, data["valid"])
            assertEquals("", data["normalizedFilter"])
            // Nothing was compiled, so no filter reached the engine.
            assertTrue(harness.source.appliedFilters.isEmpty())
        }
    }

    @Test
    fun invalidFilterIsARecoverableFailureAndNotEvidence() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            harness.source.invalidFilters = setOf("tcp.port ===")

            val result = harness.runValidate("tcp.port ===")

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_DISPLAY_FILTER, result.error?.code)
            assertTrue(result.error?.retryable == true)
            assertNull(result.data)
        }
    }

    @Test
    fun validationNeverChangesTheSessionFilter() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            harness.coordinator.applyUserFilter("dns", harness.token)
            harness.source.appliedFilters.clear()
            harness.source.invalidFilters = setOf("bogus ===")

            harness.runValidate("tcp")
            harness.runValidate("bogus ===")

            // Neither the accepted nor the rejected filter was applied.
            assertTrue(harness.source.appliedFilters.isEmpty())
            assertEquals("dns", harness.source.getAppliedDisplayFilter())
            assertEquals("dns", harness.coordinator.state.value.appliedDisplayFilter)
        }
    }

    @Test
    fun missingFilterArgumentIsRejectedBySchema() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val result = harness.runner().execute(
                AgentToolCall("call-1", "validate_display_filter", emptyMap()),
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
        }
    }

    @Test
    fun overlyLongFilterIsRejectedBySchema() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val result = harness.runValidate("a".repeat(2_049))

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
        }
    }

    @Test
    fun sessionChangeSurfacesAsErrorRatherThanInvalidFilter() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val snapshot = harness.snapshot
            harness.coordinator.invalidateSession()

            val result = harness.runValidate("tcp", snapshot)

            assertFalse(result.success)
            // The filter itself was fine; reporting valid=false would mislead.
            assertNull(result.data)
            assertNotNull(result.error)
        }
    }

    private fun AgentToolTestHarness.runner() = AgentToolRunner(
        registry = AgentToolRegistry(ValidateDisplayFilterTool()),
        repository = repository
    )

    private suspend fun AgentToolTestHarness.runValidate(
        filter: String,
        snapshot: AgentCaptureSnapshot = this.snapshot
    ) = runner().execute(
        AgentToolCall("call-1", "validate_display_filter", mapOf("filter" to filter)),
        snapshot,
        AgentPrivacyMode.RedactedMetadata
    )
}
