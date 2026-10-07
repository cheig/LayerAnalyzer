package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.cache.AgentToolCache
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * AI-24 acceptance 5: a cache hit must not change what the tool boundary
 * guarantees.  Provenance, truncation and the session check all still apply.
 */
class AgentToolRunnerCacheTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `a second identical call is served from cache without re-executing the tool`() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = countingTool()
            val runner = runner(harness, tool)

            runner.execute(tool.call("call-1"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)
            val second = runner.execute(tool.call("call-2"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertEquals(1, tool.executionCount)
            assertTrue(second.success)
            assertEquals(mapOf("value" to "fresh"), second.data)
        }
    }

    @Test
    fun `a cache hit carries this run's provenance, not the provenance it was stored with`() =
        runBlocking {
            AgentToolTestHarness.create().use { harness ->
                val tool = countingTool()
                val runner = runner(harness, tool)

                val first = runner.execute(tool.call("call-1"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)
                val second = runner.execute(tool.call("call-2"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)

                // Same capture and tool, so these match...
                assertEquals(
                    first.provenance.captureFingerprint,
                    second.provenance.captureFingerprint
                )
                assertEquals(first.provenance.toolName, second.provenance.toolName)
                assertEquals(
                    first.provenance.normalizedArgumentsHash,
                    second.provenance.normalizedArgumentsHash
                )
                // ...but the call id and the returned counts belong to this call.
                assertEquals("call-2", second.toolCallId)
                assertEquals(first.returnedCount, second.returnedCount)
                assertEquals(first.totalCount, second.totalCount)
            }
        }

    @Test
    fun `a cache hit is still truncated against the budget left at that step`() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool(name = "wide_tool", sensitivity = AgentDataSensitivity.Aggregate) { _, context ->
                context.success(
                    data = mapOf("rows" to List(400) { "row-$it-with-some-length" }),
                    returnedCount = 400L,
                    totalCount = 400L
                )
            }
            // A tight per-result allowance forces the truncator to act on both
            // the fresh read and the cached replay.
            val runner = runner(harness, tool, policy = AgentPolicy(maxToolResultBytes = 1_024))

            val first = runner.execute(tool.call("call-1"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)
            val second = runner.execute(tool.call("call-2"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertEquals(1, tool.executionCount)
            assertTrue("fresh result should be truncated", first.truncated)
            assertTrue("cached result must be truncated too", second.truncated)
            assertTrue(second.provenance.truncated)
        }
    }

    @Test
    fun `a cache hit is re-redacted for the privacy mode in force now`() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool(name = "address_tool", sensitivity = AgentDataSensitivity.Identifier) { _, context ->
                context.success(
                    data = mapOf("address" to "192.168.10.44"),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val runner = runner(harness, tool)

            // Stored while local-only (no redaction), replayed for a cloud mode.
            val local = runner.execute(tool.call("call-1"), harness.snapshot, AgentPrivacyMode.LocalOnly)
            val redacted = runner.execute(tool.call("call-2"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertEquals(1, tool.executionCount)
            assertEquals("192.168.10.44", local.data?.get("address"))
            // The cached raw value must not escape under a mode that redacts.
            assertNotEquals("192.168.10.44", redacted.data?.get("address"))
        }
    }

    @Test
    fun `an argument change misses the cache and runs the tool again`() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = countingTool()
            val runner = runner(harness, tool)

            runner.execute(tool.call("call-1", arguments = mapOf("limit" to 5)), harness.snapshot, AgentPrivacyMode.RedactedMetadata)
            runner.execute(tool.call("call-2", arguments = mapOf("limit" to 6)), harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertEquals(2, tool.executionCount)
        }
    }

    @Test
    fun `an analysis config change invalidates the cached result`() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = countingTool()
            val runner = runner(harness, tool)

            runner.execute(tool.call("call-1"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)
            // A Decode As rule or a name-resolution toggle bumps this version.
            val reconfigured = harness.snapshot.copy(analysisConfigVersion = 2)
            runner.execute(tool.call("call-2"), reconfigured, AgentPrivacyMode.RedactedMetadata)

            assertEquals(2, tool.executionCount)
        }
    }

    @Test
    fun `a different native build invalidates the cached result`() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val cache = AgentToolCache(directory = temporaryFolder.root)
            val toolA = countingTool()
            val toolB = countingTool()

            runner(harness, toolA, cache = cache, nativeBuildMarker = "wireshark-4.0.10")
                .execute(toolA.call("call-1"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)
            runner(harness, toolB, cache = cache, nativeBuildMarker = "wireshark-4.2.0")
                .execute(toolB.call("call-2"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertEquals(1, toolA.executionCount)
            assertEquals(1, toolB.executionCount)
        }
    }

    @Test
    fun `a credential tool result never reaches the cache`() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val cache = AgentToolCache(directory = temporaryFolder.root)
            val tool = FakeTool(name = "secret_tool", sensitivity = AgentDataSensitivity.Credential) { _, context ->
                context.success(mapOf("token" to "super-secret"), 1L, 1L)
            }
            // The privacy gate refuses Credential outright, so the interesting
            // assertion is that nothing was written on the way through.
            runner(harness, tool, cache = cache)
                .execute(tool.call("call-1"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertEquals(0, cache.diskEntryCount())
            val onDisk = temporaryFolder.root.listFiles().orEmpty()
                .joinToString(separator = "") { it.readText() }
            assertFalse(onDisk.contains("super-secret"))
        }
    }

    @Test
    fun `a failed call is not cached, so a retry can still succeed`() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            var attempt = 0
            val tool = FakeTool(name = "flaky_tool", sensitivity = AgentDataSensitivity.Aggregate) { _, context ->
                attempt += 1
                if (attempt == 1) {
                    throw AgentToolException(
                        code = com.example.layanalyzer.model.AgentErrorCode.INTERNAL_ERROR,
                        userMessage = "transient"
                    )
                }
                context.success(mapOf("value" to "recovered"), 1L, 1L)
            }
            val runner = runner(harness, tool)

            val failed = runner.execute(tool.call("call-1"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)
            val retried = runner.execute(tool.call("call-2"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertFalse(failed.success)
            assertTrue(retried.success)
            assertEquals(mapOf("value" to "recovered"), retried.data)
        }
    }

    @Test
    fun `a cache hit is reported in the audit trail`() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val entries = mutableListOf<AgentToolAuditEntry>()
            val tool = countingTool()
            val runner = runner(harness, tool, auditLog = { entries += it })

            runner.execute(tool.call("call-1"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)
            runner.execute(tool.call("call-2"), harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertEquals(2, entries.size)
            assertFalse(entries[0].cacheHit)
            assertTrue(entries[1].cacheHit)
            // The hash is the same, which is what lets a caller correlate them.
            assertEquals(entries[0].normalizedArgumentsHash, entries[1].normalizedArgumentsHash)
        }
    }

    private fun countingTool() = FakeTool(
        name = "counting_tool",
        sensitivity = AgentDataSensitivity.Aggregate
    ) { _, context ->
        context.success(mapOf("value" to "fresh"), returnedCount = 1L, totalCount = 1L)
    }

    private fun runner(
        harness: AgentToolTestHarness,
        tool: AgentTool,
        cache: AgentToolCache = AgentToolCache(directory = temporaryFolder.root),
        nativeBuildMarker: String = "wireshark-test",
        policy: AgentPolicy = AgentPolicy(),
        auditLog: AgentToolAuditLog? = null
    ) = AgentToolRunner(
        registry = AgentToolRegistry(tool),
        repository = harness.repository,
        policy = policy,
        auditLog = auditLog,
        cache = cache,
        nativeBuildMarker = nativeBuildMarker
    )

    private fun call(
        id: String,
        toolName: String,
        arguments: AgentJsonObject = emptyMap()
    ) = AgentToolCall(
        toolCallId = id,
        toolName = toolName,
        arguments = arguments
    )

    /** Each test registers exactly one tool, so its name identifies the call. */
    private fun AgentTool.call(
        id: String,
        arguments: AgentJsonObject = emptyMap()
    ) = call(id, definition.name, arguments)
}
