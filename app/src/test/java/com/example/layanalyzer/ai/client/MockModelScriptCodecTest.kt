// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentToolDefinition
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MockModelScriptCodecTest {

    @Test
    fun captureOverviewFixtureDecodesIntoARunnableScript() = runBlocking {
        val script = MockModelScriptCodec.decode(fixture("capture_overview_success.json"))

        assertEquals("capture_overview_success_json", script.id)
        assertEquals(3, script.turnCount)
        assertEquals(128_000, script.capabilities.maxContextTokens)
        assertFalse(script.capabilities.parallelToolCalls)

        val client = MockAiModelClient(script)
        val first = client.respond(request("req-1"))
        val overview = (first as AgentModelResponse.ToolCalls).calls.single()
        assertEquals("get_capture_overview", overview.toolName)
        // Nested JSON argument values survive as plain Kotlin types.
        assertEquals("complete_file", overview.arguments["scope"])
        assertEquals(1.0, (overview.arguments["statisticsBucketSeconds"] as Number).toDouble(), 0.0)
    }

    @Test
    fun inlineReportIsDecodedThroughTheCanonicalCodec() = runBlocking {
        val script = MockModelScriptCodec.decode(fixture("capture_overview_success.json"))
        val client = MockAiModelClient(script)

        client.respond(request("req-1"))
        client.respond(request("req-2", toolResult("call-overview", "get_capture_overview")))
        val final = client.respond(request("req-3", toolResult("call-expert", "get_expert_info")))

        val report = (final as AgentModelResponse.Final).report
        assertNotNull(report)
        assertEquals("finding-retransmissions", report?.findings?.single()?.id)
        // The raw JSON is preserved too, so host-side decoding stays testable.
        assertNotNull(final.rawJson)
    }

    @Test
    fun failureFixtureCarriesTheDeclaredErrorCode() = runBlocking {
        val script = MockModelScriptCodec.decode(fixture("session_changed.json"))
        val client = MockAiModelClient(script)

        client.respond(request("req-1"))
        client.respond(request("req-2", toolResult("call-overview", "get_capture_overview")))
        val failure = client.respond(request("req-3", toolResult("call-expert", "get_expert_info")))

        val error = (failure as AgentModelResponse.Failure).error
        assertEquals(AgentErrorCode.SESSION_CHANGED, error.code)
        assertEquals("session_changed", error.details["reason"])
    }

    @Test
    fun delayFixtureKeepsItsCancellableDelay() {
        val script = MockModelScriptCodec.decode(fixture("cancellation.json"))

        assertTrue(script.responses.all { it.delayMillis > 0L })
    }

    @Test
    fun preEncodedFinalIsLeftForTheHostToDecode() {
        val script = MockModelScriptCodec.decode(fixture("cancellation.json"))

        val final = script.responses.last().response as AgentModelResponse.Final
        assertNotNull(final.rawJson)
        // reportJson-only turns intentionally arrive undecoded.
        assertEquals(null, final.report)
    }

    @Test
    fun trailingTurnsWithoutExpectationsAreNotPadded() {
        val script = MockModelScriptCodec.decode(fixture("max_steps.json"))

        assertEquals(4, script.turnCount)
        assertTrue(script.expectedRequests.isEmpty())
    }

    @Test
    fun assetBundleDecodesEveryScript() {
        val scripts = MockModelScriptCodec.decodeAll(asset("agent_mock_scripts.json"))

        assertEquals(listOf("demo_capture_overview"), scripts.map { it.id })
        assertEquals(3, scripts.single().turnCount)
    }

    @Test
    fun everyTestFixtureDecodesWithAUniqueId() {
        val ids = FIXTURES.map { MockModelScriptCodec.decode(fixture(it)).id }

        assertEquals(FIXTURES.size, ids.toSet().size)
        // Fixture ids stay distinct from the compiled library's ids, so a test
        // cannot accidentally assert against the wrong source of a scenario.
        assertTrue(ids.none { it in MockModelScriptLibrary.ids })
    }

    @Test
    fun unknownTurnTypeIsRejected() {
        val failure = runCatching {
            MockModelScriptCodec.decode(
                """{"id":"bad","turns":[{"type":"stream_delta"}]}"""
            )
        }.exceptionOrNull()

        assertTrue(failure is IllegalArgumentException)
        assertTrue(failure?.message?.contains("stream_delta") == true)
    }

    @Test
    fun futureSchemaVersionIsRejectedRatherThanReadWithOlderSemantics() {
        val failure = runCatching {
            MockModelScriptCodec.decode(
                """{"schemaVersion":99,"id":"future","turns":[{"type":"refusal","reason":"no"}]}"""
            )
        }.exceptionOrNull()

        assertTrue(failure is IllegalArgumentException)
    }

    @Test
    fun malformedTurnsAreRejectedWithAPointedMessage() {
        val cases = mapOf(
            """{"id":"a","turns":[]}""" to "empty turns array",
            """{"id":"b","turns":[{"type":"tool_calls","calls":[]}]}""" to "empty calls array",
            """{"id":"c","turns":[{"type":"tool_calls","calls":[{"toolName":"x"}]}]}""" to "no toolCallId",
            """{"id":"d","turns":[{"type":"final"}]}""" to "report or reportJson",
            """{"id":"e","turns":[{"type":"failure","error":{"code":"NOPE"}}]}""" to "unknown error code",
            """{"turns":[{"type":"refusal","reason":"x"}]}""" to "non-blank id"
        )

        cases.forEach { (json, _) ->
            val failure = runCatching { MockModelScriptCodec.decode(json) }.exceptionOrNull()
            assertTrue(json, failure is IllegalArgumentException)
        }
    }

    @Test
    fun negativeDelayIsRejected() {
        val failure = runCatching {
            MockModelScriptCodec.decode(
                """{"id":"neg","turns":[{"type":"refusal","reason":"x","delayMillis":-1}]}"""
            )
        }.exceptionOrNull()

        assertTrue(failure is IllegalArgumentException)
    }

    /** A request shaped like the one AgentLoop builds for its first turn. */
    private fun request(
        requestId: String,
        vararg extraMessages: AgentModelMessage
    ) = AgentModelRequest(
        requestId = requestId,
        messages = listOf(AgentModelMessage.user("Why is this capture slow?")) + extraMessages,
        toolDefinitions = listOf(
            AgentToolDefinition(name = "get_capture_overview"),
            AgentToolDefinition(name = "get_expert_info"),
            AgentToolDefinition(name = "validate_display_filter")
        ),
        responseSchema = mapOf("type" to "object")
    )

    private fun toolResult(toolCallId: String, toolName: String) = AgentModelMessage(
        role = AgentModelMessageRole.Tool,
        content = "{}",
        toolCallId = toolCallId,
        toolName = toolName,
        untrustedCaptureData = true
    )

    private fun fixture(name: String): String = readResource("agent/mock_scripts/$name")

    /**
     * The Debug demo bundle lives in main assets rather than test resources, so
     * it is read from its source path; JVM tests have no AssetManager.
     */
    private fun asset(name: String): String {
        val file = java.io.File("src/main/assets/$name")
        val resolved = if (file.exists()) file else java.io.File("app/src/main/assets/$name")
        assertTrue("Missing asset: $name", resolved.exists())
        return resolved.readText()
    }

    private fun readResource(path: String): String {
        val stream = checkNotNull(javaClass.classLoader?.getResourceAsStream(path)) {
            "Missing test resource: $path"
        }
        return stream.bufferedReader().use { it.readText() }
    }

    private companion object {
        val FIXTURES = listOf(
            "capture_overview_success.json",
            "invalid_filter_recovery.json",
            "cancellation.json",
            "max_steps.json",
            "session_changed.json"
        )
    }
}
