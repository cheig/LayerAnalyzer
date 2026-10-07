package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentPrivacyMode
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 0 gate for prompt-cache work.
 *
 * Prompt caching is a pure prefix byte match: one differing byte anywhere in
 * the prefix invalidates every cache breakpoint after it.  Anthropic renders a
 * request as tools -> system -> messages, so the 14 tool schemas are the very
 * first bytes of every request and the most valuable static prefix we have.
 *
 * That prefix is only reusable if it serializes identically every time.  Tool
 * schemas are built from Kotlin `mapOf` (insertion-ordered LinkedHashMap) but
 * are rendered through `org.json.JSONObject`, whose key order is an
 * implementation detail.  These tests pin the property rather than the
 * implementation: if a future JSON backend (or an Android platform difference)
 * reorders keys, cache work downstream is silently worthless, so this must fail
 * loudly instead.
 */
class ToolSchemaSerializationDeterminismTest {

    @Test
    fun toolDefinitionOrderIsStableAcrossRegistryInstances() {
        val first = AgentToolRegistry.phase3().definitions().map { it.name }
        val second = AgentToolRegistry.phase3().definitions().map { it.name }

        assertEquals(first, second)
        assertTrue("phase3 should expose a non-trivial tool set", first.size >= 10)
    }

    @Test
    fun renderedToolsBlockIsByteIdenticalAcrossRequests() {
        val bodies = (1..5).map { encodeRequestBody() }
        val toolBlocks = bodies.map { JSONObject(it).getJSONArray("tools").toString() }

        toolBlocks.forEach { block ->
            assertEquals(
                "tools array must serialize to identical bytes on every request",
                toolBlocks.first(),
                block
            )
        }
    }

    /**
     * The whole cacheable prefix, not just the tools array.  A stable tools
     * block is worthless if `system` renders differently, because the system
     * blocks sit inside the same prefix.
     */
    @Test
    fun renderedToolsAndSystemPrefixIsByteIdenticalAcrossRequests() {
        val prefixes = (1..5).map {
            val root = JSONObject(encodeRequestBody())
            // Reconstruct only the prefix Anthropic renders before `messages`.
            JSONObject()
                .put("tools", root.getJSONArray("tools"))
                .put("system", root.getJSONArray("system"))
                .toString()
        }

        prefixes.forEach { prefix ->
            assertEquals(
                "tools + system prefix must be byte-identical across requests",
                prefixes.first(),
                prefix
            )
        }
    }

    /**
     * Key *order* is an `org.json` implementation detail and deliberately not
     * asserted here: the JVM artifact used by unit tests (`org.json:json`) is
     * HashMap-backed and scrambles keys, while Android's AOSP implementation is
     * LinkedHashMap-backed and preserves insertion order.  Caching does not need
     * a particular order — it needs the *same* order every time.
     *
     * What this test pins is that repeated construction along the same code path
     * renders identical bytes. That is the property caching depends on, and it
     * holds because `String.hashCode` is fixed by the Java language spec and
     * HashMap applies no per-process seed randomization.
     *
     * Measured caveat, and the reason this test exists: on the HashMap-backed
     * JVM artifact the emitted order depends on insertion order as well as the
     * key set (bucket collision chains preserve arrival order). Building the
     * same schema keys in a different sequence produces different bytes. So a
     * schema assembled *conditionally* — `if (flag) put("maxItems", ...)` — does
     * not merely add a key to the prefix, it can reorder the keys around it and
     * invalidate the entire cached prefix. Tool schemas must therefore stay
     * unconditional source-level literals.
     */
    @Test
    fun jsonObjectKeyOrderIsDeterministicForSchemaShapedKeys() {
        val keys = listOf(
            "type", "additionalProperties", "required", "properties",
            "minItems", "maxItems", "items", "minimum", "description"
        )

        val renders = (1..5).map { renderKeys(keys) }

        renders.forEach { rendered ->
            assertEquals(
                "identical construction must render identical bytes on every attempt",
                renders.first(),
                rendered
            )
        }
    }

    private fun renderKeys(keys: List<String>): String =
        JSONObject().apply { keys.forEach { key -> put(key, key.length) } }.toString()

    private fun encodeRequestBody(): String {
        val client = AnthropicModelClient(
            apiBaseUrl = "https://api.anthropic.com",
            transport = NoopTransport,
            providerId = "provider",
            modelId = "claude-model",
            apiKeyProvider = { "secret-key" }
        )
        return client.encodeRequest(
            AgentModelRequest(
                requestId = "req-1",
                messages = listOf(
                    AgentModelMessage.system("Use the approved tools.", cacheable = true),
                    AgentModelMessage.user("Analyze the capture")
                ),
                toolDefinitions = AgentToolRegistry.phase3().definitions(),
                privacyMode = AgentPrivacyMode.RedactedMetadata
            )
        )
    }

    private object NoopTransport : AgentHttpTransport {
        override suspend fun execute(request: AgentHttpRequest): AgentHttpResponse =
            AgentHttpResponse(statusCode = 200, body = "{}")

        override fun cancel(requestId: String) = Unit
    }
}
