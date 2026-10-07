// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentToolCall
import org.json.JSONArray
import org.json.JSONObject

/**
 * Reads a [MockModelScript] from JSON, so scenarios can be authored as data.
 *
 * Test scripts live in `app/src/test/resources/agent/mock_scripts/`; the minimal
 * Debug demo script lives in `app/src/main/assets/agent_mock_scripts.json`.
 * Keeping them as data means a new scenario needs no recompilation, and it keeps
 * the JSON vocabulary honest — anything a script can express here, a real
 * adapter must also be able to produce.
 *
 * Scripts are developer-authored fixtures, not untrusted input, so a malformed
 * script throws [IllegalArgumentException] with a pointed message instead of
 * degrading to a partial script that would fail confusingly several turns later.
 */
object MockModelScriptCodec {
    const val SCHEMA_VERSION: Int = 1

    private const val TYPE_TOOL_CALLS = "tool_calls"
    private const val TYPE_FINAL = "final"
    private const val TYPE_REFUSAL = "refusal"
    private const val TYPE_FAILURE = "failure"

    /** Decode a single script document. */
    fun decode(json: String): MockModelScript = decodeObject(JSONObject(json))

    /**
     * Decode a document holding several scripts under `scripts`.  A single
     * script object is also accepted, so one file can grow into a bundle.
     */
    fun decodeAll(json: String): List<MockModelScript> {
        val root = JSONObject(json)
        val scripts = root.optJSONArray("scripts")
            ?: return listOf(decodeObject(root))
        return (0 until scripts.length()).map { index ->
            val element = scripts.optJSONObject(index)
                ?: fail("scripts[$index] is not an object.")
            decodeObject(element)
        }
    }

    private fun decodeObject(root: JSONObject): MockModelScript {
        val version = when (val raw = root.opt("schemaVersion")) {
            null, JSONObject.NULL -> SCHEMA_VERSION
            is Number -> raw.toInt()
            else -> fail("schemaVersion must be a number.")
        }
        require(version in 1..SCHEMA_VERSION) {
            "Unsupported mock script schemaVersion $version; this build reads up to $SCHEMA_VERSION."
        }

        val id = root.optString("id").takeIf { it.isNotBlank() }
            ?: fail("A mock script needs a non-blank id.")
        val turns = root.optJSONArray("turns") ?: fail("Script $id has no turns array.")
        require(turns.length() > 0) { "Script $id has an empty turns array." }

        val responses = mutableListOf<MockScriptedResponse>()
        val expectations = mutableListOf<MockRequestExpectation?>()
        for (index in 0 until turns.length()) {
            val turn = turns.optJSONObject(index)
                ?: fail("Script $id turn $index is not an object.")
            responses += decodeTurn(id, index, turn)
            expectations += turn.optJSONObject("expect")?.let { decodeExpectation(id, index, it) }
        }

        return MockModelScript(
            id = id,
            responses = responses,
            // Trailing nulls carry no information; dropping them keeps the
            // decoded script equal to a hand-written one that simply omitted
            // expectations for its later turns.
            expectedRequests = expectations.dropLastWhile { it == null },
            capabilities = root.optJSONObject("capabilities")?.let(::decodeCapabilities)
                ?: AiModelCapabilities.PHASE0,
            description = root.optString("description")
        )
    }

    private fun decodeTurn(
        scriptId: String,
        index: Int,
        turn: JSONObject
    ): MockScriptedResponse {
        val delayMillis = when (val raw = turn.opt("delayMillis")) {
            null, JSONObject.NULL -> 0L
            is Number -> raw.toLong()
            else -> fail("Script $scriptId turn $index has a non-numeric delayMillis.")
        }
        require(delayMillis >= 0L) {
            "Script $scriptId turn $index has a negative delayMillis."
        }

        val type = turn.optString("type").takeIf { it.isNotBlank() }
            ?: fail("Script $scriptId turn $index has no type.")

        val response = when (type) {
            TYPE_TOOL_CALLS -> AgentModelResponse.ToolCalls(decodeToolCalls(scriptId, index, turn))

            TYPE_FINAL -> {
                // A script may carry the report either as an already-encoded
                // string, which keeps host-side decoding under test, or as an
                // inline object decoded through the one canonical codec.
                val reportJson = turn.optString("reportJson").takeIf { it.isNotBlank() }
                    ?: turn.optJSONObject("report")?.toString()
                    ?: fail("Script $scriptId turn $index needs report or reportJson.")
                if (turn.has("report") && !turn.has("reportJson")) {
                    val decoded = AgentJsonCodec.decodeReport(reportJson)
                    AgentModelResponse.Final(
                        report = decoded.getOrNull()
                            ?: fail("Script $scriptId turn $index has an unreadable report."),
                        reportJson = reportJson,
                        json = reportJson
                    )
                } else {
                    AgentModelResponse.Final(
                        report = null,
                        reportJson = reportJson,
                        json = reportJson
                    )
                }
            }

            TYPE_REFUSAL -> AgentModelResponse.Refusal(
                reason = turn.optString("reason").takeIf { it.isNotBlank() }
                    ?: fail("Script $scriptId turn $index needs a refusal reason.")
            )

            TYPE_FAILURE -> AgentModelResponse.Failure(decodeError(scriptId, index, turn))

            else -> fail("Script $scriptId turn $index has unknown type '$type'.")
        }

        return MockScriptedResponse(response, delayMillis)
    }

    private fun decodeToolCalls(
        scriptId: String,
        index: Int,
        turn: JSONObject
    ): List<AgentToolCall> {
        val calls = turn.optJSONArray("calls")
            ?: fail("Script $scriptId turn $index has no calls array.")
        require(calls.length() > 0) {
            "Script $scriptId turn $index has an empty calls array."
        }
        return (0 until calls.length()).map { callIndex ->
            val call = calls.optJSONObject(callIndex)
                ?: fail("Script $scriptId turn $index call $callIndex is not an object.")
            AgentToolCall(
                toolCallId = call.optString("toolCallId").takeIf { it.isNotBlank() }
                    ?: fail("Script $scriptId turn $index call $callIndex has no toolCallId."),
                toolName = call.optString("toolName").takeIf { it.isNotBlank() }
                    ?: fail("Script $scriptId turn $index call $callIndex has no toolName."),
                arguments = call.optJSONObject("arguments")?.let(::toMap).orEmpty()
            )
        }
    }

    private fun decodeError(scriptId: String, index: Int, turn: JSONObject): AgentError {
        val error = turn.optJSONObject("error")
            ?: fail("Script $scriptId turn $index has no error object.")
        val rawCode = error.optString("code")
        val code = AgentErrorCode.values().firstOrNull { it.name == rawCode }
            ?: fail("Script $scriptId turn $index has unknown error code '$rawCode'.")
        return AgentError(
            code = code,
            userMessage = error.optString("userMessage"),
            retryable = error.optBoolean("retryable", false),
            details = error.optJSONObject("details")?.let(::toMap).orEmpty()
        )
    }

    private fun decodeExpectation(
        scriptId: String,
        index: Int,
        expect: JSONObject
    ): MockRequestExpectation {
        val minMessageCount = expect.optInt("minMessageCount", 0)
        require(minMessageCount >= 0) {
            "Script $scriptId turn $index has a negative minMessageCount."
        }
        return MockRequestExpectation(
            expectedToolName = expect.optString("toolName").takeIf { it.isNotBlank() },
            expectedToolCallId = expect.optString("toolCallId").takeIf { it.isNotBlank() },
            requiredToolDefinitions = expect.optJSONArray("requiredToolDefinitions")
                ?.let { array ->
                    (0 until array.length()).mapNotNull { array.opt(it) as? String }.toSet()
                }
                .orEmpty(),
            requiresResponseSchema = expect.optBoolean("requiresResponseSchema", false),
            minMessageCount = minMessageCount
        )
    }

    private fun decodeCapabilities(json: JSONObject): AiModelCapabilities {
        val defaults = AiModelCapabilities.PHASE0
        return AiModelCapabilities(
            toolCalling = json.optBoolean("toolCalling", defaults.toolCalling),
            parallelToolCalls = json.optBoolean("parallelToolCalls", defaults.parallelToolCalls),
            structuredOutput = json.optBoolean("structuredOutput", defaults.structuredOutput),
            streaming = json.optBoolean("streaming", defaults.streaming),
            maxContextTokens = json.optInt("maxContextTokens", defaults.maxContextTokens),
            maxOutputTokens = json.optInt("maxOutputTokens", defaults.maxOutputTokens)
        )
    }

    private fun toMap(json: JSONObject): Map<String, Any?> = buildMap {
        val keys = json.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            put(key, fromJsonValue(json.opt(key)))
        }
    }

    private fun fromJsonValue(value: Any?): Any? = when (value) {
        null, JSONObject.NULL -> null
        is JSONObject -> toMap(value)
        is JSONArray -> (0 until value.length()).map { fromJsonValue(value.opt(it)) }
        else -> value
    }

    private fun fail(message: String): Nothing = throw IllegalArgumentException(message)
}
