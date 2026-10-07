package com.example.layanalyzer.ai.tools

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentResultTruncatorTest {
    @Test
    fun smallPayloadIsUnchanged() {
        val data = mapOf("packetCount" to 12, "protocols" to listOf("tcp", "udp"))

        val outcome = AgentResultTruncator.truncate(data, 32 * 1024)

        assertFalse(outcome.truncated)
        assertFalse(outcome.overflowed)
        assertEquals(data["packetCount"], outcome.data["packetCount"])
        assertEquals(listOf("tcp", "udp"), outcome.data["protocols"])
    }

    @Test
    fun truncatedOutputRemainsValidJson() {
        val rows = (1..10_000).map { mapOf("frame" to it, "info" to "X".repeat(300)) }

        val outcome = AgentResultTruncator.truncate(mapOf("packets" to rows), 4_096)

        assertTrue(outcome.truncated)
        assertTrue(outcome.byteSize <= 4_096)
        val parsed = JSONObject(outcome.json)
        assertTrue(parsed.getJSONArray("packets").length() in 1 until 10_000)
    }

    @Test
    fun fittingALargePayloadNeedsAtMostFourSearchEncodes() {
        val rows = (1..10_000).map { mapOf("frame" to it, "info" to "X".repeat(300)) }
        var encodeCount = 0

        val outcome = AgentResultTruncator.truncate(
            data = mapOf("packets" to rows),
            maxBytes = 4_096,
            encoder = { data ->
                encodeCount += 1
                AgentResultTruncator.encode(data)
            }
        )

        assertTrue(outcome.byteSize <= 4_096)
        assertTrue(encodeCount <= 4)
    }

    @Test
    fun truncationRecordsTotalAndReturnedCounts() {
        val rows = (1..500).map { mapOf("frame" to it, "info" to "Y".repeat(120)) }

        val outcome = AgentResultTruncator.truncate(mapOf("packets" to rows), 2_048)

        val parsed = JSONObject(outcome.json)
        assertTrue(parsed.getBoolean("packetsTruncated"))
        assertEquals(500, parsed.getInt("packetsTotal"))
        assertEquals(parsed.getJSONArray("packets").length(), parsed.getInt("packetsReturned"))
    }

    @Test
    fun sampleFrameTrimmingKeepsReturnedAndTotalDistinct() {
        val outcome = AgentResultTruncator.truncate(
            mapOf(
                "sampleFrames" to (1..500).map { it.toLong() },
                "anomalyFrames" to (501..700).map { it.toLong() },
                "returned" to 500,
                "total" to 10_000,
                "sampled" to true
            ),
            1_024
        )

        val parsed = JSONObject(outcome.json)
        val samples = parsed.getJSONArray("sampleFrames")
        assertTrue(outcome.truncated)
        assertTrue(samples.length() < 500)
        assertEquals(samples.length(), parsed.getInt("returned"))
        assertEquals(10_000, parsed.getInt("total"))
        assertTrue(parsed.getBoolean("payloadTruncated"))
        assertTrue(parsed.getJSONArray("omittedPaths").length() > 0)
    }

    @Test
    fun longStringsAreShortenedNotCutMidEncoding() {
        val outcome = AgentResultTruncator.truncate(
            mapOf("summary" to "S".repeat(50_000)),
            1_024
        )

        assertTrue(outcome.truncated)
        val summary = JSONObject(outcome.json).getString("summary")
        assertTrue(summary.length < 50_000)
        assertTrue(summary.endsWith("…"))
    }

    @Test
    fun nestedStructuresAreTrimmedAtEveryLevel() {
        val nested = mapOf(
            "conversations" to (1..400).map { index ->
                mapOf(
                    "id" to index,
                    "frames" to (1..200).toList(),
                    "label" to "Z".repeat(500)
                )
            }
        )

        val outcome = AgentResultTruncator.truncate(nested, 3_072)

        assertTrue(outcome.truncated)
        assertTrue(outcome.byteSize <= 3_072)
        val parsed = JSONObject(outcome.json)
        val conversations = parsed.getJSONArray("conversations")
        assertTrue(conversations.length() < 400)
        if (conversations.length() > 0) {
            assertTrue(conversations.getJSONObject(0).getJSONArray("frames").length() <= 200)
        }
    }

    @Test
    fun unrepresentableResultReportsOverflowInsteadOfBrokenJson() {
        val outcome = AgentResultTruncator.truncate(
            mapOf("k".repeat(4_000) to "v".repeat(4_000)),
            256
        )

        assertTrue(outcome.overflowed)
        assertTrue(outcome.truncated)
        val parsed = JSONObject(outcome.json)
        assertEquals("result_too_large", parsed.getString("reason"))
    }

    @Test
    fun nullAndNonFiniteValuesEncodeSafely() {
        val outcome = AgentResultTruncator.truncate(
            mapOf(
                "missing" to null,
                "ratio" to Double.NaN,
                "infinite" to Double.POSITIVE_INFINITY,
                "ok" to 1.5
            ),
            4_096
        )

        val parsed = JSONObject(outcome.json)
        assertTrue(parsed.isNull("missing"))
        assertTrue(parsed.isNull("ratio"))
        assertTrue(parsed.isNull("infinite"))
        assertEquals(1.5, parsed.getDouble("ok"), 0.0001)
    }
}
