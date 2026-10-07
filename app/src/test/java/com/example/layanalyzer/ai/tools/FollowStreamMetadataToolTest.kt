// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.FollowStreamRecord
import com.example.layanalyzer.model.FollowStreamResult
import com.example.layanalyzer.model.PacketSummary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FollowStreamMetadataToolTest {

    @Test
    fun perDirectionCountsAndFrameBoundariesAreReported() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            summaries = (1..20).map { summary(it.toLong(), time = "100.$it") }
            followStreams = mapOf("tcp:5" to stream())
        }.use { harness ->
            val result = harness.runFollowStream(mapOf("frameNumber" to 5, "protocol" to "tcp"))

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertEquals(true, data["streamFound"])
            assertEquals(7, data["streamId"])
            assertEquals(true, data["directionKnown"])
            assertEquals(4, data["frameCount"])
            assertEquals(400L, data["byteCount"])
            assertEquals(4L, data["firstFrame"])
            assertEquals(9L, data["lastFrame"])

            @Suppress("UNCHECKED_CAST")
            val directions = data["directions"] as List<Map<String, Any?>>
            assertEquals(2, directions.size)
            val client = directions.first { it["direction"] == "client" }
            assertEquals(2, client["frameCount"])
            assertEquals(200L, client["byteCount"])
            assertEquals(4L, client["firstFrame"])
            assertEquals(6L, client["lastFrame"])
        }
    }

    @Test
    fun neitherTextNorAsciiNorHexAppearsAnywhereInTheResult() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            summaries = (1..20).map { summary(it.toLong()) }
            followStreams = mapOf(
                "tcp:5" to stream(
                    text = "GET /secret HTTP/1.1\r\nAuthorization: Bearer abc123\r\n",
                    ascii = "GET /secret HTTP/1.1",
                    hex = "474554202f736563726574"
                )
            )
        }.use { harness ->
            val result = harness.runFollowStream(mapOf("frameNumber" to 5, "protocol" to "tcp"))
            val encoded = AgentResultTruncator.encode(requireNotNull(result.data))

            // The field names must be absent...
            listOf("\"text\"", "\"ascii\"", "\"hex\"").forEach { forbidden ->
                assertFalse(forbidden, encoded.contains(forbidden))
            }
            // ...and so must the reassembled content itself.
            listOf("GET /secret", "Authorization", "Bearer", "abc123", "474554").forEach { leaked ->
                assertFalse(leaked, encoded.contains(leaked))
            }
            // Existence is all that is reported.
            assertEquals(true, requireNotNull(result.data)["containsPayload"])
        }
    }

    @Test
    fun aStreamWithoutPayloadReportsContainsPayloadFalse() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            summaries = (1..20).map { summary(it.toLong()) }
            followStreams = mapOf("tcp:5" to stream(payload = false))
        }.use { harness ->
            val result = harness.runFollowStream(mapOf("frameNumber" to 5, "protocol" to "tcp"))

            assertEquals(false, requireNotNull(result.data)["containsPayload"])
        }
    }

    @Test
    fun theTimeRangeIsProjectedFromTheBoundaryFrames() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            summaries = (1..20).map { index ->
                summary(index.toLong(), time = (100 + index).toString())
            }
            followStreams = mapOf("tcp:5" to stream())
        }.use { harness ->
            val result = harness.runFollowStream(mapOf("frameNumber" to 5, "protocol" to "tcp"))

            val data = requireNotNull(result.data)
            // Frames 4 and 9 bound the stream, so times 104 and 109.
            assertEquals(104.0, data["startTime"] as Double, 1e-9)
            assertEquals(109.0, data["endTime"] as Double, 1e-9)
            assertEquals(5.0, data["durationSeconds"] as Double, 1e-9)
        }
    }

    @Test
    fun aFrameThatBelongsToNoStreamIsAnAnswerRatherThanAnError() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            summaries = (1..20).map { summary(it.toLong()) }
            // No entry for this frame, so the fake returns streamId = -1.
        }.use { harness ->
            val result = harness.runFollowStream(mapOf("frameNumber" to 5, "protocol" to "tcp"))

            assertTrue(result.success)
            val data = requireNotNull(result.data)
            assertEquals(false, data["streamFound"])
            assertNull(data["streamId"])
            assertEquals(0, data["returned"])
        }
    }

    @Test
    fun onlyTcpAndUdpAreAcceptedAsProtocols() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            summaries = (1..20).map { summary(it.toLong()) }
        }.use { harness ->
            val result = harness.runFollowStream(
                mapOf("frameNumber" to 5, "protocol" to "http")
            )

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
            // The rejection happened before any native reassembly.
            assertTrue(harness.source.followedStreams.isEmpty())
        }
    }

    @Test
    fun bothArgumentsAreRequired() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20).use { harness ->
            val missingProtocol = harness.runFollowStream(mapOf("frameNumber" to 5))
            assertFalse(missingProtocol.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, missingProtocol.error?.code)

            val missingFrame = harness.runFollowStream(mapOf("protocol" to "tcp"))
            assertFalse(missingFrame.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, missingFrame.error?.code)
        }
    }

    @Test
    fun aFrameOutsideTheCaptureIsRejectedPrecisely() = runBlocking {
        AgentToolTestHarness.create(frameCount = 5) {
            summaries = (1..5).map { summary(it.toLong()) }
        }.use { harness ->
            val result = harness.runFollowStream(
                mapOf("frameNumber" to 500, "protocol" to "tcp")
            )

            assertFalse(result.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, result.error?.code)
            assertTrue(harness.source.followedStreams.isEmpty())
        }
    }

    @Test
    fun theAnchorFrameIsChargedAgainstTheDetailBudget() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            summaries = (1..20).map { summary(it.toLong()) }
            followStreams = mapOf("tcp:5" to stream())
        }.use { harness ->
            val runner = AgentToolRunner(
                registry = AgentToolRegistry(FollowStreamMetadataTool(Dispatchers.Unconfined)),
                repository = harness.repository
            )
            runner.execute(
                AgentToolCall("call-1", "follow_stream_metadata", mapOf("frameNumber" to 5, "protocol" to "tcp")),
                harness.snapshot,
                AgentPrivacyMode.LocalOnly
            )

            // Reassembly dissects frames, so it is not a free operation.
            assertEquals(1, runner.budgetTracker.usage().detailFrames)
        }
    }

    @Test
    fun aSessionChangeIsRejectedWithAStructuredError() = runBlocking {
        AgentToolTestHarness.create(frameCount = 20) {
            summaries = (1..20).map { summary(it.toLong()) }
            followStreams = mapOf("tcp:5" to stream())
        }.use { harness ->
            val snapshot = harness.snapshot
            harness.coordinator.invalidateSession()

            val result = harness.runFollowStream(
                mapOf("frameNumber" to 5, "protocol" to "tcp"),
                snapshot = snapshot
            )

            assertFalse(result.success)
            assertNull(result.data)
            assertNotNull(result.error)
        }
    }

    private suspend fun AgentToolTestHarness.runFollowStream(
        arguments: Map<String, Any?> = emptyMap(),
        snapshot: AgentCaptureSnapshot = this.snapshot
    ) = AgentToolRunner(
        registry = AgentToolRegistry(FollowStreamMetadataTool(Dispatchers.Unconfined)),
        repository = repository
    ).execute(
        AgentToolCall("call-1", "follow_stream_metadata", arguments),
        snapshot,
        AgentPrivacyMode.LocalOnly
    )

    /** A four-record stream, two frames in each direction. */
    private fun stream(
        text: String = "hello",
        ascii: String = "hello",
        hex: String = "68656c6c6f",
        payload: Boolean = true
    ) = FollowStreamResult(
        protocol = "tcp",
        streamId = 7,
        directionKnown = true,
        scope = "complete file",
        records = listOf(
            record(4L, "client", text, ascii, hex, payload),
            record(5L, "server", text, ascii, hex, payload),
            record(6L, "client", text, ascii, hex, payload),
            record(9L, "server", text, ascii, hex, payload)
        )
    )

    private fun record(
        frame: Long,
        direction: String,
        text: String,
        ascii: String,
        hex: String,
        payload: Boolean
    ) = FollowStreamRecord(
        frameNumber = frame,
        direction = direction,
        source = "10.0.0.1",
        destination = "10.0.0.2",
        length = 100,
        payload = payload,
        text = text,
        ascii = ascii,
        hex = hex
    )

    private fun summary(frame: Long, time: String = "100.$frame") = PacketSummary(
        frameNumber = frame,
        time = time,
        source = "10.0.0.1",
        destination = "10.0.0.2",
        protocol = "TCP",
        length = 100,
        sourcePort = 12345,
        destinationPort = 443,
        info = "Frame $frame"
    )
}
