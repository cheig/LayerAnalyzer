package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.data.FollowStreamDirectionMetadata
import com.example.layanalyzer.data.FollowStreamMetadata
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

/**
 * follow_stream_metadata — the shape of a TCP/UDP conversation, without its
 * contents.
 *
 * Wireshark's Follow Stream reassembles a conversation into readable text.  That
 * text is exactly what an Agent must not receive: it is the payload, in the most
 * convenient possible form.  This tool answers the questions the reassembly is
 * *also* good for — how many frames each side sent, how many bytes, where the
 * stream starts and ends, whether it carried any payload at all — and returns
 * none of the bytes.
 *
 * The projection happens in [com.example.layanalyzer.data.AgentAnalysisRepository.getFollowStreamMetadata],
 * inside the filter lease, so the reassembled text never crosses into this file.
 * [FollowStreamMetadata] has no field to carry it even if it did.
 */
class FollowStreamMetadataTool(
    @Suppress("unused") private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {

    override val definition = AgentToolDefinition(
        name = "follow_stream_metadata",
        description = "Describe the TCP or UDP stream that a frame belongs to: stream id, " +
            "per-direction frame and byte counts, first and last frame, time range, and " +
            "whether the stream carried payload. Stream contents are never returned.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "required" to listOf("frameNumber", "protocol"),
            "properties" to mapOf(
                "frameNumber" to mapOf(
                    "type" to "integer",
                    "minimum" to 1
                ),
                "protocol" to mapOf(
                    "type" to "string",
                    "enum" to PROTOCOLS
                )
            )
        ),
        sensitivity = AgentDataSensitivity.Metadata,
        defaultTimeoutMillis = 30_000L
    )

    /** No filter argument: the stream is identified by a frame the model already has. */
    override val filterArgumentNames: Set<String> = emptySet()

    /**
     * Reassembling a stream dissects the frames that belong to it, so the
     * anchor frame is declared and charged like any other detail read.  Without
     * this, a model could walk a capture stream by stream for free.
     */
    override fun detailFrames(arguments: Map<String, Any?>): Collection<Long> =
        listOfNotNull((arguments["frameNumber"] as? Number)?.toLong())

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val frameNumber = (arguments["frameNumber"] as? Number)?.toLong()
            ?: throw AgentToolException(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "A frame number is required.",
                details = mapOf("field" to "arguments.frameNumber")
            )
        val protocol = (arguments["protocol"] as? String)?.trim()?.lowercase()
        if (protocol == null || protocol !in PROTOCOLS) {
            throw AgentToolException(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "Stream protocol must be tcp or udp.",
                details = mapOf("field" to "arguments.protocol", "allowed" to PROTOCOLS)
            )
        }

        val reading = context.repository.getFollowStreamMetadata(
            snapshot = context.snapshot,
            frame = frameNumber,
            protocol = protocol
        )
        val metadata = when (reading) {
            is AgentAnalysisResult.Failure -> throw AgentToolException(reading.error)
            is AgentAnalysisResult.Success -> reading.value
        }
        context.ensureStillValid(context.snapshot)

        // A frame that is not part of a stream is a legitimate answer, not a
        // failure: the model asked a reasonable question about a frame that
        // turned out to be, say, an ICMP packet.  Reporting it as an error would
        // push the model to retry rather than to conclude.
        if (metadata.streamId < 0) {
            val data = mapOf(
                "frameNumber" to frameNumber,
                "protocol" to protocol,
                "streamFound" to false,
                "scope" to metadata.scope,
                "returned" to 0,
                "total" to 0,
                "truncated" to false
            )
            return context.success(data = data, returnedCount = 0L, totalCount = 0L)
        }

        // Times come from the packet-list summaries of the boundary frames.  The
        // FollowStreamRecord itself carries no timestamp, and reading the two
        // frames the stream already contains is cheaper than a third pass.
        val timeRange = readTimeRange(context, metadata)

        val data = buildMap<String, Any?> {
            put("frameNumber", frameNumber)
            put("protocol", metadata.protocol)
            put("streamFound", true)
            put("streamId", metadata.streamId)
            put("directionKnown", metadata.directionKnown)
            put(
                "directions",
                metadata.directions.map { direction -> direction.toAgentJson() }
            )
            put("frameCount", metadata.frameCount)
            put("byteCount", metadata.byteCount)
            put("firstFrame", metadata.firstFrame)
            put("lastFrame", metadata.lastFrame)
            put("startTime", timeRange?.first)
            put("endTime", timeRange?.second)
            put(
                "durationSeconds",
                timeRange?.let { (start, end) -> (end - start).coerceAtLeast(0.0) }
            )
            // Existence only.  Reading the bytes is not something this tool can
            // do — see the class comment and FollowStreamMetadata.
            put("containsPayload", metadata.containsPayload)
            put("scope", metadata.scope)
            put("returned", metadata.directions.size)
            put("total", metadata.directions.size)
            put("truncated", false)
            // The anchor frame is charged like any detail read, so the same
            // budget account a multi-frame call carries applies here too.
            putAll(context.detailBudgetJson(listOf(frameNumber)))
        }

        return context.success(
            data = data,
            returnedCount = metadata.directions.size.toLong(),
            totalCount = metadata.directions.size.toLong()
        )
    }

    /**
     * Absolute start/end times, read from the first and last frame's summary.
     *
     * The two frames are fetched by display filter rather than by treating
     * `frameNumber - 1` as a row index: under a scoped run the visible set is
     * already narrowed, so an index would point at the wrong frame — or past the
     * end — and the reported time range would silently belong to other packets.
     *
     * A failure here is not fatal: the counts are the answer and the time range
     * is context, so this returns null and leaves the time fields null rather
     * than failing a call that already has everything else.
     */
    private suspend fun readTimeRange(
        context: AgentToolContext,
        metadata: FollowStreamMetadata
    ): Pair<Double, Double>? {
        val first = metadata.firstFrame ?: return null
        val last = metadata.lastFrame ?: first
        val filter = if (first == last) {
            "frame.number==$first"
        } else {
            "frame.number==$first || frame.number==$last"
        }
        val reading = context.repository.queryWithTemporaryFilter(context.snapshot, filter) { reader ->
            val times = reader.getRawPacketSummaries(0, 2)
                .mapNotNull { summary -> summary.time.toDoubleOrNull() }
            val start = times.minOrNull()
            val end = times.maxOrNull()
            if (start != null && end != null) start to end else null
        }
        return (reading as? AgentAnalysisResult.Success)?.value
    }

    private fun FollowStreamDirectionMetadata.toAgentJson(): Map<String, Any?> = mapOf(
        "direction" to direction,
        "frameCount" to frameCount,
        "byteCount" to byteCount,
        "firstFrame" to firstFrame,
        "lastFrame" to lastFrame
    )

    private companion object {
        val PROTOCOLS = listOf("tcp", "udp")
    }
}
