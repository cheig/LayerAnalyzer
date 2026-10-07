// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.tools.dto.AgentPacketSortArgument
import com.example.layanalyzer.ai.tools.dto.AgentPacketSummaryEntry
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.PacketSummary
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * query_packet_summaries — the packet list, paged, for a model.
 *
 * This is the tool an Agent uses to *locate* candidate frames.  It returns one
 * row per frame and nothing deeper: no protocol tree, no packet bytes, no
 * payload.  Reading a frame in detail is a separate, separately-budgeted step
 * through [PacketFieldsTool], which is what keeps a broad scan cheap and a deep
 * read deliberate.
 *
 * Sorting is fixed to frame order.  The alternative — accepting
 * `time_descending` and friends — would mean loading every visible frame into
 * Kotlin just to reorder it, so an unsupported value is rejected by the schema
 * rather than served expensively.
 */
class PacketSummaryQueryTool(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {

    override val definition = AgentToolDefinition(
        name = "query_packet_summaries",
        description = "List packet-list rows (frame number, time, addresses, ports, protocol, " +
            "length, info) for the frames matching an optional display filter. " +
            "Use this to find candidate frames before reading any of them in detail.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "filter" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_FILTER_LENGTH
                ),
                "offset" to mapOf(
                    "type" to "integer",
                    "minimum" to 0
                ),
                "limit" to mapOf(
                    "type" to "integer",
                    "minimum" to 1,
                    "maximum" to MAX_LIMIT
                ),
                "sort" to mapOf(
                    "type" to "string",
                    "enum" to AgentPacketSortArgument.wireNames
                )
            )
        ),
        sensitivity = AgentDataSensitivity.Identifier,
        defaultTimeoutMillis = 30_000L
    )

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val filter = (arguments["filter"] as? String)?.trim().orEmpty()
        val offset = ((arguments["offset"] as? Number)?.toInt() ?: 0).coerceAtLeast(0)
        val limit = context.summaryLimit((arguments["limit"] as? Number)?.toInt() ?: DEFAULT_LIMIT)
        val sort = AgentPacketSortArgument.fromWire(arguments["sort"] as? String)

        val reading = withContext(ioDispatcher) {
            context.ensureStillValid(context.snapshot)
            context.repository.queryPacketSummaries(
                snapshot = context.snapshot,
                filter = filter,
                offset = offset,
                limit = limit
            )
        }

        val value = when (reading) {
            is AgentAnalysisResult.Failure -> throw AgentToolException(reading.error)
            is AgentAnalysisResult.Success -> reading.value
        }

        val entries = value.page.map { summary ->
            summary.toEntry(value.captureStartTime)
        }
        val truncated = value.truncated ||
            value.offset.toLong() + entries.size < value.total.toLong()

        val data = mapOf(
            "packets" to entries.map(AgentPacketSummaryEntry::toAgentJson),
            "filter" to filter,
            "sort" to sort.wireName,
            "offset" to value.offset,
            "limit" to limit,
            "returned" to entries.size,
            "total" to value.total,
            "truncated" to truncated
        )

        return context.success(
            data = data,
            returnedCount = entries.size.toLong(),
            totalCount = value.total.toLong(),
            truncated = truncated,
            queryMode = value.queryMode
        )
    }

    /**
     * Project one row.  The raw summary carries the absolute capture timestamp
     * as text, so both times are derived here rather than inheriting whichever
     * time format the user happens to have selected in the UI.
     *
     * Addresses and Info are returned as the engine reported them.  Redaction is
     * not this tool's job: `AgentToolRunner.finish` applies the privacy layer to
     * every result, so doing it here as well would alias an alias and give one
     * endpoint two identities in the same run.
     */
    private fun PacketSummary.toEntry(
        captureStartTime: Double
    ): AgentPacketSummaryEntry {
        val absolute = time.toDoubleOrNull() ?: 0.0
        return AgentPacketSummaryEntry(
            frameNumber = frameNumber,
            absoluteTime = absolute,
            relativeTime = (absolute - captureStartTime).coerceAtLeast(0.0),
            source = source,
            destination = destination,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            protocol = protocol,
            length = length,
            info = info
        )
    }

    private companion object {
        const val DEFAULT_LIMIT = 50
        const val MAX_LIMIT = 100
        const val MAX_FILTER_LENGTH = 2048
    }
}
