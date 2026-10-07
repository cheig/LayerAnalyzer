// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.tools.dto.AgentConversationEntry
import com.example.layanalyzer.ai.tools.dto.AgentEndpointEntry
import com.example.layanalyzer.ai.tools.dto.AgentIoBucketEntry
import com.example.layanalyzer.ai.tools.dto.AgentProtocolHierarchyEntry
import com.example.layanalyzer.ai.tools.dto.AgentStatisticsProjections
import com.example.layanalyzer.ai.tools.dto.AgentStatisticsSection
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.CaptureStatistics
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * get_statistics — Wireshark's Statistics menu, sectioned and capped.
 *
 * One native traversal produces every section, so the `sections` argument is not
 * a performance control: it decides what reaches the model's context.  A model
 * investigating retransmissions asks for `tcp` and spends a few hundred bytes;
 * asking for everything would spend the whole per-call allowance on tables it
 * will not read.  Requesting no sections at all returns the default set rather
 * than an empty result, so a bare call is still useful.
 *
 * Counts and truncation flags from the native layer are propagated verbatim.
 * `truncatedPacketCount` and each protocol's `summaryTotal` matter because the
 * native analyzer caps its own per-protocol lists: without them a model would
 * read a capped table as a complete one.
 */
class StatisticsTool(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {

    override val definition = AgentToolDefinition(
        name = "get_statistics",
        description = "Capture statistics: protocol hierarchy, conversations, endpoints, " +
            "I/O graph over time, packet lengths, and TCP/DNS/TLS/HTTP metrics. Request only the sections " +
            "you need. Conversations and endpoints are ranked by bytes descending.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "filter" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_FILTER_LENGTH
                ),
                "sections" to mapOf(
                    "type" to "array",
                    "maxItems" to AgentStatisticsSection.wireNames.size,
                    "items" to mapOf(
                        "type" to "string",
                        "enum" to AgentStatisticsSection.wireNames
                    )
                ),
                "topN" to mapOf(
                    "type" to "integer",
                    "minimum" to 1,
                    "maximum" to MAX_TOP_N
                ),
                "bucketSeconds" to mapOf(
                    "type" to "number",
                    "minimum" to MIN_BUCKET_SECONDS,
                    "maximum" to MAX_BUCKET_SECONDS
                )
            )
        ),
        sensitivity = AgentDataSensitivity.Aggregate,
        defaultTimeoutMillis = 30_000L
    )

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val filter = (arguments["filter"] as? String)?.trim().orEmpty()
        val requested = (arguments["sections"] as? Iterable<*>)
            ?.mapNotNull { AgentStatisticsSection.fromWire(it as? String) }
            ?.toSet()
            .orEmpty()
        val sections = requested.ifEmpty { DEFAULT_SECTIONS }
        val topN = ((arguments["topN"] as? Number)?.toInt() ?: DEFAULT_TOP_N)
            .coerceIn(1, MAX_TOP_N)
        val bucketSeconds = (arguments["bucketSeconds"] as? Number)
            ?.toDouble()
            ?.coerceIn(MIN_BUCKET_SECONDS, MAX_BUCKET_SECONDS)
            ?: DEFAULT_BUCKET_SECONDS

        // The lease validates and applies the filter for this read only.  The
        // repository runs the native traversal on the IO dispatcher it was
        // given; the tool's own dispatcher is used for the projection below.
        val reading = context.repository.getStatistics(
            snapshot = context.snapshot,
            filter = filter,
            bucketSeconds = bucketSeconds
        )

        val statistics = when (reading) {
            is AgentAnalysisResult.Failure -> throw AgentToolException(reading.error)
            is AgentAnalysisResult.Success -> reading.value
        }
        context.ensureStillValid(context.snapshot)

        val projection = withContext(ioDispatcher) {
            project(statistics, sections, topN)
        }

        val data = buildMap<String, Any?> {
            put("filter", filter)
            put("sections", sections.map { it.wireName }.sorted())
            put("topN", topN)
            put("bucketSeconds", bucketSeconds)
            put("packetCount", statistics.packetCount)
            put("byteCount", statistics.byteCount)
            put("capturedByteCount", statistics.capturedByteCount)
            // A capture whose frames were cut short at capture time; the model
            // needs this to know a missing field may be a snaplen artefact
            // rather than a protocol-level absence.
            put("truncatedPacketCount", statistics.truncatedPacketCount)
            put("startTime", statistics.startTime)
            put("endTime", statistics.endTime)
            put("durationSeconds", (statistics.endTime - statistics.startTime).coerceAtLeast(0.0))
            putAll(projection.data)
            put("returned", projection.returned)
            put("total", projection.total)
            put("truncated", projection.truncated)
        }

        return context.success(
            data = data,
            returnedCount = projection.returned.toLong(),
            totalCount = projection.total.toLong(),
            truncated = projection.truncated
        )
    }

    /**
     * Build only the requested sections.
     *
     * Each list section reports its own total alongside the rows it returned, so
     * "the top 20 conversations of 412" is distinguishable from "all 20
     * conversations in the capture".  The aggregate `truncated` flag is the OR of
     * every section's own truncation.
     */
    private fun project(
        statistics: CaptureStatistics,
        sections: Set<AgentStatisticsSection>,
        topN: Int
    ): Projection {
        val data = mutableMapOf<String, Any?>()
        var returned = 0
        var total = 0
        var truncated = false

        fun recordList(returnedRows: Int, totalRows: Int) {
            returned += returnedRows
            total += totalRows
            if (returnedRows < totalRows) truncated = true
        }

        if (AgentStatisticsSection.ProtocolHierarchy in sections) {
            val rows = AgentStatisticsProjections.protocolHierarchy(statistics, topN)
            data["protocolHierarchy"] = rows.map(AgentProtocolHierarchyEntry::toAgentJson)
            data["protocolHierarchyTotal"] = statistics.protocolHierarchy.size
            recordList(rows.size, statistics.protocolHierarchy.size)
        }

        if (AgentStatisticsSection.Conversations in sections) {
            val rows = AgentStatisticsProjections.conversations(statistics, topN)
            data["conversations"] = rows.map(AgentConversationEntry::toAgentJson)
            data["conversationsTotal"] = statistics.conversations.size
            recordList(rows.size, statistics.conversations.size)
        }

        if (AgentStatisticsSection.Endpoints in sections) {
            val rows = AgentStatisticsProjections.endpoints(statistics, topN)
            data["endpoints"] = rows.map(AgentEndpointEntry::toAgentJson)
            data["endpointsTotal"] = statistics.endpoints.size
            recordList(rows.size, statistics.endpoints.size)
        }

        if (AgentStatisticsSection.IoGraph in sections) {
            val rows = AgentStatisticsProjections.ioGraph(statistics)
            data["ioGraph"] = rows.map(AgentIoBucketEntry::toAgentJson)
            data["ioGraphTotal"] = statistics.ioGraph.size
            // Merged buckets still cover the whole capture, so this is reported
            // as a resolution change rather than as truncation.
            data["ioGraphMerged"] = rows.size < statistics.ioGraph.size
            returned += rows.size
            total += statistics.ioGraph.size
        }

        if (AgentStatisticsSection.PacketLengths in sections) {
            data["packetLengths"] = AgentStatisticsProjections.packetLengths(statistics).toAgentJson()
        }

        if (AgentStatisticsSection.Tcp in sections) {
            val metrics = AgentStatisticsProjections.tcp(statistics, topN)
            data["tcp"] = metrics.toAgentJson()
            recordList(metrics.events.size, statistics.tcpSummaryTotal)
        }
        if (AgentStatisticsSection.Dns in sections) {
            val metrics = AgentStatisticsProjections.dns(statistics, topN)
            data["dns"] = metrics.toAgentJson()
            recordList(metrics.events.size, statistics.dnsSummaryTotal)
        }
        if (AgentStatisticsSection.Tls in sections) {
            val metrics = AgentStatisticsProjections.tls(statistics, topN)
            data["tls"] = metrics.toAgentJson()
            recordList(metrics.events.size, statistics.tlsSummaryTotal)
        }
        if (AgentStatisticsSection.Http in sections) {
            val metrics = AgentStatisticsProjections.http(statistics, topN)
            data["http"] = metrics.toAgentJson()
            recordList(metrics.events.size, statistics.httpSummaryTotal)
        }

        return Projection(data, returned, maxOf(total, returned), truncated)
    }

    private data class Projection(
        val data: Map<String, Any?>,
        val returned: Int,
        val total: Int,
        val truncated: Boolean
    )

    private companion object {
        const val DEFAULT_TOP_N = 20
        const val MAX_TOP_N = 50
        const val MIN_BUCKET_SECONDS = 0.1
        const val MAX_BUCKET_SECONDS = 60.0
        const val DEFAULT_BUCKET_SECONDS = 1.0
        const val MAX_FILTER_LENGTH = 2048

        /**
         * What a bare call returns: the shape of the traffic plus the four
         * protocol health blocks.  Conversations and endpoints are left out
         * because they are the two largest tables and a model that wants them
         * can name them.
         */
        val DEFAULT_SECTIONS = setOf(
            AgentStatisticsSection.ProtocolHierarchy,
            AgentStatisticsSection.Tcp,
            AgentStatisticsSection.Dns,
            AgentStatisticsSection.Tls,
            AgentStatisticsSection.Http
        )
    }
}
