package com.example.layanalyzer.ai.tools.dto

import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.CaptureStatistics

/**
 * Projections for the AI-10 get_statistics tool.
 *
 * As with the AI-09 DTOs, these types cannot carry what they do not declare:
 * there is no payload or file path, and protocol events retain only the frame,
 * time and bounded summary needed for evidence. Endpoint identifiers remain in
 * the explicitly requested conversations/endpoints sections.
 */

/**
 * Statistics sections a model may request. Maps to the structured outputs
 * CaptureStatistics provides.
 */
enum class AgentStatisticsSection(val wireName: String) {
    ProtocolHierarchy("protocol_hierarchy"),
    Conversations("conversations"),
    Endpoints("endpoints"),
    IoGraph("io_graph"),
    PacketLengths("packet_lengths"),
    Tcp("tcp"),
    Dns("dns"),
    Tls("tls"),
    Http("http");

    companion object {
        val wireNames: List<String> = values().map { it.wireName }

        fun fromWire(name: String?): AgentStatisticsSection? =
            values().firstOrNull { it.wireName == name }
    }
}

/** One conversation entry projected for a model. */
data class AgentConversationEntry(
    val type: String,
    val endpointA: String,
    val endpointB: String,
    val portA: Int?,
    val portB: Int?,
    val packets: Int,
    val bytes: Long,
    val startTime: Double,
    val duration: Double
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "type" to type,
        "endpointA" to endpointA,
        "endpointB" to endpointB,
        "portA" to portA,
        "portB" to portB,
        "packets" to packets,
        "bytes" to bytes,
        "startTime" to startTime,
        "duration" to duration
    )
}

/** One endpoint entry projected for a model. */
data class AgentEndpointEntry(
    val type: String,
    val address: String,
    val port: Int?,
    val packets: Int,
    val bytes: Long
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "type" to type,
        "address" to address,
        "port" to port,
        "packets" to packets,
        "bytes" to bytes
    )
}

/** One I/O graph bucket projected for a model. */
data class AgentIoBucketEntry(
    val startTime: Double,
    val endTime: Double,
    val packets: Int,
    val bytes: Long
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "startTime" to startTime,
        "endTime" to endTime,
        "packets" to packets,
        "bytes" to bytes
    )
}

/** One packet-length histogram bucket projected for a model. */
data class AgentPacketLengthBucket(
    val label: String,
    val packets: Int,
    val bytes: Long
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "label" to label,
        "packets" to packets,
        "bytes" to bytes
    )
}

/** Packet-length distribution metrics projected for a model. */
data class AgentPacketLengthMetrics(
    val min: Int,
    val max: Int,
    val average: Double,
    val totalBytes: Long,
    val buckets: List<AgentPacketLengthBucket>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "min" to min,
        "max" to max,
        "average" to average,
        "totalBytes" to totalBytes,
        "buckets" to buckets.map(AgentPacketLengthBucket::toAgentJson)
    )
}

/** A frame-addressable protocol event without endpoint identifiers. */
data class AgentProtocolEvent(
    val frameNumber: Long,
    val time: Double,
    val summary: String
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "frameNumber" to frameNumber,
        "time" to time,
        "summary" to summary
    )
}

/** TCP health metrics projected for a model. */
data class AgentTcpMetrics(
    val syn: Int,
    val synAck: Int,
    val retransmissions: Int,
    val duplicateAcks: Int,
    val resets: Int,
    val zeroWindows: Int,
    val averageRttMs: Double,
    val rttSamples: Int,
    val summaryTotal: Int,
    val events: List<AgentProtocolEvent>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "syn" to syn,
        "synAck" to synAck,
        "retransmissions" to retransmissions,
        "duplicateAcks" to duplicateAcks,
        "resets" to resets,
        "zeroWindows" to zeroWindows,
        "averageRttMs" to averageRttMs,
        "rttSamples" to rttSamples,
        "summaryTotal" to summaryTotal,
        "events" to events.map(AgentProtocolEvent::toAgentJson)
    )
}

/** DNS health metrics projected for a model. */
data class AgentDnsMetrics(
    val queries: Int,
    val responses: Int,
    val failures: Int,
    val averageResponseMs: Double,
    val firstFailureFrame: Long?,
    val summaryTotal: Int,
    val events: List<AgentProtocolEvent>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "queries" to queries,
        "responses" to responses,
        "failures" to failures,
        "averageResponseMs" to averageResponseMs,
        "firstFailureFrame" to firstFailureFrame,
        "summaryTotal" to summaryTotal,
        "events" to events.map(AgentProtocolEvent::toAgentJson)
    )
}

/** TLS health metrics projected for a model. */
data class AgentTlsMetrics(
    val versions: Map<String, Int>,
    val alerts: Int,
    val firstAlertFrame: Long?,
    val summaryTotal: Int,
    val events: List<AgentProtocolEvent>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "versions" to versions,
        "alerts" to alerts,
        "firstAlertFrame" to firstAlertFrame,
        "summaryTotal" to summaryTotal,
        "events" to events.map(AgentProtocolEvent::toAgentJson)
    )
}

/** HTTP health metrics projected for a model. */
data class AgentHttpMetrics(
    val statusCodes: Map<String, Int>,
    val errors: Int,
    val firstErrorFrame: Long?,
    val summaryTotal: Int,
    val events: List<AgentProtocolEvent>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "statusCodes" to statusCodes,
        "errors" to errors,
        "firstErrorFrame" to firstErrorFrame,
        "summaryTotal" to summaryTotal,
        "events" to events.map(AgentProtocolEvent::toAgentJson)
    )
}

/**
 * Builders that turn [CaptureStatistics] into the DTOs above.
 *
 * Kept in one object for the same reason as [AgentBaseToolProjections]: the
 * whole statistics projection is auditable in one place, and a tool cannot
 * reach a richer internal model by importing a more convenient conversion.
 */
object AgentStatisticsProjections {
    /** Buckets the I/O graph may carry after merging. */
    const val MAX_IO_BUCKETS = 120

    fun protocolHierarchy(
        statistics: CaptureStatistics,
        topN: Int
    ): List<AgentProtocolHierarchyEntry> =
        AgentBaseToolProjections.protocolHierarchy(statistics, topN)

    /**
     * Conversations ranked by bytes descending, which is the ordering the design
     * document asks for and the one that puts the heaviest talkers — the usual
     * subject of an investigation — on the first page.
     */
    fun conversations(
        statistics: CaptureStatistics,
        topN: Int
    ): List<AgentConversationEntry> = statistics.conversations
        .sortedByDescending { it.bytes }
        .take(topN.coerceAtLeast(0))
        .map { stat ->
            AgentConversationEntry(
                type = stat.type,
                endpointA = stat.endpointA,
                endpointB = stat.endpointB,
                portA = stat.portA,
                portB = stat.portB,
                packets = stat.packets,
                bytes = stat.bytes,
                startTime = stat.startTime,
                duration = stat.duration
            )
        }

    fun endpoints(
        statistics: CaptureStatistics,
        topN: Int
    ): List<AgentEndpointEntry> = statistics.endpoints
        .sortedByDescending { it.bytes }
        .take(topN.coerceAtLeast(0))
        .map { stat ->
            AgentEndpointEntry(
                type = stat.type,
                address = stat.address,
                port = stat.port,
                packets = stat.packets,
                bytes = stat.bytes
            )
        }

    /**
     * Fold the I/O graph down to at most [MAX_IO_BUCKETS] buckets by merging
     * adjacent ones.
     *
     * Taking the first 120 buckets instead would silently cut the tail off the
     * time axis, so a model reading a long capture would conclude the traffic
     * stopped when in fact the projection did.  Merging keeps the full time
     * range and only coarsens resolution, which is the property a model needs to
     * reason about *when* something happened.
     */
    fun ioGraph(
        statistics: CaptureStatistics,
        maxBuckets: Int = MAX_IO_BUCKETS
    ): List<AgentIoBucketEntry> {
        val buckets = statistics.ioGraph
        val limit = maxBuckets.coerceAtLeast(1)
        if (buckets.isEmpty()) return emptyList()
        if (buckets.size <= limit) {
            return buckets.map { bucket ->
                AgentIoBucketEntry(
                    startTime = bucket.startTime,
                    endTime = bucket.endTime,
                    packets = bucket.packets,
                    bytes = bucket.bytes
                )
            }
        }

        // Ceiling division so the merged series never exceeds the limit; the
        // final group simply holds fewer source buckets than the others.
        val groupSize = (buckets.size + limit - 1) / limit
        return buckets.chunked(groupSize).map { group ->
            AgentIoBucketEntry(
                startTime = group.first().startTime,
                endTime = group.last().endTime,
                packets = group.sumOf { it.packets },
                bytes = group.sumOf { it.bytes }
            )
        }
    }

    fun packetLengths(statistics: CaptureStatistics): AgentPacketLengthMetrics {
        val lengths = statistics.packetLengths
        return AgentPacketLengthMetrics(
            min = lengths.min,
            max = lengths.max,
            average = lengths.average,
            totalBytes = lengths.totalBytes,
            buckets = lengths.buckets.map { bucket ->
                AgentPacketLengthBucket(
                    label = bucket.label,
                    packets = bucket.packets,
                    bytes = bucket.bytes
                )
            }
        )
    }

    fun tcp(statistics: CaptureStatistics, topN: Int) = AgentTcpMetrics(
        syn = statistics.tcpSyn,
        synAck = statistics.tcpSynAck,
        retransmissions = statistics.tcpRetransmissions,
        duplicateAcks = statistics.tcpDuplicateAcks,
        resets = statistics.tcpResets,
        zeroWindows = statistics.tcpZeroWindows,
        averageRttMs = statistics.tcpAverageRttMs,
        rttSamples = statistics.tcpRttSamples,
        summaryTotal = statistics.tcpSummaryTotal,
        events = protocolEvents(statistics.tcpSummaries, topN)
    )

    fun dns(statistics: CaptureStatistics, topN: Int) = AgentDnsMetrics(
        queries = statistics.dnsQueries,
        responses = statistics.dnsResponses,
        failures = statistics.dnsFailureTotal,
        averageResponseMs = statistics.dnsAverageResponseMs,
        firstFailureFrame = statistics.dnsFirstFailureFrame,
        summaryTotal = statistics.dnsSummaryTotal,
        events = protocolEvents(statistics.dnsSummaries, topN)
    )

    fun tls(statistics: CaptureStatistics, topN: Int) = AgentTlsMetrics(
        versions = statistics.tlsVersions,
        alerts = statistics.tlsAlertTotal,
        firstAlertFrame = statistics.tlsFirstAlertFrame,
        summaryTotal = statistics.tlsSummaryTotal,
        events = protocolEvents(statistics.tlsSummaries, topN)
    )

    /**
     * HTTP indicators.  Status codes and error counts travel; hosts do not,
     * because the host list is an identifier set the model does not need to
     * judge whether HTTP is healthy.
     */
    fun http(statistics: CaptureStatistics, topN: Int) = AgentHttpMetrics(
        statusCodes = statistics.httpStatusCodes,
        errors = statistics.httpErrorTotal,
        firstErrorFrame = statistics.httpFirstErrorFrame,
        summaryTotal = statistics.httpSummaryTotal,
        events = protocolEvents(statistics.httpSummaries, topN)
    )

    private fun protocolEvents(
        summaries: List<com.example.layanalyzer.model.ProtocolSummaryItem>,
        topN: Int
    ): List<AgentProtocolEvent> = summaries
        .take(topN.coerceAtLeast(0))
        .map { item ->
            AgentProtocolEvent(
                frameNumber = item.frameNumber,
                time = item.time,
                summary = item.summary
            )
        }
}
