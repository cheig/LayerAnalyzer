// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.RadioEvent
import com.example.layanalyzer.model.RadioQueryResult
import com.example.layanalyzer.model.RtcpStreamSummary
import com.example.layanalyzer.model.RtpStreamSummary
import com.example.layanalyzer.model.SipMessage
import com.example.layanalyzer.model.TemporalCorrelation
import com.example.layanalyzer.model.TemporalCorrelationConfidence
import com.example.layanalyzer.model.UnifiedNetworkTimeline
import com.example.layanalyzer.model.UnifiedTimelineClock
import com.example.layanalyzer.model.UnifiedTimelineEvent
import com.example.layanalyzer.model.UnifiedTimelineInput
import com.example.layanalyzer.model.UnifiedTimelineTrack
import kotlin.math.abs
import java.util.Locale

/**
 * Builds a source-aware, epoch-second network timeline.
 *
 * The builder intentionally emits temporal candidates rather than causal
 * findings.  A shared time window is evidence to inspect, not proof that a
 * Radio transition caused a SIP, core, media, or transport outcome.
 */
object UnifiedNetworkTimelineBuilder {
    private const val BASE_CORRELATION_WINDOW_MILLIS = 250L
    private const val MAX_TEMPORAL_CORRELATIONS = 2_000

    fun build(input: UnifiedTimelineInput): UnifiedNetworkTimeline {
        val communication = enrichCommunication(input.communication)
        val events = mutableListOf<UnifiedTimelineEvent>()
        val clockRecords = linkedMapOf<String, UnifiedTimelineClock>()
        val configuredClocks = input.clocks.associateBy { it.source }

        fun addClock(
            source: String,
            sourceClock: String,
            manualOffsetMillis: Long = 0L,
            uncertaintyMillis: Long = 0L
        ): UnifiedTimelineClock {
            val configured = configuredClocks[source]
            val record = UnifiedTimelineClock(
                source = source,
                sourceClock = configured?.sourceClock ?: sourceClock,
                manualOffsetMillis = manualOffsetMillis + (configured?.manualOffsetMillis ?: 0L),
                uncertaintyMillis = maxOf(uncertaintyMillis, configured?.uncertaintyMillis ?: 0L)
            )
            val existing = clockRecords[source]
            clockRecords[source] = if (existing == null) record else existing.copy(
                manualOffsetMillis = if (abs(record.manualOffsetMillis) > abs(existing.manualOffsetMillis)) {
                    record.manualOffsetMillis
                } else {
                    existing.manualOffsetMillis
                },
                uncertaintyMillis = maxOf(existing.uncertaintyMillis, record.uncertaintyMillis)
            )
            return record
        }

        fun add(
            id: String,
            track: UnifiedTimelineTrack,
            type: String,
            rawStart: Double,
            rawEnd: Double = rawStart,
            source: String,
            sourceFrames: List<Long> = emptyList(),
            sourceClock: String = "epoch_seconds",
            manualOffsetMillis: Long = 0L,
            uncertaintyMillis: Long = 0L,
            details: Map<String, Any?> = emptyMap()
        ) {
            if (!rawStart.isFinite() || !rawEnd.isFinite()) return
            val clock = addClock(source, sourceClock, manualOffsetMillis, uncertaintyMillis)
            val offsetSeconds = clock.manualOffsetMillis / 1000.0
            val start = rawStart + offsetSeconds
            val end = maxOf(start, rawEnd + offsetSeconds)
            events += UnifiedTimelineEvent(
                id = id,
                track = track,
                type = type,
                startTime = start,
                endTime = end,
                source = source,
                sourceFrames = sourceFrames.distinct(),
                timeUncertaintyMillis = clock.uncertaintyMillis.coerceAtLeast(0L),
                sourcePriority = track.priority,
                details = details
            )
        }

        input.radio.events.forEachIndexed { index, event ->
            addRadioEvent(add = ::add, index = index, event = event)
        }
        communication.coreProcedures.forEachIndexed { index, procedure ->
            add(
                id = "core-procedure-$index",
                track = UnifiedTimelineTrack.Core,
                type = procedure.procedureType.ifBlank { "CORE_PROCEDURE" },
                rawStart = procedure.startTime,
                rawEnd = procedure.endTime,
                source = "capture.core",
                sourceFrames = procedure.messages.map { it.frameNumber },
                details = mapOf(
                    "localCorrelationId" to procedure.localCorrelationId,
                    "correlationQuality" to procedure.correlationQuality.wireName,
                    "confidenceScore" to procedure.correlationQuality.score,
                    "failureCauses" to procedure.failureCauses,
                    "retryCount" to procedure.retryCount,
                    "partial" to procedure.partial,
                    "limitations" to procedure.limitations,
                    "stages" to procedure.stages.map { stage ->
                        mapOf(
                            "stage" to stage.stage,
                            "startTime" to stage.startTime,
                            "endTime" to stage.endTime,
                            "frameNumbers" to stage.frameNumbers,
                            "messageTypes" to stage.messageTypes,
                            "outcomes" to stage.outcomes,
                            "causes" to stage.causes,
                            "correlationQuality" to stage.correlationQuality.wireName
                        )
                    }
                )
            )
        }
        communication.coreMessages.forEach { message ->
            add(
                id = "core-frame-${message.frameNumber}",
                track = UnifiedTimelineTrack.Core,
                type = message.messageType.ifBlank { "core.message" },
                rawStart = message.time,
                source = "capture.core",
                sourceFrames = listOf(message.frameNumber),
                details = mapOf(
                    "protocol" to message.protocol,
                    "outcome" to message.outcome,
                    "cause" to message.cause,
                    "procedureType" to message.procedureType,
                    "correlationQuality" to "source_identifier_or_engine_timeline"
                )
            )
        }
        communication.calls.forEachIndexed { index, call ->
            val registration = call.messages.any { message ->
                message.method.equals("REGISTER", ignoreCase = true) ||
                    message.cSeqMethod.equals("REGISTER", ignoreCase = true)
            }
            add(
                id = "sip-call-$index",
                track = UnifiedTimelineTrack.Sip,
                type = if (registration) "SIP_REGISTRATION" else "SIP_CALL",
                rawStart = call.startTime,
                rawEnd = call.endTime,
                source = "capture.sip",
                sourceFrames = call.messages.map { it.frameNumber },
                details = mapOf(
                    "callId" to call.callId,
                    "messageCount" to call.messages.size,
                    "failureCode" to call.failureCode,
                    "methods" to call.messages.mapNotNull { message ->
                        message.method.takeIf { it.isNotBlank() }
                    }.distinct(),
                    "phase" to if (registration) "registration" else "call"
                )
            )
        }
        communication.sipMessages.forEach { message ->
            addSipEvent(add = ::add, message = message)
        }
        communication.streams.forEachIndexed { index, stream ->
            addRtpEvent(add = ::add, index = index, stream = stream)
        }
        communication.rtcpStreams.forEachIndexed { index, stream ->
            addRtcpEvent(add = ::add, index = index, stream = stream)
        }
        input.statistics?.let { statistics ->
            addTransportEvents(add = ::add, statistics = statistics)
        }
        input.expertInfo?.let { expert ->
            addExpertEvents(add = ::add, expert = expert, statistics = input.statistics)
        }

        val ordered = events
            .distinctBy { listOf(it.id, it.startTime, it.endTime, it.type).joinToString("|") }
            .sortedWith(compareBy({ it.startTime }, { it.sourcePriority }, { it.sourceFrames.firstOrNull() ?: Long.MAX_VALUE }, { it.id }))
        val correlations = temporalCorrelations(ordered)
        val available = input.radio.dataAvailable
        val limitations = buildList {
            if (!available) {
                add(
                    input.radio.unavailableReason
                        ?: "No supported Radio data is available. The timeline cannot assess wireless-side health."
                )
                add("Radio absence is not evidence that the wireless side was healthy.")
            }
            if (input.radio.truncated) add("Radio query results were truncated; negative conclusions are limited.")
            if (communication.sipTruncated || communication.rtpTruncated ||
                communication.rtcpTruncated || communication.coreTruncated
            ) {
                add("One or more communication sources were truncated; the timeline is partial.")
            }
            add("Temporal correlations are candidates only; time proximity does not establish causality or root cause.")
        }.distinct()
        val fallbackStart = input.statistics?.startTime ?: 0.0
        val fallbackEnd = input.statistics?.endTime ?: fallbackStart
        return UnifiedNetworkTimeline(
            events = ordered,
            temporalCorrelations = correlations,
            clocks = (clockRecords.values + input.clocks).distinctBy { it.source }.sortedBy { it.source },
            startTime = ordered.minOfOrNull { it.startTime } ?: fallbackStart,
            endTime = ordered.maxOfOrNull { it.endTime } ?: fallbackEnd,
            radioAvailable = available,
            unavailableReason = if (available) null else input.radio.unavailableReason,
            limitations = limitations
        )
    }

    private fun enrichCommunication(input: CommunicationAnalysis): CommunicationAnalysis {
        val needsAggregation =
            (input.sipMessages.isNotEmpty() && input.calls.isEmpty()) ||
                (input.rtpPackets.isNotEmpty() && input.streams.isEmpty()) ||
                (input.rtcpPackets.isNotEmpty() && input.rtcpStreams.isEmpty()) ||
                (input.coreMessages.isNotEmpty() && input.coreProcedures.isEmpty())
        return if (needsAggregation) CommunicationAnalyzer.aggregate(input) else input
    }

    fun build(
        radio: RadioQueryResult,
        communication: CommunicationAnalysis = CommunicationAnalysis(),
        statistics: CaptureStatistics? = null,
        expertInfo: ExpertInfoSummary? = null,
        clocks: List<UnifiedTimelineClock> = emptyList()
    ): UnifiedNetworkTimeline = build(
        UnifiedTimelineInput(
            radio = radio,
            communication = communication,
            statistics = statistics,
            expertInfo = expertInfo,
            clocks = clocks
        )
    )

    fun build(
        radioEvents: List<RadioEvent>,
        communication: CommunicationAnalysis = CommunicationAnalysis(),
        statistics: CaptureStatistics? = null,
        expertInfo: ExpertInfoSummary? = null,
        clocks: List<UnifiedTimelineClock> = emptyList(),
        radioUnavailableReason: String? = null
    ): UnifiedNetworkTimeline = build(
        radio = RadioQueryResult(
            events = radioEvents,
            returned = radioEvents.size,
            total = radioEvents.size,
            sourceCapabilities = if (radioEvents.isEmpty()) emptyList() else {
                listOf(
                    com.example.layanalyzer.model.RadioSourceCapability(
                        source = radioEvents.first().source,
                        available = true,
                        supportsSnapshots = false,
                        supportsEvents = true,
                        description = "Radio event input"
                    )
                )
            },
            unavailableReason = radioUnavailableReason,
            dataAvailable = radioEvents.isNotEmpty()
        ),
        communication = communication,
        statistics = statistics,
        expertInfo = expertInfo,
        clocks = clocks
    )

    /** Sink passed to helpers; a fun interface keeps named arguments available. */
    private fun interface TimelineEventAdder {
        operator fun invoke(
            id: String,
            track: UnifiedTimelineTrack,
            type: String,
            rawStart: Double,
            rawEnd: Double,
            source: String,
            sourceFrames: List<Long>,
            sourceClock: String,
            manualOffsetMillis: Long,
            uncertaintyMillis: Long,
            details: Map<String, Any?>
        )
    }

    private fun addRadioEvent(
        add: TimelineEventAdder,
        index: Int,
        event: RadioEvent
    ) {
        add(
            id = "radio-${event.type.wireName}-$index",
            track = UnifiedTimelineTrack.Radio,
            type = event.type.wireName,
            rawStart = event.startTime,
            rawEnd = event.endTime,
            source = event.source,
            sourceFrames = event.sourceFrames,
            sourceClock = event.sourceClock,
            manualOffsetMillis = event.manualOffsetMillis,
            uncertaintyMillis = event.timeUncertaintyMillis,
            details = buildMap {
                put("rat", event.rat)
                put("cellIdAlias", event.cellIdAlias)
                put("severity", event.severity.wireName)
                put("confidence", event.confidence.wireName)
                put("confidenceScore", event.confidence.score)
                put("observations", event.observations)
                put("signalMetricsBefore", event.signalMetricsBefore?.toMap())
                put("signalMetricsAfter", event.signalMetricsAfter?.toMap())
            }
        )
    }

    private fun addSipEvent(
        add: TimelineEventAdder,
        message: SipMessage
    ) {
        val label = when {
            message.method.isNotBlank() -> message.method
            message.status.isNotBlank() -> message.status
            else -> "SIP_MESSAGE"
        }
        add(
            id = "sip-frame-${message.frameNumber}",
            track = UnifiedTimelineTrack.Sip,
            type = label,
            rawStart = message.time,
            rawEnd = message.time,
            source = "capture.sip",
            sourceFrames = listOf(message.frameNumber),
            sourceClock = "epoch_seconds",
            manualOffsetMillis = 0L,
            uncertaintyMillis = 0L,
            details = mapOf(
                "method" to message.method,
                "status" to message.status,
                "callId" to message.callId,
                "cSeqNumber" to message.cSeqNumber,
                "cSeqMethod" to message.cSeqMethod
            )
        )
    }

    private fun addRtpEvent(
        add: TimelineEventAdder,
        index: Int,
        stream: RtpStreamSummary
    ) {
        val first = stream.packets.minByOrNull { it.time }
        val last = stream.packets.maxByOrNull { it.time } ?: first
        val start = first?.time ?: 0.0
        val end = last?.time ?: start
        add(
            id = "rtp-stream-$index",
            track = UnifiedTimelineTrack.Media,
            type = "RTP_STREAM",
            rawStart = start,
            rawEnd = end,
            source = "capture.rtp",
            sourceFrames = listOfNotNull(first?.frameNumber, last?.frameNumber),
            sourceClock = "epoch_seconds",
            manualOffsetMillis = 0L,
            uncertaintyMillis = 0L,
            details = mapOf(
                "streamKey" to stream.key,
                "source" to stream.source,
                "destination" to stream.destination,
                "ssrc" to stream.ssrc,
                "payloadType" to stream.payloadType,
                "packetCount" to stream.packetCount,
                "lostPackets" to stream.lostPackets,
                "jitterMillis" to stream.jitterMillis
            )
        )
    }

    private fun addRtcpEvent(
        add: TimelineEventAdder,
        index: Int,
        stream: RtcpStreamSummary
    ) {
        val first = stream.reports.minByOrNull { it.time }
        val last = stream.reports.maxByOrNull { it.time } ?: first
        val start = first?.time ?: 0.0
        val end = last?.time ?: start
        add(
            id = "rtcp-stream-$index",
            track = UnifiedTimelineTrack.Media,
            type = "RTCP_REPORT",
            rawStart = start,
            rawEnd = end,
            source = "capture.rtcp",
            sourceFrames = listOfNotNull(first?.frameNumber, last?.frameNumber),
            sourceClock = "epoch_seconds",
            manualOffsetMillis = 0L,
            uncertaintyMillis = 0L,
            details = mapOf(
                "streamKey" to stream.key,
                "reportedSsrc" to stream.reportedSsrc,
                "reportCount" to stream.reportCount,
                "maxFractionLostPercent" to stream.reports.mapNotNull { it.fractionLostPercent }.maxOrNull(),
                "maxCumulativeLost" to stream.reports.mapNotNull { it.cumulativeLost }.maxOrNull()
            )
        )
    }

    private fun addTransportEvents(
        add: TimelineEventAdder,
        statistics: CaptureStatistics
    ) {
        statistics.tcpSummaries.forEachIndexed { index, item ->
            add(
                id = "transport-tcp-${item.frameNumber}-$index",
                track = UnifiedTimelineTrack.Transport,
                type = transportType("tcp", item.summary),
                rawStart = item.time,
                rawEnd = item.time,
                source = "capture.tcp",
                sourceFrames = listOf(item.frameNumber),
                sourceClock = "epoch_seconds",
                manualOffsetMillis = 0L,
                uncertaintyMillis = 0L,
                details = mapOf("protocol" to item.protocol, "summary" to item.summary)
            )
        }
        statistics.tlsSummaries.forEachIndexed { index, item ->
            add(
                id = "transport-tls-${item.frameNumber}-$index",
                track = UnifiedTimelineTrack.Transport,
                type = "TLS_ALERT",
                rawStart = item.time,
                rawEnd = item.time,
                source = "capture.tls",
                sourceFrames = listOf(item.frameNumber),
                sourceClock = "epoch_seconds",
                manualOffsetMillis = 0L,
                uncertaintyMillis = 0L,
                details = mapOf("protocol" to item.protocol, "summary" to item.summary)
            )
        }
        if (statistics.tcpRetransmissions > 0 && statistics.tcpSummaries.none { transportType("tcp", it.summary) == "TCP_RETRANSMISSION" }) {
            addAggregateTransport(add, "TCP_RETRANSMISSION", statistics.tcpRetransmissions, statistics)
        }
        if (statistics.tcpResets > 0 && statistics.tcpSummaries.none { transportType("tcp", it.summary) == "TCP_RESET" }) {
            addAggregateTransport(add, "TCP_RESET", statistics.tcpResets, statistics)
        }
        if (statistics.tcpZeroWindows > 0 && statistics.tcpSummaries.none { transportType("tcp", it.summary) == "TCP_ZERO_WINDOW" }) {
            addAggregateTransport(add, "TCP_ZERO_WINDOW", statistics.tcpZeroWindows, statistics)
        }
        if (statistics.tlsAlertTotal > 0 && statistics.tlsSummaries.isEmpty()) {
            addAggregateTransport(add, "TLS_ALERT", statistics.tlsAlertTotal, statistics)
        }
    }

    private fun addAggregateTransport(
        add: TimelineEventAdder,
        type: String,
        count: Int,
        statistics: CaptureStatistics
    ) {
        add(
            id = "transport-$type-aggregate",
            track = UnifiedTimelineTrack.Transport,
            type = type,
            rawStart = statistics.startTime,
            rawEnd = statistics.endTime,
            source = "capture.statistics",
            sourceFrames = emptyList(),
            sourceClock = "epoch_seconds",
            manualOffsetMillis = 0L,
            uncertaintyMillis = 0L,
            details = mapOf("count" to count, "aggregate" to true)
        )
    }

    private fun addExpertEvents(
        add: TimelineEventAdder,
        expert: ExpertInfoSummary,
        statistics: CaptureStatistics?
    ) {
        expert.items.forEachIndexed { index, item ->
            val time = statistics?.let { stats ->
                (stats.tcpSummaries + stats.tlsSummaries + stats.dnsSummaries + stats.httpSummaries)
                    .firstOrNull { it.frameNumber == item.frameNumber }
                    ?.time
            } ?: statistics?.startTime ?: 0.0
            add(
                id = "transport-expert-${item.frameNumber}-$index",
                track = UnifiedTimelineTrack.Transport,
                type = "EXPERT_${item.severity.uppercase(Locale.US)}",
                rawStart = time,
                rawEnd = time,
                source = "capture.expert",
                sourceFrames = listOf(item.frameNumber),
                sourceClock = "epoch_seconds",
                manualOffsetMillis = 0L,
                uncertaintyMillis = 0L,
                details = mapOf("label" to item.label, "filter" to item.filter, "severity" to item.severity)
            )
        }
    }

    private fun transportType(protocol: String, summary: String): String {
        val normalized = summary.lowercase(Locale.US)
        return when {
            protocol == "tcp" && ("retransmission" in normalized || "fast retransmission" in normalized) -> "TCP_RETRANSMISSION"
            protocol == "tcp" && ("reset" in normalized || "rst" in normalized) -> "TCP_RESET"
            protocol == "tcp" && ("zero window" in normalized || "zerowindow" in normalized) -> "TCP_ZERO_WINDOW"
            protocol == "tcp" -> "TCP_ANOMALY"
            else -> "TRANSPORT_ANOMALY"
        }
    }

    private fun temporalCorrelations(events: List<UnifiedTimelineEvent>): List<TemporalCorrelation> {
        if (events.size < 2) return emptyList()
        val result = mutableListOf<TemporalCorrelation>()
        for (leftIndex in events.indices) {
            val left = events[leftIndex]
            for (rightIndex in leftIndex + 1 until events.size) {
                val right = events[rightIndex]
                if (left.track == right.track) continue
                val windowMillis = BASE_CORRELATION_WINDOW_MILLIS +
                    left.timeUncertaintyMillis + right.timeUncertaintyMillis
                val leftEnd = left.uncertaintyEndTime
                val rightStart = right.uncertaintyStartTime
                val gapMillis = when {
                    leftEnd < rightStart -> ((rightStart - leftEnd) * 1000.0).toLong()
                    right.uncertaintyEndTime < left.uncertaintyStartTime -> ((left.uncertaintyStartTime - right.uncertaintyEndTime) * 1000.0).toLong()
                    else -> 0L
                }
                if (gapMillis > windowMillis) continue
                val start = maxOf(left.uncertaintyStartTime, right.uncertaintyStartTime)
                val end = minOf(left.uncertaintyEndTime, right.uncertaintyEndTime).coerceAtLeast(start)
                result += TemporalCorrelation(
                    fromEventId = left.id,
                    toEventId = right.id,
                    startTime = start,
                    endTime = end,
                    windowMillis = windowMillis,
                    confidence = TemporalCorrelationConfidence.Candidate,
                    basis = "timestamp_plus_both_source_uncertainties",
                    causal = false
                )
                if (result.size >= MAX_TEMPORAL_CORRELATIONS) return result
            }
        }
        return result
    }
}
