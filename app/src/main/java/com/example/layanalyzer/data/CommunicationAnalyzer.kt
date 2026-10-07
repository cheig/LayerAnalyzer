// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.CoreImsCorrelation
import com.example.layanalyzer.model.RtpPacketMetric
import com.example.layanalyzer.model.RtpStreamSummary
import com.example.layanalyzer.model.RtcpPacketMetric
import com.example.layanalyzer.model.RtcpStreamSummary
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SipCallSummary
import com.example.layanalyzer.model.toCoreSessionSummary

object CommunicationAnalyzer {
    fun aggregate(input: CommunicationAnalysis): CommunicationAnalysis {
        val correlation = SipTransactionCorrelator.correlate(input.sipMessages)
        val sdpMedia = input.sipMessages.mapNotNull { it.sdp }
        val calls = input.sipMessages.groupBy { it.callId.ifBlank { "unknown:${it.source}:${it.destination}" } }
                .map { (callId, messages) ->
                    val ordered = messages.sortedWith(compareBy({ it.time }, { it.frameNumber }))
                    SipCallSummary(
                        callId = callId,
                        messages = ordered,
                        startTime = ordered.firstOrNull()?.time ?: 0.0,
                        endTime = ordered.lastOrNull()?.time ?: 0.0,
                        failureCode = ordered.mapNotNull(::responseCode).lastOrNull { it >= 300 },
                        sdpMedia = ordered.mapNotNull { it.sdp }.distinctBy {
                            listOf(it.connectionAddress, it.mediaType, it.mediaPort, it.mediaProtocol, it.formats, it.codecs)
                        }
                    )
                }.sortedBy { it.startTime }
        val streams = input.rtpPackets.groupBy(::streamKey).map { (key, packets) ->
                aggregateRtp(key, packets, sdpClockRateFor(packets, sdpMedia))
            }
                .sortedByDescending { it.packetCount }
        val rtcpStreams = input.rtcpPackets.groupBy(::rtcpStreamKey).map { (key, reports) ->
                aggregateRtcp(key, reports)
            }.sortedByDescending { it.reportCount }
        val coreCorrelation = CoreCorrelationEngine.correlate(input.coreMessages, input.coreTruncated)
        val coreProcedures = coreCorrelation.timelines.map { timeline ->
            val imsCorrelations = calls
                .filter { call ->
                    call.callId.isNotBlank() &&
                        !call.callId.startsWith("unknown:") &&
                        call.endTime >= timeline.startTime &&
                        call.startTime <= timeline.endTime
                }
                .map { call ->
                    CoreImsCorrelation(
                        callId = call.callId,
                        startTime = call.startTime,
                        endTime = call.endTime
                    )
                }
            timeline.copy(imsCorrelations = imsCorrelations)
        }
        val coreSessions = coreProcedures
            .map { it.toCoreSessionSummary() }
            .sortedBy { it.firstFrame ?: Long.MAX_VALUE }
        return input.copy(
            calls = calls,
            streams = streams,
            rtcpStreams = rtcpStreams,
            coreSessions = coreSessions,
            coreProcedures = coreProcedures,
            coreCorrelation = coreCorrelation.copy(timelines = coreProcedures),
            sipTransactions = correlation.transactions,
            sipDialogs = correlation.dialogs
        )
    }

    internal fun aggregateRtp(
        key: String,
        input: List<RtpPacketMetric>,
        clockRate: Int? = null
    ): RtpStreamSummary {
        val packets = input.sortedWith(compareBy({ it.time }, { it.frameNumber }))
        var highestExtended: Long? = null
        val seen = mutableSetOf<Long>()
        val missing = mutableSetOf<Long>()
        var reordered = 0
        var duplicates = 0
        packets.forEach { packet ->
            val sequence = packet.sequence ?: return@forEach
            val extended = extendSequence(sequence, highestExtended)
            if (!seen.add(extended)) {
                duplicates++
            } else if (highestExtended != null && extended < highestExtended!!) {
                reordered++
                missing.remove(extended)
            } else {
                if (highestExtended != null && extended > highestExtended!! + 1) {
                    for (missingSequence in highestExtended!! + 1 until extended) missing += missingSequence
                }
                highestExtended = extended
            }
        }
        val first = packets.firstOrNull()
        val effectiveClockRate = clockRate ?: first?.payloadType?.let(::staticPayloadClockRate)
        return RtpStreamSummary(
            key = key,
            source = first?.source.orEmpty(),
            destination = first?.destination.orEmpty(),
            sourcePort = first?.sourcePort,
            destinationPort = first?.destinationPort,
            ssrc = first?.ssrc,
            payloadType = first?.payloadType,
            packetCount = packets.size,
            lostPackets = missing.size,
            reorderedPackets = reordered,
            duplicatePackets = duplicates,
            jitterMillis = effectiveClockRate?.let { calculateJitterMillis(packets, it) },
            firstFrame = first?.frameNumber,
            packets = packets
        )
    }

    internal fun aggregateRtcp(key: String, input: List<RtcpPacketMetric>): RtcpStreamSummary {
        val reports = input.sortedWith(compareBy({ it.time }, { it.frameNumber }))
        val first = reports.firstOrNull()
        return RtcpStreamSummary(
            key = key,
            source = first?.source.orEmpty(),
            destination = first?.destination.orEmpty(),
            sourcePort = first?.sourcePort,
            destinationPort = first?.destinationPort,
            senderSsrc = first?.senderSsrc,
            reportedSsrc = first?.reportedSsrc,
            reportCount = reports.size,
            firstFrame = first?.frameNumber,
            reports = reports
        )
    }

    private fun responseCode(message: com.example.layanalyzer.model.SipMessage): Int? {
        val source = message.status.ifBlank { message.info }
        return Regex("(?<!\\d)([1-6]\\d{2})(?!\\d)").find(source)?.groupValues?.get(1)?.toIntOrNull()
    }

    private fun streamKey(packet: RtpPacketMetric): String =
        "${packet.ssrc ?: "unknown"}:${packet.source}:${packet.sourcePort}->${packet.destination}:${packet.destinationPort}"

    private fun rtcpStreamKey(packet: RtcpPacketMetric): String =
        "${packet.reportedSsrc ?: packet.senderSsrc ?: "unknown"}:${packet.source}:${packet.sourcePort}->${packet.destination}:${packet.destinationPort}"

    private fun extendSequence(sequence: Int, highest: Long?): Long {
        val seq = (sequence and 0xffff).toLong()
        if (highest == null) return seq
        val cycle = highest and 0xffff0000L
        val candidates = listOf(cycle + seq, cycle + seq + 65536L, cycle + seq - 65536L)
        return candidates.minBy { kotlin.math.abs(it - highest) }
    }

    internal fun calculateJitterMillis(packets: List<RtpPacketMetric>, clockRate: Int): Double? {
        var previousTransit: Double? = null
        var jitter = 0.0
        var samples = 0
        packets.forEach { packet ->
            val rtpTimestamp = packet.timestamp ?: return@forEach
            val transit = packet.time * clockRate - rtpTimestamp.toDouble()
            previousTransit?.let { previous ->
                val delta = kotlin.math.abs(transit - previous)
                jitter += (delta - jitter) / 16.0
                samples++
            }
            previousTransit = transit
        }
        return if (samples == 0) null else jitter * 1000.0 / clockRate
    }

    internal fun staticPayloadClockRate(payloadType: Int): Int? = when (payloadType) {
        0, 3, 4, 5, 6, 7, 8, 9, 12, 13, 15, 18 -> 8000
        10, 11 -> 44100
        14, 25, 26, 28, 31, 32, 33, 34 -> 90000
        else -> null
    }

    internal fun isDynamicPayloadType(payloadType: Int): Boolean = payloadType in 96..127

    /**
     * Dynamic payload types have no globally valid clock rate.  Only use an SDP
     * mapping that matches the RTP path's advertised endpoint; otherwise leave
     * jitter unavailable rather than applying a static-table guess.
     */
    private fun sdpClockRateFor(
        packets: List<RtpPacketMetric>,
        mediaDescriptions: List<SdpMediaSummary>
    ): Int? {
        val payloadTypes = packets.mapNotNull { it.payloadType }.distinct()
        if (payloadTypes.none(::isDynamicPayloadType)) return null
        val matchingRates = packets.flatMap { packet ->
            val payloadType = packet.payloadType ?: return@flatMap emptyList()
            mediaDescriptions.asSequence()
                .filter { media -> matchesSdpEndpoint(packet, media) }
                .flatMap { media ->
                    media.payloadMappings.asSequence()
                        .filter { it.payloadType == payloadType }
                        .mapNotNull { it.clockRate }
                }
                .toList()
        }.distinct()
        return matchingRates.singleOrNull()
    }

    private fun matchesSdpEndpoint(packet: RtpPacketMetric, media: SdpMediaSummary): Boolean {
        val address = media.connectionAddress.takeIf { it.isNotBlank() } ?: return false
        val port = media.mediaPort ?: return false
        return (packet.source == address && packet.sourcePort == port) ||
            (packet.destination == address && packet.destinationPort == port)
    }
}
