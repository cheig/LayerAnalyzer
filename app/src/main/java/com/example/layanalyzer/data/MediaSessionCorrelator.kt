package com.example.layanalyzer.data

import com.example.layanalyzer.model.MediaCaptureSnapshot
import com.example.layanalyzer.model.MediaCodecMapping
import com.example.layanalyzer.model.MediaCorrelationConfidence
import com.example.layanalyzer.model.MediaEndpoint
import com.example.layanalyzer.model.MediaFinding
import com.example.layanalyzer.model.MediaFindingKind
import com.example.layanalyzer.model.MediaFindingSeverity
import com.example.layanalyzer.model.MediaLineAnalysis
import com.example.layanalyzer.model.MediaPathDirection
import com.example.layanalyzer.model.MediaRtcpAnalysis
import com.example.layanalyzer.model.MediaRtpDirectionAnalysis
import com.example.layanalyzer.model.MediaSessionAnalysis
import com.example.layanalyzer.model.RtcpStreamSummary
import com.example.layanalyzer.model.RtpPacketMetric
import com.example.layanalyzer.model.RtpStreamSummary
import com.example.layanalyzer.model.SdpMediaDirection
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SdpOfferAnswerAssociation
import com.example.layanalyzer.model.SdpPayloadMapping
import com.example.layanalyzer.model.SipDialogTimeline
import kotlin.math.abs
import kotlin.math.roundToLong

/**
 * Correlates SDP negotiation with RTP and RTCP observations without inspecting
 * SIP bodies or media payloads.  Endpoint matches are intentionally graded so
 * NAT can remain a useful candidate without being reported as proof.
 */
object MediaSessionCorrelator {
    const val HIGH_JITTER_MILLIS = 30.0
    const val HIGH_SEQUENCE_LOSS_PACKETS = 5
    const val HIGH_RTCP_LOSS_PERCENT = 5.0

    fun correlate(
        dialogs: List<SipDialogTimeline>,
        rtpStreams: List<RtpStreamSummary>,
        rtcpStreams: List<RtcpStreamSummary>,
        capture: MediaCaptureSnapshot
    ): List<MediaSessionAnalysis> = dialogs.mapNotNull { dialog ->
        correlate(dialog, rtpStreams, rtcpStreams, capture).takeIf { it.lines.isNotEmpty() }
    }

    fun correlate(
        dialog: SipDialogTimeline,
        rtpStreams: List<RtpStreamSummary>,
        rtcpStreams: List<RtcpStreamSummary>,
        capture: MediaCaptureSnapshot
    ): MediaSessionAnalysis {
        val frameTimes = dialog.events.flatMap { it.transaction.allMessages }
            .associate { it.frameNumber to it.time }
        val dialogStart = frameTimes.values.minOrNull()
        val dialogEnd = frameTimes.values.maxOrNull()
        val lines = dialog.sdpOfferAnswers.mapIndexed { index, association ->
            analyzeLine(
                index = index,
                association = association,
                negotiationStart = frameTimes[association.offerFrame] ?: dialogStart,
                rtpStreams = rtpStreams,
                rtcpStreams = rtcpStreams,
                capture = capture
            )
        }
        val allFindings = lines.flatMap { it.findings }
        return MediaSessionAnalysis(
            callId = dialog.callId,
            startTime = dialogStart,
            endTime = dialogEnd,
            lines = lines,
            findings = allFindings,
            limitations = limitations(lines, capture),
            captureSupportsNegativeEvidence = capture.supportsNegativeEvidence
        )
    }

    private fun analyzeLine(
        index: Int,
        association: SdpOfferAnswerAssociation,
        negotiationStart: Double?,
        rtpStreams: List<RtpStreamSummary>,
        rtcpStreams: List<RtcpStreamSummary>,
        capture: MediaCaptureSnapshot
    ): MediaLineAnalysis {
        val offer = association.offer
        val answer = association.answer
        val offerEndpoint = offer.toEndpoint()
        val answerEndpoint = answer?.toEndpoint()
        val rejected = isRejected(offer, answer)
        val negotiatedCodecs = commonCodecs(offer, answer)
        val expected = expectedDirections(offer.direction, answer?.direction)
        val associated = if (rejected) {
            emptyList()
        } else {
            associateStreams(
                rtpStreams = rtpStreams,
                offerEndpoint = offerEndpoint,
                answerEndpoint = answerEndpoint,
                expected = expected,
                negotiatedPayloadTypes = negotiatedPayloadTypes(offer, answer),
                negotiationStart = negotiationStart,
                captureEnd = capture.endTime
            )
        }
        val directionAnalyses = buildDirections(expected, associated, negotiatedCodecs)
        val rtcp = directionAnalyses.flatMap { direction ->
            rtcpFor(direction, rtcpStreams)
        }
        val findings = findingsFor(
            offer = offer,
            answer = answer,
            rejected = rejected,
            directions = directionAnalyses,
            rtcp = rtcp,
            capture = capture,
            negotiationStart = negotiationStart,
            negotiatedCodecs = negotiatedCodecs
        )
        return MediaLineAnalysis(
            mLineIndex = index,
            mediaType = offer.mediaType,
            mediaProtocol = answer?.mediaProtocol?.ifBlank { offer.mediaProtocol } ?: offer.mediaProtocol,
            offerFrame = association.offerFrame,
            answerFrame = association.answerFrame,
            offerEndpoint = offerEndpoint,
            answerEndpoint = answerEndpoint,
            rejected = rejected,
            negotiatedCodecs = negotiatedCodecs,
            directions = directionAnalyses,
            rtcp = rtcp,
            findings = findings
        )
    }

    private fun SdpMediaSummary.toEndpoint() = MediaEndpoint(
        connectionAddress = connectionAddress,
        port = mediaPort,
        direction = direction
    )

    private fun isRejected(offer: SdpMediaSummary, answer: SdpMediaSummary?): Boolean =
        offer.mediaPort == 0 || answer?.mediaPort == 0 ||
            offer.direction == SdpMediaDirection.Inactive ||
            answer?.direction == SdpMediaDirection.Inactive

    private fun expectedDirections(
        offerDirection: SdpMediaDirection,
        answerDirection: SdpMediaDirection?
    ): Map<MediaPathDirection, Boolean> {
        val answer = answerDirection ?: SdpMediaDirection.Unknown
        return linkedMapOf(
            MediaPathDirection.OfferToAnswer to (canSend(offerDirection) && canReceive(answer)),
            MediaPathDirection.AnswerToOffer to (canSend(answer) && canReceive(offerDirection))
        )
    }

    private fun canSend(direction: SdpMediaDirection): Boolean =
        direction != SdpMediaDirection.RecvOnly && direction != SdpMediaDirection.Inactive

    private fun canReceive(direction: SdpMediaDirection): Boolean =
        direction != SdpMediaDirection.SendOnly && direction != SdpMediaDirection.Inactive

    private fun commonCodecs(
        offer: SdpMediaSummary,
        answer: SdpMediaSummary?
    ): List<MediaCodecMapping> {
        if (answer == null) return codecMappings(offer)
        val answerProfiles = codecMappings(answer).map(::codecProfile).toSet()
        return codecMappings(offer)
            .filter { codecProfile(it) in answerProfiles }
            .distinctBy(::codecProfile)
    }

    private fun codecMappings(media: SdpMediaSummary): List<MediaCodecMapping> {
        val mappings = media.payloadMappings.map { mapping ->
            MediaCodecMapping(
                payloadType = mapping.payloadType,
                codec = mapping.encodingName,
                clockRate = mapping.clockRate,
                channels = mapping.channels
            )
        }.filter { it.codec.isNotBlank() || it.payloadType != null }
        if (mappings.isNotEmpty()) return mappings
        return media.codecs.map { codec ->
            MediaCodecMapping(payloadType = null, codec = codec, clockRate = null, channels = null)
        }
    }

    private fun codecProfile(mapping: MediaCodecMapping): String = listOf(
        mapping.codec.trim().uppercase(),
        mapping.clockRate?.toString().orEmpty(),
        mapping.channels?.toString().orEmpty()
    ).joinToString("/")

    private fun negotiatedPayloadTypes(
        offer: SdpMediaSummary,
        answer: SdpMediaSummary?
    ): Set<Int> = buildSet {
        (codecMappings(offer) + answer.orEmptyCodecs()).mapNotNullTo(this) { it.payloadType }
        offer.formats.mapNotNullTo(this) { it.toIntOrNull() }
        answer?.formats?.mapNotNullTo(this) { it.toIntOrNull() }
    }

    private fun SdpMediaSummary?.orEmptyCodecs(): List<MediaCodecMapping> =
        this?.let(::codecMappings).orEmpty()

    private fun associateStreams(
        rtpStreams: List<RtpStreamSummary>,
        offerEndpoint: MediaEndpoint,
        answerEndpoint: MediaEndpoint?,
        expected: Map<MediaPathDirection, Boolean>,
        negotiatedPayloadTypes: Set<Int>,
        negotiationStart: Double?,
        captureEnd: Double?
    ): List<AssociatedStream> = rtpStreams.mapNotNull { stream ->
        bestAssociation(
            stream = stream,
            offerEndpoint = offerEndpoint,
            answerEndpoint = answerEndpoint,
            expected = expected,
            negotiatedPayloadTypes = negotiatedPayloadTypes,
            negotiationStart = negotiationStart,
            captureEnd = captureEnd
        )
    }

    private fun bestAssociation(
        stream: RtpStreamSummary,
        offerEndpoint: MediaEndpoint,
        answerEndpoint: MediaEndpoint?,
        expected: Map<MediaPathDirection, Boolean>,
        negotiatedPayloadTypes: Set<Int>,
        negotiationStart: Double?,
        captureEnd: Double?
    ): AssociatedStream? {
        if (answerEndpoint != null) {
            pathCandidates(offerEndpoint, answerEndpoint).forEach { (direction, from, to) ->
                if (exactPath(stream, from, to)) {
                    return AssociatedStream(stream, direction, MediaCorrelationConfidence.Strong)
                }
            }
            pathCandidates(offerEndpoint, answerEndpoint).forEach { (direction, from, to) ->
                if (portPath(stream, from, to)) {
                    return AssociatedStream(stream, direction, MediaCorrelationConfidence.Medium)
                }
            }
        }
        if (negotiatedPayloadTypes.isEmpty() ||
            stream.packets.none { it.payloadType in negotiatedPayloadTypes } ||
            !overlapsWindow(stream, negotiationStart, captureEnd)
        ) {
            return null
        }
        return AssociatedStream(
            stream = stream,
            direction = weakDirection(stream, offerEndpoint, answerEndpoint, expected),
            confidence = MediaCorrelationConfidence.Weak
        )
    }

    private fun pathCandidates(
        offer: MediaEndpoint,
        answer: MediaEndpoint
    ): List<Triple<MediaPathDirection, MediaEndpoint, MediaEndpoint>> = listOf(
        Triple(MediaPathDirection.OfferToAnswer, offer, answer),
        Triple(MediaPathDirection.AnswerToOffer, answer, offer)
    )

    private fun exactPath(stream: RtpStreamSummary, from: MediaEndpoint, to: MediaEndpoint): Boolean =
        endpointHasAddressAndPort(from) && endpointHasAddressAndPort(to) &&
            stream.source == from.connectionAddress && stream.sourcePort == from.port &&
            stream.destination == to.connectionAddress && stream.destinationPort == to.port

    private fun portPath(stream: RtpStreamSummary, from: MediaEndpoint, to: MediaEndpoint): Boolean =
        from.port != null && to.port != null &&
            stream.sourcePort == from.port && stream.destinationPort == to.port

    private fun endpointHasAddressAndPort(endpoint: MediaEndpoint): Boolean =
        endpoint.connectionAddress.isNotBlank() && endpoint.port != null

    private fun overlapsWindow(
        stream: RtpStreamSummary,
        start: Double?,
        end: Double?
    ): Boolean {
        val first = stream.packets.minOfOrNull { it.time } ?: return false
        val last = stream.packets.maxOfOrNull { it.time } ?: first
        return (start == null || last >= start) && (end == null || first <= end)
    }

    private fun weakDirection(
        stream: RtpStreamSummary,
        offer: MediaEndpoint,
        answer: MediaEndpoint?,
        expected: Map<MediaPathDirection, Boolean>
    ): MediaPathDirection = when {
        stream.source == offer.connectionAddress || stream.destination == answer?.connectionAddress ->
            MediaPathDirection.OfferToAnswer
        stream.destination == offer.connectionAddress || stream.source == answer?.connectionAddress ->
            MediaPathDirection.AnswerToOffer
        expected.filterValues { it }.keys.singleOrNull() != null -> expected.filterValues { it }.keys.single()
        else -> MediaPathDirection.Unknown
    }

    private fun buildDirections(
        expected: Map<MediaPathDirection, Boolean>,
        associated: List<AssociatedStream>,
        negotiatedCodecs: List<MediaCodecMapping>
    ): List<MediaRtpDirectionAnalysis> {
        val known = MediaPathDirection.entries.filter { it != MediaPathDirection.Unknown }.map { direction ->
            directionAnalysis(direction, expected[direction] == true, associated.filter { it.direction == direction }, negotiatedCodecs)
        }
        val unknown = associated.filter { it.direction == MediaPathDirection.Unknown }
            .takeIf { it.isNotEmpty() }
            ?.let { listOf(directionAnalysis(MediaPathDirection.Unknown, false, it, negotiatedCodecs)) }
            .orEmpty()
        return known + unknown
    }

    private fun directionAnalysis(
        direction: MediaPathDirection,
        expected: Boolean,
        associated: List<AssociatedStream>,
        negotiatedCodecs: List<MediaCodecMapping>
    ): MediaRtpDirectionAnalysis {
        val streams = associated.map { it.stream }
        val packets = streams.flatMap { it.packets }.sortedWith(compareBy({ it.time }, { it.frameNumber }))
        val payloadTypes = packets.mapNotNull { it.payloadType }.distinct().sorted()
        val codecMappings = negotiatedCodecs.filter { it.payloadType in payloadTypes }
        val clockRate = clockRateFor(payloadTypes, codecMappings)
        val metrics = if (packets.isEmpty()) null else {
            CommunicationAnalyzer.aggregateRtp("media-$direction", packets, clockRate)
        }
        val firstFrame = packets.minOfOrNull { it.frameNumber }
        val lastFrame = packets.maxOfOrNull { it.frameNumber }
        val durationMillis = if (packets.size > 1) {
            ((packets.last().time - packets.first().time).coerceAtLeast(0.0) * 1_000.0).roundToLong()
        } else {
            null
        }
        val confidence = associated.map { it.confidence }.minByOrNull(::confidenceRank)
            ?: MediaCorrelationConfidence.None
        val ssrcs = packets.mapNotNull { it.ssrc }.distinct().sorted()
        return MediaRtpDirectionAnalysis(
            direction = direction,
            expected = expected,
            observed = packets.isNotEmpty(),
            confidence = confidence,
            streamKeys = streams.map { it.key }.distinct(),
            packetCount = packets.size,
            firstFrame = firstFrame,
            lastFrame = lastFrame,
            durationMillis = durationMillis,
            ssrcs = ssrcs,
            payloadTypes = payloadTypes,
            codecs = codecMappings,
            clockRate = clockRate,
            lostPackets = metrics?.lostPackets ?: 0,
            reorderedPackets = metrics?.reorderedPackets ?: 0,
            duplicatePackets = metrics?.duplicatePackets ?: 0,
            jitterMillis = metrics?.jitterMillis,
            anomalyFrames = sequenceAnomalyFrames(packets),
            displayFilters = ssrcs.map { "rtp.ssrc == $it" }
        )
    }

    private fun confidenceRank(confidence: MediaCorrelationConfidence): Int = when (confidence) {
        MediaCorrelationConfidence.Strong -> 0
        MediaCorrelationConfidence.Medium -> 1
        MediaCorrelationConfidence.Weak -> 2
        MediaCorrelationConfidence.None -> 3
    }

    private fun clockRateFor(
        payloadTypes: List<Int>,
        codecs: List<MediaCodecMapping>
    ): Int? {
        val mappedRates = codecs.filter { it.payloadType in payloadTypes }.mapNotNull { it.clockRate }.distinct()
        if (mappedRates.size == 1) return mappedRates.single()
        if (payloadTypes.any(CommunicationAnalyzer::isDynamicPayloadType)) return null
        return payloadTypes.mapNotNull(CommunicationAnalyzer::staticPayloadClockRate).distinct().singleOrNull()
    }

    private fun sequenceAnomalyFrames(packets: List<RtpPacketMetric>): List<Long> {
        var highest: Long? = null
        val seen = mutableSetOf<Long>()
        val frames = mutableListOf<Long>()
        packets.forEach { packet ->
            val sequence = packet.sequence ?: return@forEach
            val extended = extendSequence(sequence, highest)
            when {
                !seen.add(extended) -> frames += packet.frameNumber
                highest != null && extended < highest!! -> frames += packet.frameNumber
                highest != null && extended > highest!! + 1 -> {
                    frames += packet.frameNumber
                    highest = extended
                }
                else -> highest = extended
            }
        }
        return frames.distinct().take(MAX_ANOMALY_FRAMES)
    }

    private fun extendSequence(sequence: Int, highest: Long?): Long {
        val value = (sequence and 0xffff).toLong()
        if (highest == null) return value
        val cycle = highest and 0xffff0000L
        return listOf(cycle + value, cycle + value + 65536L, cycle + value - 65536L)
            .minBy { abs(it - highest) }
    }

    private fun rtcpFor(
        direction: MediaRtpDirectionAnalysis,
        rtcpStreams: List<RtcpStreamSummary>
    ): List<MediaRtcpAnalysis> = direction.ssrcs.mapNotNull { ssrc ->
        val reports = rtcpStreams.flatMap { it.reports }
            .filter { it.reportedSsrc == ssrc }
            .sortedWith(compareBy({ it.time }, { it.frameNumber }))
        reports.takeIf { it.isNotEmpty() }?.let { values ->
            val fractionLost = values.mapNotNull { it.fractionLostPercent }
            val cumulativeLost = values.mapNotNull { it.cumulativeLost }
            val interarrivalJitter = values.mapNotNull { it.interarrivalJitter }
            MediaRtcpAnalysis(
                reportedSsrc = ssrc,
                reportCount = values.size,
                firstFrame = values.first().frameNumber,
                lastFrame = values.last().frameNumber,
                fractionLostPercentRange = fractionLost.minOrNull()?.let { minimum ->
                    minimum..(fractionLost.maxOrNull() ?: minimum)
                },
                worstFractionLostPercent = fractionLost.maxOrNull(),
                cumulativeLostRange = cumulativeLost.minOrNull()?.let { minimum ->
                    minimum..(cumulativeLost.maxOrNull() ?: minimum)
                },
                worstCumulativeLost = cumulativeLost.maxOrNull(),
                interarrivalJitterRange = interarrivalJitter.minOrNull()?.let { minimum ->
                    minimum..(interarrivalJitter.maxOrNull() ?: minimum)
                },
                worstInterarrivalJitter = interarrivalJitter.maxOrNull(),
                reportFrames = values.map { it.frameNumber },
                displayFilters = listOf("rtcp.ssrc.identifier == $ssrc")
            )
        }
    }

    private fun findingsFor(
        offer: SdpMediaSummary,
        answer: SdpMediaSummary?,
        rejected: Boolean,
        directions: List<MediaRtpDirectionAnalysis>,
        rtcp: List<MediaRtcpAnalysis>,
        capture: MediaCaptureSnapshot,
        negotiationStart: Double?,
        negotiatedCodecs: List<MediaCodecMapping>
    ): List<MediaFinding> {
        val findings = mutableListOf<MediaFinding>()
        val expectedDirections = directions.filter { it.expected }
        val observedExpected = expectedDirections.filter { it.observed }
        val anyObserved = directions.any { it.observed }
        val negativeEvidenceComplete = capture.supportsNegativeEvidence &&
            (negotiationStart == null || capture.startTime!! <= negotiationStart) &&
            (negotiationStart == null || capture.endTime!! >= negotiationStart)
        val negativeSeverity = if (negativeEvidenceComplete) MediaFindingSeverity.High else MediaFindingSeverity.Warning

        if (!rejected && answer != null && negotiatedCodecs.isEmpty()) {
            findings += MediaFinding(
                kind = MediaFindingKind.CodecMismatch,
                severity = MediaFindingSeverity.High,
                summary = "The SDP offer and answer have no common codec.",
                evidenceFrames = listOfNotNull(offer.frameNumber, answer.frameNumber)
            )
        }
        if (!rejected && expectedDirections.size == 1) {
            val expectedDirection = expectedDirections.single().direction
            findings += MediaFinding(
                kind = MediaFindingKind.SdpDirectionExpected,
                severity = MediaFindingSeverity.Info,
                summary = "SDP direction expects media only from ${expectedDirection.wireValue}.",
                direction = expectedDirection,
                evidenceFrames = listOfNotNull(offer.frameNumber, answer?.frameNumber)
            )
        }
        if (!rejected && answer != null && !anyObserved) {
            findings += MediaFinding(
                kind = MediaFindingKind.NoMediaPackets,
                severity = negativeSeverity,
                summary = "SDP negotiated media but no matching RTP was observed.",
                evidenceFrames = listOfNotNull(offer.frameNumber, answer.frameNumber)
            )
        }
        if (!rejected && expectedDirections.size == 2 && observedExpected.size == 1) {
            val present = observedExpected.single()
            val absent = expectedDirections.first { !it.observed }
            findings += MediaFinding(
                kind = MediaFindingKind.OneWayMedia,
                severity = negativeSeverity,
                summary = "RTP was observed only from ${present.direction.wireValue}; ${absent.direction.wireValue} was absent.",
                direction = absent.direction,
                evidenceFrames = listOfNotNull(present.firstFrame, present.lastFrame),
                displayFilters = present.displayFilters
            )
        }
        directions.filter { it.observed && it.confidence == MediaCorrelationConfidence.Weak }.forEach { direction ->
            findings += MediaFinding(
                kind = MediaFindingKind.PortOrAddressMismatch,
                severity = MediaFindingSeverity.Warning,
                summary = "RTP matched this SDP line only by time window and payload type; the negotiated endpoint was not observed.",
                direction = direction.direction,
                evidenceFrames = listOfNotNull(direction.firstFrame, direction.lastFrame),
                displayFilters = direction.displayFilters
            )
        }
        directions.filter { it.observed }.forEach { direction ->
            val negotiatedPayloadTypes = negotiatedCodecs.mapNotNull { it.payloadType }.toSet()
            if (negotiatedPayloadTypes.isNotEmpty() && direction.payloadTypes.any { it !in negotiatedPayloadTypes }) {
                findings += MediaFinding(
                    kind = MediaFindingKind.CodecMismatch,
                    severity = MediaFindingSeverity.High,
                    summary = "Observed RTP payload type is absent from the negotiated codec mapping.",
                    direction = direction.direction,
                    evidenceFrames = listOfNotNull(direction.firstFrame, direction.lastFrame),
                    displayFilters = direction.displayFilters
                )
            }
            val rtcpForDirection = rtcp.filter { it.reportedSsrc in direction.ssrcs }
            if (direction.lostPackets >= HIGH_SEQUENCE_LOSS_PACKETS ||
                rtcpForDirection.any { (it.worstFractionLostPercent ?: 0.0) >= HIGH_RTCP_LOSS_PERCENT }
            ) {
                findings += MediaFinding(
                    kind = MediaFindingKind.HighLoss,
                    severity = MediaFindingSeverity.High,
                    summary = "RTP sequence gaps and RTCP receiver loss are both retained as separate observations.",
                    direction = direction.direction,
                    evidenceFrames = (direction.anomalyFrames + rtcpForDirection.flatMap { it.reportFrames }).distinct().take(MAX_ANOMALY_FRAMES),
                    displayFilters = direction.displayFilters + rtcpForDirection.flatMap { it.displayFilters }
                )
            }
            if ((direction.jitterMillis ?: 0.0) >= HIGH_JITTER_MILLIS) {
                findings += MediaFinding(
                    kind = MediaFindingKind.HighJitter,
                    severity = MediaFindingSeverity.High,
                    summary = "RTP interarrival jitter exceeds ${HIGH_JITTER_MILLIS.roundToLong()} ms using the negotiated clock rate.",
                    direction = direction.direction,
                    evidenceFrames = listOfNotNull(direction.firstFrame, direction.lastFrame),
                    displayFilters = direction.displayFilters
                )
            }
        }
        if (capture.sourceTruncated || capture.scopeIsFiltered || capture.encryptedMediaPossible) {
            findings += MediaFinding(
                kind = MediaFindingKind.ShortCaptureOrPartialPath,
                severity = MediaFindingSeverity.Warning,
                summary = "Capture coverage, source truncation, or encrypted media limits negative media conclusions.",
                evidenceFrames = listOfNotNull(offer.frameNumber, answer?.frameNumber)
            )
        }
        return findings
    }

    private fun limitations(
        lines: List<MediaLineAnalysis>,
        capture: MediaCaptureSnapshot
    ): List<String> = buildList {
        if (capture.sourceTruncated) add("SIP, RTP, or RTCP source data was truncated.")
        if (capture.scopeIsFiltered) add("The analysis ran on a filtered capture scope.")
        if (capture.encryptedMediaPossible) add("The negotiated media profile may be encrypted, so absent decoded RTP is inconclusive.")
        if (lines.any { line -> line.findings.any { it.kind == MediaFindingKind.OneWayMedia } }) {
            add("A capture point can observe only one media path; one-way RTP does not prove endpoint playback failure.")
        }
        if (lines.isNotEmpty() && lines.all { it.rtcp.isEmpty() }) {
            add("No RTCP receiver report was associated; this does not mean packet loss was absent.")
        }
    }

    private data class AssociatedStream(
        val stream: RtpStreamSummary,
        val direction: MediaPathDirection,
        val confidence: MediaCorrelationConfidence
    )

    private const val MAX_ANOMALY_FRAMES = 8
}
