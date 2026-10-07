// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.MediaCaptureSnapshot
import com.example.layanalyzer.model.MediaFindingKind
import com.example.layanalyzer.model.MediaFindingSeverity
import com.example.layanalyzer.model.MediaPathDirection
import com.example.layanalyzer.model.RtcpPacketMetric
import com.example.layanalyzer.model.RtpPacketMetric
import com.example.layanalyzer.model.SdpMediaDirection
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SdpOfferAnswerAssociation
import com.example.layanalyzer.model.SdpPayloadMapping
import com.example.layanalyzer.model.SipDialogTimeline
import com.example.layanalyzer.model.SipMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MediaSessionCorrelatorTest {

    @Test
    fun `bidirectional RTP is correlated with strong evidence and no one-way finding`() {
        val result = correlate(
            streams = listOf(
                stream(rtp(frame = 10, time = 1.0, source = OFFER, destination = ANSWER, sequence = 1)),
                stream(rtp(frame = 11, time = 1.02, source = ANSWER, destination = OFFER, sequence = 1, ssrc = 2))
            )
        )

        val directions = result.lines.single().directions
        assertTrue(directions.first { it.direction == MediaPathDirection.OfferToAnswer }.observed)
        assertTrue(directions.first { it.direction == MediaPathDirection.AnswerToOffer }.observed)
        assertFalse(result.findings.any { it.kind == MediaFindingKind.OneWayMedia })
    }

    @Test
    fun `SDP sendonly is reported as expected one-way media`() {
        val result = correlate(
            offerDirection = SdpMediaDirection.SendOnly,
            answerDirection = SdpMediaDirection.RecvOnly,
            streams = listOf(stream(rtp(frame = 10, time = 1.0, source = OFFER, destination = ANSWER, sequence = 1)))
        )

        assertTrue(result.findings.any { it.kind == MediaFindingKind.SdpDirectionExpected })
        assertFalse(result.findings.any { it.kind == MediaFindingKind.OneWayMedia })
    }

    @Test
    fun `negotiated media without RTP is reported with coverage-qualified severity`() {
        val result = correlate()

        val finding = result.findings.single { it.kind == MediaFindingKind.NoMediaPackets }
        assertEquals(MediaFindingSeverity.High, finding.severity)
    }

    @Test
    fun `sendrecv with one RTP direction is a high confidence one-way finding only with coverage`() {
        val result = correlate(
            streams = listOf(stream(rtp(frame = 10, time = 1.0, source = OFFER, destination = ANSWER, sequence = 1)))
        )

        val finding = result.findings.single { it.kind == MediaFindingKind.OneWayMedia }
        assertEquals(MediaFindingSeverity.High, finding.severity)
        assertEquals(MediaPathDirection.AnswerToOffer, finding.direction)
        assertTrue(result.limitations.any { it.contains("capture point") })
    }

    @Test
    fun `codec mismatch is found when offer and answer have no common codec`() {
        val result = correlate(
            answerMappings = listOf(mapping(8, "PCMA", 8_000))
        )

        assertTrue(result.findings.any { it.kind == MediaFindingKind.CodecMismatch })
    }

    @Test
    fun `dynamic payload jitter uses SDP clock rate`() {
        val mappings = listOf(mapping(96, "opus", 48_000))
        val result = correlate(
            offerMappings = mappings,
            answerMappings = mappings,
            streams = listOf(
                stream(rtp(frame = 10, time = 1.0, source = OFFER, destination = ANSWER, sequence = 1, payloadType = 96, timestamp = 0)),
                stream(rtp(frame = 11, time = 1.021, source = OFFER, destination = ANSWER, sequence = 2, payloadType = 96, timestamp = 960))
            )
        )

        val direction = result.lines.single().directions.first { it.direction == MediaPathDirection.OfferToAnswer }
        assertEquals(48_000, direction.clockRate)
        assertNotNull(direction.jitterMillis)

        val analysis = CommunicationAnalyzer.aggregate(
            CommunicationAnalysis(
                sipMessages = listOf(SipMessage(1, 0.5, OFFER, ANSWER, sdp = offer(mappings = mappings))),
                rtpPackets = listOf(
                    rtp(10, 1.0, OFFER, ANSWER, 1, payloadType = 96, timestamp = 0),
                    rtp(11, 1.021, OFFER, ANSWER, 2, payloadType = 96, timestamp = 960)
                )
            )
        )
        assertNotNull(analysis.streams.single().jitterMillis)
    }

    @Test
    fun `high jitter finding uses the negotiated dynamic clock rate`() {
        val mappings = listOf(mapping(96, "opus", 48_000))
        val packets = (0 until 40).map { index ->
            rtp(
                frame = 10L + index,
                time = 1.0 + index * 0.1,
                source = OFFER,
                destination = ANSWER,
                sequence = index,
                payloadType = 96,
                timestamp = index * 960L
            )
        }
        val result = correlate(
            offerMappings = mappings,
            answerMappings = mappings,
            streams = listOf(stream(packets))
        )

        val direction = result.lines.single().directions.first { it.direction == MediaPathDirection.OfferToAnswer }
        assertEquals(48_000, direction.clockRate)
        assertTrue((direction.jitterMillis ?: 0.0) >= MediaSessionCorrelator.HIGH_JITTER_MILLIS)
        assertTrue(result.findings.any { it.kind == MediaFindingKind.HighJitter })
    }

    @Test
    fun `sequence wrap reorder duplicate and gap retain representative evidence`() {
        val result = correlate(
            streams = listOf(
                stream(rtp(10, 1.0, OFFER, ANSWER, 65_534)),
                stream(rtp(11, 1.02, OFFER, ANSWER, 0)),
                stream(rtp(12, 1.03, OFFER, ANSWER, 65_535)),
                stream(rtp(13, 1.04, OFFER, ANSWER, 0)),
                stream(rtp(14, 1.06, OFFER, ANSWER, 7))
            )
        )

        val direction = result.lines.single().directions.first { it.direction == MediaPathDirection.OfferToAnswer }
        assertEquals(1, direction.reorderedPackets)
        assertEquals(1, direction.duplicatePackets)
        assertEquals(6, direction.lostPackets)
        assertTrue(direction.anomalyFrames.containsAll(listOf(12L, 13L, 14L)))
        assertTrue(result.findings.any { it.kind == MediaFindingKind.HighLoss })
    }

    @Test
    fun `RTCP reported SSRC exposes high loss alongside local RTP metrics`() {
        val rtp = stream(rtp(10, 1.0, OFFER, ANSWER, 1, ssrc = 77))
        val rtcp = CommunicationAnalyzer.aggregate(
            CommunicationAnalysis(
                rtcpPackets = listOf(
                    RtcpPacketMetric(
                        frameNumber = 20,
                        time = 1.1,
                        source = ANSWER,
                        destination = OFFER,
                        sourcePort = PORT,
                        destinationPort = PORT,
                        reportedSsrc = 77,
                        fractionLost = 26,
                        cumulativeLost = 4,
                        interarrivalJitter = 240
                    )
                )
            )
        ).rtcpStreams

        val result = correlate(streams = listOf(rtp), rtcpStreams = rtcp)

        val report = result.lines.single().rtcp.single()
        assertEquals(77L, report.reportedSsrc)
        assertEquals(20L, report.reportFrames.single())
        assertTrue(result.findings.any { it.kind == MediaFindingKind.HighLoss })
    }

    @Test
    fun `truncated capture limits one-way conclusion`() {
        val result = correlate(
            streams = listOf(stream(rtp(10, 1.0, OFFER, ANSWER, 1))),
            capture = baselineCapture.copy(sourceTruncated = true)
        )

        assertEquals(
            MediaFindingSeverity.Warning,
            result.findings.single { it.kind == MediaFindingKind.OneWayMedia }.severity
        )
        assertTrue(result.findings.any { it.kind == MediaFindingKind.ShortCaptureOrPartialPath })
    }

    private fun correlate(
        offerDirection: SdpMediaDirection = SdpMediaDirection.SendRecv,
        answerDirection: SdpMediaDirection = SdpMediaDirection.SendRecv,
        offerMappings: List<SdpPayloadMapping> = listOf(mapping(0, "PCMU", 8_000)),
        answerMappings: List<SdpPayloadMapping> = offerMappings,
        streams: List<com.example.layanalyzer.model.RtpStreamSummary> = emptyList(),
        rtcpStreams: List<com.example.layanalyzer.model.RtcpStreamSummary> = emptyList(),
        capture: MediaCaptureSnapshot = baselineCapture
    ) = MediaSessionCorrelator.correlate(
        dialog = SipDialogTimeline(
            callId = "call-1",
            sdpOfferAnswers = listOf(
                SdpOfferAnswerAssociation(
                    offer = offer(direction = offerDirection, mappings = offerMappings),
                    answer = answer(direction = answerDirection, mappings = answerMappings),
                    offerFrame = 1,
                    answerFrame = 2
                )
            )
        ),
        rtpStreams = streams,
        rtcpStreams = rtcpStreams,
        capture = capture
    )

    private fun offer(
        direction: SdpMediaDirection = SdpMediaDirection.SendRecv,
        mappings: List<SdpPayloadMapping>
    ) = SdpMediaSummary(
        frameNumber = 1,
        connectionAddress = OFFER,
        mediaType = "audio",
        mediaPort = PORT,
        mediaProtocol = "RTP/AVP",
        formats = mappings.mapNotNull { it.payloadType?.toString() },
        codecs = mappings.map { it.encodingName },
        direction = direction,
        payloadMappings = mappings
    )

    private fun answer(
        direction: SdpMediaDirection,
        mappings: List<SdpPayloadMapping>
    ) = SdpMediaSummary(
        frameNumber = 2,
        connectionAddress = ANSWER,
        mediaType = "audio",
        mediaPort = PORT,
        mediaProtocol = "RTP/AVP",
        formats = mappings.mapNotNull { it.payloadType?.toString() },
        codecs = mappings.map { it.encodingName },
        direction = direction,
        payloadMappings = mappings
    )

    private fun mapping(payloadType: Int, codec: String, clockRate: Int) = SdpPayloadMapping(
        payloadType = payloadType,
        encodingName = codec,
        clockRate = clockRate
    )

    private fun stream(packet: RtpPacketMetric) = stream(listOf(packet))

    private fun stream(packets: List<RtpPacketMetric>) = CommunicationAnalyzer.aggregateRtp(
        key = "${packets.first().ssrc}:${packets.first().source}->${packets.first().destination}",
        input = packets
    )

    private fun rtp(
        frame: Long,
        time: Double,
        source: String,
        destination: String,
        sequence: Int,
        ssrc: Long = 1,
        payloadType: Int = 0,
        timestamp: Long = frame * 160
    ) = RtpPacketMetric(
        frameNumber = frame,
        time = time,
        source = source,
        destination = destination,
        sourcePort = PORT,
        destinationPort = PORT,
        sequence = sequence,
        ssrc = ssrc,
        payloadType = payloadType,
        timestamp = timestamp
    )

    private companion object {
        const val OFFER = "192.0.2.10"
        const val ANSWER = "192.0.2.20"
        const val PORT = 40_000
        val baselineCapture = MediaCaptureSnapshot(startTime = 0.0, endTime = 10.0)
    }
}
