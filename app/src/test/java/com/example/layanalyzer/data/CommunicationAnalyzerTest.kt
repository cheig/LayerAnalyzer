// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.CoreSignalMessage
import com.example.layanalyzer.model.RtpPacketMetric
import com.example.layanalyzer.model.RtcpPacketMetric
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SipMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class CommunicationAnalyzerTest {
    @Test
    fun `sip messages aggregate by call id and expose failure`() {
        val messages = listOf(
            SipMessage(1, 1.0, "a", "b", method = "INVITE", callId = "call-1"),
            SipMessage(2, 1.2, "b", "a", status = "180 Ringing", callId = "call-1"),
            SipMessage(3, 1.5, "b", "a", status = "486 Busy Here", callId = "call-1")
        )

        val result = CommunicationAnalyzer.aggregate(CommunicationAnalysis(sipMessages = messages))

        assertEquals(1, result.calls.size)
        assertEquals(486, result.calls.single().failureCode)
        assertEquals(0.5, result.calls.single().duration, 0.0001)
    }

    @Test
    fun `rtp sequence handles wrap late arrival and duplicates`() {
        val packets = listOf(
            rtp(1, 1.00, 65534),
            rtp(2, 1.02, 0),
            rtp(3, 1.03, 65535),
            rtp(4, 1.04, 0)
        )

        val stream = CommunicationAnalyzer.aggregateRtp("stream", packets)

        assertEquals(0, stream.lostPackets)
        assertEquals(1, stream.reorderedPackets)
        assertEquals(1, stream.duplicatePackets)
        assertNotNull(stream.jitterMillis)
    }

    @Test
    fun `dynamic payload does not invent jitter clock rate`() {
        val stream = CommunicationAnalyzer.aggregateRtp("stream", listOf(rtp(1, 1.0, 1, 96), rtp(2, 1.02, 2, 96)))
        assertNull(stream.jitterMillis)
    }

    @Test
    fun `sip call retains distinct sdp media summaries`() {
        val audio = SdpMediaSummary(1, "192.0.2.10", "audio", 49170, "RTP/AVP", listOf("0", "8"), listOf("PCMU", "PCMA"))
        val messages = listOf(
            SipMessage(1, 1.0, "a", "b", method = "INVITE", callId = "call-1", sdp = audio),
            SipMessage(2, 1.1, "a", "b", method = "INVITE", callId = "call-1", sdp = audio.copy(frameNumber = 2))
        )

        val call = CommunicationAnalyzer.aggregate(CommunicationAnalysis(sipMessages = messages)).calls.single()

        assertEquals(1, call.sdpMedia.size)
        assertEquals("192.0.2.10", call.sdpMedia.single().connectionAddress)
        assertEquals(listOf("PCMU", "PCMA"), call.sdpMedia.single().codecs)
    }

    @Test
    fun `rtcp reports group by reported ssrc and direction`() {
        val reports = listOf(
            rtcp(10, 2.0, fractionLost = 2, cumulativeLost = 3),
            rtcp(11, 2.5, fractionLost = 4, cumulativeLost = 5)
        )

        val stream = CommunicationAnalyzer.aggregate(CommunicationAnalysis(rtcpPackets = reports)).rtcpStreams.single()

        assertEquals(2, stream.reportCount)
        assertEquals(0x11223344L, stream.reportedSsrc)
        assertEquals(5, stream.reports.last().cumulativeLost)
        assertEquals(1.5625, stream.reports.last().fractionLostPercent ?: 0.0, 0.0001)
    }

    @Test
    fun `core signaling groups only explicit correlation identifiers`() {
        val messages = listOf(
            CoreSignalMessage(10, 1.0, "DIAMETER", "a", "b", "diameter.session-id", "session-1", "CCR", "", ""),
            CoreSignalMessage(11, 1.1, "DIAMETER", "b", "a", "diameter.session-id", "session-1", "CCA", "2001", ""),
            CoreSignalMessage(12, 1.2, "PFCP", "a", "c", "pfcp.seid", "42", "Session Establishment", "1", "")
        )

        val result = CommunicationAnalyzer.aggregate(CommunicationAnalysis(coreMessages = messages))

        assertEquals(2, result.coreSessions.size)
        assertEquals(2, result.coreSessions.first { it.correlationValue == "session-1" }.messages.size)
    }

    private fun rtp(frame: Long, time: Double, sequence: Int, payloadType: Int = 0) = RtpPacketMetric(
        frameNumber = frame,
        time = time,
        source = "192.0.2.1",
        destination = "192.0.2.2",
        sourcePort = 4000,
        destinationPort = 4002,
        sequence = sequence,
        ssrc = 0xffffffffL,
        timestamp = frame * 160,
        payloadType = payloadType
    )

    private fun rtcp(frame: Long, time: Double, fractionLost: Int, cumulativeLost: Int) = RtcpPacketMetric(
        frameNumber = frame,
        time = time,
        source = "192.0.2.2",
        destination = "192.0.2.1",
        sourcePort = 4003,
        destinationPort = 4001,
        packetType = 201,
        senderSsrc = 0x55667788L,
        reportedSsrc = 0x11223344L,
        fractionLost = fractionLost,
        cumulativeLost = cumulativeLost,
        interarrivalJitter = 160L
    )
}
