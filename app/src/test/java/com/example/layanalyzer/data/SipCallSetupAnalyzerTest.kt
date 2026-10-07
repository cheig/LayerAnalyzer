package com.example.layanalyzer.data

import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ProtocolSummaryItem
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SipCallSetupCaptureRange
import com.example.layanalyzer.model.SipCallSetupCompleteness
import com.example.layanalyzer.model.SipCallSetupAttempt
import com.example.layanalyzer.model.SipCallSetupOutcome
import com.example.layanalyzer.model.SipCallSetupSelection
import com.example.layanalyzer.model.SipCallSetupStage
import com.example.layanalyzer.model.SipCallSetupTransportKind
import com.example.layanalyzer.model.SipMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SipCallSetupAnalyzerTest {

    @Test
    fun `normal invite flow exposes complete stages and ack`() {
        val result = analyze(
            request(10, 0.0, "normal", 1, "invite", "INVITE"),
            response(11, 0.1, "normal", 1, "invite", "INVITE", "100 Trying"),
            response(12, 1.0, "normal", 1, "invite", "INVITE", "180 Ringing"),
            response(13, 2.0, "normal", 1, "invite", "INVITE", "200 OK"),
            request(14, 2.1, "normal", 1, "ack", "ACK")
        )

        val attempt = requireNotNull(result.selectedAttempt)
        assertEquals(SipCallSetupOutcome.Success, attempt.outcome)
        assertEquals(14L, attempt.ackFrame)
        assertEquals(2_100L, attempt.setupDurationMillis)
        assertEquals(2_000L, attempt.inviteToFinalResponseMillis)
        val inviteToTrying = attempt.stage(SipCallSetupStage.InviteToTrying)
        assertEquals(10L, inviteToTrying.startFrame)
        assertEquals(11L, inviteToTrying.endFrame)
        assertEquals(100L, inviteToTrying.durationMillis)
        assertEquals(SipCallSetupCompleteness.Complete, inviteToTrying.completeness)
        assertEquals(SipCallSetupCompleteness.Complete, attempt.stage(SipCallSetupStage.AckCompletion).completeness)
    }

    @Test
    fun `486 is classified as final response failure with response evidence`() {
        val result = analyze(
            request(20, 0.0, "busy", 1, "invite", "INVITE"),
            response(21, 0.8, "busy", 1, "invite", "INVITE", "486 Busy Here")
        )

        val attempt = requireNotNull(result.selectedAttempt)
        assertEquals(SipCallSetupOutcome.FinalResponseFailure, attempt.outcome)
        assertEquals(486, attempt.finalResponseCode)
        assertEquals(21L, attempt.finalResponseFrame)
        assertEquals(800L, attempt.stage(SipCallSetupStage.FinalResponse).durationMillis)
    }

    @Test
    fun `cancel plus 487 is classified separately from other final failures`() {
        val result = analyze(
            request(30, 0.0, "cancelled", 1, "invite", "INVITE"),
            request(31, 0.2, "cancelled", 2, "cancel", "CANCEL"),
            response(32, 0.3, "cancelled", 2, "cancel", "CANCEL", "200 OK"),
            response(33, 0.4, "cancelled", 1, "invite", "INVITE", "487 Request Terminated")
        )

        assertEquals(SipCallSetupOutcome.CancelledBeforeAnswer, result.selectedAttempt?.outcome)
    }

    @Test
    fun `retransmitted invite without response is no final response`() {
        val result = analyze(
            request(40, 0.0, "silent", 1, "invite", "INVITE"),
            request(41, 0.5, "silent", 1, "invite", "INVITE")
        )

        val attempt = requireNotNull(result.selectedAttempt)
        assertEquals(SipCallSetupOutcome.NoFinalResponse, attempt.outcome)
        assertEquals(1, attempt.retransmissionCount)
        assertNull(attempt.finalResponseFrame)
    }

    @Test
    fun `long gap after provisional response is timeout only with configured attention threshold`() {
        val result = analyze(
            request(45, 0.0, "stalled", 1, "invite", "INVITE"),
            response(46, 0.1, "stalled", 1, "invite", "INVITE", "100 Trying"),
            response(47, 0.5, "stalled", 1, "invite", "INVITE", "180 Ringing"),
            capture = capture(endTime = 8.0),
            selection = SipCallSetupSelection(attentionThresholdMillis = 1_000)
        )

        assertEquals(SipCallSetupOutcome.ProvisionalTimeout, result.selectedAttempt?.outcome)
    }

    @Test
    fun `failed prack transaction is classified before invite final response`() {
        val result = analyze(
            request(48, 0.0, "prack-failure", 1, "invite", "INVITE"),
            response(49, 0.1, "prack-failure", 1, "invite", "INVITE", "183 Session Progress"),
            request(50, 0.2, "prack-failure", 2, "prack", "PRACK"),
            response(51, 0.3, "prack-failure", 2, "prack", "PRACK", "500 Server Internal Error")
        )

        assertEquals(SipCallSetupOutcome.PrackFailure, result.selectedAttempt?.outcome)
    }

    @Test
    fun `183 prack update sequence attributes the long delay to precondition update`() {
        val result = analyze(
            request(50, 0.0, "precondition", 1, "invite", "INVITE"),
            response(51, 0.1, "precondition", 1, "invite", "INVITE", "183 Session Progress", sdp = true),
            request(52, 0.2, "precondition", 2, "prack", "PRACK"),
            response(53, 0.3, "precondition", 2, "prack", "PRACK", "200 OK"),
            request(54, 0.4, "precondition", 3, "update", "UPDATE", sdp = true),
            response(55, 6.8, "precondition", 3, "update", "UPDATE", "200 OK", sdp = true),
            response(56, 6.9, "precondition", 1, "invite", "INVITE", "200 OK", sdp = true),
            request(57, 7.0, "precondition", 1, "ack", "ACK")
        , selection = SipCallSetupSelection(attentionThresholdMillis = 1_000))

        val attempt = requireNotNull(result.selectedAttempt)
        assertEquals(SipCallSetupOutcome.MediaPreconditionDelay, attempt.outcome)
        assertEquals(SipCallSetupStage.PreconditionOrUpdate, attempt.largestContribution?.stage)
        assertEquals(6_500L, attempt.stage(SipCallSetupStage.PreconditionOrUpdate).durationMillis)
        assertTrue(attempt.stage(SipCallSetupStage.PreconditionOrUpdate).attentionThresholdExceeded)
        assertEquals(listOf(51L, 54L, 55L, 56L), attempt.mediaNegotiationFrames)
    }

    @Test
    fun `final 200 without subsequent ack is missing ack only with complete coverage`() {
        val complete = analyze(
            request(60, 0.0, "no-ack", 1, "invite", "INVITE"),
            response(61, 1.0, "no-ack", 1, "invite", "INVITE", "200 OK"),
            capture = capture(endTime = 2.0)
        )
        val incomplete = analyze(
            request(70, 0.0, "no-ack-incomplete", 1, "invite", "INVITE"),
            response(71, 1.0, "no-ack-incomplete", 1, "invite", "INVITE", "200 OK"),
            capture = capture(endTime = 1.0)
        )

        assertEquals(SipCallSetupOutcome.MissingAck, complete.selectedAttempt?.outcome)
        assertEquals(SipCallSetupOutcome.CaptureIncomplete, incomplete.selectedAttempt?.outcome)
    }

    @Test
    fun `target setup duration chooses closest candidate and otherwise reports ambiguity`() {
        val messages = listOf(
            request(80, 0.0, "fast", 1, "invite", "INVITE"),
            response(81, 2.0, "fast", 1, "invite", "INVITE", "200 OK"),
            request(82, 2.1, "fast", 1, "ack", "ACK"),
            request(90, 10.0, "slow", 1, "invite", "INVITE"),
            response(91, 17.9, "slow", 1, "invite", "INVITE", "200 OK"),
            request(92, 18.0, "slow", 1, "ack", "ACK")
        )

        val selected = analyze(*messages.toTypedArray(), selection = SipCallSetupSelection(targetSetupMillis = 8_000))
        val ambiguous = analyze(*messages.toTypedArray())
        val unmatched = analyze(*messages.toTypedArray(), selection = SipCallSetupSelection(callId = "not-present"))

        assertEquals("slow", selected.selectedAttempt?.callId)
        assertFalse(selected.requiresUserSelection)
        assertNull(ambiguous.selectedAttempt)
        assertTrue(ambiguous.requiresUserSelection)
        assertEquals(2, ambiguous.alternateCandidates.size)
        assertNull(unmatched.selectedAttempt)
        assertTrue(unmatched.requiresUserSelection)
    }

    @Test
    fun `tcp and tls anomalies require matching call endpoints and time window`() {
        val result = analyze(
            request(100, 10.0, "transport", 1, "invite", "INVITE"),
            response(101, 11.0, "transport", 1, "invite", "INVITE", "486 Busy Here"),
            statistics = CaptureStatistics(
                tcpSummaries = listOf(
                    protocolSummary(102, 10.4, "192.0.2.10", "192.0.2.20", "TCP Retransmission"),
                    protocolSummary(103, 10.5, "192.0.2.10", "192.0.2.99", "TCP Retransmission"),
                    protocolSummary(104, 70.0, "192.0.2.10", "192.0.2.20", "TCP Retransmission")
                ),
                tlsSummaries = listOf(
                    protocolSummary(105, 10.6, "192.0.2.20", "192.0.2.10", "TLS Alert"),
                    protocolSummary(106, 10.7, "192.0.2.20", "192.0.2.77", "TLS Alert")
                )
            ),
            capture = capture(startTime = 0.0, endTime = 12.0)
        )

        val evidence = requireNotNull(result.selectedAttempt).transportEvidence
        assertEquals(listOf(102L, 105L), evidence.map { it.frameNumber })
        assertEquals(
            listOf(SipCallSetupTransportKind.TcpRetransmission, SipCallSetupTransportKind.TlsAlert),
            evidence.map { it.kind }
        )
    }

    @Test
    fun `pre invite TCP TLS preparation is retained as a timed stage`() {
        val result = analyze(
            request(120, 10.0, "prepared", 1, "invite", "INVITE"),
            response(121, 11.0, "prepared", 1, "invite", "INVITE", "200 OK"),
            request(122, 11.1, "prepared", 1, "ack", "ACK"),
            statistics = CaptureStatistics(
                tcpSummaries = listOf(protocolSummary(118, 9.3, "192.0.2.10", "192.0.2.20", "SYN")),
                tlsSummaries = listOf(protocolSummary(119, 9.8, "192.0.2.20", "192.0.2.10", "Server Hello"))
            )
        )

        val stage = requireNotNull(result.selectedAttempt).stage(SipCallSetupStage.PreInviteTransport)
        assertEquals(SipCallSetupCompleteness.Complete, stage.completeness)
        assertEquals(118L, stage.startFrame)
        assertEquals(120L, stage.endFrame)
        assertEquals(700L, stage.durationMillis)
    }

    @Test
    fun `long pre invite transport phase is marked only by configured threshold`() {
        val result = analyze(
            request(130, 10.0, "slow-transport", 1, "invite", "INVITE"),
            response(131, 10.1, "slow-transport", 1, "invite", "INVITE", "200 OK"),
            request(132, 10.2, "slow-transport", 1, "ack", "ACK"),
            statistics = CaptureStatistics(
                tcpSummaries = listOf(protocolSummary(129, 1.0, "192.0.2.10", "192.0.2.20", "SYN"))
            ),
            selection = SipCallSetupSelection(attentionThresholdMillis = 1_000)
        )

        assertEquals(SipCallSetupOutcome.TransportOrTlsDelay, result.selectedAttempt?.outcome)
    }

    @Test
    fun `truncated SIP source classifies an unfinished invite as capture incomplete`() {
        val result = analyze(
            request(110, 1.0, "truncated", 1, "invite", "INVITE"),
            capture = capture(endTime = 2.0, sipSourceTruncated = true)
        )

        assertEquals(SipCallSetupOutcome.CaptureIncomplete, result.selectedAttempt?.outcome)
        assertTrue(result.limitations.any { it.contains("truncated") })
    }

    private fun SipCallSetupAttempt.stage(stage: SipCallSetupStage) =
        requireNotNull(stages.firstOrNull { it.stage == stage })

    private fun analyze(
        vararg messages: SipMessage,
        statistics: CaptureStatistics = CaptureStatistics(),
        capture: SipCallSetupCaptureRange = capture(),
        selection: SipCallSetupSelection = SipCallSetupSelection()
    ) = SipCallSetupAnalyzer.analyze(
        timelines = SipTransactionCorrelator.correlate(messages.toList()).dialogs,
        statistics = statistics,
        captureRange = capture,
        selection = selection
    )

    private fun capture(
        startTime: Double = 0.0,
        endTime: Double = 20.0,
        sipSourceTruncated: Boolean = false
    ) = SipCallSetupCaptureRange(
        firstFrame = 1,
        lastFrame = 200,
        startTime = startTime,
        endTime = endTime,
        sipSourceTruncated = sipSourceTruncated
    )

    private fun request(
        frame: Long,
        time: Double,
        callId: String,
        cSeq: Long,
        branch: String,
        method: String,
        sdp: Boolean = false
    ) = SipMessage(
        frameNumber = frame,
        time = time,
        source = "192.0.2.10",
        destination = "192.0.2.20",
        sourcePort = 5060,
        destinationPort = 5060,
        method = method,
        callId = callId,
        cSeqNumber = cSeq,
        cSeqMethod = method,
        viaBranch = "z9hG4bK-$branch",
        sdp = sdp.takeIf { it }?.let { SdpMediaSummary(frameNumber = frame) }
    )

    private fun response(
        frame: Long,
        time: Double,
        callId: String,
        cSeq: Long,
        branch: String,
        method: String,
        status: String,
        sdp: Boolean = false
    ) = SipMessage(
        frameNumber = frame,
        time = time,
        source = "192.0.2.20",
        destination = "192.0.2.10",
        sourcePort = 5060,
        destinationPort = 5060,
        status = status,
        callId = callId,
        cSeqNumber = cSeq,
        cSeqMethod = method,
        viaBranch = "z9hG4bK-$branch",
        sdp = sdp.takeIf { it }?.let { SdpMediaSummary(frameNumber = frame) }
    )

    private fun protocolSummary(
        frame: Long,
        time: Double,
        source: String,
        destination: String,
        summary: String
    ) = ProtocolSummaryItem(
        frameNumber = frame,
        time = time,
        source = source,
        destination = destination,
        protocol = "TCP",
        summary = summary
    )
}
