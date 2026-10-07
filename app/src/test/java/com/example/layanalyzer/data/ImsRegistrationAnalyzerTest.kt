// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ExpertInfoItem
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.ImsCaptureRange
import com.example.layanalyzer.model.ImsRegistrationOutcome
import com.example.layanalyzer.model.ImsRegistrationSelection
import com.example.layanalyzer.model.SipMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ImsRegistrationAnalyzerTest {

    @Test
    fun `authenticated register ending in 200 is successful`() {
        val result = analyze(
            request(1, 1.0, "reg-a", 1),
            response(2, 1.1, "reg-a", 1, "401 Unauthorized"),
            request(3, 1.2, "reg-a", 2, authorization = true),
            response(4, 1.3, "reg-a", 2, "200 OK")
        )

        val attempt = requireNotNull(result.selectedAttempt)
        assertEquals(ImsRegistrationOutcome.Success, result.outcome)
        assertEquals(listOf(1L, 2L, 3L, 4L), attempt.timeline.map { it.frameNumber })
        assertNotNull(attempt.challenge)
        assertNotNull(attempt.authenticatedRegister)
        assertNotNull(attempt.finalResponse)
    }

    @Test
    fun `403 after authenticated register is authentication rejection`() {
        val result = analyze(
            request(10, 1.0, "reg-a", 1),
            response(11, 1.1, "reg-a", 1, "401 Unauthorized"),
            request(12, 1.2, "reg-a", 2, authorization = true),
            response(13, 1.3, "reg-a", 2, "403 Forbidden")
        )

        assertEquals(ImsRegistrationOutcome.AuthenticationRejected, result.outcome)
        assertEquals(13L, result.selectedAttempt?.finalResponse?.frameNumber)
    }

    @Test
    fun `missing response with TCP retransmission is transport failure`() {
        val result = analyze(
            request(20, 2.0, "reg-a", 1),
            request(21, 2.5, "reg-a", 1),
            statistics = CaptureStatistics(tcpRetransmissions = 1),
            expert = ExpertInfoSummary(
                items = listOf(
                    ExpertInfoItem(22, "TCP Retransmission", "tcp.analysis.retransmission", "warning", 0, 0)
                )
            ),
            capture = ImsCaptureRange(firstFrame = 1, lastFrame = 22, startTime = 0.0, endTime = 3.0)
        )

        assertEquals(ImsRegistrationOutcome.TransportFailure, result.outcome)
        assertEquals(22L, result.selectedAttempt?.transportEvidence?.firstOrNull()?.frameNumber)
    }

    @Test
    fun `challenge without authenticated retry is reported`() {
        val result = analyze(
            request(30, 3.0, "reg-a", 1),
            response(31, 3.1, "reg-a", 1, "407 Proxy Authentication Required")
        )

        assertEquals(ImsRegistrationOutcome.AuthenticationRetryMissing, result.outcome)
        assertNotNull(result.selectedAttempt?.challenge)
        assertEquals(null, result.selectedAttempt?.authenticatedRegister)
    }

    @Test
    fun `capture starting with authenticated register is incomplete`() {
        val result = analyze(
            request(40, 4.0, "reg-a", 2, authorization = true),
            response(41, 4.1, "reg-a", 2, "200 OK")
        )

        assertEquals(ImsRegistrationOutcome.CaptureIncompleteOrEncrypted, result.outcome)
        assertTrue(requireNotNull(result.selectedAttempt).missingInitialFlow)
        assertTrue(result.limitations.any { it.contains("initial REGISTER") })
    }

    @Test
    fun `call id selector chooses matching registration among candidates`() {
        val result = analyze(
            request(50, 5.0, "call-a", 1),
            response(51, 5.1, "call-a", 1, "401 Unauthorized"),
            request(52, 5.2, "call-a", 2, authorization = true),
            response(53, 5.3, "call-a", 2, "403 Forbidden"),
            request(60, 6.0, "call-b", 1),
            response(61, 6.1, "call-b", 1, "500 Server Internal Error"),
            selection = ImsRegistrationSelection(callIdContains = "call-a")
        )

        assertEquals("call-a", result.selectedAttempt?.callId)
        assertEquals(ImsRegistrationOutcome.AuthenticationRejected, result.outcome)
        assertEquals(1, result.alternateCandidates.size)
    }

    @Test
    fun `truncated source downgrades missing retry completeness`() {
        val result = analyze(
            request(70, 7.0, "reg-a", 1),
            response(71, 7.1, "reg-a", 1, "401 Unauthorized"),
            capture = ImsCaptureRange(
                firstFrame = 1,
                lastFrame = 71,
                startTime = 0.0,
                endTime = 8.0,
                sipSourceTruncated = true
            )
        )

        assertEquals(ImsRegistrationOutcome.AuthenticationRetryMissing, result.outcome)
        assertFalse(requireNotNull(result.selectedAttempt).hasCompleteNegativeEvidence)
        assertTrue(result.limitations.any { it.contains("truncated") })
    }

    private fun analyze(
        vararg messages: SipMessage,
        statistics: CaptureStatistics = CaptureStatistics(),
        expert: ExpertInfoSummary = ExpertInfoSummary(),
        capture: ImsCaptureRange = ImsCaptureRange(firstFrame = 1, lastFrame = 100, startTime = 0.0, endTime = 10.0),
        selection: ImsRegistrationSelection = ImsRegistrationSelection()
    ) = ImsRegistrationAnalyzer.analyze(
        timelines = SipTransactionCorrelator.correlate(messages.toList()).dialogs,
        statistics = statistics,
        expertInfo = expert,
        captureRange = capture,
        selection = selection
    )

    private fun request(
        frame: Long,
        time: Double,
        callId: String,
        cSeq: Long,
        authorization: Boolean = false
    ) = SipMessage(
        frameNumber = frame,
        time = time,
        source = "192.0.2.10",
        destination = "192.0.2.20",
        sourcePort = 5060,
        destinationPort = 5060,
        method = "REGISTER",
        callId = callId,
        cSeqNumber = cSeq,
        cSeqMethod = "REGISTER",
        viaBranch = "z9hG4bK-$callId-$cSeq",
        authorizationPresent = authorization
    )

    private fun response(
        frame: Long,
        time: Double,
        callId: String,
        cSeq: Long,
        status: String
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
        cSeqMethod = "REGISTER",
        viaBranch = "z9hG4bK-$callId-$cSeq"
    )
}
