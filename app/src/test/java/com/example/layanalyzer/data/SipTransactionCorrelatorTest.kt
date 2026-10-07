package com.example.layanalyzer.data

import com.example.layanalyzer.model.SipCorrelationQuality
import com.example.layanalyzer.model.SipMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SipTransactionCorrelatorTest {
    @Test
    fun `register challenge and authenticated retry form two transactions`() {
        val result = SipTransactionCorrelator.correlate(
            listOf(
                request(1, 1.0, "registration", 1, "z9hG4bK-first", "REGISTER"),
                response(2, 1.1, "registration", 1, "z9hG4bK-first", "REGISTER", "401 Unauthorized"),
                request(3, 1.2, "registration", 2, "z9hG4bK-second", "REGISTER"),
                response(4, 1.3, "registration", 2, "z9hG4bK-second", "REGISTER", "200 OK")
            )
        )

        assertEquals(2, result.transactions.size)
        assertEquals(listOf(401, 200), result.transactions.map { transaction ->
            transaction.finalResponses.single().status.substringBefore(' ').toInt()
        })
        assertTrue(result.transactions.all { it.correlationQuality == SipCorrelationQuality.Strong })
        assertEquals(2, result.dialogs.single().registrationTransactions.size)
    }

    @Test
    fun `same request retransmission does not create another transaction`() {
        val result = SipTransactionCorrelator.correlate(
            listOf(
                request(10, 10.0, "call", 7, "z9hG4bK-retry", "INVITE"),
                request(11, 10.5, "call", 7, "z9hG4bK-retry", "INVITE"),
                response(12, 11.0, "call", 7, "z9hG4bK-retry", "INVITE", "100 Trying"),
                response(13, 12.0, "call", 7, "z9hG4bK-retry", "INVITE", "200 OK")
            )
        )

        val transaction = result.transactions.single()
        assertEquals(1, transaction.retransmittedRequests.size)
        assertEquals(1, transaction.provisionalResponses.size)
        assertEquals(1, transaction.finalResponses.size)
        assertEquals(1_000L, transaction.responseDelayMillis)
    }

    @Test
    fun `forked invite branches stay separate`() {
        val result = SipTransactionCorrelator.correlate(
            listOf(
                request(20, 20.0, "forked", 9, "z9hG4bK-a", "INVITE"),
                request(21, 20.1, "forked", 9, "z9hG4bK-b", "INVITE"),
                response(22, 20.2, "forked", 9, "z9hG4bK-b", "INVITE", "180 Ringing"),
                response(23, 20.3, "forked", 9, "z9hG4bK-a", "INVITE", "486 Busy Here")
            )
        )

        assertEquals(2, result.transactions.size)
        assertEquals("486 Busy Here", result.transactions.first { it.viaBranch == "z9hG4bK-a" }.finalResponses.single().status)
        assertEquals("180 Ringing", result.transactions.first { it.viaBranch == "z9hG4bK-b" }.provisionalResponses.single().status)
    }

    @Test
    fun `missing cseq falls back to weak adjacent call id correlation`() {
        val result = SipTransactionCorrelator.correlate(
            listOf(
                request(30, 30.0, "partial", null, null, "OPTIONS"),
                response(31, 30.2, "partial", null, null, "OPTIONS", "200 OK")
            )
        )

        val transaction = result.transactions.single()
        assertEquals(SipCorrelationQuality.Weak, transaction.correlationQuality)
        assertTrue("cSeqNumber" in transaction.missingFields)
        assertEquals(1, transaction.finalResponses.size)
    }

    @Test
    fun `messages from different call ids never mix`() {
        val result = SipTransactionCorrelator.correlate(
            listOf(
                request(40, 40.0, "call-a", 1, "branch-a", "INVITE"),
                request(41, 40.1, "call-b", 1, "branch-b", "INVITE"),
                response(42, 40.2, "call-b", 1, "branch-b", "INVITE", "200 OK"),
                response(43, 40.3, "call-a", 1, "branch-a", "INVITE", "486 Busy Here")
            )
        )

        assertEquals(2, result.transactions.size)
        assertEquals("200 OK", result.transactions.first { it.callId == "call-b" }.finalResponses.single().status)
        assertEquals("486 Busy Here", result.transactions.first { it.callId == "call-a" }.finalResponses.single().status)
    }

    private fun request(
        frame: Long,
        time: Double,
        callId: String,
        cSeq: Long?,
        branch: String?,
        method: String
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
        cSeqMethod = cSeq?.let { method },
        viaBranch = branch
    )

    private fun response(
        frame: Long,
        time: Double,
        callId: String,
        cSeq: Long?,
        branch: String?,
        method: String,
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
        cSeqMethod = cSeq?.let { method },
        viaBranch = branch
    )
}
