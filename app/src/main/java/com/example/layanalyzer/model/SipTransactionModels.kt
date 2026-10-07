// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

/** Reliability of the key used to correlate a SIP request and its responses. */
enum class SipCorrelationQuality {
    Strong,
    Fallback,
    Weak
}

/**
 * A SIP client transaction with the original request, its retransmissions and
 * ordered responses. A missing request represents an orphan response observed
 * without its corresponding request in the current analysis scope.
 */
data class SipTransaction(
    val callId: String = "",
    val cSeqNumber: Long? = null,
    val cSeqMethod: String? = null,
    val viaBranch: String? = null,
    val request: SipMessage? = null,
    val provisionalResponses: List<SipMessage> = emptyList(),
    val finalResponses: List<SipMessage> = emptyList(),
    val retransmittedRequests: List<SipMessage> = emptyList(),
    val firstTime: Double = 0.0,
    val lastTime: Double = 0.0,
    val responseDelayMillis: Long? = null,
    val correlationQuality: SipCorrelationQuality = SipCorrelationQuality.Weak,
    val missingFields: List<String> = emptyList()
) {
    val firstFrame: Long?
        get() = allMessages.firstOrNull()?.frameNumber

    val allMessages: List<SipMessage>
        get() = (listOfNotNull(request) + retransmittedRequests + provisionalResponses + finalResponses)
            .sortedWith(compareBy(SipMessage::time, SipMessage::frameNumber))
}

data class SipDialogEvent(
    val transaction: SipTransaction,
    val elapsedSincePreviousMillis: Long? = null
)

/** The SDP metadata used as an offer and, when visible, its corresponding answer. */
data class SdpOfferAnswerAssociation(
    val offer: SdpMediaSummary,
    val answer: SdpMediaSummary? = null,
    val offerFrame: Long,
    val answerFrame: Long? = null
)

/** A Call-ID scoped IMS dialog and the transactions that describe it. */
data class SipDialogTimeline(
    val callId: String,
    val registrationTransactions: List<SipTransaction> = emptyList(),
    val callTransactions: List<SipTransaction> = emptyList(),
    val events: List<SipDialogEvent> = emptyList(),
    val initialFromTag: String? = null,
    val finalToTag: String? = null,
    val sdpOfferAnswers: List<SdpOfferAnswerAssociation> = emptyList()
)

data class SipCorrelationResult(
    val transactions: List<SipTransaction> = emptyList(),
    val dialogs: List<SipDialogTimeline> = emptyList()
)
