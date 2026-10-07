package com.example.layanalyzer.data

import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SdpOfferAnswerAssociation
import com.example.layanalyzer.model.SdpOfferAnswerRole
import com.example.layanalyzer.model.SipCorrelationQuality
import com.example.layanalyzer.model.SipCorrelationResult
import com.example.layanalyzer.model.SipDialogEvent
import com.example.layanalyzer.model.SipDialogTimeline
import com.example.layanalyzer.model.SipMessage
import com.example.layanalyzer.model.SipTransaction
import kotlin.math.abs
import kotlin.math.roundToLong

/**
 * Deterministically joins SIP requests to their responses without relying on
 * packet-list Info text. Strong correlations use the SIP transaction key;
 * weaker captures remain usable, but declare precisely what was unavailable.
 */
object SipTransactionCorrelator {
    private const val WEAK_WINDOW_SECONDS = 32.0
    private val RESPONSE_CODE = Regex("(?<!\\d)([1-6]\\d{2})(?!\\d)")
    private val DIALOG_METHODS = setOf("INVITE", "PRACK", "UPDATE", "CANCEL", "ACK", "BYE")

    fun correlate(messages: List<SipMessage>): SipCorrelationResult {
        val ordered = messages.sortedWith(compareBy(SipMessage::time, SipMessage::frameNumber))
        val mutableTransactions = mutableListOf<MutableTransaction>()

        ordered.filter(::isRequest).forEach { request ->
            val existing = mutableTransactions.firstOrNull { it.matchesRetransmission(request) }
            if (existing == null) {
                mutableTransactions += MutableTransaction(request = request)
            } else {
                existing.retransmittedRequests += request
            }
        }

        ordered.filter(::isResponse).forEach { response ->
            val target = mutableTransactions
                .filter { it.matchesResponse(response) }
                .minWithOrNull(
                    compareBy<MutableTransaction> {
                        it.request?.let { request -> responseDistance(request, response) } ?: Double.MAX_VALUE
                    }.thenBy { it.request?.frameNumber ?: Long.MAX_VALUE }
                )
            if (target == null) {
                mutableTransactions += MutableTransaction(orphanResponse = response)
            } else if (responseCode(response) in 100..199) {
                target.provisionalResponses += response
            } else {
                target.finalResponses += response
            }
        }

        val transactions = mutableTransactions
            .map(MutableTransaction::toImmutable)
            .sortedWith(compareBy(SipTransaction::firstTime, { it.firstFrame ?: Long.MAX_VALUE }))
        return SipCorrelationResult(
            transactions = transactions,
            dialogs = buildDialogs(transactions)
        )
    }

    private fun buildDialogs(transactions: List<SipTransaction>): List<SipDialogTimeline> =
        transactions.filter { it.callId.isNotBlank() }
            .groupBy(SipTransaction::callId)
            .map { (callId, callTransactions) ->
                val ordered = callTransactions.sortedWith(
                    compareBy(SipTransaction::firstTime, { it.firstFrame ?: Long.MAX_VALUE })
                )
                val registrations = ordered.filter { it.transactionMethod() == "REGISTER" }
                val dialogTransactions = ordered.filter { it.transactionMethod() in DIALOG_METHODS }
                val timelineTransactions = (registrations + dialogTransactions)
                    .distinct()
                    .sortedWith(compareBy(SipTransaction::firstTime, { it.firstFrame ?: Long.MAX_VALUE }))
                val events = timelineTransactions.mapIndexed { index, transaction ->
                    SipDialogEvent(
                        transaction = transaction,
                        elapsedSincePreviousMillis = timelineTransactions
                            .getOrNull(index - 1)
                            ?.let { previous -> millisBetween(previous.lastTime, transaction.firstTime) }
                    )
                }
                val messages = ordered.flatMap(SipTransaction::allMessages)
                    .sortedWith(compareBy(SipMessage::time, SipMessage::frameNumber))
                SipDialogTimeline(
                    callId = callId,
                    registrationTransactions = registrations,
                    callTransactions = dialogTransactions,
                    events = events,
                    initialFromTag = messages.firstNotNullOfOrNull { it.fromTag?.takeIf(String::isNotBlank) },
                    finalToTag = messages.asReversed().firstNotNullOfOrNull { it.toTag?.takeIf(String::isNotBlank) },
                    sdpOfferAnswers = buildSdpOfferAnswers(ordered)
                )
            }
            .sortedBy { it.events.firstOrNull()?.transaction?.firstTime ?: Double.MAX_VALUE }

    private fun buildSdpOfferAnswers(transactions: List<SipTransaction>): List<SdpOfferAnswerAssociation> =
        transactions.mapNotNull { transaction ->
            val request = transaction.request
            val requestSdp = request?.sdp
            val response = (transaction.provisionalResponses + transaction.finalResponses)
                .firstOrNull { it.sdp != null }
            when {
                requestSdp != null -> SdpOfferAnswerAssociation(
                    offer = requestSdp.copy(offerAnswerRole = SdpOfferAnswerRole.Offer),
                    answer = response?.sdp?.copy(offerAnswerRole = SdpOfferAnswerRole.Answer),
                    offerFrame = request.frameNumber,
                    answerFrame = response?.frameNumber
                )
                response?.sdp != null -> SdpOfferAnswerAssociation(
                    offer = response.sdp.copy(offerAnswerRole = SdpOfferAnswerRole.Offer),
                    offerFrame = response.frameNumber
                )
                else -> null
            }
        }

    private fun SipTransaction.transactionMethod(): String =
        cSeqMethod.normalizedMethod().ifBlank { request?.method.normalizedMethod() }

    private fun isRequest(message: SipMessage): Boolean = message.method.normalizedMethod().isNotBlank()

    private fun isResponse(message: SipMessage): Boolean =
        !isRequest(message) && responseCode(message) != null

    private fun responseCode(message: SipMessage): Int? =
        RESPONSE_CODE.find(message.status.ifBlank { message.info })?.groupValues?.get(1)?.toIntOrNull()

    private fun responseDistance(request: SipMessage, response: SipMessage): Double =
        (response.time - request.time).takeIf { it >= 0.0 } ?: Double.MAX_VALUE

    private fun millisBetween(start: Double, end: Double): Long =
        ((end - start).coerceAtLeast(0.0) * 1_000.0).roundToLong()

    private fun String?.normalizedMethod(): String = this?.trim()?.substringBefore(' ')?.uppercase().orEmpty()

    private fun hasSameDirection(first: SipMessage, second: SipMessage): Boolean =
        first.source == second.source && first.destination == second.destination &&
            portsMatch(first.sourcePort, second.sourcePort) && portsMatch(first.destinationPort, second.destinationPort)

    private fun hasReverseDirection(request: SipMessage, response: SipMessage): Boolean =
        request.source == response.destination && request.destination == response.source &&
            portsMatch(request.sourcePort, response.destinationPort) &&
            portsMatch(request.destinationPort, response.sourcePort)

    private fun portsMatch(first: Int?, second: Int?): Boolean =
        first == null || second == null || first == second

    private class MutableTransaction(
        val request: SipMessage? = null,
        orphanResponse: SipMessage? = null
    ) {
        val provisionalResponses = mutableListOf<SipMessage>()
        val finalResponses = mutableListOf<SipMessage>()
        val retransmittedRequests = mutableListOf<SipMessage>()

        init {
            orphanResponse?.let { response ->
                if (responseCode(response) in 100..199) provisionalResponses += response
                else finalResponses += response
            }
        }

        fun matchesRetransmission(candidate: SipMessage): Boolean {
            val original = request ?: return false
            if (hasStrongKey(original) && hasStrongKey(candidate)) return sameStrongKey(original, candidate)
            if (hasFallbackKey(original) && hasFallbackKey(candidate)) {
                return sameFallbackKey(original, candidate) && hasSameDirection(original, candidate)
            }
            return original.callId.isNotBlank() && original.callId == candidate.callId &&
                original.method.normalizedMethod() == candidate.method.normalizedMethod() &&
                hasSameDirection(original, candidate) && abs(original.time - candidate.time) <= WEAK_WINDOW_SECONDS
        }

        fun matchesResponse(response: SipMessage): Boolean {
            val original = request ?: return false
            if (hasStrongKey(original) && hasStrongKey(response)) return sameStrongKey(original, response)
            if (hasFallbackKey(original) && hasFallbackKey(response) &&
                sameFallbackKey(original, response) && hasReverseDirection(original, response)
            ) {
                return true
            }
            if (hasFallbackKey(original) && hasFallbackKey(response)) return false
            return original.callId.isNotBlank() && original.callId == response.callId &&
                hasReverseDirection(original, response) &&
                abs(response.time - original.time) <= WEAK_WINDOW_SECONDS
        }

        fun toImmutable(): SipTransaction {
            val all = listOfNotNull(request) + retransmittedRequests + provisionalResponses + finalResponses
            val ordered = all.sortedWith(compareBy(SipMessage::time, SipMessage::frameNumber))
            val firstResponse = (provisionalResponses + finalResponses)
                .minWithOrNull(compareBy(SipMessage::time, SipMessage::frameNumber))
            val quality = correlationQuality(request, provisionalResponses + finalResponses)
            return SipTransaction(
                callId = request?.callId ?: firstResponse?.callId.orEmpty(),
                cSeqNumber = request?.cSeqNumber ?: firstResponse?.cSeqNumber,
                cSeqMethod = request?.cSeqMethod ?: firstResponse?.cSeqMethod,
                viaBranch = request?.viaBranch ?: firstResponse?.viaBranch,
                request = request,
                provisionalResponses = provisionalResponses.sortedWith(compareBy(SipMessage::time, SipMessage::frameNumber)),
                finalResponses = finalResponses.sortedWith(compareBy(SipMessage::time, SipMessage::frameNumber)),
                retransmittedRequests = retransmittedRequests.sortedWith(compareBy(SipMessage::time, SipMessage::frameNumber)),
                firstTime = ordered.firstOrNull()?.time ?: 0.0,
                lastTime = ordered.lastOrNull()?.time ?: 0.0,
                responseDelayMillis = request?.let { original ->
                    firstResponse?.let { response -> millisBetween(original.time, response.time) }
                },
                correlationQuality = quality,
                missingFields = missingFields(request, provisionalResponses + finalResponses, quality)
            )
        }
    }

    private fun hasStrongKey(message: SipMessage): Boolean =
        hasFallbackKey(message) && !message.viaBranch.isNullOrBlank()

    private fun hasFallbackKey(message: SipMessage): Boolean =
        message.callId.isNotBlank() && message.cSeqNumber != null && !message.cSeqMethod.isNullOrBlank()

    private fun sameStrongKey(first: SipMessage, second: SipMessage): Boolean =
        sameFallbackKey(first, second) && first.viaBranch == second.viaBranch

    private fun sameFallbackKey(first: SipMessage, second: SipMessage): Boolean =
        first.callId == second.callId && first.cSeqNumber == second.cSeqNumber &&
            first.cSeqMethod.normalizedMethod() == second.cSeqMethod.normalizedMethod()

    private fun correlationQuality(
        request: SipMessage?,
        responses: List<SipMessage>
    ): SipCorrelationQuality {
        request ?: return SipCorrelationQuality.Weak
        if (hasStrongKey(request) && responses.all { hasStrongKey(it) && sameStrongKey(request, it) }) {
            return SipCorrelationQuality.Strong
        }
        if (hasFallbackKey(request) && responses.all { hasFallbackKey(it) && sameFallbackKey(request, it) }) {
            return SipCorrelationQuality.Fallback
        }
        return SipCorrelationQuality.Weak
    }

    private fun missingFields(
        request: SipMessage?,
        responses: List<SipMessage>,
        quality: SipCorrelationQuality
    ): List<String> {
        val representative = request ?: responses.firstOrNull()
        if (representative == null) return listOf("request", "callId", "cSeqNumber", "cSeqMethod", "viaBranch")
        return buildList {
            if (representative.callId.isBlank()) add("callId")
            if (representative.cSeqNumber == null) add("cSeqNumber")
            if (representative.cSeqMethod.isNullOrBlank()) add("cSeqMethod")
            if (quality != SipCorrelationQuality.Strong) add("viaBranch")
            if (request == null) add("request")
        }
    }
}
