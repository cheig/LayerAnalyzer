// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ExpertInfoItem
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.ImsCaptureRange
import com.example.layanalyzer.model.ImsRegistrationAnalysis
import com.example.layanalyzer.model.ImsRegistrationAttempt
import com.example.layanalyzer.model.ImsRegistrationCandidate
import com.example.layanalyzer.model.ImsRegistrationOutcome
import com.example.layanalyzer.model.ImsRegistrationSelection
import com.example.layanalyzer.model.ImsRegistrationStage
import com.example.layanalyzer.model.ImsRegistrationTimelineEvent
import com.example.layanalyzer.model.ImsRegistrationTransportEvidence
import com.example.layanalyzer.model.ImsTransportAnomaly
import com.example.layanalyzer.model.SipDialogTimeline
import com.example.layanalyzer.model.SipMessage
import com.example.layanalyzer.model.SipTransaction
import kotlin.math.roundToLong

/**
 * Local, deterministic IMS registration state machine.
 *
 * It deliberately consumes transaction metadata rather than packet-list text:
 * the model receives the resulting stages and evidence frames, but does not
 * need to recreate REGISTER/CSeq correlation from unstructured summaries.
 */
object ImsRegistrationAnalyzer {
    private const val AUTH_RETRY_WINDOW_SECONDS = 32.0
    private val RESPONSE_CODE = Regex("(?<!\\d)([1-6]\\d{2})(?!\\d)")

    fun analyze(
        timelines: List<SipDialogTimeline>,
        statistics: CaptureStatistics = CaptureStatistics(),
        expertInfo: ExpertInfoSummary = ExpertInfoSummary(),
        captureRange: ImsCaptureRange = ImsCaptureRange(),
        selection: ImsRegistrationSelection = ImsRegistrationSelection()
    ): ImsRegistrationAnalysis {
        val attempts = timelines.flatMap(::attemptsForTimeline)
            .sortedWith(compareBy(ImsRegistrationAttempt::startTime, { it.firstFrame ?: Long.MAX_VALUE }))
            .map { attempt -> enrich(attempt, statistics, expertInfo, captureRange) }

        if (attempts.isEmpty()) {
            return ImsRegistrationAnalysis(
                selectionReason = "No visible REGISTER transaction was found in the analyzed scope.",
                captureRange = captureRange,
                limitations = listOf(
                    "No visible SIP REGISTER transaction was available; signaling may be outside the capture or protected by encryption."
                ),
                excludedCauses = emptyList()
            )
        }

        val (selected, reason) = selectAttempt(attempts, selection)
        val alternateCandidates = attempts.asReversed()
            .filter { it.id != selected.id }
            .map { candidate ->
                ImsRegistrationCandidate(
                    id = candidate.id,
                    callId = candidate.callId,
                    outcome = candidate.outcome,
                    firstFrame = candidate.firstFrame,
                    startTime = candidate.startTime,
                    selectionReason = "Not selected: $reason"
                )
            }

        return ImsRegistrationAnalysis(
            selectedAttempt = selected,
            alternateCandidates = alternateCandidates,
            selectionReason = reason,
            captureRange = captureRange,
            limitations = selected.limitations,
            excludedCauses = excludedCauses(selected)
        )
    }

    /** Convenience overload for consumers that already narrowed to one dialog. */
    fun analyze(
        timeline: SipDialogTimeline,
        statistics: CaptureStatistics = CaptureStatistics(),
        expertInfo: ExpertInfoSummary = ExpertInfoSummary(),
        captureRange: ImsCaptureRange = ImsCaptureRange(),
        selection: ImsRegistrationSelection = ImsRegistrationSelection()
    ): ImsRegistrationAnalysis = analyze(
        timelines = listOf(timeline),
        statistics = statistics,
        expertInfo = expertInfo,
        captureRange = captureRange,
        selection = selection
    )

    private fun attemptsForTimeline(timeline: SipDialogTimeline): List<ImsRegistrationAttempt> {
        val registrations = timeline.registrationTransactions.sortedWith(
            compareBy(SipTransaction::firstTime, { it.firstFrame ?: Long.MAX_VALUE })
        )
        val attempts = mutableListOf<ImsRegistrationAttempt>()
        registrations.forEachIndexed { index, transaction ->
            val request = transaction.request ?: return@forEachIndexed
            if (request.authorizationPresent) {
                val previousWasChallenge = registrations.getOrNull(index - 1)?.challengeResponse() != null
                if (!previousWasChallenge) {
                    attempts += incompleteAttempt(timeline.callId, transaction)
                }
                return@forEachIndexed
            }
            attempts += attemptFromInitial(timeline.callId, transaction, registrations.drop(index + 1))
        }
        return attempts
    }

    private fun attemptFromInitial(
        callId: String,
        initial: SipTransaction,
        subsequent: List<SipTransaction>
    ): ImsRegistrationAttempt {
        val initialRequest = initial.request ?: return incompleteAttempt(callId, initial)
        val challenge = initial.challengeResponse()
        val authenticated = challenge?.let { response ->
            subsequent.firstOrNull { transaction ->
                val request = transaction.request
                request != null && request.authorizationPresent &&
                    transaction.firstTime >= response.time &&
                    transaction.firstTime - response.time <= AUTH_RETRY_WINDOW_SECONDS
            }
        }
        val finalMessage = authenticated?.finalResponse() ?: initial.finalResponse()
        val events = buildList {
            add(initialRequest.event(ImsRegistrationStage.InitialRegister, initialRequest.time))
            challenge?.let { add(it.event(ImsRegistrationStage.AuthenticationChallenge, initialRequest.time)) }
            authenticated?.request?.let { add(it.event(ImsRegistrationStage.AuthenticatedRegister, initialRequest.time)) }
            finalMessage?.let { add(it.event(ImsRegistrationStage.FinalResponse, initialRequest.time)) }
        }
        val first = events.minByOrNull(ImsRegistrationTimelineEvent::time)
        val last = events.maxByOrNull(ImsRegistrationTimelineEvent::time)
        return ImsRegistrationAttempt(
            id = "registration-${initialRequest.frameNumber}",
            callId = callId,
            outcome = outcomeFor(
                challenge = challenge,
                authenticated = authenticated,
                finalMessage = finalMessage
            ),
            timeline = events.sortedWith(compareBy(ImsRegistrationTimelineEvent::time, ImsRegistrationTimelineEvent::frameNumber)),
            startTime = first?.time ?: initial.firstTime,
            endTime = last?.time ?: initial.lastTime,
            firstFrame = first?.frameNumber ?: initial.firstFrame,
            lastFrame = last?.frameNumber ?: initial.allMessages.maxOfOrNull(SipMessage::frameNumber),
            retransmissionCount = initial.retransmittedRequests.size + (authenticated?.retransmittedRequests?.size ?: 0)
        )
    }

    private fun incompleteAttempt(callId: String, transaction: SipTransaction): ImsRegistrationAttempt {
        val request = transaction.request
        val final = transaction.finalResponse()
        val initialTime = request?.time ?: transaction.firstTime
        val events = buildList {
            request?.let { add(it.event(ImsRegistrationStage.AuthenticatedRegister, initialTime)) }
            final?.let { add(it.event(ImsRegistrationStage.FinalResponse, initialTime)) }
        }
        return ImsRegistrationAttempt(
            id = "registration-${transaction.firstFrame ?: 0L}",
            callId = callId,
            outcome = ImsRegistrationOutcome.CaptureIncompleteOrEncrypted,
            timeline = events,
            startTime = events.firstOrNull()?.time ?: transaction.firstTime,
            endTime = events.lastOrNull()?.time ?: transaction.lastTime,
            firstFrame = events.firstOrNull()?.frameNumber ?: transaction.firstFrame,
            lastFrame = events.lastOrNull()?.frameNumber ?: transaction.allMessages.maxOfOrNull(SipMessage::frameNumber),
            retransmissionCount = transaction.retransmittedRequests.size,
            missingInitialFlow = true,
            limitations = listOf(
                "The first visible REGISTER already carried authorization; the initial REGISTER and authentication challenge are outside the observed flow."
            )
        )
    }

    private fun enrich(
        attempt: ImsRegistrationAttempt,
        statistics: CaptureStatistics,
        expertInfo: ExpertInfoSummary,
        captureRange: ImsCaptureRange
    ): ImsRegistrationAttempt {
        val transport = transportEvidence(attempt, statistics, expertInfo, captureRange)
        val outcome = when {
            attempt.missingInitialFlow -> ImsRegistrationOutcome.CaptureIncompleteOrEncrypted
            attempt.finalResponse == null && transport.isNotEmpty() -> ImsRegistrationOutcome.TransportFailure
            else -> attempt.outcome
        }
        val hasCompleteNegativeEvidence = attempt.finalResponse == null &&
            captureRange.isCompleteForNegativeEvidence
        val limitations = buildList {
            addAll(attempt.limitations)
            if (captureRange.sipSourceTruncated) {
                add("The SIP source was truncated, so an unobserved retry or final response cannot be ruled out.")
            }
            if (captureRange.expertSourceTruncated) {
                add("The Expert Info source was truncated, so transport anomaly coverage is incomplete.")
            }
            if (captureRange.scopeIsFiltered) {
                add("The analysis used a filtered capture scope; absence conclusions apply only to that scope.")
            }
            if (attempt.finalResponse == null && !hasCompleteNegativeEvidence) {
                add("No final response is only an observed gap because the queried range is not complete for negative evidence.")
            }
            if (transport.any { it.frameNumber == null }) {
                add("Aggregate TCP statistics indicate a transport anomaly, but did not expose an individual anomaly frame in this scope.")
            }
        }.distinct()
        val timeline = (attempt.timeline + transport.mapNotNull { evidence ->
            evidence.frameNumber?.let { frame ->
                ImsRegistrationTimelineEvent(
                    stage = ImsRegistrationStage.TransportAnomaly,
                    frameNumber = frame,
                    time = attempt.endTime,
                    elapsedFromInitialMillis = elapsedMillis(attempt.startTime, attempt.endTime)
                )
            }
        }).sortedWith(compareBy(ImsRegistrationTimelineEvent::time, ImsRegistrationTimelineEvent::frameNumber))
        return attempt.copy(
            outcome = outcome,
            timeline = timeline,
            transportEvidence = transport,
            hasCompleteNegativeEvidence = hasCompleteNegativeEvidence,
            limitations = limitations
        )
    }

    private fun transportEvidence(
        attempt: ImsRegistrationAttempt,
        statistics: CaptureStatistics,
        expertInfo: ExpertInfoSummary,
        captureRange: ImsCaptureRange
    ): List<ImsRegistrationTransportEvidence> {
        val lastRelevantFrame = if (attempt.finalResponse == null) {
            captureRange.lastFrame ?: attempt.lastFrame
        } else {
            attempt.lastFrame
        }
        val range = attempt.firstFrame?.let { first ->
            lastRelevantFrame?.let { last -> first..last }
        }
        val matchingExpert = expertInfo.items.filter { item ->
            (range == null || item.frameNumber in range) && anomalyFor(item) != null
        }.sortedBy(ExpertInfoItem::frameNumber)
        val evidence = matchingExpert.map { item ->
            ImsRegistrationTransportEvidence(
                anomaly = checkNotNull(anomalyFor(item)),
                frameNumber = item.frameNumber,
                observedCount = 1,
                source = "expert_info"
            )
        }.toMutableList()
        if (evidence.isNotEmpty() || attempt.finalResponse != null) return evidence

        fun aggregate(anomaly: ImsTransportAnomaly, count: Int) {
            if (count > 0) evidence += ImsRegistrationTransportEvidence(
                anomaly = anomaly,
                observedCount = count,
                source = "capture_statistics"
            )
        }
        aggregate(ImsTransportAnomaly.TcpRetransmission, statistics.tcpRetransmissions)
        aggregate(ImsTransportAnomaly.TcpReset, statistics.tcpResets)
        aggregate(ImsTransportAnomaly.TcpZeroWindow, statistics.tcpZeroWindows)
        return evidence
    }

    private fun anomalyFor(item: ExpertInfoItem): ImsTransportAnomaly? {
        val text = "${item.label} ${item.filter.orEmpty()}".lowercase()
        return when {
            "zero window" in text -> ImsTransportAnomaly.TcpZeroWindow
            "retransmission" in text || "retransmit" in text -> ImsTransportAnomaly.TcpRetransmission
            "tcp" in text && ("reset" in text || "rst" in text) -> ImsTransportAnomaly.TcpReset
            "icmp" in text -> ImsTransportAnomaly.Icmp
            else -> null
        }
    }

    private fun outcomeFor(
        challenge: SipMessage?,
        authenticated: SipTransaction?,
        finalMessage: SipMessage?
    ): ImsRegistrationOutcome {
        if (challenge != null && authenticated == null) return ImsRegistrationOutcome.AuthenticationRetryMissing
        return when (responseCode(finalMessage)) {
            in 200..299 -> ImsRegistrationOutcome.Success
            403 -> if (authenticated != null) {
                ImsRegistrationOutcome.AuthenticationRejected
            } else {
                ImsRegistrationOutcome.ClientFailure
            }
            423 -> ImsRegistrationOutcome.RegistrationIntervalIssue
            in 500..699 -> ImsRegistrationOutcome.ServerFailure
            in 400..499 -> ImsRegistrationOutcome.ClientFailure
            in 300..399 -> ImsRegistrationOutcome.Redirected
            null -> ImsRegistrationOutcome.NoFinalResponse
            else -> ImsRegistrationOutcome.Unknown
        }
    }

    private fun selectAttempt(
        attempts: List<ImsRegistrationAttempt>,
        selection: ImsRegistrationSelection
    ): Pair<ImsRegistrationAttempt, String> {
        var candidates = attempts
        val applied = mutableListOf<String>()
        selection.callIdContains?.trim()?.takeIf(String::isNotEmpty)?.let { callId ->
            val matching = candidates.filter { it.callId.contains(callId, ignoreCase = true) }
            if (matching.isNotEmpty()) {
                candidates = matching
                applied += "matched the Call-ID selector"
            }
        }
        selection.frameNumber?.let { frame ->
            val matching = candidates.filter { attempt ->
                val first = attempt.firstFrame ?: Long.MAX_VALUE
                val last = attempt.lastFrame ?: first
                frame in first..last
            }
            if (matching.isNotEmpty()) {
                candidates = matching
                applied += "matched frame $frame"
            }
        }
        if (selection.startTime != null || selection.endTime != null) {
            val matching = candidates.filter { attempt ->
                (selection.startTime == null || attempt.endTime >= selection.startTime) &&
                    (selection.endTime == null || attempt.startTime <= selection.endTime)
            }
            if (matching.isNotEmpty()) {
                candidates = matching
                applied += "matched the requested time range"
            }
        }
        val selected = candidates
            .filter { it.outcome != ImsRegistrationOutcome.Success }
            .maxWithOrNull(compareBy(ImsRegistrationAttempt::startTime, { it.firstFrame ?: Long.MIN_VALUE }))
            ?: candidates.maxWithOrNull(compareBy(ImsRegistrationAttempt::startTime, { it.firstFrame ?: Long.MIN_VALUE }))
            ?: attempts.last()
        val reason = if (applied.isEmpty()) {
            "Selected the most recent non-successful registration attempt; no Call-ID, frame, or time selector matched a narrower attempt."
        } else {
            "Selected the most recent candidate that ${applied.joinToString(" and ")}."
        }
        return selected to reason
    }

    private fun excludedCauses(attempt: ImsRegistrationAttempt): List<String> = buildList {
        if (attempt.outcome == ImsRegistrationOutcome.Success) {
            add("A final 2xx response was observed for the selected REGISTER flow.")
        }
        if (attempt.finalResponse != null && attempt.outcome != ImsRegistrationOutcome.TransportFailure) {
            add("The selected REGISTER flow has a visible final SIP response, so it is not a no-response timeout.")
        }
        if (attempt.challenge != null && attempt.authenticatedRegister != null) {
            add("An authenticated REGISTER retry was observed after the challenge.")
        }
        if (attempt.transportEvidence.isEmpty()) {
            add("No transport anomaly was identified in the selected registration window.")
        }
    }

    private fun SipTransaction.challengeResponse(): SipMessage? =
        finalResponses.firstOrNull { responseCode(it) in setOf(401, 407) }

    private fun SipTransaction.finalResponse(): SipMessage? =
        finalResponses.firstOrNull()

    private fun SipMessage.event(
        stage: ImsRegistrationStage,
        initialTime: Double
    ) = ImsRegistrationTimelineEvent(
        stage = stage,
        frameNumber = frameNumber,
        time = time,
        statusCode = responseCode(this),
        authorizationPresent = authorizationPresent,
        elapsedFromInitialMillis = elapsedMillis(initialTime, time)
    )

    private fun responseCode(message: SipMessage?): Int? = message?.let {
        RESPONSE_CODE.find(it.status.ifBlank { it.info })?.groupValues?.get(1)?.toIntOrNull()
    }

    private fun elapsedMillis(start: Double, end: Double): Long =
        ((end - start).coerceAtLeast(0.0) * 1_000.0).roundToLong()
}
