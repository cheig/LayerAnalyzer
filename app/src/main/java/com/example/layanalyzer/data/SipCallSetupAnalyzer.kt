// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.CoreSignalMessage
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.ProtocolSummaryItem
import com.example.layanalyzer.model.RequestResponseTransaction
import com.example.layanalyzer.model.SipCallSetupAnalysis
import com.example.layanalyzer.model.SipCallSetupAttempt
import com.example.layanalyzer.model.SipCallSetupCandidate
import com.example.layanalyzer.model.SipCallSetupCaptureRange
import com.example.layanalyzer.model.SipCallSetupCompleteness
import com.example.layanalyzer.model.SipCallSetupDelayContribution
import com.example.layanalyzer.model.SipCallSetupOutcome
import com.example.layanalyzer.model.SipCallSetupSelection
import com.example.layanalyzer.model.SipCallSetupStage
import com.example.layanalyzer.model.SipCallSetupStageTiming
import com.example.layanalyzer.model.SipCallSetupTransportEvidence
import com.example.layanalyzer.model.SipCallSetupTransportKind
import com.example.layanalyzer.model.SipDialogTimeline
import com.example.layanalyzer.model.SipMessage
import com.example.layanalyzer.model.SipTransaction
import kotlin.math.abs
import kotlin.math.roundToLong

/**
 * Locally derives the establishment stages for one SIP INVITE transaction.
 *
 * The analyzer intentionally separates candidate selection from stage
 * construction. A capture can carry several dialogs (or forked INVITEs), and
 * producing one blended timeline would make frame evidence misleading.
 */
object SipCallSetupAnalyzer {
    private const val DEFAULT_TRANSPORT_ASSOCIATION_WINDOW_MILLIS = 30_000L
    private val RESPONSE_CODE = Regex("(?<!\\d)([1-6]\\d{2})(?!\\d)")

    fun analyze(
        timelines: List<SipDialogTimeline>,
        statistics: CaptureStatistics = CaptureStatistics(),
        expertInfo: ExpertInfoSummary = ExpertInfoSummary(),
        coreEvents: List<CoreSignalMessage> = emptyList(),
        captureRange: SipCallSetupCaptureRange = SipCallSetupCaptureRange(),
        selection: SipCallSetupSelection = SipCallSetupSelection(),
        transportAssociationWindowMillis: Long = DEFAULT_TRANSPORT_ASSOCIATION_WINDOW_MILLIS
    ): SipCallSetupAnalysis {
        val attempts = timelines.flatMap { timeline ->
            attemptsForTimeline(
                timeline = timeline,
                statistics = statistics,
                expertInfo = expertInfo,
                coreEvents = coreEvents,
                captureRange = captureRange,
                attentionThresholdMillis = selection.attentionThresholdMillis,
                transportAssociationWindowMillis = transportAssociationWindowMillis
            )
        }.sortedWith(compareBy(SipCallSetupAttempt::startTime, { it.inviteFrame ?: Long.MAX_VALUE }))

        if (attempts.isEmpty()) {
            return SipCallSetupAnalysis(
                selectionReason = "No visible SIP INVITE transaction was found in the analyzed scope.",
                captureRange = captureRange,
                limitations = listOf(
                    "No visible INVITE was available; call setup signaling may be outside the capture or protected by encryption."
                )
            )
        }

        val decision = selectAttempt(attempts, selection)
        val selected = decision.selected
        val candidates = attempts.filter { it.id != selected?.id }.map { attempt ->
            SipCallSetupCandidate(
                id = attempt.id,
                callId = attempt.callId,
                inviteFrame = attempt.inviteFrame,
                startTime = attempt.startTime,
                outcome = attempt.outcome,
                finalResponseCode = attempt.finalResponseCode,
                setupDurationMillis = attempt.setupDurationMillis,
                selectionReason = "Not selected: ${decision.reason}"
            )
        }
        val limits = selected?.limitations ?: buildList {
            add("Several call setup candidates match the available evidence; select a Call-ID or boundary frame before assigning a diagnosis.")
            if (captureRange.sipSourceTruncated) {
                add("The SIP source was truncated, so candidate coverage is incomplete.")
            }
        }
        return SipCallSetupAnalysis(
            selectedAttempt = selected,
            alternateCandidates = candidates,
            selectionReason = decision.reason,
            requiresUserSelection = selected == null,
            captureRange = captureRange,
            limitations = limits.distinct(),
            excludedCauses = selected?.let(::excludedCauses).orEmpty()
        )
    }

    fun analyze(
        timeline: SipDialogTimeline,
        statistics: CaptureStatistics = CaptureStatistics(),
        expertInfo: ExpertInfoSummary = ExpertInfoSummary(),
        coreEvents: List<CoreSignalMessage> = emptyList(),
        captureRange: SipCallSetupCaptureRange = SipCallSetupCaptureRange(),
        selection: SipCallSetupSelection = SipCallSetupSelection(),
        transportAssociationWindowMillis: Long = DEFAULT_TRANSPORT_ASSOCIATION_WINDOW_MILLIS
    ): SipCallSetupAnalysis = analyze(
        timelines = listOf(timeline),
        statistics = statistics,
        expertInfo = expertInfo,
        coreEvents = coreEvents,
        captureRange = captureRange,
        selection = selection,
        transportAssociationWindowMillis = transportAssociationWindowMillis
    )

    private fun attemptsForTimeline(
        timeline: SipDialogTimeline,
        statistics: CaptureStatistics,
        expertInfo: ExpertInfoSummary,
        coreEvents: List<CoreSignalMessage>,
        captureRange: SipCallSetupCaptureRange,
        attentionThresholdMillis: Long?,
        transportAssociationWindowMillis: Long
    ): List<SipCallSetupAttempt> {
        val inviteTransactions = timeline.callTransactions.filter {
            it.request?.method.normalizedMethod() == "INVITE"
        }
        if (inviteTransactions.isEmpty()) return emptyList()
        return inviteTransactions.map { invite ->
            attemptForInvite(
                timeline = timeline,
                invite = invite,
                statistics = statistics,
                expertInfo = expertInfo,
                coreEvents = coreEvents,
                captureRange = captureRange,
                attentionThresholdMillis = attentionThresholdMillis,
                transportAssociationWindowMillis = transportAssociationWindowMillis
            )
        }
    }

    private fun attemptForInvite(
        timeline: SipDialogTimeline,
        invite: SipTransaction,
        statistics: CaptureStatistics,
        expertInfo: ExpertInfoSummary,
        coreEvents: List<CoreSignalMessage>,
        captureRange: SipCallSetupCaptureRange,
        attentionThresholdMillis: Long?,
        transportAssociationWindowMillis: Long
    ): SipCallSetupAttempt {
        val inviteRequest = checkNotNull(invite.request)
        val finalResponse = invite.finalResponses.firstOrNull()
        val finalCode = responseCode(finalResponse)
        val dialogMessages = timeline.callTransactions.flatMap(SipTransaction::allMessages)
            .filter { it.time >= inviteRequest.time }
            .sortedWith(compareBy(SipMessage::time, SipMessage::frameNumber))
        val hasUnresolvedFork = dialogMessages.any { message ->
            message.method.normalizedMethod() == "INVITE" && message.viaBranch != invite.viaBranch
        } && (inviteRequest.fromTag.isNullOrBlank() ||
            (invite.provisionalResponses + invite.finalResponses).none { !it.toTag.isNullOrBlank() })
        val branchMessages = if (hasUnresolvedFork) {
            // A new Via branch has no stable dialog tags. Keep the transaction
            // evidence, but do not borrow later dialog requests from a fork.
            invite.allMessages
        } else {
            dialogMessages.filter { message -> matchesInviteDialog(message, inviteRequest, invite) }
        }
        val trying = invite.provisionalResponses.firstOrNull { responseCode(it) == 100 }
        val ringing = invite.provisionalResponses.firstOrNull { responseCode(it) in setOf(180, 183) }
        val reliableProvisional = invite.provisionalResponses.firstOrNull { responseCode(it) == 183 }
        val terminalTime = finalResponse?.time ?: captureRange.endTime ?: dialogMessages.lastOrNull()?.time ?: inviteRequest.time
        val prack = branchMessages.firstOrNull { it.method.normalizedMethod() == "PRACK" && it.time >= (reliableProvisional?.time ?: Double.MAX_VALUE) }
        val prackTransaction = prack?.let { message ->
            timeline.callTransactions.firstOrNull { transaction -> transaction.request?.frameNumber == message.frameNumber }
        }
        val prackFinal = prackTransaction?.finalResponses?.firstOrNull()
        val cancel = branchMessages.firstOrNull { it.method.normalizedMethod() == "CANCEL" }
        val update = branchMessages.firstOrNull { it.method.normalizedMethod() == "UPDATE" && it.time >= (reliableProvisional?.time ?: inviteRequest.time) }
        val updateTransaction = update?.let { message ->
            timeline.callTransactions.firstOrNull { transaction -> transaction.request?.frameNumber == message.frameNumber }
        }
        val updateFinal = updateTransaction?.finalResponses?.firstOrNull()
        val ack = finalCode?.takeIf { it in 200..299 }?.let {
            branchMessages.firstOrNull { message ->
                message.method.normalizedMethod() == "ACK" &&
                    message.time >= (finalResponse?.time ?: Double.MAX_VALUE) &&
                    (message.cSeqNumber == null || inviteRequest.cSeqNumber == null || message.cSeqNumber == inviteRequest.cSeqNumber)
            }
        }

        val transport = transportEvidence(
            invite = inviteRequest,
            terminalTime = terminalTime,
            statistics = statistics,
            associationWindowMillis = transportAssociationWindowMillis
        )
        val transportStage = transportStage(
            invite = inviteRequest,
            statistics = statistics,
            evidence = transport,
            attentionThresholdMillis = attentionThresholdMillis,
            associationWindowMillis = transportAssociationWindowMillis
        )
        val stages = listOf(
            transportStage,
            stage(SipCallSetupStage.InviteToTrying, inviteRequest, trying, attentionThresholdMillis),
            stage(SipCallSetupStage.TryingToRinging, trying, ringing, attentionThresholdMillis),
            stage(
                SipCallSetupStage.ReliableProvisional,
                reliableProvisional,
                prackFinal,
                attentionThresholdMillis,
                evidenceFrames = listOfNotNull(reliableProvisional?.frameNumber, prack?.frameNumber, prackFinal?.frameNumber)
            ),
            stage(
                SipCallSetupStage.PreconditionOrUpdate,
                prackFinal ?: reliableProvisional ?: update,
                updateFinal ?: finalResponse?.takeIf { update != null },
                attentionThresholdMillis,
                evidenceFrames = listOfNotNull(reliableProvisional?.frameNumber, prackFinal?.frameNumber, update?.frameNumber, updateFinal?.frameNumber, finalResponse?.frameNumber)
            ),
            stage(SipCallSetupStage.FinalResponse, inviteRequest, finalResponse, attentionThresholdMillis),
            stage(SipCallSetupStage.AckCompletion, finalResponse?.takeIf { finalCode in 200..299 }, ack, attentionThresholdMillis)
        )

        val completion = ack ?: finalResponse
        val contributions = delayContributions(
            transportStage = transportStage,
            invite = inviteRequest,
            trying = trying,
            ringing = ringing,
            reliableProvisional = reliableProvisional,
            prackFinal = prackFinal,
            updateFinal = updateFinal,
            finalResponse = finalResponse,
            ack = ack
        )
        val totalDuration = contributions.sumOf(SipCallSetupDelayContribution::durationMillis)
            .takeIf { it > 0L }
        val normalizedContributions = contributions.map { contribution ->
            contribution.copy(
                percentageOfTotal = totalDuration?.let { total -> contribution.durationMillis * 100.0 / total } ?: 0.0
            )
        }
        val largestContribution = normalizedContributions.maxByOrNull(SipCallSetupDelayContribution::durationMillis)
        val setupStart = normalizedContributions.firstOrNull()?.startTime ?: inviteRequest.time
        val setupEnd = completion?.time ?: terminalTime
        val mediaFrames = invite.allMessages.filter { it.sdp != null }.map(SipMessage::frameNumber) +
            listOfNotNull(update?.takeIf { it.sdp != null }?.frameNumber, updateFinal?.takeIf { it.sdp != null }?.frameNumber)
        val correlatedCore = coreEvents.filter { event ->
            event.correlationValue.equals(timeline.callId, ignoreCase = true) &&
                event.time in inviteRequest.time..terminalTime
        }
        val outcome = outcomeFor(
            invite = invite,
            finalCode = finalCode,
            cancelSeen = cancel != null,
            prackFinal = prackFinal,
            ack = ack,
            captureRange = captureRange,
            finalResponseTime = finalResponse?.time,
            lastProvisionalTime = invite.provisionalResponses.lastOrNull()?.time,
            attentionThresholdMillis = attentionThresholdMillis,
            largestContribution = largestContribution
        )
        val limitations = limitationsFor(
            invite = invite,
            finalResponse = finalResponse,
            ack = ack,
            captureRange = captureRange,
            expertInfo = expertInfo,
            transport = transport,
            coreEvents = correlatedCore,
            dialogMessages = dialogMessages
        )
        return SipCallSetupAttempt(
            id = "call-setup-${timeline.callId}-${inviteRequest.frameNumber}",
            callId = timeline.callId,
            inviteFrame = inviteRequest.frameNumber,
            finalResponseFrame = finalResponse?.frameNumber,
            ackFrame = ack?.frameNumber,
            startTime = setupStart,
            endTime = setupEnd,
            finalResponseCode = finalCode,
            outcome = outcome,
            stages = stages,
            delayContributions = normalizedContributions,
            largestContribution = largestContribution,
            setupDurationMillis = totalDuration,
            inviteToFinalResponseMillis = finalResponse?.let { millisBetween(inviteRequest.time, it.time) },
            retransmissionCount = invite.retransmittedRequests.size,
            transportEvidence = transport,
            mediaNegotiationFrames = mediaFrames.distinct().sorted(),
            coreEventFrames = correlatedCore.map(CoreSignalMessage::frameNumber),
            limitations = limitations
        )
    }

    private fun transportStage(
        invite: SipMessage,
        statistics: CaptureStatistics,
        evidence: List<SipCallSetupTransportEvidence>,
        attentionThresholdMillis: Long?,
        associationWindowMillis: Long
    ): SipCallSetupStageTiming {
        val dns = statistics.dnsTransactions.filter { transaction ->
            transaction.requestFrame <= invite.frameNumber && dnsMatchesInvite(transaction, invite)
        }
        val timestampedDns = dns.mapNotNull { transaction ->
            val start = transaction.requestTime ?: return@mapNotNull null
            val end = transaction.responseTime ?: transaction.responseTimeMillis?.let { start + it / 1_000.0 } ?: return@mapNotNull null
            if (end > invite.time) return@mapNotNull null
            TransportBoundary(transaction.requestFrame, start, transaction.responseFrame ?: transaction.requestFrame, end)
        }
        val lowerBound = invite.time - associationWindowMillis.coerceAtLeast(0L) / 1_000.0
        val summaries = (statistics.tcpSummaries + statistics.tlsSummaries).filter { item ->
            item.time in lowerBound..invite.time &&
                endpointPairMatches(item.source, item.destination, invite.source, invite.destination)
        }
        val summaryPreparation = summaries.map { item ->
            TransportBoundary(item.frameNumber, item.time, item.frameNumber, item.time)
        }
        val preInviteEvidence = evidence.filter { item -> item.time != null && item.time <= invite.time }
        val summaryBoundaries = preInviteEvidence.map { item ->
            TransportBoundary(item.frameNumber, checkNotNull(item.time), item.frameNumber, checkNotNull(item.time))
        }
        val boundaries = (timestampedDns + summaryPreparation + summaryBoundaries)
            .distinctBy { boundary -> listOf(boundary.startFrame, boundary.endFrame) }
        if (boundaries.isEmpty()) {
            return SipCallSetupStageTiming(stage = SipCallSetupStage.PreInviteTransport)
        }
        val first = boundaries.minWith(compareBy(TransportBoundary::startTime, TransportBoundary::startFrame))
        val duration = millisBetween(first.startTime, invite.time)
        return SipCallSetupStageTiming(
            stage = SipCallSetupStage.PreInviteTransport,
            startFrame = first.startFrame,
            endFrame = invite.frameNumber,
            startTime = first.startTime,
            endTime = invite.time,
            durationMillis = duration,
            completeness = SipCallSetupCompleteness.Complete,
            attentionThresholdExceeded = attentionThresholdMillis?.let { duration >= it } ?: false,
            evidenceFrames = (boundaries.flatMap { listOf(it.startFrame, it.endFrame) } + invite.frameNumber).distinct().sorted()
        )
    }

    private fun stage(
        type: SipCallSetupStage,
        start: SipMessage?,
        end: SipMessage?,
        attentionThresholdMillis: Long?,
        evidenceFrames: List<Long> = listOfNotNull(start?.frameNumber, end?.frameNumber)
    ): SipCallSetupStageTiming {
        val duration = if (start != null && end != null) millisBetween(start.time, end.time) else null
        return SipCallSetupStageTiming(
            stage = type,
            startFrame = start?.frameNumber,
            endFrame = end?.frameNumber,
            startTime = start?.time,
            endTime = end?.time,
            durationMillis = duration,
            completeness = when {
                start != null && end != null -> SipCallSetupCompleteness.Complete
                start != null || end != null -> SipCallSetupCompleteness.Partial
                else -> SipCallSetupCompleteness.NotObserved
            },
            attentionThresholdExceeded = duration?.let { value -> attentionThresholdMillis?.let { value >= it } } ?: false,
            evidenceFrames = evidenceFrames.distinct().sorted()
        )
    }

    private fun delayContributions(
        transportStage: SipCallSetupStageTiming,
        invite: SipMessage,
        trying: SipMessage?,
        ringing: SipMessage?,
        reliableProvisional: SipMessage?,
        prackFinal: SipMessage?,
        updateFinal: SipMessage?,
        finalResponse: SipMessage?,
        ack: SipMessage?
    ): List<SipCallSetupDelayContribution> {
        val result = mutableListOf<SipCallSetupDelayContribution>()
        fun add(type: SipCallSetupStage, from: SipMessage?, to: SipMessage?) {
            if (from == null || to == null || to.time < from.time) return
            result += SipCallSetupDelayContribution(
                stage = type,
                startFrame = from.frameNumber,
                endFrame = to.frameNumber,
                startTime = from.time,
                endTime = to.time,
                durationMillis = millisBetween(from.time, to.time)
            )
        }
        if (transportStage.completeness == SipCallSetupCompleteness.Complete &&
            transportStage.startFrame != null && transportStage.endFrame != null &&
            transportStage.startTime != null && transportStage.endTime != null
        ) {
            result += SipCallSetupDelayContribution(
                stage = SipCallSetupStage.PreInviteTransport,
                startFrame = transportStage.startFrame,
                endFrame = transportStage.endFrame,
                startTime = transportStage.startTime,
                endTime = transportStage.endTime,
                durationMillis = checkNotNull(transportStage.durationMillis)
            )
        }
        var checkpoint: SipMessage = invite
        trying?.let {
            add(SipCallSetupStage.InviteToTrying, checkpoint, it)
            checkpoint = it
        }
        ringing?.takeIf { it.time >= checkpoint.time }?.let {
            add(SipCallSetupStage.TryingToRinging, checkpoint, it)
            checkpoint = it
        }
        reliableProvisional?.takeIf { it.time >= checkpoint.time }?.let {
            if (it.frameNumber != checkpoint.frameNumber) {
                add(SipCallSetupStage.TryingToRinging, checkpoint, it)
                checkpoint = it
            }
        }
        prackFinal?.takeIf { it.time >= checkpoint.time }?.let {
            add(SipCallSetupStage.ReliableProvisional, checkpoint, it)
            checkpoint = it
        }
        updateFinal?.takeIf { it.time >= checkpoint.time }?.let {
            add(SipCallSetupStage.PreconditionOrUpdate, checkpoint, it)
            checkpoint = it
        }
        finalResponse?.takeIf { it.time >= checkpoint.time }?.let {
            add(
                if (updateFinal != null) SipCallSetupStage.PreconditionOrUpdate else SipCallSetupStage.FinalResponse,
                checkpoint,
                it
            )
            checkpoint = it
        }
        ack?.takeIf { it.time >= checkpoint.time }?.let {
            add(SipCallSetupStage.AckCompletion, checkpoint, it)
        }
        return result
    }

    private fun transportEvidence(
        invite: SipMessage,
        terminalTime: Double,
        statistics: CaptureStatistics,
        associationWindowMillis: Long
    ): List<SipCallSetupTransportEvidence> {
        val lowerBound = invite.time - associationWindowMillis.coerceAtLeast(0L) / 1_000.0
        fun matches(item: ProtocolSummaryItem): Boolean =
            item.time in lowerBound..terminalTime && endpointPairMatches(item.source, item.destination, invite.source, invite.destination)

        val tcp = statistics.tcpSummaries.filter(::matches).mapNotNull { item ->
            val text = item.summary.lowercase()
            when {
                "retransmission" in text || "retransmit" in text -> item.toEvidence(SipCallSetupTransportKind.TcpRetransmission)
                "reset" in text || "rst" in text -> item.toEvidence(SipCallSetupTransportKind.TcpReset)
                else -> null
            }
        }
        val tls = statistics.tlsSummaries.filter(::matches).mapNotNull { item ->
            if ("alert" in item.summary.lowercase()) item.toEvidence(SipCallSetupTransportKind.TlsAlert) else null
        }
        val dns = statistics.dnsTransactions.filter { transaction ->
            transaction.requestFrame <= invite.frameNumber && dnsMatchesInvite(transaction, invite)
        }.map { transaction ->
            SipCallSetupTransportEvidence(
                kind = SipCallSetupTransportKind.Dns,
                frameNumber = transaction.responseFrame ?: transaction.requestFrame,
                time = transaction.responseTime ?: transaction.requestTime,
                source = transaction.client,
                destination = transaction.server,
                sourceName = "dns_transaction"
            )
        }
        return (dns + tcp + tls).distinctBy { evidence -> listOf(evidence.kind, evidence.frameNumber) }
            .sortedBy(SipCallSetupTransportEvidence::frameNumber)
    }

    private fun outcomeFor(
        invite: SipTransaction,
        finalCode: Int?,
        cancelSeen: Boolean,
        prackFinal: SipMessage?,
        ack: SipMessage?,
        captureRange: SipCallSetupCaptureRange,
        finalResponseTime: Double?,
        lastProvisionalTime: Double?,
        attentionThresholdMillis: Long?,
        largestContribution: SipCallSetupDelayContribution?
    ): SipCallSetupOutcome {
        if (invite.request == null) return SipCallSetupOutcome.CaptureIncomplete
        if (finalCode == 487 && cancelSeen) {
            return SipCallSetupOutcome.CancelledBeforeAnswer
        }
        if (finalCode != null && finalCode !in 200..299) return SipCallSetupOutcome.FinalResponseFailure
        if (responseCode(prackFinal) != null && responseCode(prackFinal) !in 200..299) {
            return SipCallSetupOutcome.PrackFailure
        }
        if (finalCode in 200..299 && ack == null) {
            return if (hasCompleteNegativeEvidence(captureRange, finalResponseTime ?: 0.0)) {
                SipCallSetupOutcome.MissingAck
            } else {
                SipCallSetupOutcome.CaptureIncomplete
            }
        }
        if (finalCode == null) {
            if (captureRange.sipSourceTruncated) return SipCallSetupOutcome.CaptureIncomplete
            val observedStall = lastProvisionalTime?.let { provisionalTime ->
                attentionThresholdMillis?.let { threshold ->
                    captureRange.endTime?.let { endTime ->
                        millisBetween(provisionalTime, endTime) >= threshold
                    }
                }
            } ?: false
            return if (observedStall && hasCompleteNegativeEvidence(captureRange, lastProvisionalTime ?: 0.0)
            ) {
                SipCallSetupOutcome.ProvisionalTimeout
            } else {
                SipCallSetupOutcome.NoFinalResponse
            }
        }
        val largestStage = largestContribution?.stage
        val largestExceedsAttention = largestContribution?.durationMillis?.let { duration ->
            attentionThresholdMillis?.let { duration >= it }
        } ?: false
        return when {
            largestStage == SipCallSetupStage.PreInviteTransport && largestExceedsAttention ->
                SipCallSetupOutcome.TransportOrTlsDelay
            largestStage == SipCallSetupStage.PreconditionOrUpdate && largestExceedsAttention ->
                SipCallSetupOutcome.MediaPreconditionDelay
            else -> SipCallSetupOutcome.Success
        }
    }

    private fun limitationsFor(
        invite: SipTransaction,
        finalResponse: SipMessage?,
        ack: SipMessage?,
        captureRange: SipCallSetupCaptureRange,
        expertInfo: ExpertInfoSummary,
        transport: List<SipCallSetupTransportEvidence>,
        coreEvents: List<CoreSignalMessage>,
        dialogMessages: List<SipMessage>
    ): List<String> = buildList {
        if (invite.correlationQuality.name != "Strong") {
            add("The INVITE transaction has ${invite.correlationQuality.name.lowercase()} correlation because ${invite.missingFields.joinToString()} is unavailable.")
        }
        if (captureRange.sipSourceTruncated) {
            add("The SIP source was truncated, so an unobserved final response or ACK cannot be ruled out.")
        }
        if (captureRange.scopeIsFiltered) {
            add("The analysis used a filtered capture scope; absence conclusions apply only to that scope.")
        }
        if (captureRange.expertSourceTruncated) {
            add("The Expert Info source was truncated, so transport anomaly coverage is incomplete.")
        }
        if (finalResponse == null && !captureRange.isCompleteForNegativeEvidence) {
            add("No final response is an observed signaling gap because the current scope is incomplete for negative evidence.")
        }
        if (finalResponse != null && responseCode(finalResponse) in 200..299 && ack == null &&
            !hasCompleteNegativeEvidence(captureRange, finalResponse.time)
        ) {
            add("No ACK is visible, but the capture does not continue far enough with complete coverage to establish a missing ACK.")
        }
        if (transport.isEmpty() && (statisticsShowsTransportIssue(expertInfo) || expertInfo.items.isNotEmpty())) {
            add("No TCP or TLS anomaly was tied to this call because available Expert Info lacks both endpoint and timestamp metadata for this dialog.")
        }
        if (coreEvents.isEmpty()) {
            add("No core-network event was correlated by Call-ID and time window; no bearer or session root cause is inferred.")
        }
        if (dialogMessages.any { it.method.normalizedMethod() == "INVITE" && it.viaBranch != invite.viaBranch } &&
            (invite.request?.toTag.isNullOrBlank() || finalResponse?.toTag.isNullOrBlank())
        ) {
            add("Other INVITE branches share this Call-ID without complete dialog tags; PRACK, UPDATE, and ACK association may be incomplete.")
        }
    }.distinct()

    private fun excludedCauses(attempt: SipCallSetupAttempt): List<String> = buildList {
        if (attempt.finalResponseCode in 200..299) {
            add("A final 2xx response was observed for the selected INVITE transaction.")
        }
        if (attempt.finalResponseCode != null) {
            add("The selected INVITE has a visible final SIP response, so it is not a no-final-response observation.")
        }
        if (attempt.transportEvidence.none { it.kind != SipCallSetupTransportKind.Dns }) {
            add("No TCP or TLS anomaly was correlated to the selected call window and endpoints.")
        }
        if (attempt.coreEventFrames.isEmpty()) {
            add("No correlated core-network session event is available in this capture scope.")
        }
    }

    private fun selectAttempt(
        attempts: List<SipCallSetupAttempt>,
        selection: SipCallSetupSelection
    ): SelectionDecision {
        var candidates = attempts
        val applied = mutableListOf<String>()
        var selectorMissed = false
        selection.callId?.trim()?.takeIf(String::isNotEmpty)?.let { callId ->
            val exact = candidates.filter { it.callId.equals(callId, ignoreCase = true) }
            val matching = exact.ifEmpty { candidates.filter { it.callId.contains(callId, ignoreCase = true) } }
            if (matching.isNotEmpty()) {
                candidates = matching
                applied += if (exact.isNotEmpty()) "matched the Call-ID selector exactly" else "matched the Call-ID selector"
            } else {
                selectorMissed = true
            }
        }
        selection.frameNumber?.let { frame ->
            val matching = candidates.filter { attempt ->
                attempt.stages.any { stage -> frame in listOfNotNull(stage.startFrame, stage.endFrame, *stage.evidenceFrames.toTypedArray()) }
            }
            if (matching.isNotEmpty()) {
                candidates = matching
                applied += "matched frame $frame"
            } else {
                selectorMissed = true
            }
        }
        selection.targetSetupMillis?.takeIf { it >= 0L }?.let { target ->
            val measurable = candidates.filter { it.setupDurationMillis != null }
            if (measurable.isNotEmpty()) {
                val smallestDistance = measurable.minOf { abs(checkNotNull(it.setupDurationMillis) - target) }
                candidates = measurable.filter { abs(checkNotNull(it.setupDurationMillis) - target) == smallestDistance }
                applied += "matched the setup duration nearest ${target} ms"
            } else {
                selectorMissed = true
            }
        }
        if (selectorMissed) {
            return SelectionDecision(
                selected = null,
                reason = "No call setup candidate matches every supplied selector; choose a visible Call-ID or INVITE boundary frame."
            )
        }
        if (candidates.size == 1) {
            return SelectionDecision(candidates.single(), "Selected the only candidate that ${applied.ifEmpty { listOf("is visible in the scope") }.joinToString(" and ")}.")
        }
        if (selection.callId != null || selection.frameNumber != null || selection.targetSetupMillis != null) {
            return SelectionDecision(
                selected = null,
                reason = "The supplied selector does not uniquely identify one call setup candidate; choose a Call-ID or an INVITE boundary frame."
            )
        }
        val failed = candidates.filter { it.outcome != SipCallSetupOutcome.Success }
        val latestFailed = failed.maxWithOrNull(compareBy(SipCallSetupAttempt::startTime, { it.inviteFrame ?: Long.MIN_VALUE }))
        return if (latestFailed != null) {
            SelectionDecision(
                latestFailed,
                "Selected the most recent non-successful call setup attempt because no Call-ID, frame, or target duration was supplied."
            )
        } else {
            SelectionDecision(
                selected = null,
                reason = "Several successful call setup candidates are visible; choose a Call-ID or an INVITE boundary frame before reporting one timeline."
            )
        }
    }

    private fun matchesInviteDialog(message: SipMessage, invite: SipMessage, transaction: SipTransaction): Boolean {
        if (message.callId != invite.callId || message.time < invite.time) return false
        val responseToTag = (transaction.provisionalResponses + transaction.finalResponses)
            .firstNotNullOfOrNull { it.toTag?.takeIf(String::isNotBlank) }
        if (!invite.fromTag.isNullOrBlank() && !message.fromTag.isNullOrBlank() && message.fromTag != invite.fromTag) return false
        if (responseToTag != null && !message.toTag.isNullOrBlank() && message.toTag != responseToTag) return false
        return true
    }

    private fun dnsMatchesInvite(transaction: RequestResponseTransaction, invite: SipMessage): Boolean =
        endpointMatches(transaction.client, invite.source) &&
            (endpointMatches(transaction.server, invite.destination) ||
                transaction.response.orEmpty().contains(invite.destination, ignoreCase = true) ||
                transaction.request.contains(invite.destination, ignoreCase = true))

    private fun endpointPairMatches(
        firstSource: String,
        firstDestination: String,
        secondSource: String,
        secondDestination: String
    ): Boolean =
        endpointMatches(firstSource, secondSource) && endpointMatches(firstDestination, secondDestination) ||
            endpointMatches(firstSource, secondDestination) && endpointMatches(firstDestination, secondSource)

    private fun endpointMatches(observed: String, endpoint: String): Boolean {
        if (observed.equals(endpoint, ignoreCase = true)) return true
        val normalized = observed.removePrefix("[").substringBefore("]")
        return normalized.equals(endpoint, ignoreCase = true) || observed.substringBefore(':').equals(endpoint, ignoreCase = true)
    }

    private fun ProtocolSummaryItem.toEvidence(kind: SipCallSetupTransportKind) = SipCallSetupTransportEvidence(
        kind = kind,
        frameNumber = frameNumber,
        time = time,
        source = source,
        destination = destination,
        sourceName = "protocol_summary"
    )

    private fun hasCompleteNegativeEvidence(range: SipCallSetupCaptureRange, terminalTime: Double): Boolean =
        range.isCompleteForNegativeEvidence && (range.endTime == null || range.endTime > terminalTime)

    private fun statisticsShowsTransportIssue(expertInfo: ExpertInfoSummary): Boolean =
        expertInfo.items.any { item ->
            val text = "${item.label} ${item.filter.orEmpty()}".lowercase()
            "retransmission" in text || "retransmit" in text || "reset" in text || "rst" in text || "tls" in text
        }

    private fun responseCode(message: SipMessage?): Int? = message?.let {
        RESPONSE_CODE.find(it.status.ifBlank { it.info })?.groupValues?.get(1)?.toIntOrNull()
    }

    private fun String?.normalizedMethod(): String = this?.trim()?.substringBefore(' ')?.uppercase().orEmpty()

    private fun millisBetween(start: Double, end: Double): Long =
        ((end - start).coerceAtLeast(0.0) * 1_000.0).roundToLong()

    private data class SelectionDecision(val selected: SipCallSetupAttempt?, val reason: String)

    private data class TransportBoundary(
        val startFrame: Long,
        val startTime: Double,
        val endFrame: Long,
        val endTime: Double
    )
}
