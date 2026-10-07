package com.example.layanalyzer.ai.tools.dto

import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.CoreCorrelationConfidence
import com.example.layanalyzer.model.CoreCorrelationEdge
import com.example.layanalyzer.model.CoreImsCorrelation
import com.example.layanalyzer.model.CoreProcedureStage
import com.example.layanalyzer.model.CoreProcedureTimeline
import com.example.layanalyzer.model.CoreSessionSummary
import com.example.layanalyzer.model.CoreSignalMessage
import com.example.layanalyzer.model.ImsRegistrationAnalysis
import com.example.layanalyzer.model.ImsRegistrationAttempt
import com.example.layanalyzer.model.ImsRegistrationCandidate
import com.example.layanalyzer.model.ImsRegistrationTimelineEvent
import com.example.layanalyzer.model.ImsRegistrationTransportEvidence
import com.example.layanalyzer.model.MediaCodecMapping
import com.example.layanalyzer.model.MediaEndpoint
import com.example.layanalyzer.model.MediaFinding
import com.example.layanalyzer.model.MediaLineAnalysis
import com.example.layanalyzer.model.MediaRtcpAnalysis
import com.example.layanalyzer.model.MediaRtpDirectionAnalysis
import com.example.layanalyzer.model.MediaSessionAnalysis
import com.example.layanalyzer.model.RtcpStreamSummary
import com.example.layanalyzer.model.RtpStreamSummary
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SdpPayloadMapping
import com.example.layanalyzer.model.SipCallSetupAnalysis
import com.example.layanalyzer.model.SipCallSetupAttempt
import com.example.layanalyzer.model.SipCallSetupCandidate
import com.example.layanalyzer.model.SipCallSetupDelayContribution
import com.example.layanalyzer.model.SipCallSetupStageTiming
import com.example.layanalyzer.model.SipCallSetupTransportEvidence
import com.example.layanalyzer.model.SipCallSummary
import com.example.layanalyzer.model.SipMessage

/**
 * Projections for the AI-10 get_communication_analysis tool.
 *
 * The internal models carry the full message list for every call and every
 * packet for every RTP stream.  None of these DTOs has a field for a SIP body,
 * an SDP blob or an RTP payload, so the tool returns signalling *metadata* — who
 * called whom, when, and what the outcome was — and structurally cannot return
 * the content of a call.
 */

/** Communication domains a model may request. */
enum class AgentCommunicationDomain(val wireName: String) {
    Sip("sip"),
    Rtp("rtp"),
    Rtcp("rtcp"),
    Core("core");

    companion object {
        val wireNames: List<String> = values().map { it.wireName }

        fun fromWire(name: String?): AgentCommunicationDomain? =
            values().firstOrNull { it.wireName == name }
    }
}

/**
 * One SIP message, reduced to its routing and outcome fields.
 *
 * There is deliberately no `body` and no raw header list: [info] is the
 * packet-list summary the engine already produced, and the privacy layer in
 * `AgentToolRunner.finish` redacts it along with every other
 * capture-controlled string.
 */
data class AgentSipMessageEntry(
    val frameNumber: Long,
    val time: Double,
    val source: String,
    val destination: String,
    val sourcePort: Int?,
    val destinationPort: Int?,
    val method: String,
    val status: String,
    val cSeqNumber: Long?,
    val cSeqMethod: String?,
    val viaBranch: String?,
    val fromTag: String?,
    val toTag: String?,
    val requestUri: String?,
    val authorizationPresent: Boolean,
    val authorizationScheme: String?,
    val contentType: String?,
    val info: String
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "frameNumber" to frameNumber,
        "time" to time,
        "source" to source,
        "destination" to destination,
        "sourcePort" to sourcePort,
        "destinationPort" to destinationPort,
        "method" to method,
        "status" to status,
        "cSeqNumber" to cSeqNumber,
        "cSeqMethod" to cSeqMethod,
        "viaBranch" to viaBranch,
        "fromTag" to fromTag,
        "toTag" to toTag,
        "requestUri" to requestUri,
        "authorizationPresent" to authorizationPresent,
        "authorizationScheme" to authorizationScheme,
        "contentType" to contentType,
        "info" to info
    )
}

data class AgentSdpPayloadMappingEntry(
    val payloadType: Int?,
    val encodingName: String,
    val clockRate: Int?,
    val channels: Int?,
    val fmtpParameters: List<String>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "payloadType" to payloadType,
        "encodingName" to encodingName,
        "clockRate" to clockRate,
        "channels" to channels,
        "fmtpParameters" to fmtpParameters
    )
}

/** Media negotiated in an SDP offer/answer, without the SDP text itself. */
data class AgentSdpMediaEntry(
    val frameNumber: Long,
    val connectionAddress: String,
    val mediaType: String,
    val mediaPort: Int?,
    val mediaProtocol: String,
    val codecs: List<String>,
    val direction: String,
    val offerAnswerRole: String,
    val payloadMappings: List<AgentSdpPayloadMappingEntry>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "frameNumber" to frameNumber,
        "connectionAddress" to connectionAddress,
        "mediaType" to mediaType,
        "mediaPort" to mediaPort,
        "mediaProtocol" to mediaProtocol,
        "codecs" to codecs,
        "direction" to direction,
        "offerAnswerRole" to offerAnswerRole,
        "payloadMappings" to payloadMappings.map(AgentSdpPayloadMappingEntry::toAgentJson)
    )
}

/**
 * One SIP call.
 *
 * [messageCount] is always present while [messages] is populated only when the
 * caller asked for it, so a model can see how large a call is before deciding to
 * spend a step reading its messages.
 */
data class AgentSipCallEntry(
    val callId: String,
    val startTime: Double,
    val endTime: Double,
    val duration: Double,
    val failureCode: Int?,
    val firstFrame: Long?,
    val messageCount: Int,
    val sdpMedia: List<AgentSdpMediaEntry>,
    val messages: List<AgentSipMessageEntry>? = null
) {
    fun toAgentJson(): AgentJsonObject = buildMap {
        put("callId", callId)
        put("startTime", startTime)
        put("endTime", endTime)
        put("duration", duration)
        put("failureCode", failureCode)
        put("firstFrame", firstFrame)
        put("messageCount", messageCount)
        put("sdpMedia", sdpMedia.map(AgentSdpMediaEntry::toAgentJson))
        if (messages != null) {
            put("messages", messages.map(AgentSipMessageEntry::toAgentJson))
        }
    }
}

/** One RTP stream's quality metrics; individual packets are never projected. */
data class AgentRtpStreamEntry(
    val source: String,
    val destination: String,
    val sourcePort: Int?,
    val destinationPort: Int?,
    val ssrc: Long?,
    val payloadType: Int?,
    val packetCount: Int,
    val lostPackets: Int,
    val reorderedPackets: Int,
    val duplicatePackets: Int,
    val jitterMillis: Double?,
    val firstFrame: Long?
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "source" to source,
        "destination" to destination,
        "sourcePort" to sourcePort,
        "destinationPort" to destinationPort,
        "ssrc" to ssrc,
        "payloadType" to payloadType,
        "packetCount" to packetCount,
        "lostPackets" to lostPackets,
        "reorderedPackets" to reorderedPackets,
        "duplicatePackets" to duplicatePackets,
        "jitterMillis" to jitterMillis,
        "firstFrame" to firstFrame
    )
}

/**
 * One RTCP stream, summarised by its worst reported loss.
 *
 * The maximum fraction lost is carried rather than every report, because it is
 * the value that decides whether a stream had a quality problem; the individual
 * reports would be a long list the model has to summarise itself.
 */
data class AgentRtcpStreamEntry(
    val source: String,
    val destination: String,
    val sourcePort: Int?,
    val destinationPort: Int?,
    val senderSsrc: Long?,
    val reportedSsrc: Long?,
    val reportCount: Int,
    val maxFractionLostPercent: Double?,
    val maxCumulativeLost: Int?,
    val firstFrame: Long?
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "source" to source,
        "destination" to destination,
        "sourcePort" to sourcePort,
        "destinationPort" to destinationPort,
        "senderSsrc" to senderSsrc,
        "reportedSsrc" to reportedSsrc,
        "reportCount" to reportCount,
        "maxFractionLostPercent" to maxFractionLostPercent,
        "maxCumulativeLost" to maxCumulativeLost,
        "firstFrame" to firstFrame
    )
}

data class AgentMediaCodecEntry(
    val payloadType: Int?,
    val codec: String,
    val clockRate: Int?,
    val channels: Int?
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "payloadType" to payloadType,
        "codec" to codec,
        "clockRate" to clockRate,
        "channels" to channels
    )
}

data class AgentMediaEndpointEntry(
    val connectionAddress: String,
    val port: Int?,
    val direction: String
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "connectionAddress" to connectionAddress,
        "port" to port,
        "direction" to direction
    )
}

data class AgentMediaRtpDirectionEntry(
    val direction: String,
    val expected: Boolean,
    val observed: Boolean,
    val correlationConfidence: String,
    val packetCount: Int,
    val firstFrame: Long?,
    val lastFrame: Long?,
    val durationMillis: Long?,
    val ssrcs: List<Long>,
    val payloadTypes: List<Int>,
    val codecs: List<AgentMediaCodecEntry>,
    val clockRate: Int?,
    val lostPackets: Int,
    val reorderedPackets: Int,
    val duplicatePackets: Int,
    val jitterMillis: Double?,
    val anomalyFrames: List<Long>,
    val displayFilters: List<String>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "direction" to direction,
        "expected" to expected,
        "observed" to observed,
        "correlationConfidence" to correlationConfidence,
        "packetCount" to packetCount,
        "firstFrame" to firstFrame,
        "lastFrame" to lastFrame,
        "durationMillis" to durationMillis,
        "ssrcs" to ssrcs,
        "payloadTypes" to payloadTypes,
        "codecs" to codecs.map(AgentMediaCodecEntry::toAgentJson),
        "clockRate" to clockRate,
        "lostPackets" to lostPackets,
        "reorderedPackets" to reorderedPackets,
        "duplicatePackets" to duplicatePackets,
        "jitterMillis" to jitterMillis,
        "anomalyFrames" to anomalyFrames,
        "displayFilters" to displayFilters
    )
}

data class AgentMediaRtcpEntry(
    val reportedSsrc: Long?,
    val reportCount: Int,
    val firstFrame: Long?,
    val lastFrame: Long?,
    val fractionLostPercentMin: Double?,
    val fractionLostPercentMax: Double?,
    val worstFractionLostPercent: Double?,
    val cumulativeLostMin: Int?,
    val cumulativeLostMax: Int?,
    val worstCumulativeLost: Int?,
    val interarrivalJitterMin: Long?,
    val interarrivalJitterMax: Long?,
    val worstInterarrivalJitter: Long?,
    val reportFrames: List<Long>,
    val displayFilters: List<String>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "reportedSsrc" to reportedSsrc,
        "reportCount" to reportCount,
        "firstFrame" to firstFrame,
        "lastFrame" to lastFrame,
        "fractionLostPercentMin" to fractionLostPercentMin,
        "fractionLostPercentMax" to fractionLostPercentMax,
        "worstFractionLostPercent" to worstFractionLostPercent,
        "cumulativeLostMin" to cumulativeLostMin,
        "cumulativeLostMax" to cumulativeLostMax,
        "worstCumulativeLost" to worstCumulativeLost,
        "interarrivalJitterMin" to interarrivalJitterMin,
        "interarrivalJitterMax" to interarrivalJitterMax,
        "worstInterarrivalJitter" to worstInterarrivalJitter,
        "reportFrames" to reportFrames,
        "displayFilters" to displayFilters
    )
}

data class AgentMediaFindingEntry(
    val kind: String,
    val severity: String,
    val summary: String,
    val direction: String?,
    val evidenceFrames: List<Long>,
    val displayFilters: List<String>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "kind" to kind,
        "severity" to severity,
        "summary" to summary,
        "direction" to direction,
        "evidenceFrames" to evidenceFrames,
        "displayFilters" to displayFilters
    )
}

data class AgentMediaLineEntry(
    val mLineIndex: Int,
    val mediaType: String,
    val mediaProtocol: String,
    val offerFrame: Long,
    val answerFrame: Long?,
    val offerEndpoint: AgentMediaEndpointEntry,
    val answerEndpoint: AgentMediaEndpointEntry?,
    val rejected: Boolean,
    val negotiatedCodecs: List<AgentMediaCodecEntry>,
    val directions: List<AgentMediaRtpDirectionEntry>,
    val rtcpReports: List<AgentMediaRtcpEntry>,
    val findings: List<AgentMediaFindingEntry>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "mLineIndex" to mLineIndex,
        "mediaType" to mediaType,
        "mediaProtocol" to mediaProtocol,
        "offerFrame" to offerFrame,
        "answerFrame" to answerFrame,
        "offerEndpoint" to offerEndpoint.toAgentJson(),
        "answerEndpoint" to answerEndpoint?.toAgentJson(),
        "rejected" to rejected,
        "negotiatedCodecs" to negotiatedCodecs.map(AgentMediaCodecEntry::toAgentJson),
        "directions" to directions.map(AgentMediaRtpDirectionEntry::toAgentJson),
        "rtcpReports" to rtcpReports.map(AgentMediaRtcpEntry::toAgentJson),
        "findings" to findings.map(AgentMediaFindingEntry::toAgentJson)
    )
}

/** Correlated SDP/RTP/RTCP diagnosis for one SIP dialog, without packet bodies. */
data class AgentMediaSessionEntry(
    val callId: String,
    val startTime: Double?,
    val endTime: Double?,
    val mLines: List<AgentMediaLineEntry>,
    val findings: List<AgentMediaFindingEntry>,
    val limitations: List<String>,
    val captureSupportsNegativeEvidence: Boolean
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "callId" to callId,
        "startTime" to startTime,
        "endTime" to endTime,
        "mLines" to mLines.map(AgentMediaLineEntry::toAgentJson),
        "findings" to findings.map(AgentMediaFindingEntry::toAgentJson),
        "limitations" to limitations,
        "captureSupportsNegativeEvidence" to captureSupportsNegativeEvidence
    )
}

/** One core-network signalling message, reduced to its correlation fields. */
data class AgentCoreMessageEntry(
    val frameNumber: Long,
    val time: Double,
    val protocol: String,
    val source: String,
    val destination: String,
    val messageType: String,
    val outcome: String,
    val info: String,
    val procedureType: String,
    val commandCode: Int?,
    val applicationId: Long?,
    val request: Boolean?,
    val resultCode: String,
    val experimentalResult: String,
    val sequenceNumber: Long?,
    val cause: String,
    val procedureCode: String,
    val registrationState: String,
    val sessionState: String,
    val fields: Map<String, String>,
    val fieldPresence: List<String>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "frameNumber" to frameNumber,
        "time" to time,
        "protocol" to protocol,
        "source" to source,
        "destination" to destination,
        "messageType" to messageType,
        "outcome" to outcome,
        "info" to info,
        "procedureType" to procedureType,
        "commandCode" to commandCode,
        "applicationId" to applicationId,
        "request" to request,
        "resultCode" to resultCode,
        "experimentalResult" to experimentalResult,
        "sequenceNumber" to sequenceNumber,
        "cause" to cause,
        "procedureCode" to procedureCode,
        "registrationState" to registrationState,
        "sessionState" to sessionState,
        "fields" to fields,
        "fieldPresence" to fieldPresence
    )
}

data class AgentCoreStageEntry(
    val stage: String,
    val startTime: Double,
    val endTime: Double,
    val frameNumbers: List<Long>,
    val messageTypes: List<String>,
    val outcomes: List<String>,
    val causes: List<String>,
    val correlationQuality: String,
    val confidence: Double,
    val retryCount: Int
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "stage" to stage,
        "startTime" to startTime,
        "endTime" to endTime,
        "frameNumbers" to frameNumbers,
        "messageTypes" to messageTypes,
        "outcomes" to outcomes,
        "causes" to causes,
        "correlationQuality" to correlationQuality,
        "confidence" to confidence,
        "retryCount" to retryCount
    )
}

data class AgentCoreCorrelationEdgeEntry(
    val fromFrame: Long,
    val toFrame: Long,
    val type: String,
    val confidence: String,
    val confidenceScore: Double,
    val basisFields: List<String>,
    val timeDeltaMillis: Long?,
    val fromNodeId: String,
    val toNodeId: String
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "fromFrame" to fromFrame,
        "toFrame" to toFrame,
        "type" to type,
        "confidence" to confidence,
        "confidenceScore" to confidenceScore,
        "basisFields" to basisFields,
        "timeDeltaMillis" to timeDeltaMillis,
        "fromNodeId" to fromNodeId,
        "toNodeId" to toNodeId
    )
}

data class AgentCoreImsCorrelationEntry(
    val callId: String,
    val startTime: Double,
    val endTime: Double,
    val relation: String,
    val confidence: String,
    val confidenceScore: Double
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "callId" to callId,
        "startTime" to startTime,
        "endTime" to endTime,
        "relation" to relation,
        "confidence" to confidence,
        "confidenceScore" to confidenceScore
    )
}

/** One correlated core-network procedure timeline. */
data class AgentCoreSessionEntry(
    val protocol: String,
    val correlationField: String,
    val correlationValue: String,
    val messageCount: Int,
    val startTime: Double,
    val endTime: Double,
    val firstFrame: Long?,
    val lastFrame: Long?,
    val procedureType: String,
    val localCorrelationId: String,
    val correlationQuality: String,
    val confidence: Double,
    val protocols: List<String>,
    val failureCauses: List<String>,
    val retryCount: Int,
    val stages: List<AgentCoreStageEntry>,
    val edges: List<AgentCoreCorrelationEdgeEntry>,
    val limitations: List<String>,
    val partial: Boolean,
    val imsCorrelations: List<AgentCoreImsCorrelationEntry>,
    val messages: List<AgentCoreMessageEntry>? = null
) {
    fun toAgentJson(): AgentJsonObject = buildMap {
        put("protocol", protocol)
        put("correlationField", correlationField)
        put("correlationValue", correlationValue)
        put("messageCount", messageCount)
        put("startTime", startTime)
        put("endTime", endTime)
        put("firstFrame", firstFrame)
        put("lastFrame", lastFrame)
        put("procedureType", procedureType)
        put("localCorrelationId", localCorrelationId)
        put("correlationQuality", correlationQuality)
        put("confidence", confidence)
        put("protocols", protocols)
        put("failureCauses", failureCauses)
        put("retryCount", retryCount)
        put("stages", stages.map(AgentCoreStageEntry::toAgentJson))
        put("edges", edges.map(AgentCoreCorrelationEdgeEntry::toAgentJson))
        put("limitations", limitations)
        put("partial", partial)
        put("imsCorrelations", imsCorrelations.map(AgentCoreImsCorrelationEntry::toAgentJson))
        if (messages != null) {
            put("messages", messages.map(AgentCoreMessageEntry::toAgentJson))
        }
    }
}

/**
 * Native truncation state for one domain.
 *
 * These counts come straight from [com.example.layanalyzer.model.CommunicationAnalysis]
 * and are reported per domain rather than folded into a single flag, because the
 * native analyzer caps SIP, RTP, RTCP and core messages independently.  A model
 * that sees `rtpTruncated` must not conclude the SIP view was also cut short —
 * or the reverse, which would be worse: treating a capped RTP list as complete.
 */
data class AgentDomainTotals(
    val total: Int,
    val truncated: Boolean
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "total" to total,
        "truncated" to truncated
    )
}

/** Local IMS registration state projected without SIP bodies or credentials. */
data class AgentImsRegistrationAnalysisEntry(
    val outcome: String,
    val selectionReason: String,
    val selectedAttempt: AgentImsRegistrationAttemptEntry?,
    val alternateCandidates: List<AgentImsRegistrationCandidateEntry>,
    val limitations: List<String>,
    val excludedCauses: List<String>,
    val captureRange: Map<String, Any?>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "outcome" to outcome,
        "selectionReason" to selectionReason,
        "selectedAttempt" to selectedAttempt?.toAgentJson(),
        "alternateCandidates" to alternateCandidates.map(AgentImsRegistrationCandidateEntry::toAgentJson),
        "limitations" to limitations,
        "excludedCauses" to excludedCauses,
        "captureRange" to captureRange
    )
}

data class AgentImsRegistrationAttemptEntry(
    val id: String,
    val callId: String,
    val outcome: String,
    val startTime: Double,
    val endTime: Double,
    val firstFrame: Long?,
    val lastFrame: Long?,
    val retransmissionCount: Int,
    val timeline: List<AgentImsRegistrationTimelineEventEntry>,
    val transportEvidence: List<AgentImsRegistrationTransportEvidenceEntry>,
    val completeNegativeEvidence: Boolean
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "id" to id,
        "callId" to callId,
        "outcome" to outcome,
        "startTime" to startTime,
        "endTime" to endTime,
        "firstFrame" to firstFrame,
        "lastFrame" to lastFrame,
        "retransmissionCount" to retransmissionCount,
        "timeline" to timeline.map(AgentImsRegistrationTimelineEventEntry::toAgentJson),
        "transportEvidence" to transportEvidence.map(AgentImsRegistrationTransportEvidenceEntry::toAgentJson),
        "completeNegativeEvidence" to completeNegativeEvidence
    )
}

data class AgentImsRegistrationTimelineEventEntry(
    val stage: String,
    val frameNumber: Long,
    val time: Double,
    val statusCode: Int?,
    val authorizationPresent: Boolean,
    val elapsedFromInitialMillis: Long?
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "stage" to stage,
        "frameNumber" to frameNumber,
        "time" to time,
        "statusCode" to statusCode,
        "authorizationPresent" to authorizationPresent,
        "elapsedFromInitialMillis" to elapsedFromInitialMillis
    )
}

data class AgentImsRegistrationTransportEvidenceEntry(
    val anomaly: String,
    val frameNumber: Long?,
    val observedCount: Int,
    val source: String
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "anomaly" to anomaly,
        "frameNumber" to frameNumber,
        "observedCount" to observedCount,
        "source" to source
    )
}

data class AgentImsRegistrationCandidateEntry(
    val id: String,
    val callId: String,
    val outcome: String,
    val firstFrame: Long?,
    val startTime: Double,
    val selectionReason: String
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "id" to id,
        "callId" to callId,
        "outcome" to outcome,
        "firstFrame" to firstFrame,
        "startTime" to startTime,
        "selectionReason" to selectionReason
    )
}

/** Local call setup diagnosis with stage boundary frames and derived timing. */
data class AgentSipCallSetupAnalysisEntry(
    val outcome: String?,
    val selectionReason: String,
    val requiresUserSelection: Boolean,
    val selectedAttempt: AgentSipCallSetupAttemptEntry?,
    val alternateCandidates: List<AgentSipCallSetupCandidateEntry>,
    val limitations: List<String>,
    val excludedCauses: List<String>,
    val captureRange: Map<String, Any?>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "outcome" to outcome,
        "selectionReason" to selectionReason,
        "requiresUserSelection" to requiresUserSelection,
        "selectedAttempt" to selectedAttempt?.toAgentJson(),
        "alternateCandidates" to alternateCandidates.map(AgentSipCallSetupCandidateEntry::toAgentJson),
        "limitations" to limitations,
        "excludedCauses" to excludedCauses,
        "captureRange" to captureRange
    )
}

data class AgentSipCallSetupAttemptEntry(
    val id: String,
    val callId: String,
    val inviteFrame: Long?,
    val finalResponseFrame: Long?,
    val ackFrame: Long?,
    val startTime: Double,
    val endTime: Double,
    val finalResponseCode: Int?,
    val outcome: String,
    val setupDurationMillis: Long?,
    val inviteToFinalResponseMillis: Long?,
    val retransmissionCount: Int,
    val stages: List<AgentSipCallSetupStageEntry>,
    val delayContributions: List<AgentSipCallSetupContributionEntry>,
    val largestContribution: AgentSipCallSetupContributionEntry?,
    val transportEvidence: List<AgentSipCallSetupTransportEvidenceEntry>,
    val mediaNegotiationFrames: List<Long>,
    val coreEventFrames: List<Long>,
    val limitations: List<String>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "id" to id,
        "callId" to callId,
        "inviteFrame" to inviteFrame,
        "finalResponseFrame" to finalResponseFrame,
        "ackFrame" to ackFrame,
        "startTime" to startTime,
        "endTime" to endTime,
        "finalResponseCode" to finalResponseCode,
        "outcome" to outcome,
        "setupDurationMillis" to setupDurationMillis,
        "inviteToFinalResponseMillis" to inviteToFinalResponseMillis,
        "retransmissionCount" to retransmissionCount,
        "stages" to stages.map(AgentSipCallSetupStageEntry::toAgentJson),
        "delayContributions" to delayContributions.map(AgentSipCallSetupContributionEntry::toAgentJson),
        "largestContribution" to largestContribution?.toAgentJson(),
        "transportEvidence" to transportEvidence.map(AgentSipCallSetupTransportEvidenceEntry::toAgentJson),
        "mediaNegotiationFrames" to mediaNegotiationFrames,
        "coreEventFrames" to coreEventFrames,
        "limitations" to limitations
    )
}

data class AgentSipCallSetupStageEntry(
    val stage: String,
    val startFrame: Long?,
    val endFrame: Long?,
    val startTime: Double?,
    val endTime: Double?,
    val durationMillis: Long?,
    val completeness: String,
    val attentionThresholdExceeded: Boolean,
    val evidenceFrames: List<Long>
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "stage" to stage,
        "startFrame" to startFrame,
        "endFrame" to endFrame,
        "startTime" to startTime,
        "endTime" to endTime,
        "durationMillis" to durationMillis,
        "completeness" to completeness,
        "attentionThresholdExceeded" to attentionThresholdExceeded,
        "evidenceFrames" to evidenceFrames
    )
}

data class AgentSipCallSetupContributionEntry(
    val stage: String,
    val startFrame: Long,
    val endFrame: Long,
    val startTime: Double,
    val endTime: Double,
    val durationMillis: Long,
    val percentageOfTotal: Double
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "stage" to stage,
        "startFrame" to startFrame,
        "endFrame" to endFrame,
        "startTime" to startTime,
        "endTime" to endTime,
        "durationMillis" to durationMillis,
        "percentageOfTotal" to percentageOfTotal
    )
}

data class AgentSipCallSetupTransportEvidenceEntry(
    val kind: String,
    val frameNumber: Long,
    val time: Double?,
    val source: String,
    val destination: String,
    val sourceName: String
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "kind" to kind,
        "frameNumber" to frameNumber,
        "time" to time,
        "source" to source,
        "destination" to destination,
        "sourceName" to sourceName
    )
}

data class AgentSipCallSetupCandidateEntry(
    val id: String,
    val callId: String,
    val inviteFrame: Long?,
    val startTime: Double,
    val outcome: String,
    val finalResponseCode: Int?,
    val setupDurationMillis: Long?,
    val selectionReason: String
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "id" to id,
        "callId" to callId,
        "inviteFrame" to inviteFrame,
        "startTime" to startTime,
        "outcome" to outcome,
        "finalResponseCode" to finalResponseCode,
        "setupDurationMillis" to setupDurationMillis,
        "selectionReason" to selectionReason
    )
}

/**
 * Builders that turn the communication models into the DTOs above.
 *
 * These projections return capture values as the engine reported them.
 * Redaction is enforced once, centrally, in `AgentToolRunner.finish`; doing it
 * here as well would alias an alias and split one endpoint into two identities.
 */
object AgentCommunicationProjections {
    fun mediaSession(analysis: MediaSessionAnalysis): AgentMediaSessionEntry = AgentMediaSessionEntry(
        callId = analysis.callId,
        startTime = analysis.startTime,
        endTime = analysis.endTime,
        mLines = analysis.lines.map(::mediaLine),
        findings = analysis.findings.map(::mediaFinding),
        limitations = analysis.limitations,
        captureSupportsNegativeEvidence = analysis.captureSupportsNegativeEvidence
    )

    private fun mediaLine(line: MediaLineAnalysis) = AgentMediaLineEntry(
        mLineIndex = line.mLineIndex,
        mediaType = line.mediaType,
        mediaProtocol = line.mediaProtocol,
        offerFrame = line.offerFrame,
        answerFrame = line.answerFrame,
        offerEndpoint = mediaEndpoint(line.offerEndpoint),
        answerEndpoint = line.answerEndpoint?.let(::mediaEndpoint),
        rejected = line.rejected,
        negotiatedCodecs = line.negotiatedCodecs.map(::mediaCodec),
        directions = line.directions.map(::mediaDirection),
        rtcpReports = line.rtcp.map(::mediaRtcp),
        findings = line.findings.map(::mediaFinding)
    )

    private fun mediaCodec(mapping: MediaCodecMapping) = AgentMediaCodecEntry(
        payloadType = mapping.payloadType,
        codec = mapping.codec,
        clockRate = mapping.clockRate,
        channels = mapping.channels
    )

    private fun mediaEndpoint(endpoint: MediaEndpoint) = AgentMediaEndpointEntry(
        connectionAddress = endpoint.connectionAddress,
        port = endpoint.port,
        direction = endpoint.direction.wireValue
    )

    private fun mediaDirection(direction: MediaRtpDirectionAnalysis) = AgentMediaRtpDirectionEntry(
        direction = direction.direction.wireValue,
        expected = direction.expected,
        observed = direction.observed,
        correlationConfidence = direction.confidence.name,
        packetCount = direction.packetCount,
        firstFrame = direction.firstFrame,
        lastFrame = direction.lastFrame,
        durationMillis = direction.durationMillis,
        ssrcs = direction.ssrcs,
        payloadTypes = direction.payloadTypes,
        codecs = direction.codecs.map(::mediaCodec),
        clockRate = direction.clockRate,
        lostPackets = direction.lostPackets,
        reorderedPackets = direction.reorderedPackets,
        duplicatePackets = direction.duplicatePackets,
        jitterMillis = direction.jitterMillis,
        anomalyFrames = direction.anomalyFrames,
        displayFilters = direction.displayFilters
    )

    private fun mediaRtcp(rtcp: MediaRtcpAnalysis) = AgentMediaRtcpEntry(
        reportedSsrc = rtcp.reportedSsrc,
        reportCount = rtcp.reportCount,
        firstFrame = rtcp.firstFrame,
        lastFrame = rtcp.lastFrame,
        fractionLostPercentMin = rtcp.fractionLostPercentRange?.start,
        fractionLostPercentMax = rtcp.fractionLostPercentRange?.endInclusive,
        worstFractionLostPercent = rtcp.worstFractionLostPercent,
        cumulativeLostMin = rtcp.cumulativeLostRange?.first,
        cumulativeLostMax = rtcp.cumulativeLostRange?.last,
        worstCumulativeLost = rtcp.worstCumulativeLost,
        interarrivalJitterMin = rtcp.interarrivalJitterRange?.first,
        interarrivalJitterMax = rtcp.interarrivalJitterRange?.last,
        worstInterarrivalJitter = rtcp.worstInterarrivalJitter,
        reportFrames = rtcp.reportFrames,
        displayFilters = rtcp.displayFilters
    )

    private fun mediaFinding(finding: MediaFinding) = AgentMediaFindingEntry(
        kind = finding.kind.name,
        severity = finding.severity.name,
        summary = finding.summary,
        direction = finding.direction?.wireValue,
        evidenceFrames = finding.evidenceFrames,
        displayFilters = finding.displayFilters
    )

    fun callSetupAnalysis(
        analysis: SipCallSetupAnalysis
    ) = AgentSipCallSetupAnalysisEntry(
        outcome = analysis.selectedAttempt?.outcome?.name,
        selectionReason = analysis.selectionReason,
        requiresUserSelection = analysis.requiresUserSelection,
        selectedAttempt = analysis.selectedAttempt?.let(::callSetupAttempt),
        alternateCandidates = analysis.alternateCandidates.map(::callSetupCandidate),
        limitations = analysis.limitations,
        excludedCauses = analysis.excludedCauses,
        captureRange = mapOf(
            "firstFrame" to analysis.captureRange.firstFrame,
            "lastFrame" to analysis.captureRange.lastFrame,
            "startTime" to analysis.captureRange.startTime,
            "endTime" to analysis.captureRange.endTime,
            "displayFilter" to analysis.captureRange.displayFilter,
            "completeNegativeEvidence" to analysis.captureRange.isCompleteForNegativeEvidence
        )
    )

    private fun callSetupAttempt(
        attempt: SipCallSetupAttempt
    ) = AgentSipCallSetupAttemptEntry(
        id = attempt.id,
        callId = attempt.callId,
        inviteFrame = attempt.inviteFrame,
        finalResponseFrame = attempt.finalResponseFrame,
        ackFrame = attempt.ackFrame,
        startTime = attempt.startTime,
        endTime = attempt.endTime,
        finalResponseCode = attempt.finalResponseCode,
        outcome = attempt.outcome.name,
        setupDurationMillis = attempt.setupDurationMillis,
        inviteToFinalResponseMillis = attempt.inviteToFinalResponseMillis,
        retransmissionCount = attempt.retransmissionCount,
        stages = attempt.stages.map(::callSetupStage),
        delayContributions = attempt.delayContributions.map(::callSetupContribution),
        largestContribution = attempt.largestContribution?.let(::callSetupContribution),
        transportEvidence = attempt.transportEvidence.map(::callSetupTransportEvidence),
        mediaNegotiationFrames = attempt.mediaNegotiationFrames,
        coreEventFrames = attempt.coreEventFrames,
        limitations = attempt.limitations
    )

    private fun callSetupStage(
        timing: SipCallSetupStageTiming
    ) = AgentSipCallSetupStageEntry(
        stage = timing.stage.name,
        startFrame = timing.startFrame,
        endFrame = timing.endFrame,
        startTime = timing.startTime,
        endTime = timing.endTime,
        durationMillis = timing.durationMillis,
        completeness = timing.completeness.name,
        attentionThresholdExceeded = timing.attentionThresholdExceeded,
        evidenceFrames = timing.evidenceFrames
    )

    private fun callSetupContribution(
        contribution: SipCallSetupDelayContribution
    ) = AgentSipCallSetupContributionEntry(
        stage = contribution.stage.name,
        startFrame = contribution.startFrame,
        endFrame = contribution.endFrame,
        startTime = contribution.startTime,
        endTime = contribution.endTime,
        durationMillis = contribution.durationMillis,
        percentageOfTotal = contribution.percentageOfTotal
    )

    private fun callSetupTransportEvidence(
        evidence: SipCallSetupTransportEvidence
    ) = AgentSipCallSetupTransportEvidenceEntry(
        kind = evidence.kind.name,
        frameNumber = evidence.frameNumber,
        time = evidence.time,
        source = evidence.source,
        destination = evidence.destination,
        sourceName = evidence.sourceName
    )

    private fun callSetupCandidate(
        candidate: SipCallSetupCandidate
    ) = AgentSipCallSetupCandidateEntry(
        id = candidate.id,
        callId = candidate.callId,
        inviteFrame = candidate.inviteFrame,
        startTime = candidate.startTime,
        outcome = candidate.outcome.name,
        finalResponseCode = candidate.finalResponseCode,
        setupDurationMillis = candidate.setupDurationMillis,
        selectionReason = candidate.selectionReason
    )

    fun registrationAnalysis(
        analysis: ImsRegistrationAnalysis
    ) = AgentImsRegistrationAnalysisEntry(
        outcome = analysis.outcome.name,
        selectionReason = analysis.selectionReason,
        selectedAttempt = analysis.selectedAttempt?.let(::registrationAttempt),
        alternateCandidates = analysis.alternateCandidates.map(::registrationCandidate),
        limitations = analysis.limitations,
        excludedCauses = analysis.excludedCauses,
        captureRange = mapOf(
            "firstFrame" to analysis.captureRange.firstFrame,
            "lastFrame" to analysis.captureRange.lastFrame,
            "startTime" to analysis.captureRange.startTime,
            "endTime" to analysis.captureRange.endTime,
            "displayFilter" to analysis.captureRange.displayFilter,
            "registerFilter" to "sip.CSeq.method == \"REGISTER\"",
            "completeNegativeEvidence" to analysis.captureRange.isCompleteForNegativeEvidence
        )
    )

    private fun registrationAttempt(
        attempt: ImsRegistrationAttempt
    ) = AgentImsRegistrationAttemptEntry(
        id = attempt.id,
        callId = attempt.callId,
        outcome = attempt.outcome.name,
        startTime = attempt.startTime,
        endTime = attempt.endTime,
        firstFrame = attempt.firstFrame,
        lastFrame = attempt.lastFrame,
        retransmissionCount = attempt.retransmissionCount,
        timeline = attempt.timeline.map(::registrationTimelineEvent),
        transportEvidence = attempt.transportEvidence.map(::registrationTransportEvidence),
        completeNegativeEvidence = attempt.hasCompleteNegativeEvidence
    )

    private fun registrationTimelineEvent(
        event: ImsRegistrationTimelineEvent
    ) = AgentImsRegistrationTimelineEventEntry(
        stage = event.stage.name,
        frameNumber = event.frameNumber,
        time = event.time,
        statusCode = event.statusCode,
        authorizationPresent = event.authorizationPresent,
        elapsedFromInitialMillis = event.elapsedFromInitialMillis
    )

    private fun registrationTransportEvidence(
        evidence: ImsRegistrationTransportEvidence
    ) = AgentImsRegistrationTransportEvidenceEntry(
        anomaly = evidence.anomaly.name,
        frameNumber = evidence.frameNumber,
        observedCount = evidence.observedCount,
        source = evidence.source
    )

    private fun registrationCandidate(
        candidate: ImsRegistrationCandidate
    ) = AgentImsRegistrationCandidateEntry(
        id = candidate.id,
        callId = candidate.callId,
        outcome = candidate.outcome.name,
        firstFrame = candidate.firstFrame,
        startTime = candidate.startTime,
        selectionReason = candidate.selectionReason
    )

    fun sipMessage(
        message: SipMessage
    ) = AgentSipMessageEntry(
        frameNumber = message.frameNumber,
        time = message.time,
        source = message.source,
        destination = message.destination,
        sourcePort = message.sourcePort,
        destinationPort = message.destinationPort,
        method = message.method,
        status = message.status,
        cSeqNumber = message.cSeqNumber,
        cSeqMethod = message.cSeqMethod,
        viaBranch = message.viaBranch,
        fromTag = message.fromTag,
        toTag = message.toTag,
        requestUri = message.requestUri,
        authorizationPresent = message.authorizationPresent,
        authorizationScheme = message.authorizationScheme,
        contentType = message.contentType,
        info = message.info
    )

    fun sdpMedia(
        media: SdpMediaSummary
    ) = AgentSdpMediaEntry(
        frameNumber = media.frameNumber,
        connectionAddress = media.connectionAddress,
        mediaType = media.mediaType,
        mediaPort = media.mediaPort,
        mediaProtocol = media.mediaProtocol,
        codecs = media.codecs,
        direction = media.direction.wireValue,
        offerAnswerRole = media.offerAnswerRole.wireValue,
        payloadMappings = media.payloadMappings.map(::sdpPayloadMapping)
    )

    private fun sdpPayloadMapping(mapping: SdpPayloadMapping) = AgentSdpPayloadMappingEntry(
        payloadType = mapping.payloadType,
        encodingName = mapping.encodingName,
        clockRate = mapping.clockRate,
        channels = mapping.channels,
        fmtpParameters = mapping.fmtpParameters
    )

    /**
     * Project one call.  [includeMessages] adds the per-message list; the
     * message projection itself is the same either way, so turning it on cannot
     * widen what a single message reveals — only how many of them are returned.
     */
    fun call(
        call: SipCallSummary,
        includeMessages: Boolean,
        maxMessages: Int
    ) = AgentSipCallEntry(
        // The Call-ID is an identifier, so it is redacted for display while the
        // caller's own selector matched against the real value.
        callId = call.callId,
        startTime = call.startTime,
        endTime = call.endTime,
        duration = call.duration,
        failureCode = call.failureCode,
        firstFrame = call.firstFrame,
        messageCount = call.messages.size,
        sdpMedia = call.sdpMedia.map { media -> sdpMedia(media) },
        messages = if (includeMessages) {
            call.messages.take(maxMessages.coerceAtLeast(0))
                .map { message -> sipMessage(message) }
        } else {
            null
        }
    )

    fun rtpStream(
        stream: RtpStreamSummary
    ) = AgentRtpStreamEntry(
        source = stream.source,
        destination = stream.destination,
        sourcePort = stream.sourcePort,
        destinationPort = stream.destinationPort,
        ssrc = stream.ssrc,
        payloadType = stream.payloadType,
        packetCount = stream.packetCount,
        lostPackets = stream.lostPackets,
        reorderedPackets = stream.reorderedPackets,
        duplicatePackets = stream.duplicatePackets,
        jitterMillis = stream.jitterMillis,
        firstFrame = stream.firstFrame
    )

    fun rtcpStream(
        stream: RtcpStreamSummary
    ) = AgentRtcpStreamEntry(
        source = stream.source,
        destination = stream.destination,
        sourcePort = stream.sourcePort,
        destinationPort = stream.destinationPort,
        senderSsrc = stream.senderSsrc,
        reportedSsrc = stream.reportedSsrc,
        reportCount = stream.reportCount,
        maxFractionLostPercent = stream.reports.mapNotNull { it.fractionLostPercent }.maxOrNull(),
        maxCumulativeLost = stream.reports.mapNotNull { it.cumulativeLost }.maxOrNull(),
        firstFrame = stream.firstFrame
    )

    fun coreMessage(
        message: CoreSignalMessage
    ): AgentCoreMessageEntry = AgentCoreMessageEntry(
        frameNumber = message.frameNumber,
        time = message.time,
        protocol = message.protocol,
        source = message.source,
        destination = message.destination,
        messageType = message.messageType,
        outcome = message.outcome,
        info = message.info,
        procedureType = message.procedureType,
        commandCode = message.commandCode,
        applicationId = message.applicationId,
        request = message.request,
        resultCode = message.resultCode,
        experimentalResult = message.experimentalResult,
        sequenceNumber = message.sequenceNumber,
        cause = message.cause,
        procedureCode = message.procedureCode,
        registrationState = message.registrationState,
        sessionState = message.sessionState,
        fields = coreFields(message),
        fieldPresence = message.fieldPresence.toList().sorted()
    )

    fun coreSession(
        session: CoreSessionSummary,
        includeMessages: Boolean,
        maxMessages: Int
    ): AgentCoreSessionEntry = coreEntry(
        protocol = session.protocol,
        correlationField = session.correlationField,
        correlationValue = session.correlationValue,
        messageCount = session.messages.size,
        startTime = session.startTime,
        endTime = session.endTime,
        firstFrame = session.firstFrame,
        lastFrame = session.messages.lastOrNull()?.frameNumber,
        procedureType = session.procedureType,
        localCorrelationId = session.localCorrelationId,
        correlationQuality = session.correlationQuality,
        protocols = session.protocols,
        failureCauses = session.failureCauses,
        retryCount = session.retryCount,
        stages = session.stages,
        edges = session.edges,
        limitations = session.limitations,
        partial = session.partial,
        imsCorrelations = session.imsCorrelations,
        messages = if (includeMessages) {
            session.messages.take(maxMessages.coerceAtLeast(0)).map(::coreMessage)
        } else {
            null
        }
    )

    fun coreProcedure(
        timeline: CoreProcedureTimeline,
        includeMessages: Boolean,
        maxMessages: Int
    ): AgentCoreSessionEntry {
        val first = timeline.messages.firstOrNull()
        val keyed = timeline.messages.firstOrNull { it.correlationValue.isNotBlank() } ?: first
        return coreEntry(
            protocol = keyed?.protocol.orEmpty(),
            correlationField = keyed?.correlationField.orEmpty(),
            correlationValue = keyed?.correlationValue.orEmpty(),
            messageCount = timeline.messages.size,
            startTime = timeline.startTime,
            endTime = timeline.endTime,
            firstFrame = timeline.firstFrame,
            lastFrame = timeline.lastFrame,
            procedureType = timeline.procedureType,
            localCorrelationId = timeline.localCorrelationId,
            correlationQuality = timeline.correlationQuality,
            protocols = timeline.messages.map { it.protocol }.filter { it.isNotBlank() }.distinct(),
            failureCauses = timeline.failureCauses,
            retryCount = timeline.retryCount,
            stages = timeline.stages,
            edges = timeline.edges,
            limitations = timeline.limitations,
            partial = timeline.partial,
            imsCorrelations = timeline.imsCorrelations,
            messages = if (includeMessages) {
                timeline.messages.take(maxMessages.coerceAtLeast(0)).map(::coreMessage)
            } else {
                null
            }
        )
    }

    private fun coreEntry(
        protocol: String,
        correlationField: String,
        correlationValue: String,
        messageCount: Int,
        startTime: Double,
        endTime: Double,
        firstFrame: Long?,
        lastFrame: Long?,
        procedureType: String,
        localCorrelationId: String,
        correlationQuality: CoreCorrelationConfidence,
        protocols: List<String>,
        failureCauses: List<String>,
        retryCount: Int,
        stages: List<CoreProcedureStage>,
        edges: List<CoreCorrelationEdge>,
        limitations: List<String>,
        partial: Boolean,
        imsCorrelations: List<CoreImsCorrelation>,
        messages: List<AgentCoreMessageEntry>?
    ) = AgentCoreSessionEntry(
        protocol = protocol,
        correlationField = correlationField,
        correlationValue = correlationValue,
        messageCount = messageCount,
        startTime = startTime,
        endTime = endTime,
        firstFrame = firstFrame,
        lastFrame = lastFrame,
        procedureType = procedureType,
        localCorrelationId = localCorrelationId,
        correlationQuality = correlationQuality.wireName,
        confidence = correlationQuality.score,
        protocols = protocols,
        failureCauses = failureCauses,
        retryCount = retryCount,
        stages = stages.map(::coreStage),
        edges = edges.map(::coreEdge),
        limitations = limitations,
        partial = partial,
        imsCorrelations = imsCorrelations.map(::coreIms),
        messages = messages
    )

    private fun coreStage(stage: CoreProcedureStage): AgentCoreStageEntry = AgentCoreStageEntry(
        stage = stage.stage,
        startTime = stage.startTime,
        endTime = stage.endTime,
        frameNumbers = stage.frameNumbers,
        messageTypes = stage.messageTypes,
        outcomes = stage.outcomes,
        causes = stage.causes,
        correlationQuality = stage.correlationQuality.wireName,
        confidence = stage.correlationQuality.score,
        retryCount = stage.retryCount
    )

    private fun coreEdge(edge: CoreCorrelationEdge): AgentCoreCorrelationEdgeEntry = AgentCoreCorrelationEdgeEntry(
        fromFrame = edge.fromFrame,
        toFrame = edge.toFrame,
        type = edge.type.wireName,
        confidence = edge.confidence.wireName,
        confidenceScore = edge.confidence.score,
        basisFields = edge.basisFields,
        timeDeltaMillis = edge.timeDeltaMillis,
        fromNodeId = edge.fromNodeId,
        toNodeId = edge.toNodeId
    )

    private fun coreIms(correlation: CoreImsCorrelation): AgentCoreImsCorrelationEntry = AgentCoreImsCorrelationEntry(
        callId = correlation.callId,
        startTime = correlation.startTime,
        endTime = correlation.endTime,
        relation = correlation.relation,
        confidence = correlation.confidence.wireName,
        confidenceScore = correlation.confidence.score
    )

    private fun coreFields(message: CoreSignalMessage): Map<String, String> = buildMap {
        putAll(message.fields)
        fun putValue(name: String, value: String?) {
            if (!value.isNullOrBlank()) put(name, value)
        }
        putValue("diameter.sessionId", message.sessionId)
        putValue("diameter.commandCode", message.commandCode?.toString())
        putValue("diameter.applicationId", message.applicationId?.toString())
        putValue("diameter.request", message.request?.toString())
        putValue("diameter.resultCode", message.resultCode)
        putValue("diameter.experimentalResult", message.experimentalResult)
        putValue("diameter.originRealm", message.originRealm)
        putValue("diameter.destinationRealm", message.destinationRealm)
        putValue("pfcp.seid", message.seid)
        putValue("gtp.teid", message.teid)
        putValue("sequenceNumber", message.sequenceNumber?.toString())
        putValue("cause", message.cause)
        putValue("nodeId", message.nodeId)
        putValue("ueId", message.ueId)
        putValue("procedureCode", message.procedureCode)
        putValue("bearerId", message.bearerId)
        putValue("procedureTransactionIdentity", message.procedureTransactionIdentity?.toString())
        putValue("registrationState", message.registrationState)
        putValue("sessionState", message.sessionState)
        putValue("subscriberId", message.subscriberId)
        putValue("apnOrDnn", message.apnOrDnn)
    }
}
