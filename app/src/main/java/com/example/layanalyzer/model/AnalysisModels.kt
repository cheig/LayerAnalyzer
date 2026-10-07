// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

data class DisplayFilterResult(
    val success: Boolean,
    val filteredCount: Int,
    val error: String? = null
)

enum class FilterSyntaxStatus {
    Unchecked,
    Checking,
    Valid,
    Invalid
}

data class DisplayFilterUiState(
    val draftExpression: String = "",
    val appliedExpression: String = "",
    val syntaxStatus: FilterSyntaxStatus = FilterSyntaxStatus.Unchecked,
    val syntaxError: String? = null,
    val visibleCount: Int = 0,
    val totalCount: Int = 0
) {
    val hasUnappliedChanges: Boolean
        get() = draftExpression.trim() != appliedExpression
}

enum class PacketSearchMode(val nativeName: String, val label: String) {
    Number("number", "Number"),
    Text("text", "Text"),
    Hex("hex", "Hex"),
    Field("field", "Field")
}

data class PacketSearchState(
    val mode: PacketSearchMode = PacketSearchMode.Text,
    val query: String = "",
    val results: List<Long> = emptyList(),
    val selectedResultIndex: Int = -1,
    val isSearching: Boolean = false,
    val hasSearched: Boolean = false,
    val error: String? = null
) {
    val selectedFrame: Long? = results.getOrNull(selectedResultIndex)
}

data class SummaryCacheStats(
    val frames: Int = 0,
    val valid: Int = 0,
    val hits: Long = 0,
    val misses: Long = 0
)

data class ExpertInfoSummary(
    val warningPackets: Int = 0,
    val errorPackets: Int = 0,
    val items: List<ExpertInfoItem> = emptyList(),
    val totalItems: Int = 0,
    val truncated: Boolean = false,
    val isLoading: Boolean = false,
    val analyzed: Boolean = false,
    val error: String? = null
)

data class ExpertInfoItem(
    val frameNumber: Long,
    val label: String,
    val filter: String?,
    val severity: String,
    val start: Int,
    val length: Int
)

data class FollowStreamResult(
    val protocol: String,
    val streamId: Int,
    val records: List<FollowStreamRecord>,
    val scope: String = "current filtered packet set",
    val directionKnown: Boolean = false,
    val error: String? = null
)

data class FollowStreamRecord(
    val frameNumber: Long,
    val direction: String,
    val source: String,
    val destination: String,
    val length: Int,
    val payload: Boolean,
    val text: String,
    val ascii: String,
    val hex: String
)

data class CaptureStatistics(
    val packetCount: Int = 0,
    val byteCount: Long = 0,
    val capturedByteCount: Long = 0,
    val truncatedPacketCount: Int = 0,
    val startTime: Double = 0.0,
    val endTime: Double = 0.0,
    val protocolHierarchy: List<ProtocolStat> = emptyList(),
    val conversations: List<ConversationStat> = emptyList(),
    val endpoints: List<EndpointStat> = emptyList(),
    val ioGraph: List<IoBucket> = emptyList(),
    val packetLengths: PacketLengthStats = PacketLengthStats(),
    val dnsTransactions: List<RequestResponseTransaction> = emptyList(),
    val httpTransactions: List<RequestResponseTransaction> = emptyList(),
    val dnsSummaries: List<ProtocolSummaryItem> = emptyList(),
    val dnsSummaryTotal: Int = 0,
    val dnsQueries: Int = 0,
    val dnsResponses: Int = 0,
    val dnsAverageResponseMs: Double = 0.0,
    val dnsTopDomains: Map<String, Int> = emptyMap(),
    val httpSummaries: List<ProtocolSummaryItem> = emptyList(),
    val httpSummaryTotal: Int = 0,
    val tlsSummaries: List<ProtocolSummaryItem> = emptyList(),
    val tlsSummaryTotal: Int = 0,
    val tcpSummaries: List<ProtocolSummaryItem> = emptyList(),
    val tcpSummaryTotal: Int = 0,
    val tcpSyn: Int = 0,
    val tcpSynAck: Int = 0,
    val tcpRetransmissions: Int = 0,
    val tcpDuplicateAcks: Int = 0,
    val tcpResets: Int = 0,
    val tcpZeroWindows: Int = 0,
    val tcpAverageRttMs: Double = 0.0,
    val tcpRttSamples: Int = 0,
    val tlsVersions: Map<String, Int> = emptyMap(),
    val tlsSni: Map<String, Int> = emptyMap(),
    val httpStatusCodes: Map<String, Int> = emptyMap(),
    val httpHosts: Map<String, Int> = emptyMap(),
    val dnsFailureTotal: Int = 0,
    val tlsAlertTotal: Int = 0,
    val httpErrorTotal: Int = 0,
    val dnsFirstFailureFrame: Long? = null,
    val tlsFirstAlertFrame: Long? = null,
    val httpFirstErrorFrame: Long? = null
)

data class RequestResponseTransaction(
    val protocol: String,
    val requestFrame: Long,
    val responseFrame: Long? = null,
    val requestTime: Double? = null,
    val responseTime: Double? = null,
    val client: String,
    val server: String,
    val request: String,
    val response: String? = null,
    val responseTimeMillis: Double? = null
)

data class ProtocolStat(
    val name: String,
    val packetCount: Int,
    val byteCount: Long,
    val packetPercent: Double,
    val bytePercent: Double
)

data class ConversationStat(
    val type: String,
    val endpointA: String,
    val endpointB: String,
    val portA: Int? = null,
    val portB: Int? = null,
    val packets: Int,
    val bytes: Long,
    val startTime: Double,
    val duration: Double,
    val aToBPackets: Int,
    val bToAPackets: Int
)

data class EndpointStat(
    val type: String,
    val address: String,
    val port: Int? = null,
    val packets: Int,
    val bytes: Long,
    val sentPackets: Int,
    val receivedPackets: Int
)

data class IoBucket(
    val startTime: Double,
    val endTime: Double,
    val packets: Int,
    val bytes: Long
)

data class PacketLengthStats(
    val min: Int = 0,
    val max: Int = 0,
    val average: Double = 0.0,
    val totalBytes: Long = 0,
    val buckets: List<PacketLengthBucket> = emptyList()
)

data class PacketLengthBucket(
    val label: String,
    val packets: Int,
    val bytes: Long
)

data class ProtocolSummaryItem(
    val frameNumber: Long,
    val time: Double,
    val source: String,
    val destination: String,
    val protocol: String,
    val summary: String
)

data class StatisticsUiState(
    val isLoading: Boolean = false,
    val statistics: CaptureStatistics? = null,
    val error: String? = null,
    val bucketSeconds: Double = 1.0,
    val job: AnalysisJobState = AnalysisJobState()
)

enum class TimeDisplayFormat { Relative, Delta, Absolute, Utc }

/**
 * ESP NULL 解密策略。原生侧对应 Wireshark 的
 * `esp.enable_null_encryption_decode_heuristic` 偏好（进程级）。
 *
 * - [Probe]（默认）打开抓包时探测：只有确认是 NULL 加密才真正开启，
 *   否则回落到关闭，避免把真正加密的 ESP 误判成明文。
 * - [All] 无条件开启，对所有 ESP 报文尝试解密。
 * - [Off] 关闭。
 */
enum class EspDecryptionMode(val nativeValue: String) {
    Probe("probe"),
    All("all"),
    Off("off");

    companion object {
        /** 未知/缺失的值一律回落到默认的 [Probe]。 */
        fun fromNativeValue(value: String?): EspDecryptionMode =
            values().firstOrNull { it.nativeValue == value || it.name == value } ?: Probe
    }
}

data class EspDecryptionResult(
    val mode: EspDecryptionMode,
    /** 生效状态：`Probe` 探测失败时为 false。 */
    val enabled: Boolean,
    /** 探测是否真的解出了一个 ESP 报文；非 `Probe` 时等于 [enabled]。 */
    val decoded: Boolean,
    val framesScanned: Int,
    val error: String
) {
    val isSuccess: Boolean get() = error.isEmpty()
}

data class AnalyzerPreferences(
    val timeDisplayFormat: TimeDisplayFormat = TimeDisplayFormat.Relative,
    val nameResolutionEnabled: Boolean = false,
    val colorRulesEnabled: Boolean = true,
    val defaultTreeExpansionDepth: Int = 1,
    val rtpHeuristicEnabled: Boolean = false,
    val espDecryptionMode: EspDecryptionMode = EspDecryptionMode.Probe,
    val uiLanguage: UiLanguage = UiLanguage.SYSTEM
)

enum class DecodeAsScope(val label: String) {
    Port("Port")
}

enum class DecodeAsTransport(val nativeTable: String, val label: String) {
    TCP("tcp.port", "TCP"),
    UDP("udp.port", "UDP")
}

data class DecodeAsRule(
    val id: String,
    val scope: DecodeAsScope,
    val transport: DecodeAsTransport,
    val source: String,
    val destination: String,
    val sourcePort: Int?,
    val destinationPort: Int?,
    val protocol: String
) {
    val ports: List<Int>
        get() = listOfNotNull(destinationPort ?: sourcePort).distinct()
}

data class ExportResult(
    val filePath: String,
    val displayName: String,
    val mimeType: String
)

data class ExportUiState(
    val isExporting: Boolean = false,
    val error: String? = null,
    val message: String? = null,
    val shareResult: ExportResult? = null
)

data class HttpObjectEntry(
    val id: Int,
    val frameNumber: Long,
    val hostname: String,
    val contentType: String,
    val filename: String,
    val size: Long
)

data class HttpObjectsState(
    val isLoading: Boolean = false,
    val analyzed: Boolean = false,
    val objects: List<HttpObjectEntry> = emptyList(),
    val error: String? = null
)

enum class EvidenceExportMode {
    Original,
    Redacted,
    MetadataOnly
}

data class LiveCaptureSettings(
    val excludeSelf: Boolean = true,
    val captureIpv6: Boolean = false,
    val maxDurationMinutes: Int = 15,
    val maxSizeMegabytes: Int = 256,
    val segmentSizeMegabytes: Int = 64,
    val allowedApplications: List<String> = emptyList()
)

data class LiveCapturePacketPreview(
    val number: Long,
    val timeMillis: Long,
    val length: Int,
    val ipVersion: Int,
    val protocol: String,
    val source: String,
    val destination: String
)

data class LiveCaptureState(
    val isCapturing: Boolean = false,
    val startedAtMillis: Long = 0L,
    val stoppedAtMillis: Long = 0L,
    val packetCount: Long = 0L,
    val byteCount: Long = 0L,
    val offeredPacketCount: Long = 0L,
    val droppedPacketCount: Long = 0L,
    val ioErrorCount: Long = 0L,
    val lastIoError: String? = null,
    val outputPath: String? = null,
    val segmentPaths: List<String> = emptyList(),
    val interrupted: Boolean = false,
    val incomplete: Boolean = false,
    val error: String? = null,
    val recentPackets: List<LiveCapturePacketPreview> = emptyList()
) {
    val captureIsComplete: Boolean
        get() = !isCapturing && !interrupted && !incomplete && offeredPacketCount == packetCount && droppedPacketCount == 0L && ioErrorCount == 0L

    val hasSavedCapture: Boolean
        get() = !outputPath.isNullOrBlank() && packetCount > 0
}

/** Shared contract for every long-running analysis operation. */
enum class AnalysisJobPhase {
    /** Accepted but not yet executing; the foreground service is coming up. */
    Queued,
    Preparing,
    Running,
    Completed,
    Failed,
    Cancelled,
    /** The process died mid-run; the checkpoint may allow a manual resume. */
    Interrupted
}

enum class AnalysisScope { CompleteFile, CurrentFilter, CurrentSession, RecentCapture }

data class AnalysisJobState(
    val phase: AnalysisJobPhase = AnalysisJobPhase.Preparing,
    val processed: Long = 0,
    val total: Long = 0,
    val speedPerSecond: Double = 0.0,
    val scope: AnalysisScope = AnalysisScope.CompleteFile,
    val truncated: Boolean = false,
    val errorCode: String? = null,
    val message: String? = null
) {
    val progress: Float?
        get() = if (total > 0) (processed.toFloat() / total).coerceIn(0f, 1f) else null
}

enum class HealthSeverity { Healthy, Notice, Warning, Error }

data class HealthCard(
    val id: String,
    val title: String,
    val value: String,
    val detail: String,
    val severity: HealthSeverity = HealthSeverity.Healthy,
    val frameNumber: Long? = null,
    val filter: String? = null,
    val returned: Int = 0,
    val total: Int = 0,
    val truncated: Boolean = false
)

data class CaptureHealthSummary(
    val scope: AnalysisScope = AnalysisScope.CompleteFile,
    val cards: List<HealthCard> = emptyList(),
    val generatedAtMillis: Long = 0L,
    val isLoading: Boolean = false,
    val error: String? = null
) {
    val hasErrors: Boolean get() = cards.any { it.severity == HealthSeverity.Error }
}

data class ScenarioStep(
    val id: String,
    val title: String,
    val filter: String,
    val conclusion: String
)

data class ScenarioTemplate(
    val id: String,
    val version: Int,
    val title: String,
    val description: String,
    val steps: List<ScenarioStep>
)

data class WorkspaceNote(
    val frameNumber: Long,
    val text: String,
    val updatedAtMillis: Long,
    val sourceType: WorkspaceNoteSourceType = WorkspaceNoteSourceType.Manual,
    val sourceId: String? = null
)

/** Identifies whether a workspace note was written by the user or saved from a reviewed finding. */
enum class WorkspaceNoteSourceType { Manual, Agent }

/**
 * A user-approved Agent conclusion retained with a capture workspace.
 *
 * This intentionally stores only the compact, already-sanitized conclusion and
 * provenance identifiers.  It never stores model messages, tool arguments,
 * tool results, or hidden reasoning.
 */
data class AgentSavedFinding(
    val findingId: String,
    val title: String,
    val summary: String,
    val sourceId: String,
    val sourceToolCallIds: List<String> = emptyList(),
    val evidenceFrames: Set<Long> = emptySet(),
    val savedAtMillis: Long
)

/** Identifies how an evidence frame entered the workspace evidence set. */
enum class EvidenceSource { Manual, AgentFinding }

/**
 * One evidence frame plus its provenance.
 *
 * The note text is deliberately NOT stored here: notes stay in `workspace.notes`
 * keyed by `frameNumber` so the two can never drift apart.
 */
data class EvidenceItem(
    val frameNumber: Long,
    val source: EvidenceSource = EvidenceSource.Manual,
    /** Only meaningful when [source] is [EvidenceSource.AgentFinding]: the findingId of the origin conclusion. */
    val sourceFindingId: String? = null,
    val addedAtMillis: Long = 0L
)

/** Which packet range an evidence export covers. */
enum class EvidenceExportScope { EvidenceFrames, CurrentView }

data class AnalysisWorkspace(
    val fileFingerprint: String,
    val displayName: String,
    val analysisConfigVersion: Int = 1,
    val displayFilter: String = "",
    val selectedFrame: Long? = null,
    val bookmarks: Set<Long> = emptySet(),
    val notes: List<WorkspaceNote> = emptyList(),
    val tags: Set<String> = emptySet(),
    val evidenceItems: List<EvidenceItem> = emptyList(),
    val filterHistory: List<String> = emptyList(),
    val favoriteFilters: Set<String> = emptySet(),
    val agentFindings: List<AgentSavedFinding> = emptyList()
) {
    /** Derived view: every existing read site (evidence badge, export, checks) keeps working unchanged. */
    val evidenceFrames: Set<Long>
        get() = evidenceItems.mapTo(LinkedHashSet()) { it.frameNumber }
}

data class SipMessage(
    val frameNumber: Long,
    val time: Double,
    val source: String,
    val destination: String,
    val sourcePort: Int? = null,
    val destinationPort: Int? = null,
    val method: String = "",
    val status: String = "",
    val callId: String = "",
    val cSeqNumber: Long? = null,
    val cSeqMethod: String? = null,
    val viaBranch: String? = null,
    val fromTag: String? = null,
    val toTag: String? = null,
    val requestUri: String? = null,
    val authorizationPresent: Boolean = false,
    val authorizationScheme: String? = null,
    val contentType: String? = null,
    val fieldPresence: SipMessageFieldPresence = SipMessageFieldPresence(),
    val info: String = "",
    val sdp: SdpMediaSummary? = null
)

/** Presence flags distinguish an absent protocol-tree field from an empty value. */
data class SipMessageFieldPresence(
    val cSeqNumber: Boolean = false,
    val cSeqMethod: Boolean = false,
    val viaBranch: Boolean = false,
    val fromTag: Boolean = false,
    val toTag: Boolean = false,
    val requestUri: Boolean = false,
    val authorization: Boolean = false,
    val contentType: Boolean = false,
    val sdpDirection: Boolean = false,
    val sdpPayloadMappings: Boolean = false,
    val sdpOfferAnswerRole: Boolean = false
)

enum class SdpMediaDirection(val wireValue: String) {
    SendRecv("sendrecv"),
    SendOnly("sendonly"),
    RecvOnly("recvonly"),
    Inactive("inactive"),
    Unknown("unknown");

    companion object {
        fun fromWire(value: String?): SdpMediaDirection =
            entries.firstOrNull { it.wireValue == value?.trim()?.lowercase() } ?: Unknown
    }
}

enum class SdpOfferAnswerRole(val wireValue: String) {
    Offer("offer"),
    Answer("answer"),
    Unknown("unknown");

    companion object {
        fun fromWire(value: String?): SdpOfferAnswerRole =
            entries.firstOrNull { it.wireValue == value?.trim()?.lowercase() } ?: Unknown
    }
}

/** One dynamic (or static) RTP payload mapping exposed by SDP without SDP text. */
data class SdpPayloadMapping(
    val payloadType: Int? = null,
    val encodingName: String = "",
    val clockRate: Int? = null,
    val channels: Int? = null,
    /** Only allow-listed, non-secret fmtp parameter names are retained. */
    val fmtpParameters: List<String> = emptyList()
)

data class SdpMediaSummary(
    val frameNumber: Long,
    val connectionAddress: String = "",
    val mediaType: String = "",
    val mediaPort: Int? = null,
    val mediaProtocol: String = "",
    val formats: List<String> = emptyList(),
    val codecs: List<String> = emptyList(),
    val direction: SdpMediaDirection = SdpMediaDirection.Unknown,
    val payloadMappings: List<SdpPayloadMapping> = emptyList(),
    val offerAnswerRole: SdpOfferAnswerRole = SdpOfferAnswerRole.Unknown
)

data class SipCallSummary(
    val callId: String,
    val messages: List<SipMessage>,
    val startTime: Double,
    val endTime: Double,
    val failureCode: Int? = null,
    val sdpMedia: List<SdpMediaSummary> = emptyList()
) {
    val duration: Double get() = (endTime - startTime).coerceAtLeast(0.0)
    val firstFrame: Long? get() = messages.firstOrNull()?.frameNumber
}

data class RtpPacketMetric(
    val frameNumber: Long,
    val time: Double,
    val source: String,
    val destination: String,
    val sourcePort: Int? = null,
    val destinationPort: Int? = null,
    val sequence: Int? = null,
    val ssrc: Long? = null,
    val timestamp: Long? = null,
    val payloadType: Int? = null
)

data class RtpStreamSummary(
    val key: String,
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
    val firstFrame: Long?,
    val packets: List<RtpPacketMetric>
)

data class RtcpPacketMetric(
    val frameNumber: Long,
    val time: Double,
    val source: String,
    val destination: String,
    val sourcePort: Int? = null,
    val destinationPort: Int? = null,
    val packetType: Int? = null,
    val senderSsrc: Long? = null,
    val reportedSsrc: Long? = null,
    val fractionLost: Int? = null,
    val cumulativeLost: Int? = null,
    val interarrivalJitter: Long? = null
) {
    val fractionLostPercent: Double?
        get() = fractionLost?.let { it * 100.0 / 256.0 }
}

data class RtcpStreamSummary(
    val key: String,
    val source: String,
    val destination: String,
    val sourcePort: Int?,
    val destinationPort: Int?,
    val senderSsrc: Long?,
    val reportedSsrc: Long?,
    val reportCount: Int,
    val firstFrame: Long?,
    val reports: List<RtcpPacketMetric>
)

data class CoreSignalMessage(
    val frameNumber: Long,
    val time: Double,
    val protocol: String,
    val source: String,
    val destination: String,
    val correlationField: String,
    val correlationValue: String,
    val messageType: String,
    val outcome: String,
    val info: String,
    val procedureType: String = "",
    val commandCode: Int? = null,
    val applicationId: Long? = null,
    val request: Boolean? = null,
    val resultCode: String = "",
    val experimentalResult: String = "",
    val originRealm: String = "",
    val destinationRealm: String = "",
    val sessionId: String = "",
    val sequenceNumber: Long? = null,
    val cause: String = "",
    val nodeId: String = "",
    val teid: String = "",
    val seid: String = "",
    val ueId: String = "",
    val ueIdType: String = "",
    val procedureCode: String = "",
    val bearerId: String = "",
    val procedureTransactionIdentity: Int? = null,
    val registrationState: String = "",
    val sessionState: String = "",
    val subscriberId: String = "",
    val apnOrDnn: String = "",
    val explicitReference: String = "",
    val fields: Map<String, String> = emptyMap(),
    val fieldPresence: Set<String> = emptySet()
)

data class CoreSessionSummary(
    val key: String,
    val protocol: String,
    val correlationField: String,
    val correlationValue: String,
    val messages: List<CoreSignalMessage>,
    val firstFrame: Long?,
    val procedureType: String = "",
    val localCorrelationId: String = key,
    val correlationQuality: CoreCorrelationConfidence = CoreCorrelationConfidence.Weak,
    val protocols: List<String> = emptyList(),
    val startTime: Double = messages.firstOrNull()?.time ?: 0.0,
    val endTime: Double = messages.lastOrNull()?.time ?: startTime,
    val failureCauses: List<String> = emptyList(),
    val retryCount: Int = 0,
    val stages: List<CoreProcedureStage> = emptyList(),
    val edges: List<CoreCorrelationEdge> = emptyList(),
    val limitations: List<String> = emptyList(),
    val partial: Boolean = false,
    val imsCorrelations: List<CoreImsCorrelation> = emptyList()
)

data class CommunicationAnalysis(
    val schemaVersion: Int = 1,
    val sipMessages: List<SipMessage> = emptyList(),
    val sipTotal: Int = 0,
    val sipTruncated: Boolean = false,
    val rtpPackets: List<RtpPacketMetric> = emptyList(),
    val rtpTotal: Int = 0,
    val rtpTruncated: Boolean = false,
    val rtcpPackets: List<RtcpPacketMetric> = emptyList(),
    val rtcpTotal: Int = 0,
    val rtcpTruncated: Boolean = false,
    val coreMessages: List<CoreSignalMessage> = emptyList(),
    val coreTotal: Int = 0,
    val coreTruncated: Boolean = false,
    val calls: List<SipCallSummary> = emptyList(),
    val streams: List<RtpStreamSummary> = emptyList(),
    val rtcpStreams: List<RtcpStreamSummary> = emptyList(),
    val coreSessions: List<CoreSessionSummary> = emptyList(),
    val coreProcedures: List<CoreProcedureTimeline> = emptyList(),
    val coreCorrelation: CoreCorrelationAnalysis = CoreCorrelationAnalysis(),
    val sipTransactions: List<SipTransaction> = emptyList(),
    val sipDialogs: List<SipDialogTimeline> = emptyList(),
    val isLoading: Boolean = false,
    val error: String? = null
)
