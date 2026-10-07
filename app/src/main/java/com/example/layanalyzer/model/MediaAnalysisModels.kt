package com.example.layanalyzer.model

/** Strength of the evidence linking an observed RTP stream to an SDP media line. */
enum class MediaCorrelationConfidence {
    Strong,
    Medium,
    Weak,
    None
}

/** Direction expressed relative to the SDP offerer and answerer. */
enum class MediaPathDirection(val wireValue: String) {
    OfferToAnswer("offer-to-answer"),
    AnswerToOffer("answer-to-offer"),
    Unknown("unknown")
}

enum class MediaFindingKind {
    NoMediaPackets,
    OneWayMedia,
    SdpDirectionExpected,
    PortOrAddressMismatch,
    CodecMismatch,
    HighLoss,
    HighJitter,
    ShortCaptureOrPartialPath
}

enum class MediaFindingSeverity {
    Info,
    Warning,
    High
}

/** Capture conditions that qualify negative media evidence. */
data class MediaCaptureSnapshot(
    val endpoints: Set<String> = emptySet(),
    val firstFrame: Long? = null,
    val lastFrame: Long? = null,
    val startTime: Double? = null,
    val endTime: Double? = null,
    val sourceTruncated: Boolean = false,
    val scopeIsFiltered: Boolean = false,
    val encryptedMediaPossible: Boolean = false
) {
    val supportsNegativeEvidence: Boolean
        get() = !sourceTruncated && !scopeIsFiltered && startTime != null && endTime != null
}

data class MediaCodecMapping(
    val payloadType: Int?,
    val codec: String,
    val clockRate: Int?,
    val channels: Int?
)

data class MediaEndpoint(
    val connectionAddress: String = "",
    val port: Int? = null,
    val direction: SdpMediaDirection = SdpMediaDirection.Unknown
)

/** Per-direction local RTP observation and the correlation that led to it. */
data class MediaRtpDirectionAnalysis(
    val direction: MediaPathDirection,
    val expected: Boolean,
    val observed: Boolean,
    val confidence: MediaCorrelationConfidence = MediaCorrelationConfidence.None,
    val streamKeys: List<String> = emptyList(),
    val packetCount: Int = 0,
    val firstFrame: Long? = null,
    val lastFrame: Long? = null,
    val durationMillis: Long? = null,
    val ssrcs: List<Long> = emptyList(),
    val payloadTypes: List<Int> = emptyList(),
    val codecs: List<MediaCodecMapping> = emptyList(),
    val clockRate: Int? = null,
    val lostPackets: Int = 0,
    val reorderedPackets: Int = 0,
    val duplicatePackets: Int = 0,
    val jitterMillis: Double? = null,
    val anomalyFrames: List<Long> = emptyList(),
    val displayFilters: List<String> = emptyList()
)

/** RTCP receiver-report values linked by reported SSRC, with their frame evidence. */
data class MediaRtcpAnalysis(
    val reportedSsrc: Long? = null,
    val reportCount: Int = 0,
    val firstFrame: Long? = null,
    val lastFrame: Long? = null,
    val fractionLostPercentRange: ClosedFloatingPointRange<Double>? = null,
    val worstFractionLostPercent: Double? = null,
    val cumulativeLostRange: IntRange? = null,
    val worstCumulativeLost: Int? = null,
    val interarrivalJitterRange: LongRange? = null,
    val worstInterarrivalJitter: Long? = null,
    val reportFrames: List<Long> = emptyList(),
    val displayFilters: List<String> = emptyList()
)

data class MediaFinding(
    val kind: MediaFindingKind,
    val severity: MediaFindingSeverity,
    val summary: String,
    val direction: MediaPathDirection? = null,
    val evidenceFrames: List<Long> = emptyList(),
    val displayFilters: List<String> = emptyList()
)

/** One SDP m-line and its negotiated and observed media paths. */
data class MediaLineAnalysis(
    val mLineIndex: Int,
    val mediaType: String,
    val mediaProtocol: String,
    val offerFrame: Long,
    val answerFrame: Long? = null,
    val offerEndpoint: MediaEndpoint = MediaEndpoint(),
    val answerEndpoint: MediaEndpoint? = null,
    val rejected: Boolean = false,
    val negotiatedCodecs: List<MediaCodecMapping> = emptyList(),
    val directions: List<MediaRtpDirectionAnalysis> = emptyList(),
    val rtcp: List<MediaRtcpAnalysis> = emptyList(),
    val findings: List<MediaFinding> = emptyList()
)

/** A Call-ID scoped media diagnosis. */
data class MediaSessionAnalysis(
    val callId: String,
    val startTime: Double? = null,
    val endTime: Double? = null,
    val lines: List<MediaLineAnalysis> = emptyList(),
    val findings: List<MediaFinding> = emptyList(),
    val limitations: List<String> = emptyList(),
    val captureSupportsNegativeEvidence: Boolean = false
)
