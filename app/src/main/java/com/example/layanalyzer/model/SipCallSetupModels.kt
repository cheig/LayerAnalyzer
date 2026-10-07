package com.example.layanalyzer.model

/** The observable parts of a SIP call establishment sequence. */
enum class SipCallSetupStage {
    PreInviteTransport,
    InviteToTrying,
    TryingToRinging,
    ReliableProvisional,
    PreconditionOrUpdate,
    FinalResponse,
    AckCompletion
}

/** Whether both boundary messages for a stage were visible in the capture. */
enum class SipCallSetupCompleteness {
    Complete,
    Partial,
    NotObserved
}

/** Deterministic classifications made from the selected INVITE attempt. */
enum class SipCallSetupOutcome {
    Success,
    FinalResponseFailure,
    CancelledBeforeAnswer,
    NoFinalResponse,
    MissingAck,
    ProvisionalTimeout,
    PrackFailure,
    TransportOrTlsDelay,
    MediaPreconditionDelay,
    CaptureIncomplete
}

/** The type of a transport event that was correlated to a setup attempt. */
enum class SipCallSetupTransportKind {
    Dns,
    TcpRetransmission,
    TcpReset,
    TlsAlert
}

/** One stage, with nullable boundaries when the observed flow is incomplete. */
data class SipCallSetupStageTiming(
    val stage: SipCallSetupStage,
    val startFrame: Long? = null,
    val endFrame: Long? = null,
    val startTime: Double? = null,
    val endTime: Double? = null,
    val durationMillis: Long? = null,
    val completeness: SipCallSetupCompleteness = SipCallSetupCompleteness.NotObserved,
    val attentionThresholdExceeded: Boolean = false,
    val evidenceFrames: List<Long> = emptyList()
)

/** A non-overlapping part of the observed setup duration used for percentages. */
data class SipCallSetupDelayContribution(
    val stage: SipCallSetupStage,
    val startFrame: Long,
    val endFrame: Long,
    val startTime: Double,
    val endTime: Double,
    val durationMillis: Long,
    val percentageOfTotal: Double = 0.0
)

/** A time- and endpoint-correlated DNS, TCP, or TLS observation. */
data class SipCallSetupTransportEvidence(
    val kind: SipCallSetupTransportKind,
    val frameNumber: Long,
    val time: Double? = null,
    val source: String = "",
    val destination: String = "",
    val sourceName: String = ""
)

/** The capture boundaries that qualify absence-based setup findings. */
data class SipCallSetupCaptureRange(
    val firstFrame: Long? = null,
    val lastFrame: Long? = null,
    val startTime: Double? = null,
    val endTime: Double? = null,
    val sipSourceTruncated: Boolean = false,
    val expertSourceTruncated: Boolean = false,
    val scopeIsFiltered: Boolean = false,
    val displayFilter: String = ""
) {
    val isCompleteForNegativeEvidence: Boolean
        get() = !sipSourceTruncated && !expertSourceTruncated && !scopeIsFiltered
}

/** Optional constraints for choosing exactly one INVITE transaction. */
data class SipCallSetupSelection(
    val callId: String? = null,
    val frameNumber: Long? = null,
    val targetSetupMillis: Long? = null,
    val attentionThresholdMillis: Long? = null
)

/** A compact candidate supplied when the analyzer cannot safely choose a call. */
data class SipCallSetupCandidate(
    val id: String,
    val callId: String,
    val inviteFrame: Long?,
    val startTime: Double,
    val outcome: SipCallSetupOutcome,
    val finalResponseCode: Int? = null,
    val setupDurationMillis: Long? = null,
    val selectionReason: String
)

/** One INVITE attempt and the setup stages derived from its dialog. */
data class SipCallSetupAttempt(
    val id: String,
    val callId: String,
    val inviteFrame: Long?,
    val finalResponseFrame: Long? = null,
    val ackFrame: Long? = null,
    val startTime: Double = 0.0,
    val endTime: Double = 0.0,
    val finalResponseCode: Int? = null,
    val outcome: SipCallSetupOutcome = SipCallSetupOutcome.CaptureIncomplete,
    val stages: List<SipCallSetupStageTiming> = emptyList(),
    val delayContributions: List<SipCallSetupDelayContribution> = emptyList(),
    val largestContribution: SipCallSetupDelayContribution? = null,
    val setupDurationMillis: Long? = null,
    val inviteToFinalResponseMillis: Long? = null,
    val retransmissionCount: Int = 0,
    val transportEvidence: List<SipCallSetupTransportEvidence> = emptyList(),
    val mediaNegotiationFrames: List<Long> = emptyList(),
    val coreEventFrames: List<Long> = emptyList(),
    val limitations: List<String> = emptyList()
)

/** Result of local, deterministic call setup diagnosis. */
data class SipCallSetupAnalysis(
    val selectedAttempt: SipCallSetupAttempt? = null,
    val alternateCandidates: List<SipCallSetupCandidate> = emptyList(),
    val selectionReason: String = "",
    val requiresUserSelection: Boolean = false,
    val captureRange: SipCallSetupCaptureRange = SipCallSetupCaptureRange(),
    val limitations: List<String> = emptyList(),
    val excludedCauses: List<String> = emptyList()
)
