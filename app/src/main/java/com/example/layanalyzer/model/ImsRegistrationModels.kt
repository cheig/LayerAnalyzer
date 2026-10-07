package com.example.layanalyzer.model

/** A deterministic classification of one observed IMS REGISTER attempt. */
enum class ImsRegistrationOutcome {
    Success,
    AuthenticationRejected,
    AuthenticationRetryMissing,
    NoFinalResponse,
    TransportFailure,
    ServerFailure,
    RegistrationIntervalIssue,
    ClientFailure,
    Redirected,
    CaptureIncompleteOrEncrypted,
    Unknown
}

/** Stages that can be shown in a registration timeline and cited by frame. */
enum class ImsRegistrationStage {
    InitialRegister,
    AuthenticationChallenge,
    AuthenticatedRegister,
    FinalResponse,
    TransportAnomaly
}

enum class ImsTransportAnomaly {
    TcpRetransmission,
    TcpReset,
    TcpZeroWindow,
    Icmp,
    Unknown
}

/** The observed scope in which a negative registration conclusion is valid. */
data class ImsCaptureRange(
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

/** Optional user-supplied constraints used to select one attempt from a capture. */
data class ImsRegistrationSelection(
    val callIdContains: String? = null,
    val frameNumber: Long? = null,
    val startTime: Double? = null,
    val endTime: Double? = null
)

data class ImsRegistrationTimelineEvent(
    val stage: ImsRegistrationStage,
    val frameNumber: Long,
    val time: Double,
    val statusCode: Int? = null,
    val authorizationPresent: Boolean = false,
    val elapsedFromInitialMillis: Long? = null
)

data class ImsRegistrationTransportEvidence(
    val anomaly: ImsTransportAnomaly,
    val frameNumber: Long? = null,
    val observedCount: Int = 0,
    val source: String = ""
)

/** One REGISTER sequence organised by Call-ID and REGISTER CSeq transactions. */
data class ImsRegistrationAttempt(
    val id: String,
    val callId: String,
    val outcome: ImsRegistrationOutcome,
    val timeline: List<ImsRegistrationTimelineEvent> = emptyList(),
    val startTime: Double = 0.0,
    val endTime: Double = 0.0,
    val firstFrame: Long? = null,
    val lastFrame: Long? = null,
    val retransmissionCount: Int = 0,
    val transportEvidence: List<ImsRegistrationTransportEvidence> = emptyList(),
    val missingInitialFlow: Boolean = false,
    val hasCompleteNegativeEvidence: Boolean = false,
    val limitations: List<String> = emptyList()
) {
    val initialRegister: ImsRegistrationTimelineEvent?
        get() = timeline.firstOrNull { it.stage == ImsRegistrationStage.InitialRegister }

    val challenge: ImsRegistrationTimelineEvent?
        get() = timeline.firstOrNull { it.stage == ImsRegistrationStage.AuthenticationChallenge }

    val authenticatedRegister: ImsRegistrationTimelineEvent?
        get() = timeline.firstOrNull { it.stage == ImsRegistrationStage.AuthenticatedRegister }

    val finalResponse: ImsRegistrationTimelineEvent?
        get() = timeline.firstOrNull { it.stage == ImsRegistrationStage.FinalResponse }
}

/** A compact explanation of an attempt that was not selected for the report. */
data class ImsRegistrationCandidate(
    val id: String,
    val callId: String,
    val outcome: ImsRegistrationOutcome,
    val firstFrame: Long?,
    val startTime: Double,
    val selectionReason: String
)

/** Result of the local IMS registration analysis; no model inference is required. */
data class ImsRegistrationAnalysis(
    val selectedAttempt: ImsRegistrationAttempt? = null,
    val alternateCandidates: List<ImsRegistrationCandidate> = emptyList(),
    val selectionReason: String = "",
    val captureRange: ImsCaptureRange = ImsCaptureRange(),
    val limitations: List<String> = emptyList(),
    val excludedCauses: List<String> = emptyList()
) {
    val outcome: ImsRegistrationOutcome
        get() = selectedAttempt?.outcome ?: ImsRegistrationOutcome.CaptureIncompleteOrEncrypted
}
