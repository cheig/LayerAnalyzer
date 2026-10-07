// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

/** The relationship used to connect two core signalling messages. */
enum class CoreCorrelationEdgeType(val wireName: String) {
    SameSessionId("sameSessionId"),
    SameTeid("sameTeid"),
    SameUeId("sameUeId"),
    SameSequence("sameSequence"),
    TimeAdjacent("timeAdjacent"),
    ExplicitReference("explicitReference")
}

/** Confidence is deliberately coarse so a weak temporal candidate cannot look deterministic. */
enum class CoreCorrelationConfidence(val wireName: String, val score: Double) {
    High("High", 0.95),
    Medium("Medium", 0.70),
    Weak("Weak", 0.30)
}

enum class CoreProcedureType(val wireName: String) {
    RegistrationAttach("registration_attach"),
    AuthenticationSecurityMode("authentication_security_mode"),
    SessionBearerPduEstablishment("session_bearer_pdu_establishment"),
    PolicySessionControl("policy_session_control"),
    ReleaseDetach("release_detach"),
    Unknown("unknown")
}

/** Classification used by the native field allow-list and the privacy projection. */
enum class CoreFieldClassification {
    Aggregate,
    Identifier,
    Credential
}

/** A field occurrence can report presence without carrying a credential value. */
data class CoreSignalField(
    val name: String,
    val value: String? = null,
    val present: Boolean = value != null,
    val classification: CoreFieldClassification = CoreFieldClassification.Aggregate
)

data class CoreCorrelationNode(
    val id: String,
    val kind: String,
    val frameNumber: Long? = null,
    val time: Double? = null,
    val protocol: String? = null,
    val fieldName: String? = null,
    val value: String? = null
)

data class CoreCorrelationEdge(
    val fromFrame: Long,
    val toFrame: Long,
    val type: CoreCorrelationEdgeType,
    val confidence: CoreCorrelationConfidence,
    val basisFields: List<String> = emptyList(),
    val timeDeltaMillis: Long? = null,
    val fromNodeId: String = "",
    val toNodeId: String = ""
)

data class CoreCorrelationGraph(
    val signalNodes: List<CoreCorrelationNode> = emptyList(),
    val identifierNodes: List<CoreCorrelationNode> = emptyList(),
    val endpointNodes: List<CoreCorrelationNode> = emptyList(),
    val timeNodes: List<CoreCorrelationNode> = emptyList(),
    val edges: List<CoreCorrelationEdge> = emptyList()
)

data class CoreProcedureStage(
    val stage: String,
    val startTime: Double,
    val endTime: Double,
    val frameNumbers: List<Long> = emptyList(),
    val messages: List<CoreSignalMessage> = emptyList(),
    val messageTypes: List<String> = emptyList(),
    val outcomes: List<String> = emptyList(),
    val causes: List<String> = emptyList(),
    val correlationQuality: CoreCorrelationConfidence = CoreCorrelationConfidence.Weak,
    val retryCount: Int = 0
)

/** A time-window relationship to an IMS call, never a causal root-cause claim. */
data class CoreImsCorrelation(
    val callId: String,
    val startTime: Double,
    val endTime: Double,
    val relation: String = "timeWindow",
    val confidence: CoreCorrelationConfidence = CoreCorrelationConfidence.Weak
)

data class CoreProcedureTimeline(
    val localCorrelationId: String,
    val procedureType: String,
    val startTime: Double,
    val endTime: Double,
    val firstFrame: Long?,
    val lastFrame: Long?,
    val messages: List<CoreSignalMessage> = emptyList(),
    val stages: List<CoreProcedureStage> = emptyList(),
    val correlationQuality: CoreCorrelationConfidence = CoreCorrelationConfidence.Weak,
    val failureCauses: List<String> = emptyList(),
    val retryCount: Int = 0,
    val edges: List<CoreCorrelationEdge> = emptyList(),
    val limitations: List<String> = emptyList(),
    val partial: Boolean = false,
    val imsCorrelations: List<CoreImsCorrelation> = emptyList()
)

data class CoreCorrelationAnalysis(
    val graph: CoreCorrelationGraph = CoreCorrelationGraph(),
    val timelines: List<CoreProcedureTimeline> = emptyList(),
    val sourceTruncated: Boolean = false
)

fun CoreProcedureTimeline.toCoreSessionSummary(): CoreSessionSummary {
    val first = messages.firstOrNull()
    val keyed = messages.firstOrNull { it.correlationValue.isNotBlank() } ?: first
    return CoreSessionSummary(
        key = localCorrelationId,
        protocol = keyed?.protocol.orEmpty(),
        correlationField = keyed?.correlationField.orEmpty(),
        correlationValue = keyed?.correlationValue.orEmpty(),
        messages = messages,
        firstFrame = firstFrame,
        procedureType = procedureType,
        localCorrelationId = localCorrelationId,
        correlationQuality = correlationQuality,
        protocols = messages.map { it.protocol }.filter { it.isNotBlank() }.distinct(),
        startTime = startTime,
        endTime = endTime,
        failureCauses = failureCauses,
        retryCount = retryCount,
        stages = stages,
        edges = edges,
        limitations = limitations,
        partial = partial,
        imsCorrelations = imsCorrelations
    )
}
