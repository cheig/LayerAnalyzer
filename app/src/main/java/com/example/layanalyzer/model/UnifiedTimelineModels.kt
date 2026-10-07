package com.example.layanalyzer.model

enum class UnifiedTimelineTrack(val wireName: String, val priority: Int) {
    Radio("radio", 10),
    Core("core", 20),
    Sip("sip", 30),
    Media("media", 40),
    Transport("transport", 50)
}

/** Clock metadata retained after converting a source to epoch seconds. */
data class UnifiedTimelineClock(
    val source: String,
    val sourceClock: String = "epoch_seconds",
    val manualOffsetMillis: Long = 0L,
    val uncertaintyMillis: Long = 0L,
    val normalizedClock: String = "epoch_seconds"
)

data class UnifiedTimelineEvent(
    val id: String,
    val track: UnifiedTimelineTrack,
    val type: String,
    val startTime: Double,
    val endTime: Double,
    val source: String,
    val sourceFrames: List<Long> = emptyList(),
    val timeUncertaintyMillis: Long = 0L,
    val sourcePriority: Int = track.priority,
    val details: AgentJsonObject = emptyMap()
) {
    val uncertaintyStartTime: Double
        get() = startTime - timeUncertaintyMillis / 1000.0

    val uncertaintyEndTime: Double
        get() = endTime + timeUncertaintyMillis / 1000.0
}

/** Time proximity is deliberately represented as a candidate relationship. */
enum class TemporalCorrelationConfidence(val wireName: String, val score: Double) {
    Candidate("Candidate", 0.30),
    Weak("Weak", 0.15)
}

data class TemporalCorrelation(
    val fromEventId: String,
    val toEventId: String,
    val relation: String = "temporal_candidate",
    val startTime: Double,
    val endTime: Double,
    val windowMillis: Long,
    val confidence: TemporalCorrelationConfidence = TemporalCorrelationConfidence.Candidate,
    val basis: String = "timestamp_plus_source_uncertainty",
    val causal: Boolean = false
)

data class UnifiedNetworkTimeline(
    val events: List<UnifiedTimelineEvent> = emptyList(),
    val temporalCorrelations: List<TemporalCorrelation> = emptyList(),
    val clocks: List<UnifiedTimelineClock> = emptyList(),
    val startTime: Double = events.firstOrNull()?.startTime ?: 0.0,
    val endTime: Double = events.lastOrNull()?.endTime ?: startTime,
    val radioAvailable: Boolean = false,
    val unavailableReason: String? = null,
    val limitations: List<String> = emptyList()
)

data class UnifiedTimelineInput(
    val radio: RadioQueryResult = RadioQueryResult(),
    val communication: CommunicationAnalysis = CommunicationAnalysis(),
    val statistics: CaptureStatistics? = null,
    val expertInfo: ExpertInfoSummary? = null,
    val clocks: List<UnifiedTimelineClock> = emptyList()
)
