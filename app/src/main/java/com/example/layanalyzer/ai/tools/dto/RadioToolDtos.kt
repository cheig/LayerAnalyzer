// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools.dto

import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.RadioEvent
import com.example.layanalyzer.model.RadioQueryResult
import com.example.layanalyzer.model.RadioSourceCapability
import com.example.layanalyzer.model.UnifiedNetworkTimeline
import com.example.layanalyzer.model.UnifiedTimelineEvent

/** Privacy-safe projections for Radio queries and the unified timeline. */
object AgentRadioProjections {
    fun query(result: RadioQueryResult): AgentJsonObject = mapOf(
        "events" to result.events.map(::event),
        "returned" to result.returned,
        "total" to result.total,
        "truncated" to result.truncated,
        "unavailableReason" to result.unavailableReason,
        "dataAvailable" to result.dataAvailable,
        "sourceCapabilities" to result.sourceCapabilities.map(::capability)
    )

    fun event(value: RadioEvent): AgentJsonObject = mapOf(
        "type" to value.type.wireName,
        "startTime" to value.startTime,
        "endTime" to value.endTime,
        "normalizedStartTime" to value.normalizedStartTime,
        "normalizedEndTime" to value.normalizedEndTime,
        "durationMillis" to value.durationMillis,
        "severity" to value.severity.wireName,
        "rat" to value.rat,
        "cellIdAlias" to value.cellIdAlias,
        "signalMetricsBefore" to value.signalMetricsBefore?.toMap(),
        "signalMetricsAfter" to value.signalMetricsAfter?.toMap(),
        "observations" to value.observations,
        "source" to value.source,
        "sourceFrames" to value.sourceFrames,
        "timeUncertaintyMillis" to value.timeUncertaintyMillis,
        "confidence" to value.confidence.wireName,
        "confidenceScore" to value.confidence.score,
        "sourceClock" to value.sourceClock,
        "manualOffsetMillis" to value.manualOffsetMillis,
        "uncertainStartTime" to value.startTime - value.timeUncertaintyMillis / 1000.0,
        "uncertainEndTime" to value.endTime + value.timeUncertaintyMillis / 1000.0
    )

    fun capability(value: RadioSourceCapability): AgentJsonObject = mapOf(
        "source" to value.source,
        "available" to value.available,
        "supportsSnapshots" to value.supportsSnapshots,
        "supportsEvents" to value.supportsEvents,
        "description" to value.description,
        "unavailableReason" to value.unavailableReason
    )

    fun timeline(value: UnifiedNetworkTimeline, maxEvents: Int = 200): AgentJsonObject = mapOf(
        "events" to value.events.take(maxEvents.coerceAtLeast(0)).map(::timelineEvent),
        "eventTotal" to value.events.size,
        "eventTruncated" to (value.events.size > maxEvents),
        "temporalCorrelations" to value.temporalCorrelations.take(MAX_CORRELATIONS).map { correlation ->
            mapOf(
                "fromEventId" to correlation.fromEventId,
                "toEventId" to correlation.toEventId,
                "relation" to correlation.relation,
                "startTime" to correlation.startTime,
                "endTime" to correlation.endTime,
                "windowMillis" to correlation.windowMillis,
                "confidence" to correlation.confidence.wireName,
                "confidenceScore" to correlation.confidence.score,
                "basis" to correlation.basis,
                "causal" to correlation.causal
            )
        },
        "temporalCorrelationTotal" to value.temporalCorrelations.size,
        "clocks" to value.clocks.map { clock ->
            mapOf(
                "source" to clock.source,
                "sourceClock" to clock.sourceClock,
                "manualOffsetMillis" to clock.manualOffsetMillis,
                "uncertaintyMillis" to clock.uncertaintyMillis,
                "normalizedClock" to clock.normalizedClock
            )
        },
        "startTime" to value.startTime,
        "endTime" to value.endTime,
        "radioAvailable" to value.radioAvailable,
        "unavailableReason" to value.unavailableReason,
        "limitations" to value.limitations
    )

    private fun timelineEvent(value: UnifiedTimelineEvent): AgentJsonObject = mapOf(
        "id" to value.id,
        "track" to value.track.wireName,
        "type" to value.type,
        "startTime" to value.startTime,
        "endTime" to value.endTime,
        "uncertainStartTime" to value.uncertaintyStartTime,
        "uncertainEndTime" to value.uncertaintyEndTime,
        "source" to value.source,
        "sourceFrames" to value.sourceFrames,
        "timeUncertaintyMillis" to value.timeUncertaintyMillis,
        "sourcePriority" to value.sourcePriority,
        "details" to value.details
    )

    private const val MAX_CORRELATIONS = 2_000
}
