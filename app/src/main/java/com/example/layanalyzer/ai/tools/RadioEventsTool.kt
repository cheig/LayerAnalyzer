package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.tools.dto.AgentRadioProjections
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.RadioEventType
import com.example.layanalyzer.model.RadioSeverity
import com.example.layanalyzer.model.UnifiedNetworkTimeline
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Query supported Radio/RRC observations without claiming wireless-side health. */
class RadioEventsTool(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {
    override val definition = AgentToolDefinition(
        name = "get_radio_events",
        description = "Query supported Radio snapshots and structured Radio/RRC events in an epoch-second range.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "startTime" to mapOf("type" to "number"),
                "endTime" to mapOf("type" to "number"),
                "eventTypes" to mapOf(
                    "type" to "array",
                    "maxItems" to RadioEventType.entries.size,
                    "items" to mapOf(
                        "type" to "string",
                        "enum" to RadioEventType.entries.map { it.wireName }
                    )
                ),
                "minimumSeverity" to mapOf(
                    "type" to "string",
                    "enum" to RadioSeverity.entries.map { it.wireName }
                ),
                "limit" to mapOf(
                    "type" to "integer",
                    "minimum" to 1,
                    "maximum" to MAX_LIMIT
                )
            )
        ),
        sensitivity = AgentDataSensitivity.Identifier,
        defaultTimeoutMillis = 15_000L
    )

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val startTime = (arguments["startTime"] as? Number)?.toDouble()
        val endTime = (arguments["endTime"] as? Number)?.toDouble()
        if (startTime != null && endTime != null && endTime < startTime) {
            throw AgentToolException(
                code = com.example.layanalyzer.model.AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "The Radio time range is invalid.",
                details = mapOf("field" to "endTime")
            )
        }
        val types = parseTypes(arguments["eventTypes"])
        val minimumSeverity = parseSeverity(arguments["minimumSeverity"])
        val limit = ((arguments["limit"] as? Number)?.toInt() ?: DEFAULT_LIMIT)
            .coerceIn(1, MAX_LIMIT)
        val result = when (
            val reading = context.repository.getRadioEvents(
                snapshot = context.snapshot,
                startTime = startTime,
                endTime = endTime,
                eventTypes = types,
                minimumSeverity = minimumSeverity,
                limit = limit
            )
        ) {
            is AgentAnalysisResult.Failure -> throw AgentToolException(reading.error)
            is AgentAnalysisResult.Success -> reading.value
        }
        context.ensureStillValid(context.snapshot)
        val data = withContext(ioDispatcher) {
            buildMap<String, Any?> {
                put("startTime", startTime)
                put("endTime", endTime)
                put("eventTypes", types.map { it.wireName })
                put("minimumSeverity", minimumSeverity.wireName)
                put("limit", limit)
                putAll(AgentRadioProjections.query(result))
            }
        }
        return context.success(
            data = data,
            returnedCount = result.returned.toLong(),
            totalCount = result.total.toLong(),
            truncated = result.truncated
        )
    }

    private fun parseTypes(raw: Any?): Set<RadioEventType> {
        if (raw == null) return emptySet()
        return (raw as? Iterable<*>)?.map {
            RadioEventType.fromWire(it as? String)
                ?: throw AgentToolException(
                    code = com.example.layanalyzer.model.AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                    userMessage = "The Radio event type is invalid.",
                    details = mapOf("field" to "eventTypes")
                )
        }?.toSet().orEmpty()
    }

    private fun parseSeverity(raw: Any?): RadioSeverity {
        if (raw == null) return RadioSeverity.Info
        return RadioSeverity.fromWire(raw as? String)
            ?: throw AgentToolException(
                code = com.example.layanalyzer.model.AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "The Radio severity is invalid.",
                details = mapOf("field" to "minimumSeverity")
            )
    }

    private companion object {
        const val DEFAULT_LIMIT = 20
        const val MAX_LIMIT = 100
    }
}

/** Query the cross-layer timeline assembled from Radio, core, IMS, media, and transport facts. */
class UnifiedNetworkTimelineTool(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {
    override val definition = AgentToolDefinition(
        name = "get_unified_network_timeline",
        description = "Build a source-aware epoch-second timeline and temporal candidate correlations across Radio and network layers.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "startTime" to mapOf("type" to "number"),
                "endTime" to mapOf("type" to "number"),
                "eventTypes" to mapOf(
                    "type" to "array",
                    "maxItems" to RadioEventType.entries.size,
                    "items" to mapOf("type" to "string", "enum" to RadioEventType.entries.map { it.wireName })
                ),
                "minimumSeverity" to mapOf("type" to "string", "enum" to RadioSeverity.entries.map { it.wireName }),
                "maxEvents" to mapOf("type" to "integer", "minimum" to 1, "maximum" to MAX_EVENTS),
                "filter" to mapOf("type" to "string", "maxLength" to MAX_FILTER_LENGTH)
            )
        ),
        sensitivity = AgentDataSensitivity.Identifier,
        defaultTimeoutMillis = 30_000L
    )

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val startTime = (arguments["startTime"] as? Number)?.toDouble()
        val endTime = (arguments["endTime"] as? Number)?.toDouble()
        if (startTime != null && endTime != null && endTime < startTime) {
            throw AgentToolException(
                code = com.example.layanalyzer.model.AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "The timeline time range is invalid.",
                details = mapOf("field" to "endTime")
            )
        }
        val types = parseTypes(arguments["eventTypes"])
        val minimumSeverity = parseSeverity(arguments["minimumSeverity"])
        val maxEvents = ((arguments["maxEvents"] as? Number)?.toInt() ?: DEFAULT_MAX_EVENTS)
            .coerceIn(1, MAX_EVENTS)
        val filter = (arguments["filter"] as? String)?.trim().orEmpty()
        val timeline = when (
            val reading = context.repository.getUnifiedNetworkTimeline(
                snapshot = context.snapshot,
                filter = filter,
                startTime = startTime,
                endTime = endTime,
                eventTypes = types,
                minimumSeverity = minimumSeverity,
                radioLimit = MAX_RADIO_EVENTS
            )
        ) {
            is AgentAnalysisResult.Failure -> throw AgentToolException(reading.error)
            is AgentAnalysisResult.Success -> reading.value
        }
        context.ensureStillValid(context.snapshot)
        val bounded = timeline.within(startTime, endTime)
        val data = withContext(ioDispatcher) {
            buildMap<String, Any?> {
                put("startTime", startTime)
                put("endTime", endTime)
                put("eventTypes", types.map { it.wireName })
                put("minimumSeverity", minimumSeverity.wireName)
                put("maxEvents", maxEvents)
                put("filter", filter)
                putAll(AgentRadioProjections.timeline(bounded, maxEvents))
            }
        }
        return context.success(
            data = data,
            returnedCount = minOf(bounded.events.size, maxEvents).toLong(),
            totalCount = bounded.events.size.toLong(),
            truncated = bounded.events.size > maxEvents || bounded.temporalCorrelations.size >= MAX_CORRELATIONS
        )
    }

    private fun parseTypes(raw: Any?): Set<RadioEventType> {
        if (raw == null) return emptySet()
        return (raw as? Iterable<*>)?.map {
            RadioEventType.fromWire(it as? String)
                ?: throw AgentToolException(
                    code = com.example.layanalyzer.model.AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                    userMessage = "The Radio event type is invalid.",
                    details = mapOf("field" to "eventTypes")
                )
        }?.toSet().orEmpty()
    }

    private fun parseSeverity(raw: Any?): RadioSeverity {
        if (raw == null) return RadioSeverity.Info
        return RadioSeverity.fromWire(raw as? String)
            ?: throw AgentToolException(
                code = com.example.layanalyzer.model.AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "The Radio severity is invalid.",
                details = mapOf("field" to "minimumSeverity")
            )
    }

    private fun UnifiedNetworkTimeline.within(start: Double?, end: Double?): UnifiedNetworkTimeline {
        if (start == null && end == null) return this
        val selected = events.filter { event ->
            (start == null || event.endTime >= start) && (end == null || event.startTime <= end)
        }
        val ids = selected.mapTo(mutableSetOf()) { it.id }
        val correlations = temporalCorrelations.filter { it.fromEventId in ids && it.toEventId in ids }
        return copy(
            events = selected,
            temporalCorrelations = correlations,
            startTime = selected.minOfOrNull { it.startTime } ?: start ?: this.startTime,
            endTime = selected.maxOfOrNull { it.endTime } ?: end ?: this.endTime
        )
    }

    private companion object {
        const val DEFAULT_MAX_EVENTS = 200
        const val MAX_EVENTS = 500
        const val MAX_RADIO_EVENTS = 100
        const val MAX_FILTER_LENGTH = 2_048
        const val MAX_CORRELATIONS = 2_000
    }
}
