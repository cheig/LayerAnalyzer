// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data.radio

import com.example.layanalyzer.model.RadioEvent
import com.example.layanalyzer.model.RadioEventConfidence
import com.example.layanalyzer.model.RadioEventType
import com.example.layanalyzer.model.RadioImportSummary
import com.example.layanalyzer.model.RadioQueryResult
import com.example.layanalyzer.model.RadioSeverity
import com.example.layanalyzer.model.RadioSignalMetrics
import com.example.layanalyzer.model.RadioSnapshot
import com.example.layanalyzer.model.RadioSourceCapability
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeParseException
import java.util.Locale

/**
 * Read-only source contract for Radio data.  An adapter must never return raw
 * subscriber, cell, or geographic identifiers; the repository applies the
 * import boundary to structured logs and keeps the public model alias-only.
 */
interface RadioSourceAdapter {
    val sourceId: String
    val capabilities: RadioSourceCapability

    fun readSnapshots(): List<RadioSnapshot> = emptyList()

    fun readEvents(): List<RadioEvent> = emptyList()
}

/**
 * Repository for supported Radio snapshots and events.
 *
 * Imported data is retained in memory for the active capture workspace.  The
 * repository intentionally has no file-path API: callers provide bounded
 * structured content, which keeps parsing and privacy checks at one boundary.
 */
class RadioRepository(
    private val adapters: List<RadioSourceAdapter> = emptyList(),
    private val maxImportBytes: Int = MAX_IMPORT_BYTES
) {
    private val lock = Any()
    private val importedEvents = mutableListOf<RadioEvent>()
    private val importedSnapshots = mutableListOf<RadioSnapshot>()
    private val importedSources = linkedSetOf<String>()
    private val _snapshots = MutableStateFlow<List<RadioSnapshot>>(emptyList())

    init {
        refreshSnapshots()
    }

    /** Snapshots observed from imports and currently configured adapters. */
    fun observeSnapshots(): StateFlow<List<RadioSnapshot>> = _snapshots.asStateFlow()

    /** Re-read adapter snapshots and publish the current immutable snapshot list. */
    fun refreshSnapshots(): List<RadioSnapshot> = synchronized(lock) {
        val adapterSnapshots = adapters.flatMap { adapter ->
            runCatching { adapter.readSnapshots() }.getOrDefault(emptyList())
        }
        val merged = (importedSnapshots + adapterSnapshots)
            .filter { it.timestamp.isFinite() }
            .sortedWith(compareBy({ it.timestamp }, { it.source }, { it.rat }))
            .distinctBy(::snapshotIdentity)
        _snapshots.value = merged
        merged
    }

    /** A property is convenient for UI and application wiring. */
    val sourceCapabilities: List<RadioSourceCapability>
        get() = capabilitiesSnapshot()

    /** A function form keeps the repository convenient for non-Compose callers. */
    fun sourceCapabilities(): List<RadioSourceCapability> = capabilitiesSnapshot()

    /**
     * Import a UTF-8 structured Radio document.  Failure is represented as a
     * Result with a generic, safe exception message; no partial data is kept.
     */
    fun importEvents(json: String): Result<RadioImportSummary> =
        if (json.length > maxImportBytes || json.length > MAX_IMPORT_BYTES) {
            Result.failure(IllegalArgumentException("Radio import is too large."))
        } else {
            importEvents(json.toByteArray(StandardCharsets.UTF_8))
        }

    fun importEvents(bytes: ByteArray): Result<RadioImportSummary> {
        if (bytes.size > maxImportBytes || bytes.size > MAX_IMPORT_BYTES) {
            return Result.failure(IllegalArgumentException("Radio import is too large."))
        }
        val parsed = try {
            parseDocument(String(bytes, StandardCharsets.UTF_8))
        } catch (error: RadioImportException) {
            return Result.failure(error)
        } catch (_: Exception) {
            return Result.failure(IllegalArgumentException("Radio import is malformed."))
        }

        synchronized(lock) {
            importedEvents += parsed.events
            importedSnapshots += parsed.snapshots
            importedSources += parsed.source
            importedSources += parsed.events.map { it.source }
            importedSources += parsed.snapshots.map { it.source }
            val derived = deriveSnapshotEvents(parsed.snapshots)
            importedEvents += derived
            refreshSnapshots()
            return Result.success(
                RadioImportSummary(
                    source = parsed.source,
                    importedEvents = parsed.events.size,
                    importedSnapshots = parsed.snapshots.size,
                    derivedEvents = derived.size,
                    timeBase = parsed.timeBase,
                    timezone = parsed.timezone
                )
            )
        }
    }

    /** Import an already validated adapter payload without going through JSON. */
    fun importEvents(events: List<RadioEvent>, snapshots: List<RadioSnapshot> = emptyList()): Result<RadioImportSummary> {
        if (events.size > MAX_IMPORT_ITEMS || snapshots.size > MAX_IMPORT_ITEMS) {
            return Result.failure(IllegalArgumentException("Radio import contains too many entries."))
        }
        if (events.any { it.source.isBlank() } || snapshots.any { it.source.isBlank() }) {
            return Result.failure(IllegalArgumentException("Radio import source is missing."))
        }
        if (events.any { !it.startTime.isFinite() || !it.endTime.isFinite() || it.endTime < it.startTime } ||
            snapshots.any { !it.timestamp.isFinite() }
        ) {
            return Result.failure(IllegalArgumentException("Radio import contains invalid timestamps."))
        }
        val sources = (events.map { it.source } + snapshots.map { it.source }).distinct()
        val source = sources.firstOrNull()
            ?: return Result.failure(IllegalArgumentException("Radio import source is missing."))
        synchronized(lock) {
            importedEvents += events
            importedSnapshots += snapshots
            importedSources += sources
            val derived = deriveSnapshotEvents(snapshots)
            importedEvents += derived
            refreshSnapshots()
            return Result.success(
                RadioImportSummary(
                    source = source,
                    importedEvents = events.size,
                    importedSnapshots = snapshots.size,
                    derivedEvents = derived.size,
                    timeBase = "epoch_seconds",
                    timezone = "UTC"
                )
            )
        }
    }

    fun importEvents(document: JSONObject): Result<RadioImportSummary> = importEvents(document.toString())

    /** Remove only in-memory imported data; adapter data is unaffected. */
    fun clearImported() = synchronized(lock) {
        importedEvents.clear()
        importedSnapshots.clear()
        importedSources.clear()
        refreshSnapshots()
    }

    fun queryEvents(
        startTime: Double? = null,
        endTime: Double? = null,
        types: Set<RadioEventType> = emptySet(),
        limit: Int = MAX_QUERY_LIMIT,
        minimumSeverity: RadioSeverity = RadioSeverity.Info
    ): RadioQueryResult = synchronized(lock) {
        val adapterEvents = adapters.flatMap { adapter ->
            runCatching { adapter.readEvents() }.getOrDefault(emptyList())
        }
        val adapterSnapshots = adapters.flatMap { adapter ->
            runCatching { adapter.readSnapshots() }.getOrDefault(emptyList())
        }
        val derived = deriveSnapshotEvents(importedSnapshots + adapterSnapshots)
        val allEvents = (importedEvents + adapterEvents + derived)
            .filter { it.startTime.isFinite() && it.endTime.isFinite() }
            .distinctBy(::eventIdentity)
            .sortedWith(eventComparator)
        val matching = allEvents.filter { event ->
            (startTime == null || effectiveEndTime(event) >= startTime) &&
                (endTime == null || effectiveStartTime(event) <= endTime) &&
                (types.isEmpty() || event.type in types) &&
                event.severity.rank >= minimumSeverity.rank
        }
        val boundedLimit = limit.coerceIn(1, MAX_QUERY_LIMIT)
        val page = matching.take(boundedLimit)
        val capabilities = capabilitiesSnapshot()
        val unavailable = if (allEvents.isEmpty()) {
            unavailableReason(capabilities)
        } else {
            null
        }
        RadioQueryResult(
            events = page,
            returned = page.size,
            total = matching.size,
            truncated = matching.size > page.size,
            unavailableReason = unavailable,
            sourceCapabilities = capabilities,
            dataAvailable = allEvents.isNotEmpty() || importedSnapshots.isNotEmpty() || adapterSnapshots.isNotEmpty()
        )
    }

    private fun capabilitiesSnapshot(): List<RadioSourceCapability> = synchronized(lock) {
        val result = mutableListOf<RadioSourceCapability>()
        result += adapters.map { adapter ->
            runCatching { adapter.capabilities }.getOrElse {
                RadioSourceCapability(
                    source = adapter.sourceId,
                    available = false,
                    supportsSnapshots = false,
                    supportsEvents = false,
                    description = "Radio adapter",
                    unavailableReason = "Radio adapter is unavailable."
                )
            }
        }
        importedSources.forEach { source ->
            result += RadioSourceCapability(
                source = source,
                available = true,
                supportsSnapshots = importedSnapshots.any { it.source == source },
                supportsEvents = importedEvents.any { it.source == source },
                description = "User-imported structured Radio log"
            )
        }
        if (result.isEmpty()) {
            result += RadioSourceCapability(
                source = "radio",
                available = false,
                supportsSnapshots = false,
                supportsEvents = false,
                description = "Supported Telephony, structured-log, or Wireshark Radio sources",
                unavailableReason = NO_RADIO_SOURCE_REASON
            )
        }
        result.distinctBy { it.source }
    }

    private fun unavailableReason(capabilities: List<RadioSourceCapability>): String =
        if (capabilities.any { it.available }) {
            "No Radio events were observed in the requested range. This does not establish that the wireless side was healthy."
        } else {
            capabilities.firstNotNullOfOrNull { it.unavailableReason } ?: NO_RADIO_SOURCE_REASON
        }

    private fun parseDocument(json: String): ParsedRadioDocument {
        if (json.length > maxImportBytes || json.length > MAX_IMPORT_BYTES) {
            throw RadioImportException("Radio import is too large.")
        }
        val root = try {
            JSONObject(json)
        } catch (_: Exception) {
            throw RadioImportException("Radio import is malformed.")
        }
        if (containsSensitiveGeography(root)) {
            throw RadioImportException("Radio import contains unsupported geographic data.")
        }
        val schemaVersion = root.opt("schemaVersion")
        if (schemaVersion !is Number || schemaVersion.toDouble() != SCHEMA_VERSION.toDouble()) {
            throw RadioImportException("Radio import schema is unsupported.")
        }
        val timeBase = root.stringValue("timeBase")
            ?: root.optJSONObject("timeBase")?.stringValue("kind")
            ?: throw RadioImportException("Radio import time base is missing.")
        val normalizedTimeBase = normalizeTimeBase(timeBase)
        val timezone = root.stringValue("timezone") ?: "UTC"
        try {
            ZoneId.of(timezone)
        } catch (_: Exception) {
            throw RadioImportException("Radio import timezone is invalid.")
        }
        val source = (root.stringValue("source")
            ?: root.stringValue("sourceDescription")
            ?: "imported_radio_log").bounded("source", MAX_SOURCE_LENGTH)
        val anchor = root.numberValue("epochStartSeconds")
            ?: root.numberValue("startTimeEpochSeconds")
            ?: root.numberValue("epochStart")
        if (normalizedTimeBase in RELATIVE_TIME_BASES && anchor == null) {
            throw RadioImportException("Relative Radio timestamps need an epoch anchor.")
        }
        val defaultOffset = boundedOffset(root.longValue("manualOffsetMillis") ?: 0L)
        val defaultUncertainty = boundedUncertainty(root.longValue("timeUncertaintyMillis") ?: 0L)
        val eventsArray = root.optJSONArray("events") ?: root.optJSONArray("radioEvents") ?: JSONArray()
        val snapshotsArray = root.optJSONArray("snapshots") ?: root.optJSONArray("radioSnapshots") ?: JSONArray()
        if (eventsArray.length() > MAX_IMPORT_ITEMS || snapshotsArray.length() > MAX_IMPORT_ITEMS) {
            throw RadioImportException("Radio import contains too many entries.")
        }
        val events = (0 until eventsArray.length()).map { index ->
            val item = eventsArray.optJSONObject(index) ?: throw RadioImportException("Radio event is malformed.")
            parseEvent(item, source, normalizedTimeBase, anchor, defaultOffset, defaultUncertainty)
        }
        val snapshots = (0 until snapshotsArray.length()).map { index ->
            val item = snapshotsArray.optJSONObject(index) ?: throw RadioImportException("Radio snapshot is malformed.")
            parseSnapshot(item, source, normalizedTimeBase, anchor, defaultOffset, defaultUncertainty)
        }
        return ParsedRadioDocument(
            source = source,
            timeBase = normalizedTimeBase,
            timezone = timezone,
            events = events,
            snapshots = snapshots
        )
    }

    private fun parseEvent(
        item: JSONObject,
        defaultSource: String,
        timeBase: String,
        anchor: Double?,
        defaultOffset: Long,
        defaultUncertainty: Long
    ): RadioEvent {
        val type = RadioEventType.fromWire(item.stringValue("type"))
            ?: throw RadioImportException("Radio event type is unsupported.")
        val start = parseTimestamp(item.opt("startTime") ?: item.opt("timestamp"), timeBase, anchor)
            ?: throw RadioImportException("Radio event start time is missing.")
        val end = parseTimestamp(item.opt("endTime"), timeBase, anchor) ?: start
        if (end < start) throw RadioImportException("Radio event time range is invalid.")
        val severity = item.stringValue("severity")?.let(RadioSeverity::fromWire)
            ?: RadioSeverity.Notice
        val confidence = item.stringValue("confidence")?.let(RadioEventConfidence::fromWire)
            ?: RadioEventConfidence.Medium
        val observations = parseObservations(item.optJSONObject("observations"))
        val sourceFrames = parseFrames(item.optJSONArray("sourceFrames"))
        val source = (item.stringValue("source") ?: defaultSource).bounded("source", MAX_SOURCE_LENGTH)
        val uncertainty = boundedUncertainty(item.longValue("timeUncertaintyMillis") ?: defaultUncertainty)
        val offset = boundedOffset(item.longValue("manualOffsetMillis") ?: defaultOffset)
        val metricsBefore = parseMetrics(item.optJSONObject("signalMetricsBefore"))
        val metricsAfter = parseMetrics(item.optJSONObject("signalMetricsAfter"))
        return RadioEvent(
            type = type,
            startTime = start,
            endTime = end,
            severity = severity,
            observations = observations,
            sourceFrames = sourceFrames,
            confidence = confidence,
            source = source,
            timeUncertaintyMillis = uncertainty,
            rat = item.stringValue("rat").orEmpty().bounded("rat", MAX_VALUE_LENGTH),
            cellIdAlias = item.primitiveStringValue("cellIdAlias")?.let(::normalizeCellIdAlias)
                ?: item.primitiveStringValue("cellId")?.let(::aliasCellId),
            signalMetricsBefore = metricsBefore,
            signalMetricsAfter = metricsAfter,
            sourceClock = item.stringValue("sourceClock") ?: timeBase,
            manualOffsetMillis = offset
        )
    }

    private fun parseSnapshot(
        item: JSONObject,
        defaultSource: String,
        timeBase: String,
        anchor: Double?,
        defaultOffset: Long,
        defaultUncertainty: Long
    ): RadioSnapshot {
        val timestamp = parseTimestamp(item.opt("timestamp") ?: item.opt("startTime"), timeBase, anchor)
            ?: throw RadioImportException("Radio snapshot timestamp is missing.")
        val source = (item.stringValue("source") ?: defaultSource).bounded("source", MAX_SOURCE_LENGTH)
        val uncertainty = boundedUncertainty(item.longValue("timeUncertaintyMillis") ?: defaultUncertainty)
        val offset = boundedOffset(item.longValue("manualOffsetMillis") ?: defaultOffset)
        val cell = item.primitiveStringValue("cellIdAlias") ?: item.primitiveStringValue("cellId")
        return RadioSnapshot(
            timestamp = timestamp,
            rat = item.stringValue("rat").orEmpty().ifBlank { "UNKNOWN" }.bounded("rat", MAX_VALUE_LENGTH),
            cellIdAlias = cell?.let(::normalizeCellIdAlias),
            signalMetrics = parseMetrics(item.optJSONObject("signalMetrics")) ?: RadioSignalMetrics(),
            registrationState = item.stringValue("registrationState").orEmpty().bounded("registrationState", MAX_VALUE_LENGTH),
            dataState = item.stringValue("dataState").orEmpty().bounded("dataState", MAX_VALUE_LENGTH),
            source = source,
            timeUncertaintyMillis = uncertainty,
            sourceClock = item.stringValue("sourceClock") ?: timeBase,
            manualOffsetMillis = offset
        )
    }

    private fun parseTimestamp(raw: Any?, timeBase: String, anchor: Double?): Double? {
        if (raw == null || raw == JSONObject.NULL) return null
        val value = when (raw) {
            is Number -> raw.toDouble()
            is String -> raw.toDoubleOrNull() ?: parseInstant(raw)
            else -> null
        } ?: throw RadioImportException("Radio timestamp is malformed.")
        if (!value.isFinite()) throw RadioImportException("Radio timestamp is invalid.")
        val epoch = when (timeBase) {
            "epoch_seconds" -> value
            "epoch_millis" -> value / 1000.0
            in RELATIVE_TIME_BASES -> (anchor ?: throw RadioImportException("Radio epoch anchor is missing.")) +
                if (timeBase == "monotonic_millis") value / 1000.0 else value
            else -> throw RadioImportException("Radio time base is unsupported.")
        }
        if (!epoch.isFinite()) throw RadioImportException("Radio timestamp is invalid.")
        return epoch
    }

    private fun parseInstant(value: String): Double? = try {
        Instant.parse(value).toEpochMilli() / 1000.0
    } catch (_: DateTimeParseException) {
        null
    }

    private fun parseMetrics(item: JSONObject?): RadioSignalMetrics? {
        if (item == null) return null
        val known = setOf("rsrpDbm", "rsrqDb", "sinrDb", "rssiDbm", "asu", "level")
        val values = linkedMapOf<String, Double>()
        item.keys().forEach { name ->
            val value = item.numberValue(name)
                ?: throw RadioImportException("Radio signal metric is malformed.")
            if (!value.isFinite()) throw RadioImportException("Radio signal metric is invalid.")
            values[name.bounded("signalMetric", MAX_VALUE_LENGTH)] = value
        }
        return RadioSignalMetrics(
            rsrpDbm = values.remove("rsrpDbm"),
            rsrqDb = values.remove("rsrqDb"),
            sinrDb = values.remove("sinrDb"),
            rssiDbm = values.remove("rssiDbm"),
            asu = values.remove("asu"),
            level = values.remove("level"),
            metrics = values.filterKeys { it !in known }
        )
    }

    private fun parseObservations(item: JSONObject?): Map<String, String> {
        if (item == null) return emptyMap()
        if (item.length() > MAX_OBSERVATIONS) throw RadioImportException("Radio observations are too large.")
        return buildMap {
            item.keys().forEach { rawName ->
                val name = rawName.bounded("observation", MAX_VALUE_LENGTH)
                val rawValue = item.opt(rawName)
                val value = when (rawValue) {
                    null, JSONObject.NULL -> ""
                    is String, is Number, is Boolean -> rawValue.toString().bounded("observation", MAX_VALUE_LENGTH)
                    else -> throw RadioImportException("Radio observation is malformed.")
                }
                put(name, if (isIdentifierName(name)) aliasIdentifier(value, "id") else value)
            }
        }
    }

    private fun parseFrames(array: JSONArray?): List<Long> {
        if (array == null) return emptyList()
        if (array.length() > MAX_SOURCE_FRAMES) throw RadioImportException("Radio source frame list is too large.")
        return (0 until array.length()).map { index ->
            val frame = array.opt(index)
            val value = when (frame) {
                is Number -> frame.toLong()
                is String -> frame.toLongOrNull()
                else -> null
            }
            if (value == null || value < 1L) throw RadioImportException("Radio source frame is invalid.")
            value
        }.distinct()
    }

    private fun deriveSnapshotEvents(snapshots: List<RadioSnapshot>): List<RadioEvent> =
        snapshots
            .groupBy { it.source }
            .values
            .flatMap(::deriveSnapshotEventsForSource)
            .sortedWith(eventComparator)

    private fun deriveSnapshotEventsForSource(snapshots: List<RadioSnapshot>): List<RadioEvent> {
        val ordered = snapshots.sortedWith(compareBy({ it.timestamp }, { it.source }, { it.rat }))
        if (ordered.size < 2) return emptyList()
        return ordered.zipWithNext().flatMap { (before, after) ->
            val uncertainty = maxOf(before.timeUncertaintyMillis, after.timeUncertaintyMillis)
            val common = mapOf("beforeTimestamp" to before.timestamp.toString(), "afterTimestamp" to after.timestamp.toString())
            buildList {
                if (!before.rat.equals(after.rat, ignoreCase = true) && after.rat.isNotBlank()) {
                    add(
                        RadioEvent(
                            type = RadioEventType.RatChange,
                            startTime = before.timestamp,
                            endTime = after.timestamp,
                            severity = RadioSeverity.Notice,
                            observations = common + mapOf("beforeRat" to before.rat, "afterRat" to after.rat),
                            confidence = RadioEventConfidence.Medium,
                            source = after.source,
                            timeUncertaintyMillis = uncertainty,
                            rat = after.rat,
                            cellIdAlias = after.cellIdAlias,
                            sourceClock = after.sourceClock,
                            manualOffsetMillis = after.manualOffsetMillis
                        )
                    )
                }
                if (before.cellIdAlias != null && after.cellIdAlias != null &&
                    before.cellIdAlias != after.cellIdAlias
                ) {
                    add(
                        RadioEvent(
                            type = RadioEventType.CellChangeCandidate,
                            startTime = before.timestamp,
                            endTime = after.timestamp,
                            severity = RadioSeverity.Notice,
                            observations = common + mapOf(
                                "beforeCellIdAlias" to before.cellIdAlias,
                                "afterCellIdAlias" to after.cellIdAlias
                            ),
                            confidence = RadioEventConfidence.Low,
                            source = after.source,
                            timeUncertaintyMillis = uncertainty,
                            rat = after.rat,
                            cellIdAlias = after.cellIdAlias,
                            sourceClock = after.sourceClock,
                            manualOffsetMillis = after.manualOffsetMillis
                        )
                    )
                }
                val signalBefore = before.signalMetrics.primaryValue()
                val signalAfter = after.signalMetrics.primaryValue()
                if (signalBefore != null && signalAfter != null && signalBefore - signalAfter >= SIGNAL_DROP_THRESHOLD) {
                    add(
                        RadioEvent(
                            type = RadioEventType.SignalDrop,
                            startTime = before.timestamp,
                            endTime = after.timestamp,
                            severity = RadioSeverity.Warning,
                            observations = common + mapOf(
                                "beforeSignal" to signalBefore.toString(),
                                "afterSignal" to signalAfter.toString()
                            ),
                            confidence = RadioEventConfidence.Medium,
                            source = after.source,
                            timeUncertaintyMillis = uncertainty,
                            rat = after.rat,
                            cellIdAlias = after.cellIdAlias,
                            signalMetricsBefore = before.signalMetrics,
                            signalMetricsAfter = after.signalMetrics,
                            sourceClock = after.sourceClock,
                            manualOffsetMillis = after.manualOffsetMillis
                        )
                    )
                }
                val wasOut = isOutOfService(before.registrationState)
                val isOut = isOutOfService(after.registrationState)
                if (!wasOut && isOut) {
                    add(
                        RadioEvent(
                            type = RadioEventType.OutOfService,
                            startTime = after.timestamp,
                            severity = RadioSeverity.Error,
                            observations = common + mapOf("registrationState" to after.registrationState),
                            confidence = RadioEventConfidence.Medium,
                            source = after.source,
                            timeUncertaintyMillis = uncertainty,
                            rat = after.rat,
                            cellIdAlias = after.cellIdAlias,
                            sourceClock = after.sourceClock,
                            manualOffsetMillis = after.manualOffsetMillis
                        )
                    )
                } else if (wasOut && !isOut) {
                    add(
                        RadioEvent(
                            type = RadioEventType.Recovery,
                            startTime = after.timestamp,
                            severity = RadioSeverity.Notice,
                            observations = common + mapOf("registrationState" to after.registrationState),
                            confidence = RadioEventConfidence.Medium,
                            source = after.source,
                            timeUncertaintyMillis = uncertainty,
                            rat = after.rat,
                            cellIdAlias = after.cellIdAlias,
                            sourceClock = after.sourceClock,
                            manualOffsetMillis = after.manualOffsetMillis
                        )
                    )
                }
                if (!isDataConnected(before.dataState) && isDataConnected(after.dataState)) {
                    add(
                        RadioEvent(
                            type = RadioEventType.Recovery,
                            startTime = after.timestamp,
                            severity = RadioSeverity.Notice,
                            observations = common + mapOf("dataState" to after.dataState),
                            confidence = RadioEventConfidence.Low,
                            source = after.source,
                            timeUncertaintyMillis = uncertainty,
                            rat = after.rat,
                            cellIdAlias = after.cellIdAlias,
                            sourceClock = after.sourceClock,
                            manualOffsetMillis = after.manualOffsetMillis
                        )
                    )
                } else if (isDataConnected(before.dataState) && !isDataConnected(after.dataState)) {
                    add(
                        RadioEvent(
                            type = RadioEventType.DataDisconnected,
                            startTime = after.timestamp,
                            severity = RadioSeverity.Warning,
                            observations = common + mapOf("dataState" to after.dataState),
                            confidence = RadioEventConfidence.Medium,
                            source = after.source,
                            timeUncertaintyMillis = uncertainty,
                            rat = after.rat,
                            cellIdAlias = after.cellIdAlias,
                            sourceClock = after.sourceClock,
                            manualOffsetMillis = after.manualOffsetMillis
                        )
                    )
                }
            }
        }
    }

    private fun isOutOfService(state: String): Boolean = state.lowercase(Locale.US) in setOf(
        "out_of_service", "out-of-service", "not_registered", "denied", "emergency_only", "no_service"
    )

    private fun isDataConnected(state: String): Boolean = state.lowercase(Locale.US) in setOf(
        "connected", "data_connected", "connected_home", "connected_roaming", "in_service"
    )

    private fun snapshotIdentity(snapshot: RadioSnapshot): String = listOf(
        snapshot.timestamp,
        snapshot.source,
        snapshot.rat,
        snapshot.cellIdAlias,
        snapshot.registrationState,
        snapshot.dataState,
        snapshot.signalMetrics.toMap(),
        snapshot.timeUncertaintyMillis,
        snapshot.sourceClock,
        snapshot.manualOffsetMillis
    ).joinToString("|")

    private fun eventIdentity(event: RadioEvent): String = listOf(
        event.type.wireName,
        event.startTime,
        event.endTime,
        event.source,
        event.sourceFrames,
        event.rat,
        event.cellIdAlias,
        event.observations,
        event.sourceClock,
        event.manualOffsetMillis
    ).joinToString("|")

    private fun effectiveStartTime(event: RadioEvent): Double = event.normalizedStartTime

    private fun effectiveEndTime(event: RadioEvent): Double = event.normalizedEndTime

    private fun normalizeTimeBase(value: String): String = when (value.trim().lowercase(Locale.US)
        .replace('-', '_').replace(' ', '_')) {
        "epoch_seconds", "epoch", "unix_seconds" -> "epoch_seconds"
        "epoch_millis", "unix_millis", "epoch_milliseconds" -> "epoch_millis"
        "relative_seconds", "relative", "monotonic_seconds" -> "relative_seconds"
        "monotonic_millis", "monotonic_milliseconds" -> "monotonic_millis"
        else -> throw RadioImportException("Radio time base is unsupported.")
    }

    private fun boundedUncertainty(value: Long): Long {
        if (value < 0L || value > MAX_UNCERTAINTY_MILLIS) {
            throw RadioImportException("Radio time uncertainty is invalid.")
        }
        return value
    }

    private fun boundedOffset(value: Long): Long {
        if (value < -MAX_MANUAL_OFFSET_MILLIS || value > MAX_MANUAL_OFFSET_MILLIS) {
            throw RadioImportException("Radio manual clock offset is invalid.")
        }
        return value
    }

    private fun containsSensitiveGeography(value: Any?): Boolean = when (value) {
        is JSONObject -> value.keys().asSequence().any { key ->
            isGeographicKey(key) || containsSensitiveGeography(value.opt(key))
        }
        is JSONArray -> (0 until value.length()).any { containsSensitiveGeography(value.opt(it)) }
        else -> false
    }

    private fun isGeographicKey(value: String): Boolean {
        val key = value.lowercase(Locale.US).replace('-', '_')
        return key in setOf("latitude", "longitude", "lat", "lon", "lng", "altitude", "geohash", "location", "geo") ||
            key.contains("latitude") || key.contains("longitude")
    }

    private fun isIdentifierName(value: String): Boolean {
        val key = value.lowercase(Locale.US).replace('-', '_')
        return key.contains("cell") || key.contains("subscriber") || key.contains("imsi") ||
            key.contains("imei") || key.contains("supi") || key.contains("user") || key.endsWith("_id")
    }

    private fun aliasCellId(value: String): String = aliasIdentifier(value, "cell")

    private fun normalizeCellIdAlias(value: String): String {
        val bounded = value.bounded("cellIdAlias", MAX_VALUE_LENGTH)
        return if (CELL_ALIAS_PATTERN.matches(bounded)) bounded else aliasCellId(bounded)
    }

    private fun aliasIdentifier(value: String, prefix: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { byte -> "%02x".format(Locale.US, byte) }
        return "$prefix-${digest.take(16)}"
    }

    private fun JSONObject.stringValue(name: String): String? =
        opt(name).takeUnless { it == null || it == JSONObject.NULL } as? String

    private fun JSONObject.primitiveStringValue(name: String): String? = when (val value = opt(name)) {
        null, JSONObject.NULL -> null
        is String, is Number, is Boolean -> value.toString()
        else -> null
    }

    private fun JSONObject.numberValue(name: String): Double? = when (val value = opt(name)) {
        is Number -> value.toDouble()
        is String -> value.toDoubleOrNull()
        else -> null
    }

    private fun JSONObject.longValue(name: String): Long? = when (val value = opt(name)) {
        is Number -> value.toLong()
        is String -> value.toLongOrNull()
        else -> null
    }

    private fun String.bounded(field: String, maxLength: Int): String {
        if (length > maxLength) throw RadioImportException("Radio $field is too long.")
        return this
    }

    private data class ParsedRadioDocument(
        val source: String,
        val timeBase: String,
        val timezone: String,
        val events: List<RadioEvent>,
        val snapshots: List<RadioSnapshot>
    )

    private class RadioImportException(message: String) : IllegalArgumentException(message)

    private companion object {
        const val SCHEMA_VERSION = 1
        const val MAX_IMPORT_BYTES = 2 * 1024 * 1024
        const val MAX_IMPORT_ITEMS = 10_000
        const val MAX_OBSERVATIONS = 64
        const val MAX_SOURCE_FRAMES = 128
        const val MAX_SOURCE_LENGTH = 128
        const val MAX_VALUE_LENGTH = 256
        const val MAX_UNCERTAINTY_MILLIS = 86_400_000L
        const val MAX_MANUAL_OFFSET_MILLIS = 7L * 86_400_000L
        const val MAX_QUERY_LIMIT = 100
        const val SIGNAL_DROP_THRESHOLD = 8.0
        val CELL_ALIAS_PATTERN = Regex("^cell-[0-9a-f]{16}$")
        const val NO_RADIO_SOURCE_REASON =
            "No supported Radio data is available. The capture does not expose wireless-side health."
        val RELATIVE_TIME_BASES = setOf("relative_seconds", "monotonic_millis")
        val eventComparator = compareBy<RadioEvent>({ it.startTime }, { it.endTime }, { it.type.wireName }, { it.source }, { it.sourceFrames.firstOrNull() ?: Long.MAX_VALUE })
    }
}
