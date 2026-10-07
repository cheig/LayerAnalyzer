// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

/** Radio event types supported by the local analysis contract. */
enum class RadioEventType(val wireName: String) {
    RatChange("RAT_CHANGE"),
    CellChangeCandidate("CELL_CHANGE_CANDIDATE"),
    SignalDrop("SIGNAL_DROP"),
    OutOfService("OUT_OF_SERVICE"),
    Recovery("RECOVERY"),
    DataDisconnected("DATA_DISCONNECTED"),
    RegistrationFailure("REGISTRATION_FAILURE");

    companion object {
        fun fromWire(value: String?): RadioEventType? {
            val normalized = value?.trim()?.replace('-', '_')?.replace(' ', '_')?.uppercase()
                ?: return null
            return entries.firstOrNull { it.wireName == normalized || it.name.uppercase() == normalized }
        }
    }
}

enum class RadioSeverity(val wireName: String, val rank: Int) {
    Info("INFO", 0),
    Notice("NOTICE", 1),
    Warning("WARNING", 2),
    Error("ERROR", 3),
    Critical("CRITICAL", 4);

    companion object {
        fun fromWire(value: String?): RadioSeverity? {
            val normalized = value?.trim()?.replace('-', '_')?.replace(' ', '_')?.uppercase()
                ?: return null
            return entries.firstOrNull { it.wireName == normalized || it.name.uppercase() == normalized }
        }
    }
}

/** Confidence on a Radio observation, independent from temporal correlation. */
enum class RadioEventConfidence(val wireName: String, val score: Double) {
    High("High", 0.95),
    Medium("Medium", 0.70),
    Low("Low", 0.35),
    Unknown("Unknown", 0.0);

    companion object {
        fun fromWire(value: String?): RadioEventConfidence? {
            val normalized = value?.trim()?.lowercase() ?: return null
            return entries.firstOrNull { it.wireName.lowercase() == normalized || it.name.lowercase() == normalized }
        }
    }
}

/** Common signal metrics plus an extensible allow-listed numeric map. */
data class RadioSignalMetrics(
    val rsrpDbm: Double? = null,
    val rsrqDb: Double? = null,
    val sinrDb: Double? = null,
    val rssiDbm: Double? = null,
    val asu: Double? = null,
    val level: Double? = null,
    val metrics: Map<String, Double> = emptyMap()
) {
    fun toMap(): Map<String, Double> = buildMap {
        rsrpDbm?.let { put("rsrpDbm", it) }
        rsrqDb?.let { put("rsrqDb", it) }
        sinrDb?.let { put("sinrDb", it) }
        rssiDbm?.let { put("rssiDbm", it) }
        asu?.let { put("asu", it) }
        level?.let { put("level", it) }
        putAll(metrics)
    }

    fun primaryValue(): Double? = rsrpDbm ?: rssiDbm ?: sinrDb ?: level
}

/** A point-in-time snapshot obtained from a supported Radio source. */
data class RadioSnapshot(
    val timestamp: Double,
    val rat: String = "UNKNOWN",
    val cellIdAlias: String? = null,
    val signalMetrics: RadioSignalMetrics = RadioSignalMetrics(),
    val registrationState: String = "",
    val dataState: String = "",
    val source: String = "unknown",
    val timeUncertaintyMillis: Long = 0L,
    val sourceClock: String = "epoch_seconds",
    val manualOffsetMillis: Long = 0L
)

/** A Radio state transition or source-reported Radio observation. */
data class RadioEvent(
    val type: RadioEventType,
    val startTime: Double,
    val endTime: Double = startTime,
    val severity: RadioSeverity = RadioSeverity.Notice,
    val observations: Map<String, String> = emptyMap(),
    val sourceFrames: List<Long> = emptyList(),
    val confidence: RadioEventConfidence = RadioEventConfidence.Medium,
    val source: String = "unknown",
    val timeUncertaintyMillis: Long = 0L,
    val rat: String = "",
    val cellIdAlias: String? = null,
    val signalMetricsBefore: RadioSignalMetrics? = null,
    val signalMetricsAfter: RadioSignalMetrics? = null,
    val sourceClock: String = "epoch_seconds",
    val manualOffsetMillis: Long = 0L
) {
    val durationMillis: Long
        get() = ((endTime - startTime).coerceAtLeast(0.0) * 1000.0).toLong()

    val normalizedStartTime: Double
        get() = startTime + manualOffsetMillis / 1000.0

    val normalizedEndTime: Double
        get() = endTime + manualOffsetMillis / 1000.0
}

/** Capabilities and availability boundary for one Radio source. */
data class RadioSourceCapability(
    val source: String,
    val available: Boolean,
    val supportsSnapshots: Boolean,
    val supportsEvents: Boolean,
    val description: String = "",
    val unavailableReason: String? = null
)

data class RadioQueryResult(
    val events: List<RadioEvent> = emptyList(),
    val returned: Int = events.size,
    val total: Int = events.size,
    val truncated: Boolean = false,
    val unavailableReason: String? = null,
    val sourceCapabilities: List<RadioSourceCapability> = emptyList(),
    val dataAvailable: Boolean = events.isNotEmpty()
)

data class RadioImportSummary(
    val source: String,
    val importedEvents: Int,
    val importedSnapshots: Int,
    val derivedEvents: Int,
    val timeBase: String,
    val timezone: String
)
