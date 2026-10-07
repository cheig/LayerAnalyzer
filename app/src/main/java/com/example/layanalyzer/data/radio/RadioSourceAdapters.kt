// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data.radio

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.ServiceState
import android.telephony.SignalStrength
import android.telephony.TelephonyManager
import com.example.layanalyzer.model.RadioEvent
import com.example.layanalyzer.model.RadioEventConfidence
import com.example.layanalyzer.model.RadioEventType
import com.example.layanalyzer.model.RadioSnapshot
import com.example.layanalyzer.model.RadioSourceCapability
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.CoreSignalMessage

/** Simple adapter useful for controlled platforms and JVM-facing integration tests. */
class InMemoryRadioSourceAdapter(
    override val sourceId: String,
    private val snapshots: List<RadioSnapshot> = emptyList(),
    private val events: List<RadioEvent> = emptyList(),
    description: String = "Controlled Radio source"
) : RadioSourceAdapter {
    override val capabilities: RadioSourceCapability = RadioSourceCapability(
        source = sourceId,
        available = snapshots.isNotEmpty() || events.isNotEmpty(),
        supportsSnapshots = snapshots.isNotEmpty(),
        supportsEvents = events.isNotEmpty(),
        description = description,
        unavailableReason = if (snapshots.isEmpty() && events.isEmpty()) {
            "The Radio adapter has no observations."
        } else {
            null
        }
    )

    override fun readSnapshots(): List<RadioSnapshot> = snapshots

    override fun readEvents(): List<RadioEvent> = events
}

/**
 * Adapter boundary for a Wireshark or controlled dissection pipeline.
 *
 * The provider returns already structured, alias-safe events.  Keeping the
 * dissection contract here means native field support can evolve without
 * changing the Agent-facing Radio repository or tool.
 */
class WiresharkRadioSourceAdapter(
    override val sourceId: String = "wireshark-radio",
    private val eventProvider: () -> List<RadioEvent>,
    private val snapshotProvider: () -> List<RadioSnapshot> = { emptyList() }
) : RadioSourceAdapter {
    override val capabilities: RadioSourceCapability = RadioSourceCapability(
        source = sourceId,
        available = true,
        supportsSnapshots = true,
        supportsEvents = true,
        description = "Wireshark or controlled Radio/RRC dissection adapter"
    )

    override fun readSnapshots(): List<RadioSnapshot> = snapshotProvider()

    override fun readEvents(): List<RadioEvent> = eventProvider()
}

/**
 * Maps structured RRC facts already present in a communication analysis to
 * Radio events.  It is intentionally conservative: an unclassified RRC frame
 * is omitted instead of being presented as a wireless failure.
 */
class CommunicationRadioSourceAdapter(
    override val sourceId: String = "wireshark-radio",
    private val communicationProvider: () -> CommunicationAnalysis
) : RadioSourceAdapter {
    override val capabilities: RadioSourceCapability = RadioSourceCapability(
        source = sourceId,
        available = true,
        supportsSnapshots = false,
        supportsEvents = true,
        description = "Radio/RRC events exposed by the Wireshark communication analysis"
    )

    override fun readEvents(): List<RadioEvent> =
        communicationProvider().coreMessages.mapNotNull { message -> RadioEventExtractor.fromCoreMessage(message, sourceId) }
}

object RadioEventExtractor {
    fun fromCommunication(input: CommunicationAnalysis, source: String = "wireshark-radio"): List<RadioEvent> =
        input.coreMessages.mapNotNull { fromCoreMessage(it, source) }

    fun fromCoreMessage(message: CoreSignalMessage, source: String = "wireshark-radio"): RadioEvent? {
        val protocol = message.protocol.uppercase()
        val text = listOf(message.messageType, message.info, message.outcome, message.cause)
            .joinToString(" ")
            .lowercase()
        if (!protocol.contains("RRC") && !protocol.contains("RADIO")) return null
        val type = when {
            "out of service" in text || "no service" in text || "oos" in text -> RadioEventType.OutOfService
            "recover" in text || "in service" in text -> RadioEventType.Recovery
            "registration fail" in text || "registration reject" in text -> RadioEventType.RegistrationFailure
            "signal" in text || "rsrp" in text || "rsrq" in text || "sinr" in text -> RadioEventType.SignalDrop
            "handover" in text || "cell" in text || "mobility" in text -> RadioEventType.CellChangeCandidate
            "rat" in text || "system information" in text -> RadioEventType.RatChange
            else -> return null
        }
        val observations = buildMap {
            put("protocol", message.protocol)
            put("messageType", message.messageType)
            if (message.outcome.isNotBlank()) put("outcome", message.outcome)
            if (message.cause.isNotBlank()) put("cause", message.cause)
            message.fields.entries
                .filter { (name, _) ->
                    val normalized = name.lowercase()
                    normalized.contains("rsrp") || normalized.contains("rsrq") ||
                        normalized.contains("sinr") || normalized.endsWith(".rat")
                }
                .take(MAX_RADIO_OBSERVATIONS)
                .forEach { (name, value) -> put(name, value) }
        }
        return RadioEvent(
            type = type,
            startTime = message.time,
            severity = if (type == RadioEventType.OutOfService || type == RadioEventType.RegistrationFailure) {
                com.example.layanalyzer.model.RadioSeverity.Error
            } else {
                com.example.layanalyzer.model.RadioSeverity.Notice
            },
            observations = observations,
            sourceFrames = listOf(message.frameNumber),
            confidence = RadioEventConfidence.Medium,
            source = source,
            timeUncertaintyMillis = DEFAULT_CAPTURE_UNCERTAINTY_MILLIS,
            rat = message.fields.entries.firstOrNull { (name, _) -> name.endsWith(".rat", ignoreCase = true) }?.value.orEmpty()
        )
    }

    private const val MAX_RADIO_OBSERVATIONS = 16
    private const val DEFAULT_CAPTURE_UNCERTAINTY_MILLIS = 50L
}

/**
 * Best-effort Telephony snapshot adapter using app-readable state only.
 * Cell identity and location are intentionally not requested; a missing
 * permission becomes an explicit unavailable capability.
 */
class TelephonyRadioSourceAdapter(
    private val context: Context,
    private val clock: () -> Double = { System.currentTimeMillis() / 1000.0 }
) : RadioSourceAdapter {
    override val sourceId: String = "telephony"

    override val capabilities: RadioSourceCapability
        get() {
            val permitted = hasReadPhoneState()
            return RadioSourceCapability(
                source = sourceId,
                available = permitted,
                supportsSnapshots = permitted,
                supportsEvents = false,
                description = "Application-readable Telephony registration, data, RAT, and signal snapshot",
                unavailableReason = if (permitted) null else {
                    "READ_PHONE_STATE permission is unavailable; Telephony Radio snapshots cannot be read."
                }
            )
        }

    override fun readSnapshots(): List<RadioSnapshot> {
        if (!hasReadPhoneState()) return emptyList()
        val manager = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            ?: return emptyList()
        return runCatching {
            val serviceState = readServiceState(manager)
            val signal = readSignalStrength(manager)
            listOf(
                RadioSnapshot(
                    timestamp = clock(),
                    rat = ratName(manager.dataNetworkType),
                    signalMetrics = signalMetrics(signal),
                    registrationState = registrationName(serviceState?.state),
                    dataState = dataStateName(manager.dataState),
                    source = sourceId,
                    timeUncertaintyMillis = DEFAULT_UNCERTAINTY_MILLIS,
                    sourceClock = "wall_clock_epoch_seconds"
                )
            )
        }.getOrDefault(emptyList())
    }

    private fun hasReadPhoneState(): Boolean =
        context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED

    private fun readServiceState(manager: TelephonyManager): ServiceState? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            runCatching { manager.serviceState }.getOrNull()
        } else {
            null
        }

    private fun readSignalStrength(manager: TelephonyManager): SignalStrength? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            runCatching { manager.signalStrength }.getOrNull()
        } else {
            null
        }

    private fun signalMetrics(signal: SignalStrength?): com.example.layanalyzer.model.RadioSignalMetrics {
        val asu = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && signal != null) {
            runCatching {
                signal.cellSignalStrengths
                    .mapNotNull { cell -> cell.asuLevel.takeIf { it != Int.MAX_VALUE } }
                    .maxOrNull()
            }.getOrNull()
        } else {
            null
        }
        return com.example.layanalyzer.model.RadioSignalMetrics(
            asu = asu?.toDouble(),
            level = signal?.level?.toDouble()
        )
    }

    private fun ratName(networkType: Int): String = when (networkType) {
        TelephonyManager.NETWORK_TYPE_NR -> "NR"
        TelephonyManager.NETWORK_TYPE_LTE -> "LTE"
        TelephonyManager.NETWORK_TYPE_HSDPA,
        TelephonyManager.NETWORK_TYPE_HSUPA,
        TelephonyManager.NETWORK_TYPE_HSPA,
        TelephonyManager.NETWORK_TYPE_HSPAP,
        TelephonyManager.NETWORK_TYPE_UMTS -> "UMTS"
        TelephonyManager.NETWORK_TYPE_EDGE,
        TelephonyManager.NETWORK_TYPE_GPRS,
        TelephonyManager.NETWORK_TYPE_CDMA,
        TelephonyManager.NETWORK_TYPE_1xRTT -> "2G_OR_CDMA"
        else -> "UNKNOWN"
    }

    private fun registrationName(state: Int?): String = when (state) {
        ServiceState.STATE_IN_SERVICE -> "in_service"
        ServiceState.STATE_OUT_OF_SERVICE -> "out_of_service"
        ServiceState.STATE_EMERGENCY_ONLY -> "emergency_only"
        ServiceState.STATE_POWER_OFF -> "power_off"
        else -> "unknown"
    }

    private fun dataStateName(state: Int): String = when (state) {
        TelephonyManager.DATA_CONNECTED -> "connected"
        TelephonyManager.DATA_CONNECTING -> "connecting"
        TelephonyManager.DATA_DISCONNECTED -> "disconnected"
        TelephonyManager.DATA_SUSPENDED -> "suspended"
        else -> "unknown"
    }

    private companion object {
        const val DEFAULT_UNCERTAINTY_MILLIS = 2_000L
    }
}
