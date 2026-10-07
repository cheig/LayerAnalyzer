package com.example.layanalyzer.ai.tools.dto

import com.example.layanalyzer.ai.privacy.AgentFieldSensitivity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.PacketSearchMode

/**
 * Projections for the AI-09 packet tools.
 *
 * As with [AgentBaseToolProjections], the point of these DTOs is that they
 * cannot carry what they do not declare: there is no packet-bytes field, no
 * protocol subtree and no byte range, so no amount of upstream change can make
 * `query_packet_summaries` or `get_packet_fields` leak one.
 */

/** Sort orders a model may request.  MVP declares exactly one. */
enum class AgentPacketSortArgument(val wireName: String) {
    FrameAscending("frame_ascending");

    companion object {
        val wireNames: List<String> = values().map { it.wireName }

        /**
         * Unknown values never reach here — the schema's enum rejects them — so
         * an absent argument simply means the only supported order.
         */
        fun fromWire(name: String?): AgentPacketSortArgument =
            values().firstOrNull { it.wireName == name } ?: FrameAscending
    }
}

/** Search modes a model may request, in the engine's own vocabulary. */
enum class AgentSearchModeArgument(val wireName: String, val mode: PacketSearchMode) {
    Number("number", PacketSearchMode.Number),
    Text("text", PacketSearchMode.Text),
    Hex("hex", PacketSearchMode.Hex),
    Field("field", PacketSearchMode.Field);

    companion object {
        val wireNames: List<String> = values().map { it.wireName }

        fun fromWire(name: String?): AgentSearchModeArgument? =
            values().firstOrNull { it.wireName == name }
    }
}

/**
 * One packet-list row projected for a model.
 *
 * Both timestamps are reported because they answer different questions: the
 * absolute time correlates the capture with an external log, while the relative
 * time is what the user sees in the packet list.  Neither is the user's
 * currently-selected time format, so the payload does not change meaning when
 * someone toggles a display preference mid-run.
 */
data class AgentPacketSummaryEntry(
    val frameNumber: Long,
    val absoluteTime: Double,
    val relativeTime: Double,
    val source: String,
    val destination: String,
    val sourcePort: Int?,
    val destinationPort: Int?,
    val protocol: String,
    val length: Int,
    val info: String
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "frameNumber" to frameNumber,
        "absoluteTime" to absoluteTime,
        "relativeTime" to relativeTime,
        "source" to source,
        "destination" to destination,
        "sourcePort" to sourcePort,
        "destinationPort" to destinationPort,
        "protocol" to protocol,
        "length" to length,
        "info" to info
    )
}

/**
 * One observation of a requested protocol field inside one frame.
 *
 * [requestedName] is the spelling the model asked for and [actualFieldName] is
 * the abbreviation the engine reported, so a model can tell a case-insensitive
 * match from an exact one.  A credential field carries [present] and [scheme]
 * instead of its value; the value itself is dropped here rather than being
 * redacted, because a redacted secret is still a secret's shape.
 */
data class AgentFieldOccurrence(
    val requestedName: String,
    val actualFieldName: String,
    val displayValue: String? = null,
    val filterValue: String? = null,
    val generated: Boolean = false,
    val hidden: Boolean = false,
    val credential: Boolean = false,
    val payload: Boolean = false,
    val present: Boolean = true,
    val scheme: String? = null
) {
    fun toAgentJson(): AgentJsonObject = buildMap {
        put("requestedName", requestedName)
        put("actualFieldName", actualFieldName)
        put("generated", generated)
        put("hidden", hidden)
        if (credential) {
            put("credential", true)
            put("present", present)
            put("scheme", scheme)
        } else if (payload) {
            put("payload", true)
            put("present", present)
        } else {
            put("displayValue", displayValue)
            put("filterValue", filterValue)
        }
    }
}

/**
 * Field projection for one frame.
 *
 * [detailAvailable] and [missingFields] are deliberately independent: a frame
 * whose details could not be dissected reports `detailAvailable = false` with an
 * empty projection, while a successfully dissected frame that simply does not
 * carry the field reports `detailAvailable = true` and lists it in
 * [missingFields].  Collapsing the two would let a model read "the field is
 * absent" from what was really a read failure.
 */
data class AgentFrameFields(
    val frameNumber: Long,
    val detailAvailable: Boolean,
    val fields: Map<String, List<AgentFieldOccurrence>>,
    val missingFields: List<String>,
    val truncated: Boolean
) {
    val occurrenceCount: Int
        get() = fields.values.sumOf { it.size }

    fun toAgentJson(): AgentJsonObject = mapOf(
        "frameNumber" to frameNumber,
        "detailAvailable" to detailAvailable,
        "fields" to fields.mapValues { (_, occurrences) ->
            occurrences.map(AgentFieldOccurrence::toAgentJson)
        },
        "missingFields" to missingFields,
        "truncated" to truncated
    )
}

/** Sampling modes for the local field-distribution scan. */
enum class AgentFieldAggregateSampleMode(val wireName: String) {
    FirstLastAnomaly("first_last_anomaly"),
    FirstLast("first_last"),
    Uniform("uniform");

    companion object {
        val wireNames: List<String> = values().map { it.wireName }

        fun fromWire(name: String?): AgentFieldAggregateSampleMode? =
            values().firstOrNull { it.wireName == name }
    }
}

/** Counts for one requested field; values are deliberately absent. */
data class AgentFieldAggregate(
    val fieldName: String,
    val presentFrames: Int,
    val occurrenceCount: Int,
    val firstFrame: Long?,
    val lastFrame: Long?,
    val credential: Boolean,
    val payload: Boolean,
    val schemes: List<String> = emptyList()
) {
    fun toAgentJson(): AgentJsonObject = buildMap {
        put("presentFrames", presentFrames)
        put("occurrenceCount", occurrenceCount)
        put("firstFrame", firstFrame)
        put("lastFrame", lastFrame)
        put("credential", credential)
        put("payload", payload)
        if (credential) put("schemes", schemes)
    }
}

/** Bounded result of scanning a filtered packet set for field distribution. */
data class AgentPacketFieldAggregate(
    val filter: String,
    val scope: String,
    val queryMode: String,
    val matchedPackets: Int,
    val scannedPackets: Int,
    val fields: Map<String, AgentFieldAggregate>,
    val sampleFrames: List<Long>,
    val anomalyFrames: List<Long>,
    val sampleMode: String,
    val sampleLimit: Int,
    val sampled: Boolean,
    val coverageComplete: Boolean,
    val detailUnavailablePackets: Int,
    val truncated: Boolean
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "filter" to filter,
        "scope" to scope,
        "queryMode" to queryMode,
        "matchedPackets" to matchedPackets,
        "scannedPackets" to scannedPackets,
        "fields" to fields.mapValues { (_, aggregate) -> aggregate.toAgentJson() },
        "sampleFrames" to sampleFrames,
        "anomalyFrames" to anomalyFrames,
        "sampleMode" to sampleMode,
        "sampleLimit" to sampleLimit,
        "sampled" to sampled,
        "coverageComplete" to coverageComplete,
        "detailUnavailablePackets" to detailUnavailablePackets,
        "returned" to sampleFrames.size,
        "total" to matchedPackets,
        "truncated" to truncated
    )
}

/**
 * Protocol fields whose value is a credential.
 *
 * Classification is by field name rather than by value, because a value-based
 * rule only recognises the secrets it has seen before.  The list is matched
 * against the last dotted segment of the engine's field abbreviation, so
 * `sip.Authorization` and `http.authorization` are both caught without needing
 * a per-protocol entry.
 *
 * AI-11 replaces this with the full AgentFieldSensitivity table; until then it
 * is the single place that decides a value must never be projected.
 */
object AgentCredentialFields {
    /** Known authentication schemes safe to report as a bare label. */
    private val SCHEMES = listOf("digest", "basic", "bearer", "negotiate", "ntlm", "aka")

    fun isCredential(fieldName: String): Boolean = AgentFieldSensitivity.isCredential(fieldName)

    fun isPayload(fieldName: String): Boolean = AgentFieldSensitivity.isPayload(fieldName)

    /**
     * The scheme named at the start of a credential header, if it is one this
     * host already knows.  An unrecognised scheme returns null rather than
     * echoing the first token, which would otherwise carry capture text
     * straight into the payload.
     */
    fun scheme(rawValue: String?): String? {
        val text = rawValue?.trim()?.lowercase() ?: return null
        return SCHEMES.firstOrNull { scheme ->
            text == scheme || text.startsWith("$scheme ")
        }
    }
}
