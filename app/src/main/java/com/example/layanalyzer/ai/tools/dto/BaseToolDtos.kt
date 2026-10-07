package com.example.layanalyzer.ai.tools.dto

import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.CaptureHealthSummary
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ExpertInfoItem
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.HealthSeverity

/**
 * Projections of the internal analysis models into the small, stable JSON shapes
 * the Phase 0 tools return.
 *
 * These DTOs exist so a model never receives a whole [CaptureStatistics],
 * [CaptureHealthSummary] or [com.example.layanalyzer.model.FileSessionInfo].
 * In particular there is deliberately no field carrying a local file path: the
 * projection cannot leak one because it never accepts one.
 */

/** Scope vocabulary a model may request; maps onto the internal [AnalysisScope]. */
enum class AgentScopeArgument(val wireName: String, val scope: AnalysisScope) {
    CompleteFile("complete_file", AnalysisScope.CompleteFile),
    CurrentFilter("current_filter", AnalysisScope.CurrentFilter);

    companion object {
        val wireNames: List<String> = values().map { it.wireName }

        fun fromWire(name: String?): AgentScopeArgument? =
            values().firstOrNull { it.wireName == name }

        /** The argument value that corresponds to an existing snapshot scope. */
        fun of(scope: AnalysisScope): AgentScopeArgument = when (scope) {
            AnalysisScope.CurrentFilter -> CurrentFilter
            else -> CompleteFile
        }
    }
}

/** Expert severities a model may filter on, in Wireshark's own vocabulary. */
enum class AgentExpertSeverity(val wireName: String) {
    Error("error"),
    Warning("warning"),
    Note("note"),
    Chat("chat");

    companion object {
        val wireNames: List<String> = values().map { it.wireName }

        /**
         * Native spellings that do not equal a [wireName].
         *
         * The engine reports a warning as `warn` (`severity_from_flags` in
         * native-lib.cpp), while this enum — and therefore every `severities`
         * argument a model may send — uses `warning`.  Without the alias
         * `fromNative("warn")` returns null, so filtering for warnings silently
         * matches nothing on a real capture even though the entries are there.
         */
        private val NATIVE_ALIASES: Map<String, AgentExpertSeverity> = mapOf(
            "warn" to Warning
        )

        /**
         * Normalise a native severity label.  Unknown labels return null so an
         * unexpected value is simply not matched instead of being reported as a
         * severity the caller never asked for.
         */
        fun fromNative(label: String?): AgentExpertSeverity? {
            val normalized = label?.trim()?.lowercase() ?: return null
            return values().firstOrNull { it.wireName == normalized }
                ?: NATIVE_ALIASES[normalized]
        }
    }
}

private fun HealthSeverity.wireName(): String = name.lowercase()

/** One protocol-hierarchy row, without the UI formatting. */
data class AgentProtocolHierarchyEntry(
    val name: String,
    val packets: Int,
    val bytes: Long,
    val packetPercent: Double,
    val bytePercent: Double
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "name" to name,
        "packets" to packets,
        "bytes" to bytes,
        "packetPercent" to packetPercent,
        "bytePercent" to bytePercent
    )
}

/**
 * Health indicators for one protocol family.
 *
 * [metrics] holds the numeric signals for that family, [displayFilter] is the
 * drill-down filter the model may cite as evidence, and [severity] is the
 * verdict [CaptureHealthSummary] already reached for the same data.
 */
data class AgentProtocolHealth(
    val id: String,
    val events: Int,
    val problems: Int,
    val severity: String,
    val firstProblemFrame: Long? = null,
    val displayFilter: String? = null,
    val truncated: Boolean = false,
    val metrics: Map<String, Any?> = emptyMap()
) {
    fun toAgentJson(): AgentJsonObject = buildMap {
        put("events", events)
        put("problems", problems)
        put("severity", severity)
        put("firstProblemFrame", firstProblemFrame)
        put("displayFilter", displayFilter)
        put("truncated", truncated)
        metrics.forEach { (key, value) -> put(key, value) }
    }
}

/** Complete get_capture_overview payload. */
data class AgentCaptureOverview(
    val fileType: String,
    val encapsulation: String,
    val frameCount: Int,
    val visibleFrameCount: Int,
    val startTime: Double,
    val endTime: Double,
    val durationSeconds: Double,
    val scope: String,
    val displayFilter: String,
    val protocolHierarchy: List<AgentProtocolHierarchyEntry>,
    val protocolHierarchyTotal: Int,
    val health: List<AgentProtocolHealth>,
    val expertErrorCount: Int,
    val expertWarningCount: Int,
    val capturedByteCount: Long,
    val truncatedPacketCount: Int,
    val returned: Int,
    val total: Int,
    val truncated: Boolean
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "fileType" to fileType,
        "encapsulation" to encapsulation,
        "frameCount" to frameCount,
        "visibleFrameCount" to visibleFrameCount,
        "startTime" to startTime,
        "endTime" to endTime,
        "durationSeconds" to durationSeconds,
        "scope" to scope,
        "displayFilter" to displayFilter,
        "protocolHierarchy" to protocolHierarchy.map { it.toAgentJson() },
        "protocolHierarchyTotal" to protocolHierarchyTotal,
        "health" to health.associate { it.id to it.toAgentJson() },
        "expertErrorCount" to expertErrorCount,
        "expertWarningCount" to expertWarningCount,
        "capturedByteCount" to capturedByteCount,
        "truncatedPacketCount" to truncatedPacketCount,
        "returned" to returned,
        "total" to total,
        "truncated" to truncated
    )
}

/** One Expert Info row projected for a model. */
data class AgentExpertInfoEntry(
    val frameNumber: Long,
    val severity: String,
    val label: String,
    val displayFilter: String?
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "frameNumber" to frameNumber,
        "severity" to severity,
        "label" to label,
        "displayFilter" to displayFilter
    )
}

/**
 * Builders that turn the internal models into the DTOs above.
 *
 * Kept as an object rather than extension functions so the whole projection is
 * in one auditable place, and so the tools cannot accidentally serialise a
 * richer internal object by importing a more convenient conversion.
 */
object AgentBaseToolProjections {
    /** Maximum protocol-hierarchy rows the overview reports, per AI-04. */
    const val MAX_PROTOCOL_HIERARCHY_ENTRIES = 20

    fun protocolHierarchy(
        statistics: CaptureStatistics,
        limit: Int = MAX_PROTOCOL_HIERARCHY_ENTRIES
    ): List<AgentProtocolHierarchyEntry> = statistics.protocolHierarchy
        .take(limit.coerceAtLeast(0))
        .map { stat ->
            AgentProtocolHierarchyEntry(
                name = stat.name,
                packets = stat.packetCount,
                bytes = stat.byteCount,
                packetPercent = stat.packetPercent,
                bytePercent = stat.bytePercent
            )
        }

    /**
     * DNS/TCP/TLS/HTTP indicators.  Severity and first-problem frames are read
     * from the [CaptureHealthSummary] the UI already uses, so the model and the
     * user always see the same verdict for the same capture.
     */
    fun health(
        statistics: CaptureStatistics,
        summary: CaptureHealthSummary
    ): List<AgentProtocolHealth> {
        val cards = summary.cards.associateBy { it.id }
        fun severityOf(id: String): String =
            cards[id]?.severity?.wireName() ?: HealthSeverity.Healthy.wireName()

        return listOf(
            AgentProtocolHealth(
                id = "dns",
                events = statistics.dnsSummaryTotal,
                problems = statistics.dnsFailureTotal,
                severity = severityOf("dns"),
                firstProblemFrame = statistics.dnsFirstFailureFrame,
                displayFilter = cards["dns"]?.filter,
                truncated = cards["dns"]?.truncated ?: false,
                metrics = mapOf(
                    "queries" to statistics.dnsQueries,
                    "responses" to statistics.dnsResponses,
                    "averageResponseMs" to statistics.dnsAverageResponseMs
                )
            ),
            AgentProtocolHealth(
                id = "tcp",
                events = statistics.tcpSummaryTotal,
                problems = statistics.tcpRetransmissions +
                    statistics.tcpDuplicateAcks +
                    statistics.tcpResets +
                    statistics.tcpZeroWindows,
                severity = severityOf("tcp"),
                firstProblemFrame = cards["tcp"]?.frameNumber,
                displayFilter = cards["tcp"]?.filter,
                truncated = cards["tcp"]?.truncated ?: false,
                metrics = mapOf(
                    "syn" to statistics.tcpSyn,
                    "synAck" to statistics.tcpSynAck,
                    "retransmissions" to statistics.tcpRetransmissions,
                    "duplicateAcks" to statistics.tcpDuplicateAcks,
                    "resets" to statistics.tcpResets,
                    "zeroWindows" to statistics.tcpZeroWindows,
                    "averageRttMs" to statistics.tcpAverageRttMs,
                    "rttSamples" to statistics.tcpRttSamples
                )
            ),
            AgentProtocolHealth(
                id = "tls",
                events = statistics.tlsSummaryTotal,
                problems = statistics.tlsAlertTotal,
                severity = severityOf("tls"),
                firstProblemFrame = statistics.tlsFirstAlertFrame,
                displayFilter = cards["tls"]?.filter,
                truncated = cards["tls"]?.truncated ?: false,
                metrics = mapOf(
                    "versions" to statistics.tlsVersions,
                    "sniCount" to statistics.tlsSni.size
                )
            ),
            AgentProtocolHealth(
                id = "http",
                events = statistics.httpSummaryTotal,
                problems = statistics.httpErrorTotal,
                severity = severityOf("http"),
                firstProblemFrame = statistics.httpFirstErrorFrame,
                displayFilter = cards["http"]?.filter,
                truncated = cards["http"]?.truncated ?: false,
                metrics = mapOf(
                    "statusCodes" to statistics.httpStatusCodes,
                    "hostCount" to statistics.httpHosts.size
                )
            )
        )
    }

    /**
     * Project Expert items.  [start] and [length] are intentionally dropped:
     * AI-04 keeps them for local navigation only, and the model has no use for
     * a byte range it is not allowed to read.
     */
    fun expertEntry(item: ExpertInfoItem): AgentExpertInfoEntry = AgentExpertInfoEntry(
        frameNumber = item.frameNumber,
        severity = AgentExpertSeverity.fromNative(item.severity)?.wireName
            ?: item.severity.trim().lowercase(),
        label = item.label,
        displayFilter = item.filter?.takeIf { it.isNotBlank() }
    )

    /**
     * Error/warning counts for the overview.  [ExpertInfoSummary] reports these
     * as packet counts, which is what the design document asks the overview to
     * surface.
     */
    fun expertCounts(expert: ExpertInfoSummary): Pair<Int, Int> =
        expert.errorPackets to expert.warningPackets
}
