package com.example.layanalyzer.capture.tls

import org.json.JSONObject

/** Numeric diagnostics only. Queues exclude the consumer's in-flight record. */
data class TlsRuntimeMetrics(
    val certificateCacheEntries: Long,
    val certificateCacheHits: Long,
    val goSecretsQueueBytes: Long,
    val kotlinSecretsQueueBytes: Long
)

/** Bounded allowlist of numeric Go diagnostics; arbitrary keys/text never reach the report. */
data class TlsEngineDiagnostics(
    val state: String?,
    val snapshotAtMillis: Long?,
    val budget: Map<String, Long>,
    val events: Map<String, Long>,
    val gateway: Map<String, Long>,
    val runtime: Map<String, Long>,
    val goSecretsIncomplete: Boolean?,
    val invalidFields: Boolean,
    val passthroughReasons: Map<String, Long> = emptyMap()
) {
    fun toJson() = JSONObject().put("state", state ?: JSONObject.NULL)
        .put("snapshotAtMillis", snapshotAtMillis ?: JSONObject.NULL)
        .put("budget", JSONObject(budget)).put("events", JSONObject(events).put("passthroughReasons", JSONObject(passthroughReasons)))
        .put("gateway", JSONObject(gateway)).put("runtimeMetrics", JSONObject(runtime).apply {
            goSecretsIncomplete?.let { put("goSecretsIncomplete", it) }
        }).put("invalidFields", invalidFields)

    companion object {
        private val budgetKeys = "connections handshakes connectionLimit handshakeLimit peakConnections peakHandshakes refusedConnections refusedHandshakes".split(' ')
        private val eventKeys = ("connectionsAccepted connectionsProxied connectionsPassthrough connectionsClosed connectionsFailed handshakesFailed secretsIncomplete secretRecordsAccepted secretRecordsPersisted bytesToUpstream bytesToDownstream eventsPublished eventsDropped terminalsSuppressed eventsQueued terminalsRetained activeRecords peakActiveRecords peakEventsQueued recordLimit terminalLimit recordsRefused terminalsEvicted handshakeCapacityPassthrough secretsIncompletePassthrough").split(' ')
        private val gatewayKeys = "authenticationFailures authentication active acceptedCurrent authenticationLimit activeLimit acceptedLimit socketLimit peakAuthentication peakActive peakAccepted accepted authenticated rejectedBeforeAuthentication rejectedActiveCapacity dialAttempts dialFailures ready".split(' ')
        private val runtimeKeys = ("certificateCacheEntries certificateCacheHits certificateCacheMisses certificateCacheEvictions certificateCachePeakEntries certificateIssuances certificateIssueFailures certificateIssuancesInFlight certificateIssuancesPeakInFlight certificateIssueWaiters certificateIssuePeakWaiters certificateIssuesShared goSecretsQueueBytes goSecretsQueueRecords goSecretsQueuePeakBytes goSecretsQueuePeakRecords goSecretsInFlightBytes goSecretsPeakRetainedBytes goSecretsQueueLimitBytes goSecretsOffered goSecretsAccepted goSecretsRejected goSecretsDropped goSecretsSettleWaiters goSecretsPeakSettleWaiters goSecretsSettleTimeouts goSecretsDrainTimeouts probesActive probesPeakActive probesStarted probesFinished probesIncomplete probePrefixCapacityBytes probePeakPrefixCapacityBytes probePrefixCapacityLimitBytes").split(' ')

        fun read(root: JSONObject): TlsEngineDiagnostics {
            var invalid = false
            fun nonnegative(value: Any?): Long? = when (value) {
                is Int -> value.toLong().takeIf { it >= 0 }
                is Long -> value.takeIf { it >= 0 }
                else -> null
            }
            fun fields(name: String, keys: List<String>): Map<String, Long> {
                if (!root.has(name)) return emptyMap()
                val raw = root.optJSONObject(name) ?: run { invalid = true; return emptyMap() }
                return buildMap {
                    keys.forEach { key -> if (raw.has(key)) {
                        val value = nonnegative(raw.opt(key))
                        if (value == null) invalid = true else put(key, value)
                    } }
                }
            }
            val budget = fields("budget", budgetKeys)
            val events = fields("events", eventKeys)
            val gateway = fields("gateway", gatewayKeys)
            val runtime = fields("runtimeMetrics", runtimeKeys)
            fun bounded(map: Map<String, Long>, keys: List<String>, max: Long) {
                if (keys.any { (map[it] ?: 0) > max }) invalid = true
            }
            bounded(budget, listOf("connections", "connectionLimit", "peakConnections"), 1024)
            bounded(budget, listOf("handshakes", "handshakeLimit", "peakHandshakes"), 8)
            bounded(gateway, listOf("authentication", "authenticationLimit", "peakAuthentication"), 128)
            bounded(gateway, listOf("active", "activeLimit", "peakActive"), 1024)
            bounded(runtime, listOf("certificateCacheEntries", "certificateCachePeakEntries"), 256)
            bounded(runtime, listOf("goSecretsQueueBytes", "goSecretsQueuePeakBytes", "goSecretsQueueLimitBytes"), 1_048_576)
            bounded(runtime, listOf("goSecretsInFlightBytes"), 8192)
            bounded(runtime, listOf("probesActive", "probesPeakActive"), 1024)
            bounded(runtime, listOf("probePrefixCapacityBytes", "probePeakPrefixCapacityBytes"), 64L * 1024 * 1024)
            fun consistent(map: Map<String, Long>, current: String, limit: String) {
                if (map[current] != null && map[limit] != null && map.getValue(current) > map.getValue(limit)) invalid = true
            }
            consistent(budget, "connections", "connectionLimit")
            consistent(budget, "handshakes", "handshakeLimit")
            consistent(gateway, "authentication", "authenticationLimit")
            consistent(gateway, "active", "activeLimit")
            val reasons = buildMap<String, Long> {
                val raw = root.optJSONObject("events")?.optJSONObject("passthroughReasons")
                val allowed = "handshake_capacity_exceeded connection_capacity_exceeded secrets_incomplete fallback_downstream_leaf_unavailable disabled port_not_candidate application_not_selected bypass_rule no_include_match not_handshake_record bad_record_version bad_record_length malformed_client_hello unexpected_handshake_type client_hello_too_large no_supported_version prefix_budget_exceeded probe_timeout stream_ended read_error other".split(' ')
                allowed.forEach { key -> if (raw?.has(key) == true) {
                    val value = nonnegative(raw.opt(key))
                    if (value == null) invalid = true else put(key, value)
                } }
            }
            val state = root.opt("state")?.let {
                (it as? String)?.takeIf { name -> name in setOf("NEW", "STARTING", "RUNNING", "STOPPING", "STOPPED") }
                    .also { valid -> if (valid == null) invalid = true }
            }
            val time = if (root.has("snapshotAtMillis")) nonnegative(root.opt("snapshotAtMillis"))
                .also { if (it == null) invalid = true } else null
            val raw = root.optJSONObject("runtimeMetrics")
            val incomplete = if (raw?.has("goSecretsIncomplete") == true)
                (raw.opt("goSecretsIncomplete") as? Boolean).also { if (it == null) invalid = true } else null
            return TlsEngineDiagnostics(state, time, budget, events, gateway, runtime, incomplete, invalid, reasons)
        }
    }
}
