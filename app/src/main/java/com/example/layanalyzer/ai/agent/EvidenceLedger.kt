package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.AnalysisScope

/**
 * What one tool call actually returned, reduced to the facts a later citation
 * can be checked against.
 *
 * The entry deliberately keeps sets of observed frames, fields, metrics and
 * filters rather than the payload itself: the validator only ever needs to
 * answer "did this call really return that?", and holding the full result for
 * the length of a run would keep capture data alive long after the model
 * consumed it.
 */
data class EvidenceLedgerEntry(
    val toolCallId: String,
    val toolName: String,
    val stepIndex: Int,
    val success: Boolean,
    val truncated: Boolean,
    val scope: AnalysisScope,
    val displayFilter: String,
    val returnedCount: Long,
    val totalCount: Long,
    /** True when the full candidate set was scanned but only samples were returned. */
    val sampled: Boolean = false,
    /** Explicit scan coverage; null preserves the legacy returned/total rule. */
    val coverageComplete: Boolean? = null,
    val queryMode: String? = null,
    val resultBytes: Int = 0,
    /** Frame numbers that appeared anywhere in the returned payload. */
    val frameNumbers: Set<Long> = emptySet(),
    /** Field names the payload projected, if the tool projects fields at all. */
    val fields: Set<String> = emptySet(),
    /** Key names and dotted paths, so a cited metric can be shown to exist. */
    val metrics: Set<String> = emptySet(),
    /** Only scalar leaf metrics, excluding container paths. */
    val leafMetrics: Set<String> = emptySet(),
    /** Scalar leaf metric values, indexed by short key and dotted path. */
    val metricValues: Map<String, String> = emptyMap(),
    /** Filters the host compiled or the engine itself produced for this call. */
    val validatedFilters: Set<String> = emptySet(),
    /** Filters actually executed by this call and their observed match count. */
    val executedFilterMatches: Map<String, Long> = emptyMap(),
    val errorCode: AgentErrorCode? = null
) {
    /**
     * True when this call saw everything it was asked about.  A truncated
     * result, or one whose scan did not cover the requested set, cannot support
     * a statement about data the call never looked at. An aggregate may be a
     * complete scan while returning only bounded sample frame numbers.
     */
    val complete: Boolean
        get() = success && !truncated && (coverageComplete ?: (returnedCount >= totalCount))

    /** One redacted line describing what was confirmed, safe to show and log. */
    fun describe(): String {
        val state = when {
            !success -> "failed (${errorCode?.name ?: "unknown"})"
            truncated -> "returned $returnedCount of $totalCount, truncated"
            sampled && coverageComplete == true ->
                "scanned $totalCount, returned $returnedCount sample frame(s)"
            else -> "returned $returnedCount of $totalCount"
        }
        return "$toolName [$toolCallId]: $state"
    }
}

/**
 * The set of tool results a report is allowed to cite.
 *
 * Only results that actually ran in *this* run are registered, so a model
 * cannot reference a tool call from an earlier conversation, a call it invented,
 * or a call the host rejected before execution.  Failed calls are recorded too,
 * but marked unsuccessful: they are useful for explaining why a report is
 * partial, and they must never back a finding.
 *
 * The ledger is synchronized because tool execution may overlap and
 * cancellation/UI reads may arrive from other threads.
 */
class EvidenceLedger {
    private val guard = Any()
    private val entries = LinkedHashMap<String, EvidenceLedgerEntry>()

    val size: Int
        get() = synchronized(guard) { entries.size }

    /** Tool call ids in execution order; recorded in report provenance. */
    val toolCallIds: List<String>
        get() = synchronized(guard) { entries.keys.toList() }

    fun contains(toolCallId: String): Boolean =
        synchronized(guard) { entries.containsKey(toolCallId) }

    fun find(toolCallId: String): EvidenceLedgerEntry? =
        synchronized(guard) { entries[toolCallId] }

    fun all(): List<EvidenceLedgerEntry> = synchronized(guard) { entries.values.toList() }

    fun successful(): List<EvidenceLedgerEntry> = all().filter { it.success }

    /** Tool calls that were actually attempted but did not produce evidence. */
    fun failed(): List<EvidenceLedgerEntry> = all().filterNot { it.success }

    /** True when any recorded call cut its own result short. */
    fun anyTruncated(): Boolean = all().any { it.success && it.truncated }

    fun anyFailed(): Boolean = all().any { !it.success }

    /**
     * Every filter the host compiled during this run.  Filter validity is a
     * property of the engine rather than of one call, so a filter proven valid
     * by `validate_display_filter` may be cited from any finding.
     */
    fun validatedFilters(): Set<String> = synchronized(guard) {
        entries.values.flatMapTo(LinkedHashSet()) { it.validatedFilters }
    }

    /** Filters actually executed during this run and the largest observed count. */
    fun executedFilterMatches(): Map<String, Long> = synchronized(guard) {
        val matches = LinkedHashMap<String, Long>()
        entries.values.asSequence()
            .filter { it.success }
            .flatMap { it.executedFilterMatches.entries.asSequence() }
            .forEach { (filter, count) ->
                matches[filter] = maxOf(matches[filter] ?: 0L, count)
            }
        matches
    }

    /** Redacted, human-readable facts for an incomplete report. */
    fun confirmedFacts(limit: Int = MAX_FACTS): List<String> = successful()
        .take(limit.coerceAtLeast(0))
        .map { it.describe() }

    /**
     * Register a completed call.  [result] is the post-runner value, so its
     * truncation flag and counts are the ones the model actually saw.
     */
    fun record(
        call: AgentToolCall,
        result: AgentToolResult,
        stepIndex: Int
    ): EvidenceLedgerEntry {
        val extraction = EvidencePayloadExtractor.extract(result.data)
        val entry = EvidenceLedgerEntry(
            toolCallId = call.toolCallId,
            // The runner blanks the tool name for a call it refused to resolve.
            // Falling back to the model-supplied string would reflect a crafted
            // name from an injected prompt into the report and the audit log, so
            // an unresolved call stays anonymous.
            toolName = result.toolName.ifBlank { UNKNOWN_TOOL_NAME },
            stepIndex = stepIndex,
            success = result.success,
            truncated = result.truncated || result.provenance.truncated ||
                result.truncation.truncated || result.provenance.truncation.truncated,
            scope = result.provenance.scope,
            displayFilter = result.provenance.displayFilter,
            returnedCount = result.returnedCount,
            totalCount = maxOf(result.totalCount, result.returnedCount),
            sampled = result.data?.get("sampled") as? Boolean ?: false,
            coverageComplete = result.data?.get("coverageComplete") as? Boolean,
            queryMode = result.queryMode ?: result.provenance.queryMode,
            resultBytes = result.resultBytes,
            frameNumbers = extraction.frames,
            fields = extraction.fields,
            metrics = extraction.metrics,
            leafMetrics = extraction.leafMetrics,
            metricValues = extraction.metricValues,
            validatedFilters = if (result.success) {
                LinkedHashSet<String>().apply {
                    addAll(extraction.filters)
                    addAll(argumentFilters(call, result))
                    // The runner records the capture's host-owned filter in
                    // provenance even when the tool has no filter argument.
                    result.provenance.displayFilter.trim()
                        .takeIf { it.isNotEmpty() }
                        ?.let(::add)
                }
            } else {
                emptySet()
            },
            executedFilterMatches = executedFilterMatches(call, result),
            errorCode = result.error?.code
        )
        synchronized(guard) { entries[call.toolCallId] = entry }
        return entry
    }

    /**
     * Filters supplied as arguments to a call that succeeded.
     *
     * [com.example.layanalyzer.ai.tools.AgentToolRunner] compiles every filter
     * argument before the tool runs, so reaching a successful result proves the
     * engine accepted them.  The one exception is a tool that *reports* on a
     * filter: when it answers `valid: false` the argument is known-bad and must
     * not be promoted to a validated filter.
     */
    private fun argumentFilters(call: AgentToolCall, result: AgentToolResult): Set<String> {
        if (result.data?.get("valid") == false) return emptySet()
        return call.arguments.entries
            .asSequence()
            .filter { (key, _) -> isFilterKey(key) }
            .mapNotNull { (_, value) -> (value as? String)?.trim()?.takeIf { it.isNotEmpty() } }
            .toCollection(LinkedHashSet())
    }

    /**
     * Record only filters that were part of an actual read.  A successful
     * validate_display_filter call proves syntax, not execution, so it is
     * deliberately excluded.  Root-level result filters are trusted because
     * tools write them from the filter lease; nested drill-down filters are
     * merely suggestions and must not be treated as executed queries.
     */
    private fun executedFilterMatches(
        call: AgentToolCall,
        result: AgentToolResult
    ): Map<String, Long> {
        if (!result.success || call.toolName.trim() == VALIDATE_FILTER_TOOL) return emptyMap()

        val filters = LinkedHashSet<String>()
        fun addFilter(value: Any?) {
            (value as? String)?.trim()?.takeIf { it.isNotEmpty() }?.let(filters::add)
        }

        addFilter(result.provenance.displayFilter)
        call.arguments.entries
            .filter { (key, _) -> isFilterKey(key) }
            .forEach { (_, value) -> addFilter(value) }
        result.data?.let { data ->
            addFilter(data["filter"])
            addFilter(data["displayFilter"])
            addFilter(data["appliedFilter"])
        }
        if (filters.isEmpty()) return emptyMap()

        val matches = result.data?.let(::matchCount)
            ?: maxOf(result.totalCount, result.provenance.totalCount)
        return filters.associateWith { matches.coerceAtLeast(0L) }
    }

    private fun matchCount(data: Map<String, Any?>): Long? = listOf(
        "matchedPackets",
        "packetCount",
        "visibleFrameCount",
        "totalCount",
        "totalItems",
        "total"
    ).firstNotNullOfOrNull { key ->
        when (val value = data[key]) {
            is Number -> value.toLong()
            is String -> value.trim().toLongOrNull()
            else -> null
        }
    }

    private companion object {
        const val MAX_FACTS = 8
        const val UNKNOWN_TOOL_NAME = "unknown_tool"
        const val VALIDATE_FILTER_TOOL = "validate_display_filter"

        fun isFilterKey(key: String): Boolean =
            key == "filter" || key.endsWith("Filter") || key.endsWith("Filters")
    }
}

/** Sets pulled out of one tool payload. */
internal data class EvidencePayload(
    val frames: Set<Long>,
    val fields: Set<String>,
    val metrics: Set<String>,
    val leafMetrics: Set<String>,
    val metricValues: Map<String, String>,
    val filters: Set<String>
)

/**
 * Reduces a structured tool payload to the citable facts it contains.
 *
 * The walk is key-driven rather than schema-driven so it keeps working as
 * AI-09/AI-10 add tools: any payload that names a frame, a field or a filter in
 * the shared vocabulary becomes checkable without the validator having to know
 * which tool produced it.  Every collection is capped, because the payload
 * comes from a capture file and must never be able to grow host memory
 * without bound.
 */
internal object EvidencePayloadExtractor {
    private const val MAX_TRACKED = 4_096
    private const val MAX_DEPTH = 12

    private val FRAME_KEYS = setOf(
        "frame",
        "frames",
        "frameNumber",
        "frameNumbers",
        "offerFrame",
        "answerFrame",
        "firstFrame",
        "lastFrame",
        "startFrame",
        "endFrame",
        "packetNumber",
        "packetNumbers",
        "firstProblemFrame",
        "firstErrorFrame",
        "firstFailureFrame",
        "firstAlertFrame",
        "reportFrames",
        "evidenceFrames",
        "anomalyFrames",
        "mediaNegotiationFrames",
        "inviteFrame",
        "finalResponseFrame",
        "ackFrame",
        "sampleFrames"
    )

    private val FILTER_KEYS = setOf(
        "filter",
        "filters",
        "displayFilter",
        "displayFilters",
        "normalizedFilter",
        "drilldownFilter"
    )

    private val FIELD_KEYS = setOf("field", "fields", "fieldName", "fieldNames")

    fun extract(data: Map<String, Any?>?): EvidencePayload {
        val collector = Collector()
        if (data != null) collector.walkMap(data, path = "", depth = 0, filtersTrusted = true)
        return EvidencePayload(
            frames = collector.frames,
            fields = collector.fields,
            metrics = collector.metrics,
            leafMetrics = collector.leafMetrics,
            metricValues = collector.metricValues,
            filters = collector.filters
        )
    }

    private class Collector {
        val frames = LinkedHashSet<Long>()
        val fields = LinkedHashSet<String>()
        val metrics = LinkedHashSet<String>()
        val leafMetrics = LinkedHashSet<String>()
        val metricValues = LinkedHashMap<String, String>()
        val filters = LinkedHashSet<String>()

        fun walkMap(source: Map<*, *>, path: String, depth: Int, filtersTrusted: Boolean) {
            if (depth > MAX_DEPTH) return

            // A tool that answers "this filter does not compile" carries the bad
            // filter in its own payload.  Nothing inside such an object may be
            // treated as host-validated.
            val trusted = filtersTrusted && source["valid"] != false

            source.forEach { (rawKey, value) ->
                val key = rawKey?.toString() ?: return@forEach
                val childPath = if (path.isEmpty()) key else "$path.$key"
                add(metrics, key)
                add(metrics, childPath)
                collectLeafMetric(key, childPath, value)

                when {
                    key in FRAME_KEYS -> collectFrames(value)
                    key in FILTER_KEYS && trusted -> collectStrings(filters, value)
                    key in FIELD_KEYS -> collectFieldNames(value)
                }
                walkValue(value, childPath, depth + 1, trusted)
            }
        }

        private fun walkValue(value: Any?, path: String, depth: Int, filtersTrusted: Boolean) {
            if (depth > MAX_DEPTH) return
            when (value) {
                is Map<*, *> -> walkMap(value, path, depth, filtersTrusted)
                is Iterable<*> -> value.forEach { walkValue(it, path, depth + 1, filtersTrusted) }
                is Array<*> -> value.forEach { walkValue(it, path, depth + 1, filtersTrusted) }
                else -> Unit
            }
        }

        /** `fields` may be a list of names or an object keyed by name. */
        private fun collectFieldNames(value: Any?) {
            when (value) {
                is Map<*, *> -> value.keys.forEach { key ->
                    key?.toString()?.let { add(fields, it) }
                }
                else -> collectStrings(fields, value)
            }
        }

        private fun collectFrames(value: Any?) {
            when (value) {
                null -> Unit
                is Number -> addFrame(value.toLong())
                is String -> value.trim().toLongOrNull()?.let(::addFrame)
                is Iterable<*> -> value.forEach { collectFrames(it) }
                is Array<*> -> value.forEach { collectFrames(it) }
                is Map<*, *> -> value.values.forEach { collectFrames(it) }
                else -> Unit
            }
        }

        private fun collectStrings(target: LinkedHashSet<String>, value: Any?) {
            when (value) {
                null -> Unit
                is String -> add(target, value.trim())
                is Iterable<*> -> value.forEach { collectStrings(target, it) }
                is Array<*> -> value.forEach { collectStrings(target, it) }
                else -> Unit
            }
        }

        private fun collectLeafMetric(key: String, path: String, value: Any?) {
            if (key in FRAME_KEYS || key in FILTER_KEYS || key in FIELD_KEYS) return

            scalarValue(value)?.let { scalar ->
                addLeafMetric(key, path, scalar)
                return
            }

            // A list of primitive labels/numbers is itself a useful bounded
            // metric (for example a small protocol list), while a list of
            // objects remains a container and is intentionally not promoted.
            val collection = scalarCollection(value)
            if (collection.isNotEmpty()) {
                addLeafMetric(key, path, collection.joinToString(", "))
            }
        }

        private fun addLeafMetric(key: String, path: String, value: String) {
            add(leafMetrics, key)
            add(leafMetrics, path)
            putMetricValue(key, value)
            putMetricValue(path, value)
        }

        private fun putMetricValue(key: String, value: String) {
            if (key.isEmpty()) return
            if (metricValues.size < MAX_TRACKED || metricValues.containsKey(key)) {
                metricValues[key] = value
            }
        }

        private fun scalarValue(value: Any?): String? = when (value) {
            is Number, is Boolean -> value.toString()
            is String -> value.trim().takeIf { it.isNotEmpty() }
            else -> null
        }

        private fun scalarCollection(value: Any?): List<String> = when (value) {
            is Iterable<*> -> value.mapNotNull(::scalarValue).takeIf { values ->
                values.size == value.count()
            }.orEmpty()
            is Array<*> -> value.mapNotNull(::scalarValue).takeIf { values ->
                values.size == value.size
            }.orEmpty()
            else -> emptyList()
        }

        private fun addFrame(frame: Long) {
            if (frame > 0L && frames.size < MAX_TRACKED) frames.add(frame)
        }

        private fun add(target: LinkedHashSet<String>, value: String) {
            if (value.isNotEmpty() && target.size < MAX_TRACKED) target.add(value)
        }
    }
}
