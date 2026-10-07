package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentToolResult
import java.util.IdentityHashMap

data class ContextPlan(
    val messages: List<AgentModelMessage>,
    val estimatedInputTokens: Int,
    val reservedOutputTokens: Int,
    val contextLimitTokens: Int,
    val trimmed: Boolean,
    /** True means even the protected context did not fit and no model call is safe. */
    val partial: Boolean,
    /** Compact tool messages that the caller must persist in the live transcript. */
    val compactedByToolCallId: Map<String, AgentModelMessage> = emptyMap()
)

/** Applies the progressive context budget before every model request. */
class ContextPlanner(
    internal val estimator: TokenEstimator = ContentAwareTokenEstimator(),
    private val defaultContextTokens: Int = DEFAULT_CONTEXT_TOKENS,
    private val defaultOutputReserve: Int = DEFAULT_OUTPUT_RESERVE
) {
    /**
     * The input-token budget [plan] will apply for a reported capability.
     *
     * The compactor measures its trigger against this rather than the raw
     * context window: with a large output reserve on a small window the reserve
     * can exceed a quarter of the window, and a trigger derived from the window
     * would then sit *above* the input limit — the planner would trim (churning
     * the prefix every turn) while compaction never fired.
     */
    internal fun effectiveInputLimit(
        reportedContextLimit: Int,
        reportedOutputLimit: Int
    ): Int {
        val contextLimit = reportedContextLimit.takeIf { it > 0 } ?: defaultContextTokens
        return (contextLimit - outputReserve(contextLimit, reportedOutputLimit))
            .coerceAtLeast(1)
    }

    /**
     * The reserve is an upper bound on one generation, not a share of the
     * window: scaling it with the context limit asks a 1M-token model to hold
     * back ~384k tokens for a report that uses a few thousand. An oversized
     * ceiling can also slow a provider's first byte enough to trip an
     * intermediary's idle timeout, so it is capped absolutely.
     */
    private fun outputReserve(contextLimit: Int, reportedOutputLimit: Int): Int =
        (reportedOutputLimit.takeIf { it > 0 } ?: defaultOutputReserve)
            .coerceAtMost(
                if (reportedOutputLimit > AgentOutputBudget.FINAL_REPORT_TOKENS) {
                    WIDE_OUTPUT_RESERVE
                } else {
                    MAX_OUTPUT_RESERVE
                }
            )
            .coerceAtMost((contextLimit / 2).coerceAtLeast(1))

    /**
     * Build a bounded transcript for the one no-tools request used after a
     * host stop.  A normal turn should retain as much evidence as the model's
     * context permits; a forced summary must still be able to run when the
     * original transcript contains several large protected results.
     */
    fun planForFinalSummary(
        source: List<AgentModelMessage>,
        reportedContextLimit: Int,
        reportedOutputLimit: Int
    ): ContextPlan {
        // Reserve space for the actual recovery generation, not the model's
        // full advertised output window.  A 100k-token capability must not
        // make a compact 4k-token summary sacrifice most of its input budget.
        val requestedSummaryOutputLimit = AgentOutputBudget.tokens(
            AgentModelRequestStage.ForcedSummary,
            reportedOutputLimit
        )
        // A negotiated provider ceiling is authoritative. Reserving 4k
        // tokens when the adapter can only return 200 would evict useful
        // evidence and can make recovery look context-limited too early.
        val summaryOutputLimit = if (reportedOutputLimit > 0) {
            minOf(requestedSummaryOutputLimit, reportedOutputLimit)
        } else {
            requestedSummaryOutputLimit
        }
        return plan(
            source = summarySource(source),
            reportedContextLimit = reportedContextLimit,
            reportedOutputLimit = summaryOutputLimit
        )
    }

    fun plan(
        source: List<AgentModelMessage>,
        reportedContextLimit: Int,
        reportedOutputLimit: Int
    ): ContextPlan {
        val estimates = RequestScopedMessageEstimates(estimator)
        val contextLimit = reportedContextLimit.takeIf { it > 0 } ?: defaultContextTokens
        val reserve = outputReserve(contextLimit, reportedOutputLimit)
        val inputLimit = (contextLimit - reserve).coerceAtLeast(1)
        val compactedByToolCallId = linkedMapOf<String, AgentModelMessage>()
        // Keep the non-tool turns that define a valid provider conversation.
        // In particular, an assistant tool-call message must survive beside the
        // Tool result it introduced; OpenAI-compatible APIs reject orphaned Tool
        // messages. Later User messages are host nudges and must also remain.
        val fixed = source.filter { it.role != AgentModelMessageRole.Tool }
        val toolMessages = source.withIndex()
            .filter { it.value.role == AgentModelMessageRole.Tool }
            .sortedWith(compareByDescending<IndexedValue<AgentModelMessage>> { evidenceWeight(it.value) }
                .thenByDescending { priority(it.value) }
                .thenByDescending { it.index })

        val included = fixed.toMutableList()
        val sourceOrder = IdentityHashMap<AgentModelMessage, Int>()
        source.forEachIndexed { index, message ->
            if (message.role != AgentModelMessageRole.Tool) sourceOrder[message] = index
        }
        var includedTokens = estimates.estimateMessages(fixed)
        var trimmed = source.size != fixed.size
        toolMessages.forEach { indexed ->
            val full = indexed.value
            val fullTokens = estimates.estimateMessage(full)
            if (includedTokens + fullTokens <= inputLimit) {
                included += full
                includedTokens += fullTokens
                sourceOrder[full] = indexed.index
            } else {
                val compact = compact(full)
                full.toolCallId?.let { compactedByToolCallId[it] = compact }
                val compactTokens = estimates.estimateMessage(compact)
                if (includedTokens + compactTokens <= inputLimit) {
                    included += compact
                    includedTokens += compactTokens
                    sourceOrder[compact] = indexed.index
                    trimmed = true
                } else if (isProtected(full)) {
                    // Errors, truncation and frame/filter/field evidence cannot
                    // be silently discarded. A final partial report is safer.
                    return ContextPlan(
                        messages = fixed,
                        estimatedInputTokens = estimates.estimateMessages(fixed),
                        reservedOutputTokens = reserve,
                        contextLimitTokens = contextLimit,
                        trimmed = true,
                        partial = true,
                        compactedByToolCallId = compactedByToolCallId
                    )
                } else {
                    trimmed = true
                }
            }
        }

        val ordered = included.sortedBy { sourceOrder[it] ?: Int.MAX_VALUE }
        val validConversation = retainCompleteToolTurns(ordered, source)
        if (validConversation.size != ordered.size) trimmed = true
        val estimated = estimates.estimateMessages(validConversation)
        return ContextPlan(
            messages = validConversation,
            estimatedInputTokens = estimated,
            reservedOutputTokens = reserve,
            contextLimitTokens = contextLimit,
            trimmed = trimmed,
            partial = estimated > inputLimit,
            compactedByToolCallId = compactedByToolCallId
        )
    }

    /** Keep the original question and only the final host instruction. */
    private fun summarySource(source: List<AgentModelMessage>): List<AgentModelMessage> {
        val userIndexes = source.withIndex()
            .filter { it.value.role == AgentModelMessageRole.User }
            .map { it.index }
        val firstUserIndex = userIndexes.firstOrNull()
        val lastUserIndex = userIndexes.lastOrNull()

        return source.mapIndexedNotNull { index, message ->
            when (message.role) {
                AgentModelMessageRole.System -> message
                AgentModelMessageRole.User ->
                    message.takeIf { index == firstUserIndex || index == lastUserIndex }
                AgentModelMessageRole.Assistant ->
                    message.takeIf { it.toolCalls.isNotEmpty() }?.copy(
                        // Reasoning and assistant prose are not evidence. They
                        // can be very large on thinking models and are the
                        // main source of transcript growth after many turns.
                        content = "",
                        reasoningContent = null
                    )
                AgentModelMessageRole.Tool -> compactForFinalSummary(message)
                AgentModelMessageRole.Unknown -> null
            }
        }
    }

    /** Holds message references only for the duration of one [plan] call. */
    private class RequestScopedMessageEstimates(
        private val estimator: TokenEstimator
    ) {
        private val estimates = IdentityHashMap<AgentModelMessage, Int>()

        fun estimateMessages(messages: List<AgentModelMessage>): Int =
            messages.sumOf { message -> estimateMessage(message) }

        fun estimateMessage(message: AgentModelMessage): Int =
            estimates[message] ?: estimator.estimateMessage(message).also { estimate ->
                estimates[message] = estimate
            }
    }

    /** Remove an assistant call group and its results unless the complete group survived trimming. */
    private fun retainCompleteToolTurns(
        planned: List<AgentModelMessage>,
        source: List<AgentModelMessage>
    ): List<AgentModelMessage> {
        val includedToolIds = planned
            .filter { it.role == AgentModelMessageRole.Tool }
            .mapNotNull { it.toolCallId }
            .toSet()
        val sourceAssistantByToolId = buildMap<String, AgentModelMessage> {
            source.filter { it.role == AgentModelMessageRole.Assistant }.forEach { assistant ->
                assistant.toolCalls.forEach { call -> put(call.toolCallId, assistant) }
            }
        }
        val retainedAssistants = planned
            .filter { it.role == AgentModelMessageRole.Assistant && it.toolCalls.isNotEmpty() }
            .filter { assistant -> assistant.toolCalls.all { it.toolCallId in includedToolIds } }
            .toSet()

        return planned.filter { message ->
            when (message.role) {
                AgentModelMessageRole.Assistant ->
                    message.toolCalls.isEmpty() || message in retainedAssistants
                AgentModelMessageRole.Tool -> {
                    val sourceAssistant = message.toolCallId?.let(sourceAssistantByToolId::get)
                    sourceAssistant == null || sourceAssistant in retainedAssistants
                }
                else -> true
            }
        }
    }

    private fun isProtected(message: AgentModelMessage): Boolean {
        return evidenceWeight(message) >= PROTECTED_EVIDENCE_WEIGHT
    }

    internal fun evidenceWeight(message: AgentModelMessage): Int {
        val result = message.toolResult ?: return 0
        if (isBootstrapExpert(message)) return BOOTSTRAP_EXPERT_EVIDENCE_WEIGHT
        if (!result.success) return Int.MAX_VALUE
        if (result.truncated) return PROTECTED_EVIDENCE_WEIGHT

        val keys = collectKeys(result.data)
        val hasFrame = keys.any { it in FRAME_EVIDENCE_KEYS }
        val hasField = keys.any { it in FIELD_EVIDENCE_KEYS }
        return when {
            hasFrame && hasField -> FIELD_PROJECTION_EVIDENCE_WEIGHT
            message.toolName == "validate_display_filter" -> FILTER_VALIDATION_EVIDENCE_WEIGHT
            keys.any { it in LIGHTWEIGHT_EVIDENCE_KEYS } -> LIGHTWEIGHT_EVIDENCE_WEIGHT
            else -> 0
        }
    }

    private fun priority(message: AgentModelMessage): Int = when (message.toolName) {
        "get_capture_overview" -> 60
        "get_expert_info" -> 55
        "get_communication_analysis" -> 50
        "query_packet_field_aggregate" -> 48
        "query_packet_summaries", "search_packets" -> 40
        "get_packet_fields" -> 30
        "get_statistics" -> 20
        else -> 10
    }

    private fun isBootstrapExpert(message: AgentModelMessage): Boolean =
        message.toolName == "get_expert_info" &&
            message.toolCallId?.startsWith(HOST_BOOTSTRAP_EXPERT_PREFIX) == true

    private fun compactForFinalSummary(message: AgentModelMessage): AgentModelMessage =
        compact(
            message = message,
            evidenceLimit = SUMMARY_EVIDENCE_ITEMS,
            maxStringLength = SUMMARY_EVIDENCE_STRING_LENGTH
        )

    private fun compact(
        message: AgentModelMessage,
        evidenceLimit: Int = MAX_EVIDENCE_ITEMS,
        maxStringLength: Int = COMPACT_STRING_LENGTH
    ): AgentModelMessage {
        val result = message.toolResult ?: return message.copy(content = "Earlier tool result compacted by host.")
        val compactedTruncation = result.truncation.copy(contextCompacted = true)
        val compactData = buildMap<String, Any?> {
            put("contextSummary", mapOf(
                "toolName" to result.toolName,
                "returnedCount" to result.returnedCount,
                "totalCount" to result.totalCount,
                "truncated" to result.truncated,
                "success" to result.success,
                "contextCompacted" to true,
                "continuation" to result.truncation.continuation
            ))
            extractEvidence(result.data)
                .take(evidenceLimit)
                .map { evidence -> compactEvidence(evidence, maxStringLength) }
                .takeIf { it.isNotEmpty() }
                ?.let { put("evidence", it) }
        }
        val compactResult = result.copy(
            data = compactData,
            truncated = result.truncated,
            provenance = result.provenance.copy(truncation = compactedTruncation),
            truncation = compactedTruncation
        )
        return AgentModelMessage.fromToolResult(compactResult, "Earlier tool result compacted by host.")
    }

    private fun compactEvidence(
        evidence: Map<String, Any?>,
        maxStringLength: Int
    ): Map<String, Any?> = evidence.entries.associate { (key, value) ->
        key to compactValue(value, depth = 0, maxStringLength = maxStringLength)
    }

    private fun compactValue(value: Any?, depth: Int, maxStringLength: Int): Any? = when {
        value == null -> null
        value is String -> value.take(maxStringLength).let { text ->
            if (value.length > maxStringLength) "$text..." else text
        }
        value is Number || value is Boolean -> value
        depth >= MAX_COMPACT_VALUE_DEPTH -> value.toString().take(maxStringLength)
        value is Map<*, *> -> value.entries
            .take(MAX_COMPACT_MAP_FIELDS)
            .associate { (key, item) ->
                key.toString() to compactValue(item, depth + 1, maxStringLength)
            }
        value is Iterable<*> -> value
            .take(MAX_COMPACT_COLLECTION_ITEMS)
            .map { item -> compactValue(item, depth + 1, maxStringLength) }
        else -> value.toString().take(maxStringLength)
    }

    private fun collectKeys(value: Any?, depth: Int = 0): Set<String> {
        if (depth > MAX_EVIDENCE_DEPTH) return emptySet()
        return when (value) {
            is Map<*, *> -> buildSet {
                value.forEach { (key, nested) ->
                    add(key.toString())
                    addAll(collectKeys(nested, depth + 1))
                }
            }
            is Iterable<*> -> buildSet {
                value.forEach { addAll(collectKeys(it, depth + 1)) }
            }
            else -> emptySet()
        }
    }

    private fun extractEvidence(value: Any?, depth: Int = 0): List<Map<String, Any?>> {
        if (depth > MAX_EVIDENCE_DEPTH) return emptyList()
        return when (value) {
            is Map<*, *> -> {
                val safe = value.entries.associate { it.key.toString() to it.value }
                val local = safe.filterKeys { it in EVIDENCE_KEYS }
                buildList {
                    if (local.isNotEmpty()) add(local)
                    safe.values.forEach { nested ->
                        if (size < MAX_EVIDENCE_ITEMS) addAll(extractEvidence(nested, depth + 1).take(MAX_EVIDENCE_ITEMS - size))
                    }
                }
            }
            is Iterable<*> -> buildList {
                value.forEach { nested ->
                    if (size < MAX_EVIDENCE_ITEMS) addAll(extractEvidence(nested, depth + 1).take(MAX_EVIDENCE_ITEMS - size))
                }
            }
            else -> emptyList()
        }
    }

    companion object {
        const val DEFAULT_CONTEXT_TOKENS = 32_768
        const val DEFAULT_OUTPUT_RESERVE = 1_024
        /**
         * Absolute ceiling on the output reserve.
         *
         * Observed reports run a few thousand tokens; this leaves an order of
         * magnitude of headroom while keeping the reserve from scaling into the
         * hundreds of thousands on a very large context window.
         */
        /** The largest normal generation reserve; phase budgets are smaller. */
        const val MAX_OUTPUT_RESERVE = 8_192
        const val WIDE_OUTPUT_RESERVE = AgentOutputBudget.WIDE_FINAL_REPORT_TOKENS
        private const val MAX_EVIDENCE_DEPTH = 16
        private const val MAX_EVIDENCE_ITEMS = 12
        private const val SUMMARY_EVIDENCE_ITEMS = 6
        private const val COMPACT_STRING_LENGTH = 256
        private const val SUMMARY_EVIDENCE_STRING_LENGTH = 192
        private const val MAX_COMPACT_VALUE_DEPTH = 4
        private const val MAX_COMPACT_MAP_FIELDS = 12
        private const val MAX_COMPACT_COLLECTION_ITEMS = 6
        private const val PROTECTED_EVIDENCE_WEIGHT = 1_000
        private const val FIELD_PROJECTION_EVIDENCE_WEIGHT = 500
        private const val FILTER_VALIDATION_EVIDENCE_WEIGHT = 300
        private const val LIGHTWEIGHT_EVIDENCE_WEIGHT = 100
        private const val BOOTSTRAP_EXPERT_EVIDENCE_WEIGHT = 50
        private const val HOST_BOOTSTRAP_EXPERT_PREFIX = "host-bootstrap-expert-"
        private val FIELD_EVIDENCE_KEYS = setOf(
            "field", "actualFieldName", "requestedName", "observedValue"
        )
        private val FRAME_EVIDENCE_KEYS = setOf(
            "frameNumber", "firstFrame", "lastFrame", "firstProblemFrame",
            "sampleFrames", "anomalyFrames", "presentFrames"
        )
        private val LIGHTWEIGHT_EVIDENCE_KEYS = FRAME_EVIDENCE_KEYS + setOf(
            "displayFilter", "normalizedFilter", "valid", "matchedPackets", "scannedPackets",
            "occurrenceCount", "coverageComplete", "sampled", "metric", "groupKey"
        )
        private val EVIDENCE_KEYS = setOf(
            "frameNumber", "displayFilter", "field", "actualFieldName", "requestedName",
            "firstFrame", "lastFrame", "firstProblemFrame", "sampleFrames", "anomalyFrames",
            "matchedPackets", "scannedPackets", "presentFrames", "occurrenceCount",
            "coverageComplete", "sampled", "metric", "observedValue",
            // A distribution group is only actionable while it keeps its
            // drill-down handle. The group's filter travels under the existing
            // `displayFilter` key above, so only the key itself is new here;
            // deliberately not `count`/`summary`, which are common enough to
            // start pulling unrelated payload fragments into evidence.
            "groupKey"
        )
    }
}
