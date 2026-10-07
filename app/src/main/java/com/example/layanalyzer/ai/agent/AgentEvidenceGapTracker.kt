// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolResult

/**
 * One truncated result that is still worth re-reading, and the call that would
 * do it.
 *
 * [toolName] is the tool the continuation points at, which is not always the
 * tool that produced the gap: a detail budget cut by `get_packet_fields` is
 * continued by calling `get_packet_fields` again with the omitted frames, while
 * an Expert distribution is continued by asking the same tool for one group.
 */
internal data class AgentEvidenceGap(
    /** Tool call whose result was cut; also this gap's identity. */
    val sourceToolCallId: String,
    val sourceToolName: String,
    val toolName: String,
    val continuation: AgentJsonObject
) {
    /** Short, redacted label for diagnostics and nudge text. */
    fun describe(): String = buildString {
        append(toolName)
        val hint = continuation["groupKey"] ?: continuation["mode"] ?: continuation["offset"]
        if (hint != null) {
            append('(')
            append(hint.toString().take(MAX_HINT_CHARS))
            append(')')
        }
    }

    private companion object {
        const val MAX_HINT_CHARS = 40
    }
}

/**
 * The gaps a run is still allowed to spend host-granted turns on.
 *
 * Gap-fill exists because a plan sized before any result was seen cannot
 * anticipate truncation. But a grant that any tool call can spend is not a grant
 * to fill gaps — it is four extra turns of unrestricted discovery, which is
 * exactly what the observed run used them for while the truncated evidence sat
 * unread. This tracker is what makes the grant mean what it says: a call must
 * match a pending gap to be allowed, and only a call that actually advances one
 * costs quota.
 *
 * Identity is the *source* tool call id, so a gap is retired when the thing that
 * created it has been followed up, and re-reading the same page twice cannot
 * quietly satisfy two gaps.
 */
internal class AgentEvidenceGapTracker {
    private val pending = LinkedHashMap<String, AgentEvidenceGap>()

    val isEmpty: Boolean
        get() = pending.isEmpty()

    val size: Int
        get() = pending.size

    /**
     * Gaps in the order the model should address them.
     *
     * A gap whose continuation opens an unread *category* outranks one that
     * merely extends a page the model has already seen part of: the first can
     * change a conclusion, the second usually confirms it.
     */
    fun ordered(): List<AgentEvidenceGap> = pending.values.sortedByDescending { gap ->
        when {
            gap.continuation["groupKey"] != null -> 3
            gap.continuation["mode"] != null -> 3
            gap.continuation["frames"] != null -> 2
            else -> 1
        }
    }

    /** Register a truncated result that carried a usable continuation. */
    fun record(call: AgentToolCall, result: AgentToolResult) {
        val continuation = result.truncation.continuation ?: return
        if (continuation["available"] == false) return
        if (call.toolCallId.isBlank()) return
        pending[call.toolCallId] = AgentEvidenceGap(
            sourceToolCallId = call.toolCallId,
            sourceToolName = result.toolName.ifBlank { call.toolName },
            toolName = (continuation["tool"] as? String)?.takeIf { it.isNotBlank() }
                ?: result.toolName.ifBlank { call.toolName },
            continuation = continuation
        )
    }

    /**
     * The pending gap [call] would advance, or null if it advances none.
     *
     * The match is deliberately permissive about *values* and strict about
     * *intent*. A model that reads offset 120 when the host suggested 100, or
     * asks for a different group than the one listed first, is still doing the
     * thing the grant was for; rejecting it would push the run back into the
     * failure this whole mechanism exists to prevent. What is not accepted is a
     * call to a tool no pending gap names, or a re-read of a page the gap did not
     * ask about — those are new investigation wearing a continuation's clothes.
     */
    fun matching(call: AgentToolCall): AgentEvidenceGap? =
        ordered().firstOrNull { gap -> matches(gap, call) }

    private fun matches(gap: AgentEvidenceGap, call: AgentToolCall): Boolean {
        if (call.toolName != gap.toolName) return false
        val continuation = gap.continuation

        // A group drill-down must name a group, but not necessarily the one the
        // summary happened to list first.
        (continuation["availableGroupKeys"] as? Iterable<*>)?.let { keys ->
            val requested = (call.arguments["groupKey"] as? String)?.trim()
            if (!requested.isNullOrEmpty()) {
                return keys.any { it?.toString() == requested }
            }
        }
        (continuation["groupKey"] as? String)?.takeIf { it.isNotBlank() }?.let { suggested ->
            val requested = (call.arguments["groupKey"] as? String)?.trim()
            return requested == suggested
        }

        // A detail continuation is satisfied by reading any of the frames it
        // listed; the budget may not grant all of them in one call.
        (continuation["frames"] as? Iterable<*>)?.let { frames ->
            val wanted = frames.mapNotNull { asLong(it) }.toSet()
            if (wanted.isNotEmpty()) {
                val requested = (call.arguments["frames"] as? Iterable<*>)
                    ?.mapNotNull { asLong(it) }
                    .orEmpty()
                return requested.any { it in wanted }
            }
        }

        // A paging continuation is satisfied by advancing past what was already
        // returned, or by re-reading the same offset with a smaller page when the
        // host asked for exactly that.
        val suggestedOffset = asLong(continuation["offset"])
        if (suggestedOffset != null) {
            val requestedOffset = asLong(call.arguments["offset"]) ?: 0L
            if (continuation["reason"] == RETRY_WITH_SMALLER_LIMIT) {
                val suggestedLimit = asLong(continuation["limit"])
                val requestedLimit = asLong(call.arguments["limit"])
                return requestedOffset == suggestedOffset &&
                    (suggestedLimit == null || requestedLimit == null || requestedLimit <= suggestedLimit)
            }
            return requestedOffset >= suggestedOffset
        }

        // A continuation naming only a tool (an explicit mode switch, say) is
        // satisfied by calling that tool at all.
        return continuation["mode"] != null || continuation["tool"] != null
    }

    /** Retire a filled gap so the nudge stops asking for it. */
    fun retire(gap: AgentEvidenceGap) {
        pending.remove(gap.sourceToolCallId)
    }

    private fun asLong(value: Any?): Long? = when (value) {
        is Number -> value.toLong()
        is String -> value.trim().toLongOrNull()
        else -> null
    }

    private companion object {
        const val RETRY_WITH_SMALLER_LIMIT = "retry_with_smaller_limit"
    }
}
