// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.tools.dto.AgentExpertSeverity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.ExpertInfoItem

/**
 * One category of Expert entries: what it is, how often it happened, and where
 * to look next.
 *
 * [displayFilter] is the drill-down the model may cite and reuse verbatim, which
 * is the whole point of grouping — a summary the model cannot act on would just
 * be a smaller way of saying "there was too much data".  It uses the shared
 * `displayFilter` key rather than a tool-private name so the existing evidence
 * extraction and context compaction recognise it without special-casing.
 */
data class AgentExpertGroup(
    val groupKey: String,
    val severity: String,
    val summary: String,
    val count: Int,
    val firstFrame: Long,
    val lastFrame: Long,
    val sampleFrames: List<Long>,
    val displayFilter: String?
) {
    fun toAgentJson(): AgentJsonObject = mapOf(
        "groupKey" to groupKey,
        "severity" to severity,
        "summary" to summary,
        "count" to count,
        "firstFrame" to firstFrame,
        "lastFrame" to lastFrame,
        "sampleFrames" to sampleFrames,
        "displayFilter" to displayFilter
    )
}

/**
 * Collapses Expert entries into their real categories.
 *
 * A 188-frame capture produces 228 Expert entries but only a handful of distinct
 * problems: one `(severity, category)` pair repeats dozens of times.  Returning
 * the raw list spends the whole byte allowance restating the same fact, so this
 * grouper answers the question the entries actually carry — which problems
 * occurred, how often, and which frames to inspect.
 *
 * The grouping key is deliberately *not* the label.  [ExpertInfoItem.label] is
 * free text containing frame-specific values ("Bad checksum [0x1234]"), so
 * keying on it would scatter one problem across dozens of single-entry groups
 * and degrade the summary back into the list it replaces.  Wireshark's own field
 * abbreviation is used instead, because it names the category rather than the
 * occurrence.
 */
internal object AgentExpertGrouper {

    /**
     * Hard ceiling on returned groups.
     *
     * Aligned with [com.example.layanalyzer.ai.agent.ContextPlanner]'s
     * `MAX_COMPACT_COLLECTION_ITEMS`: a group beyond that index would be dropped
     * the first time the transcript is compacted, so promising it here would be
     * promising something the model may never get to read.
     */
    const val MAX_GROUPS = 6

    /** Frame samples per group; enough to drill down, bounded so it stays cheap. */
    const val MAX_SAMPLE_FRAMES = 3

    private const val MAX_LABEL_KEY_CHARS = 48
    private const val VARIABLE_PLACEHOLDER = "#"

    /**
     * Group [items] and return the most informative [MAX_GROUPS] of them.
     *
     * Ordering is by severity first and count second, so a single `error` is
     * never crowded out by a 96-occurrence `warning`: the rare serious finding is
     * usually the answer to the user's question, while the frequent one is
     * usually background noise. [groupsTotal] reports how many categories existed
     * before that cut, so the model can tell "6 groups" from "6 of 20".
     */
    fun group(items: List<ExpertInfoItem>): AgentExpertGrouping {
        if (items.isEmpty()) return AgentExpertGrouping(emptyList(), 0)

        val accumulators = LinkedHashMap<String, Accumulator>()
        items.forEach { item ->
            val key = groupKeyOf(item)
            accumulators.getOrPut(key) {
                Accumulator(
                    groupKey = key,
                    severity = severityOf(item),
                    // The first label seen is the representative text. Later
                    // labels in the same category differ only in their
                    // frame-specific values, so keeping one avoids paying for
                    // near-duplicates.
                    summary = item.label.trim(),
                    displayFilter = item.filter?.takeIf { it.isNotBlank() }
                )
            }.observe(item.frameNumber)
        }

        val ordered = accumulators.values.sortedWith(
            compareByDescending<Accumulator> { severityRank(it.severity) }
                .thenByDescending { it.count }
                .thenBy { it.firstFrame }
        )
        return AgentExpertGrouping(
            groups = ordered.take(MAX_GROUPS).map { it.toGroup() },
            groupsTotal = accumulators.size
        )
    }

    /**
     * The group key for one entry: `severity/category`.
     *
     * This is the single definition of group identity, shared by summary
     * construction and by the drill-down that selects one group's entries.  Were
     * the two to derive keys independently they could disagree, and a `groupKey`
     * the summary advertised would then silently select nothing.
     */
    fun groupKeyOf(item: ExpertInfoItem): String = "${severityOf(item)}/${categoryOf(item)}"

    /** Normalised severity, falling back to the raw label for unknown values. */
    fun severityOf(item: ExpertInfoItem): String =
        AgentExpertSeverity.fromNative(item.severity)?.wireName
            ?: item.severity.trim().lowercase()

    /**
     * The stable category for one entry.
     *
     * Wireshark's field abbreviation (`tcp.analysis.retransmission`) is a
     * dissector-owned identifier for the *kind* of problem, so it is preferred
     * whenever present.  Only when the engine supplied no abbreviation does this
     * fall back to the label, normalized so that entries differing only in a
     * frame number, offset or checksum still land together.
     */
    fun categoryOf(item: ExpertInfoItem): String {
        val abbrev = item.filter?.trim()?.takeIf { it.isNotEmpty() }
        if (abbrev != null) return abbrev
        return normalizeLabel(item.label)
    }

    /**
     * Reduce a free-text Expert label to its invariant part.
     *
     * Every run of digits, every hex literal and every bracketed or parenthesised
     * aside is replaced rather than removed: "Bad checksum [0x1234]" and "Bad
     * checksum [0xbeef]" describe one problem and must produce one key, while
     * "Bad checksum" and "Bad sequence number" must stay distinct. Replacing
     * keeps that distinction visible; deleting would blur it.
     */
    fun normalizeLabel(label: String): String {
        if (label.isBlank()) return "unlabelled"
        var normalized = label.trim().lowercase()
        // Hex literals first: 0x1234 would otherwise leave a stray "x" behind
        // once its digit run was replaced.
        normalized = HEX_LITERAL.replace(normalized, VARIABLE_PLACEHOLDER)
        normalized = BRACKETED.replace(normalized, VARIABLE_PLACEHOLDER)
        normalized = DIGIT_RUN.replace(normalized, VARIABLE_PLACEHOLDER)
        normalized = WHITESPACE.replace(normalized, " ").trim()
        if (normalized.isEmpty()) return "unlabelled"
        return normalized.take(MAX_LABEL_KEY_CHARS)
    }

    /** Error above warning above note above chat; unknown labels sort last. */
    private fun severityRank(severity: String): Int = when (severity) {
        AgentExpertSeverity.Error.wireName -> 4
        AgentExpertSeverity.Warning.wireName -> 3
        AgentExpertSeverity.Note.wireName -> 2
        AgentExpertSeverity.Chat.wireName -> 1
        else -> 0
    }

    private class Accumulator(
        val groupKey: String,
        val severity: String,
        val summary: String,
        val displayFilter: String?
    ) {
        var count: Int = 0
            private set
        var firstFrame: Long = Long.MAX_VALUE
            private set
        private var lastFrame: Long = 0L
        private val samples = LinkedHashSet<Long>()

        fun observe(frame: Long) {
            count += 1
            if (frame < firstFrame) firstFrame = frame
            if (frame > lastFrame) lastFrame = frame
            if (samples.size < MAX_SAMPLE_FRAMES) samples += frame
        }

        fun toGroup(): AgentExpertGroup = AgentExpertGroup(
            groupKey = groupKey,
            severity = severity,
            summary = summary,
            count = count,
            firstFrame = if (firstFrame == Long.MAX_VALUE) 0L else firstFrame,
            lastFrame = lastFrame,
            sampleFrames = samples.sorted(),
            displayFilter = displayFilter
        )
    }

    private val HEX_LITERAL = Regex("0x[0-9a-f]+")
    private val BRACKETED = Regex("[\\[(][^\\])]*[\\])]")
    private val DIGIT_RUN = Regex("\\d+")
    private val WHITESPACE = Regex("\\s+")
}

/** Groups that fit, plus how many existed before the cut. */
internal data class AgentExpertGrouping(
    val groups: List<AgentExpertGroup>,
    val groupsTotal: Int
)
