// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.tools.AgentExpertGrouper
import com.example.layanalyzer.ai.tools.dto.AgentExpertSeverity
import com.example.layanalyzer.model.AgentToolResult
import java.security.MessageDigest
import java.util.Locale

/**
 * One host-enumerated signal: a bounded aggregate fact the baseline calls
 * already established, so "the overview said there are problems and the
 * report never mentions them" becomes a checkable membership test (design
 * §5.2, OPT-VAL-02).
 *
 * A signal carries counts, names and percentages only — never frame numbers
 * or capture payload — and [signalId] is a content hash, stable across runs
 * and across the calls that reported the same content, so findings and
 * limitations can point at it without restating the fact.
 */
data class AgentSignal(
    val signalId: String,
    val kind: String,
    val value: String,
    val unit: String
)

/**
 * One tool call as the signal extractor sees it: the decoded result map
 * ([AgentToolResult.data], the same payload the ledger's payload extractor
 * walks) plus the identity and success the ledger records.
 *
 * [toolCallId] is not used for extraction — signals are call-id agnostic, so
 * a bootstrap call and a model re-run of the same question yield the same
 * signal ids. It travels along so OPT-VAL-02-02 can attribute a signal back
 * to the call that produced it when it annotates the transcript.
 */
data class HostCallPayload(
    val toolCallId: String,
    val toolName: String,
    val success: Boolean = true,
    val data: Map<String, Any?>?
)

/**
 * The ordered, bounded signal set one run's baseline produced.
 *
 * [signals] is in host-priority order (see [AgentSignalExtractor]) and holds
 * at most [AgentSignalExtractor.MAX_SIGNALS] entries; when candidates were
 * dropped, the last entry is the `signals_capped` meta-signal and
 * [droppedSignalCount] repeats its value for callers that want a number
 * instead of a string.
 */
data class AgentSignalSet(
    val signals: List<AgentSignal>,
    val droppedSignalCount: Int = 0
) {
    val isEmpty: Boolean get() = signals.isEmpty()

    val signalIds: List<String> get() = signals.map { it.signalId }
}

/**
 * Extracts the bounded signal set of OPT-VAL-02-01 from the successful
 * `get_capture_overview` / `get_expert_info` calls of a run — the
 * `host-bootstrap-overview-1` / `host-bootstrap-expert-2` calls and any
 * model re-runs of the same tools.
 *
 * This class is pure: no ledger, no loop, no state. OPT-VAL-02-02 wires it
 * by handing the run's tool results to [extractFromResults]; nothing here
 * knows or cares how the calls were selected, only that failed calls and
 * non-baseline tools are silently ignored.
 *
 * Signal families and the host rules that define them:
 *
 *  - `expert_group` — one per *nonzero* Expert-Info category reported by
 *    `get_expert_info`, which answers in two shapes and is read in both:
 *    - **group (summary) shape**: every entry of `groups` whose `count > 0`;
 *      value = the group's `count`, unit = `items`;
 *    - **items shape without a payload `groupKey`** (the bootstrap call's
 *      shape): items are aggregated per group, a group being the pair
 *      `(severity, category)` the grouper itself uses — category is the
 *      item's `displayFilter` when present and its [AgentExpertGrouper]
 *      normalized label otherwise. Value = the number of *returned* items in
 *      that group (the page bound, at most `limit`; a lower bound that never
 *      overstates the group);
 *    - **items shape with a payload `groupKey`** (a drill-down of one named
 *      group): a single signal, value = the payload `total` — the group's
 *      true size, which that call computed over the whole group — falling
 *      back to the returned count when `total` is absent or not positive.
 *    Both shapes spell the group key `severity/category` the same way, so a
 *    bootstrap item page and a summary re-run that report the *same count*
 *    for the *same* category dedupe to one id. Different counts for one
 *    category are different content and therefore different ids; the pair is
 *    itself informative (page bound vs. true total).
 *    The overview's scalar `expertErrorCount`/`expertWarningCount` get no
 *    signal of their own: they name no group, and the bootstrap runs the
 *    expert call exactly when they are nonzero.
 *
 *  - `health_problems` — one per overview `health` family with `problems > 0`
 *    or a severity at or above `warning` (the wire severities are
 *    `healthy` < `notice` < `warning` < `error`); value = `problems`
 *    (zero when only the severity qualifies), unit = `problems`. The family
 *    id and severity feed the signal id's hash source, so a family
 *    escalating notice→warning yields a new id.
 *
 *  - `protocol_share` — one per overview `protocolHierarchy` entry whose
 *    `packetPercent` reaches [DOMINANT_PROTOCOL_PACKET_PERCENT] (inclusive,
 *    floating-point comparison): a single protocol carrying at least half
 *    the packets is the deterministic "one protocol dominates this capture"
 *    anomaly, which is exactly the kind of overview fact a report must
 *    address or explain. value = the percent fixed to three decimals,
 *    unit = `percent`.
 *
 *  - `signals_capped` — the overflow meta-signal; value = how many distinct
 *    signals were dropped, unit = `signals`.
 *
 * Pipeline, pinned by tests: generate → order → dedupe by id → cap.
 * Ordering is severity-first and fully deterministic: all `expert_group`
 * signals first (severity `error` > `warning` > `note` > `chat` > unknown,
 * then group key), then `health_problems` (severity descending, then family
 * id), then `protocol_share` (percent descending, then name); equal ranks
 * fall back to generation order, which is call execution order. Only then
 * are duplicate ids (same content from bootstrap and a re-run) collapsed,
 * keeping the first occurrence in that order. When more than [MAX_SIGNALS]
 * distinct signals remain, the first `MAX_SIGNALS - 1` survive in order and
 * the rest fold into one trailing `signals_capped` signal, so a capped set
 * is exactly [MAX_SIGNALS] long. Empty input gives an empty set; malformed
 * or missing keys skip that signal family — this extractor never throws,
 * because a baseline payload it cannot read must not be able to take the
 * agent loop down.
 *
 * Like [ReportCoverageValidator], subtractive by construction: it only
 * enumerates facts the host already had; it raises no confidence and gates
 * nothing by itself.
 */
class AgentSignalExtractor {

    /**
     * The signal families, ordered by extraction priority. OPT-VAL-02-03's
     * coverage gate reads these back off the ledger annotations, so the
     * names are part of the host vocabulary, not private wording.
     */
    companion object {
        const val TOOL_CAPTURE_OVERVIEW = "get_capture_overview"
        const val TOOL_EXPERT_INFO = "get_expert_info"

        const val KIND_EXPERT_GROUP = "expert_group"
        const val KIND_HEALTH_PROBLEMS = "health_problems"
        const val KIND_PROTOCOL_SHARE = "protocol_share"
        const val KIND_SIGNALS_CAPPED = "signals_capped"

        const val UNIT_ITEMS = "items"
        const val UNIT_PROBLEMS = "problems"
        const val UNIT_PERCENT = "percent"
        const val UNIT_SIGNALS = "signals"

        /**
         * A protocol at or above this share of packets is flagged as
         * dominating the capture (see class doc).
         */
        const val DOMINANT_PROTOCOL_PACKET_PERCENT = 50.0

        /** Hard ceiling on the emitted set, `signals_capped` included. */
        const val MAX_SIGNALS = 20

        private const val FAMILY_RANK_EXPERT = 0
        private const val FAMILY_RANK_HEALTH = 1
        private const val FAMILY_RANK_PROTOCOL = 2

        /** Health severities at or above this rank qualify without a problem count. */
        private const val HEALTH_RANK_WARNING = 3

        private const val HASH_SCHEME = "agent-signal-v1"
        private const val HASH_ALGORITHM = "SHA-256"
        private const val SIGNAL_ID_PREFIX = "sig-"
        private const val SIGNAL_ID_HASH_CHARS = 12

        private fun expertSeverityRank(severity: String): Int = when (severity) {
            AgentExpertSeverity.Error.wireName -> 4
            AgentExpertSeverity.Warning.wireName -> 3
            AgentExpertSeverity.Note.wireName -> 2
            AgentExpertSeverity.Chat.wireName -> 1
            else -> 0
        }

        private fun healthSeverityRank(severity: String): Int = when (severity) {
            "error" -> 4
            "warning" -> 3
            "notice" -> 2
            "healthy" -> 1
            else -> 0
        }
    }

    /** A candidate signal plus the keys that place it in the host order. */
    private data class RankedSignal(
        val familyRank: Int,
        val severityRank: Int,
        val percent: Double,
        val discriminator: String,
        val sequence: Int,
        val signal: AgentSignal
    )

    /**
     * The signal set for the calls of one run, in host priority order and
     * capped at [MAX_SIGNALS]. Calls that failed, are not a baseline tool,
     * or carry a payload this extractor cannot read contribute nothing.
     */
    fun extract(calls: List<HostCallPayload>): AgentSignalSet {
        val candidates = ArrayList<RankedSignal>()
        calls.forEach { call ->
            if (!call.success) return@forEach
            when (call.toolName) {
                TOOL_CAPTURE_OVERVIEW -> {
                    addHealthSignals(call.data, candidates)
                    addProtocolShareSignals(call.data, candidates)
                }
                TOOL_EXPERT_INFO -> addExpertSignals(call.data, candidates)
            }
        }
        candidates.sortWith(
            compareBy<RankedSignal> { it.familyRank }
                .thenByDescending { it.severityRank }
                .thenByDescending { it.percent }
                .thenBy { it.discriminator }
                .thenBy { it.sequence }
        )
        // Dedupe by content-hash id before capping: re-states of one fact
        // must not crowd distinct facts out of the bounded set.
        val distinct = ArrayList<RankedSignal>(candidates.size)
        val seen = HashSet<String>(candidates.size)
        for (candidate in candidates) {
            if (seen.add(candidate.signal.signalId)) distinct.add(candidate)
        }
        if (distinct.size <= MAX_SIGNALS) {
            return AgentSignalSet(distinct.map { it.signal })
        }
        val kept = distinct.take(MAX_SIGNALS - 1).map { it.signal }
        val dropped = distinct.size - kept.size
        return AgentSignalSet(
            signals = kept + buildSignal(
                kind = KIND_SIGNALS_CAPPED,
                discriminator = KIND_SIGNALS_CAPPED,
                value = dropped.toString(),
                unit = UNIT_SIGNALS
            ),
            droppedSignalCount = dropped
        )
    }

    /**
     * Ledger/loop-side selection helper for OPT-VAL-02-02: maps raw tool
     * results — the shape the bootstrap execution and the tool runner
     * already return, and the same `data` map the evidence ledger reduces —
     * onto [HostCallPayload] and extracts. Ordering of [results] is kept as
     * generation order, so it should be execution order.
     */
    fun extractFromResults(results: List<AgentToolResult>): AgentSignalSet = extract(
        results.map { result ->
            HostCallPayload(
                toolCallId = result.toolCallId,
                toolName = result.toolName,
                success = result.success,
                data = result.data
            )
        }
    )

    // ------------------------------------------------------------- families

    /**
     * `expert_group` from either get_expert_info shape; a payload carrying
     * neither list (or a malformed one) simply contributes nothing.
     */
    private fun addExpertSignals(data: Map<String, Any?>?, out: MutableList<RankedSignal>) {
        data ?: return

        (data["groups"] as? List<*>)?.forEach { row ->
            val group = row as? Map<*, *> ?: return@forEach
            val count = group["count"].asCount() ?: return@forEach
            if (count <= 0L) return@forEach
            val severity = expertSeverityOf(group["severity"])
            val groupKey = textOf(group["groupKey"])
            val summary = textOf(group["summary"])
            val discriminator = when {
                groupKey.isNotEmpty() -> groupKey
                // A group without its key is still identifiable by the very
                // pair the key is made of; lacking both parts it is noise.
                severity.isNotEmpty() || summary.isNotEmpty() -> "$severity/$summary"
                else -> return@forEach
            }
            addSignal(
                out = out,
                familyRank = FAMILY_RANK_EXPERT,
                severityRank = expertSeverityRank(severity),
                percent = 0.0,
                kind = KIND_EXPERT_GROUP,
                discriminator = discriminator,
                value = count.toString(),
                unit = UNIT_ITEMS
            )
        }

        val items = data["items"] as? List<*> ?: return
        val payloadGroupKey = textOf(data["groupKey"])
        if (payloadGroupKey.isNotEmpty()) {
            // A drill-down is about exactly one named group: report the
            // total the call computed over the whole group, not its page.
            val projected = items.count { it as? Map<*, *> != null }
            val total = data["total"].asCount()
            val count = total?.takeIf { it > 0L } ?: projected.toLong()
            if (count > 0L) {
                val severity = payloadGroupKey.substringBefore('/', "")
                    .let { expertSeverityOf(it) }
                addSignal(
                    out = out,
                    familyRank = FAMILY_RANK_EXPERT,
                    severityRank = expertSeverityRank(severity),
                    percent = 0.0,
                    kind = KIND_EXPERT_GROUP,
                    discriminator = payloadGroupKey,
                    value = count.toString(),
                    unit = UNIT_ITEMS
                )
            }
            return
        }
        // A page over the whole list: count the returned items per group.
        // (Aggregated counts are always >= 1, so the nonzero test below is
        // symmetry with the other shapes, not a live zero case.)
        val countsByGroup = LinkedHashMap<String, Long>()
        items.forEach { row ->
            val item = row as? Map<*, *> ?: return@forEach
            val severity = expertSeverityOf(item["severity"])
            // An item with no severity cannot join the `severity/category`
            // identity the summary shape uses; a blank label/filter is fine,
            // the grouper itself normalizes those to "unlabelled".
            if (severity.isEmpty()) return@forEach
            val category = textOf(item["displayFilter"])
                .ifEmpty { AgentExpertGrouper.normalizeLabel(textOf(item["label"])) }
            val discriminator = "$severity/$category"
            countsByGroup[discriminator] = (countsByGroup[discriminator] ?: 0L) + 1L
        }
        countsByGroup.forEach { (discriminator, count) ->
            addSignal(
                out = out,
                familyRank = FAMILY_RANK_EXPERT,
                severityRank = expertSeverityRank(discriminator.substringBefore('/', "")),
                percent = 0.0,
                kind = KIND_EXPERT_GROUP,
                discriminator = discriminator,
                value = count.toString(),
                unit = UNIT_ITEMS
            )
        }
    }

    /** `health_problems` from the overview's family-keyed `health` map. */
    private fun addHealthSignals(data: Map<String, Any?>?, out: MutableList<RankedSignal>) {
        val health = data?.get("health") as? Map<*, *> ?: return
        health.forEach { (familyKey, row) ->
            val family = textOf(familyKey)
            val entry = row as? Map<*, *> ?: return@forEach
            if (family.isEmpty()) return@forEach
            val severity = textOf(entry["severity"]).lowercase()
            val rank = healthSeverityRank(severity)
            val problems = entry["problems"].asCount() ?: 0L
            if (problems <= 0L && rank < HEALTH_RANK_WARNING) return@forEach
            addSignal(
                out = out,
                familyRank = FAMILY_RANK_HEALTH,
                severityRank = rank,
                percent = 0.0,
                kind = KIND_HEALTH_PROBLEMS,
                discriminator = "$family|$severity",
                value = problems.coerceAtLeast(0L).toString(),
                unit = UNIT_PROBLEMS
            )
        }
    }

    /** `protocol_share` from the overview's bounded protocol distribution. */
    private fun addProtocolShareSignals(data: Map<String, Any?>?, out: MutableList<RankedSignal>) {
        val hierarchy = data?.get("protocolHierarchy") as? List<*> ?: return
        hierarchy.forEach { row ->
            val entry = row as? Map<*, *> ?: return@forEach
            val name = textOf(entry["name"])
            if (name.isEmpty()) return@forEach
            val percent = entry["packetPercent"].asDouble() ?: return@forEach
            if (percent < DOMINANT_PROTOCOL_PACKET_PERCENT) return@forEach
            addSignal(
                out = out,
                familyRank = FAMILY_RANK_PROTOCOL,
                severityRank = 0,
                percent = percent,
                kind = KIND_PROTOCOL_SHARE,
                discriminator = name,
                value = String.format(Locale.ROOT, "%.3f", percent),
                unit = UNIT_PERCENT
            )
        }
    }

    // ------------------------------------------------------------- plumbing

    private fun addSignal(
        out: MutableList<RankedSignal>,
        familyRank: Int,
        severityRank: Int,
        percent: Double,
        kind: String,
        discriminator: String,
        value: String,
        unit: String
    ) {
        out.add(
            RankedSignal(
                familyRank = familyRank,
                severityRank = severityRank,
                percent = percent,
                discriminator = discriminator,
                sequence = out.size,
                signal = buildSignal(kind, discriminator, value, unit)
            )
        )
    }

    /** The single place signal ids are minted; see [signalId]. */
    private fun buildSignal(
        kind: String,
        discriminator: String,
        value: String,
        unit: String
    ): AgentSignal = AgentSignal(
        signalId = signalId(kind, discriminator, value, unit),
        kind = kind,
        value = value,
        unit = unit
    )

    private fun textOf(value: Any?): String = (value as? String)?.trim().orEmpty()

    /** Normalized expert severity, mirroring the tool's own projection. */
    private fun expertSeverityOf(value: Any?): String {
        val raw = textOf(value)
        if (raw.isEmpty()) return ""
        return AgentExpertSeverity.fromNative(raw)?.wireName ?: raw.lowercase()
    }

    /** Integer count, tolerant of JSON re-encoding as Double or String. */
    private fun Any?.asCount(): Long? = when (this) {
        is Number -> toDouble().takeIf { it.isFinite() }?.toLong()
        is String -> trim().toLongOrNull()
        else -> null
    }

    private fun Any?.asDouble(): Double? = when (this) {
        is Number -> toDouble().takeIf { it.isFinite() }
        is String -> trim().toDoubleOrNull()?.takeIf { it.isFinite() }
        else -> null
    }

    /**
     * `sig-` + the first [SIGNAL_ID_HASH_CHARS] hex chars of SHA-256 over
     * `scheme|kind|discriminator|value|unit` with every segment
     * length-prefixed, so no separator can bleed one field into the next.
     * Text-only input and a fixed algorithm make ids stable across JVM
     * runs; nothing here uses identity hashes or iteration order.
     */
    private fun signalId(kind: String, discriminator: String, value: String, unit: String): String {
        val canonical = buildString {
            append(HASH_SCHEME)
            for (segment in listOf(kind, discriminator, value, unit)) {
                append('|')
                append(segment.length)
                append(':')
                append(segment)
            }
        }
        val digest = MessageDigest.getInstance(HASH_ALGORITHM)
            .digest(canonical.toByteArray(Charsets.UTF_8))
        val digits = "0123456789abcdef"
        val hex = CharArray(digest.size * 2)
        digest.forEachIndexed { index, byte ->
            hex[index * 2] = digits[(byte.toInt() shr 4) and 0x0F]
            hex[index * 2 + 1] = digits[byte.toInt() and 0x0F]
        }
        return SIGNAL_ID_PREFIX + String(hex, 0, SIGNAL_ID_HASH_CHARS)
    }
}
