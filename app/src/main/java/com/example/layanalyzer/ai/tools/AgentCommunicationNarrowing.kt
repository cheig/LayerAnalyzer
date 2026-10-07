package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.AgentJsonObject

/**
 * Narrows a communication-analysis payload by depth rather than by page.
 *
 * The observed 29 KB result held only four sessions: the weight was never list
 * length but per-entry depth — `stages`, `edges`, `delayContributions`,
 * `transportEvidence` and a whole nested `callSetupAnalysis` travel with each
 * entry. Paging cannot help with that shape, and neither can a smaller `limit`;
 * both return fewer of the same oversized entries.
 *
 * So this collapses the heavy nested collections to their sizes and leaves the
 * identity, outcome, timing and boundary frames intact. What survives is what a
 * model needs to say *which* session is interesting; the depth it needs to
 * explain *why* is then one selector away. Counts are kept rather than dropped
 * because "this session has 9 stages I have not shown you" is actionable, while
 * a silently absent key reads as "this session has no stages".
 */
internal object AgentCommunicationNarrowing {

    /**
     * Nested collections replaced by a `<key>Count` sibling.
     *
     * Frame-bearing lists are deliberately absent: `mediaNegotiationFrames`,
     * `evidenceFrames`, `reportFrames` and `coreEventFrames` are the citable
     * evidence a finding hangs off, and they are cheap. Removing them would save
     * little and cost the model exactly the values it is expected to cite.
     */
    private val HEAVY_KEYS = setOf(
        "stages",
        "edges",
        "imsCorrelations",
        "limitations",
        "delayContributions",
        "transportEvidence",
        "alternateCandidates",
        "attempts",
        "timeline",
        "candidates",
        "excludedCauses",
        "messages",
        "lines",
        "rtcp",
        "directions",
        "sdpMedia",
        "payloadMappings",
        "codecs",
        "endpoints",
        "findings"
    )

    /** Keys whose own value is a heavy object rather than a heavy list. */
    private val HEAVY_OBJECT_KEYS = setOf(
        "selectedAttempt",
        "largestContribution",
        "captureRange"
    )

    /**
     * Whether [data] needs narrowing to fit [allowance].
     *
     * Reserves a quarter of the allowance for the envelope, matching
     * [ExpertInfoTool] and `AgentPolicy.detailByteFit`.
     */
    fun exceedsAllowance(data: AgentJsonObject, allowance: Int): Boolean {
        val budget = allowance.toLong() * 3L / 4L
        return encodedSize(data) > budget
    }

    fun encodedSize(data: AgentJsonObject): Long =
        AgentResultTruncator.encode(data).toByteArray(Charsets.UTF_8).size.toLong()

    /**
     * Collapse heavy structures anywhere inside [data].
     *
     * The walk is key-driven rather than schema-driven so it keeps working as the
     * communication DTOs grow: a new nested list named in [HEAVY_KEYS] is
     * narrowed without this object needing to know which entry type introduced
     * it.
     */
    fun narrow(data: AgentJsonObject): AgentJsonObject = narrowMap(data, depth = 0)

    private fun narrowMap(source: Map<*, *>, depth: Int): AgentJsonObject {
        val result = LinkedHashMap<String, Any?>(source.size)
        source.forEach { (rawKey, value) ->
            val key = rawKey.toString()
            when {
                // Top-level domain lists are the answer itself and must survive;
                // only the structures *inside* their entries are collapsed.
                depth == 0 && (value is Iterable<*> || value is Array<*>) ->
                    result[key] = narrowList(value, depth + 1)

                key in HEAVY_KEYS && (value is Iterable<*> || value is Array<*>) -> {
                    val size = sizeOf(value)
                    if (size > 0) result["${key}Count"] = size
                }

                key in HEAVY_OBJECT_KEYS && value is Map<*, *> ->
                    result[key] = narrowMap(value, depth + 1)

                value is Map<*, *> -> result[key] = narrowMap(value, depth + 1)
                value is Iterable<*> || value is Array<*> -> result[key] = narrowList(value, depth + 1)
                else -> result[key] = value
            }
        }
        return result
    }

    private fun narrowList(value: Any?, depth: Int): List<Any?> {
        val items = when (value) {
            is Collection<*> -> value.toList()
            is Iterable<*> -> value.toList()
            is Array<*> -> value.toList()
            else -> return emptyList()
        }
        return items.map { item ->
            when (item) {
                is Map<*, *> -> narrowMap(item, depth)
                is Iterable<*>, is Array<*> -> narrowList(item, depth + 1)
                else -> item
            }
        }
    }

    private fun sizeOf(value: Any?): Int = when (value) {
        is Collection<*> -> value.size
        is Iterable<*> -> value.count()
        is Array<*> -> value.size
        else -> 0
    }
}
