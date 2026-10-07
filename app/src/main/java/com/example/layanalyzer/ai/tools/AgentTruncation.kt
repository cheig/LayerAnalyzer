// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentTruncationInfo

/** Internal helpers for the model-visible truncation/continuation contract. */
internal object AgentTruncation {
    fun fromData(
        data: AgentJsonObject?,
        returned: Long,
        total: Long,
        fallbackTruncated: Boolean = false
    ): AgentTruncationInfo {
        val value = data.orEmpty()
        val omittedFrames = buildList {
            addAll(longList(value["omittedFrames"]))
            addAll(longList(value["payloadOmittedFrames"]))
        }.distinct()
        val sourceTruncated = value["sourceTruncated"] == true ||
            listOf("sipSource", "rtpSource", "rtcpSource", "coreSource")
                .mapNotNull { value[it] as? Map<*, *> }
                .any { it["truncated"] == true }
        val quotaTruncated = value["omittedByBudget"] == true ||
            value["detailBudgetExhausted"] == true ||
            omittedFrames.isNotEmpty()
        val explicit = value["truncation"] as? Map<*, *>
        val payloadTruncated = value["payloadTruncated"] == true ||
            explicit?.get("payloadTruncated") == true ||
            (fallbackTruncated && !sourceTruncated && !quotaTruncated)
        val omittedPaths = stringList(explicit?.get("omittedPaths")) +
            stringList(value["omittedPaths"])
        val continuation = mapValue(explicit?.get("continuation"))
            ?: mapValue(value["continuation"])
            ?: pagingContinuation(value, returned, total)
            ?: payloadRetryContinuation(value, returned, payloadTruncated, omittedFrames)
            ?: detailContinuation(value, omittedFrames)
            ?: genericContinuation(value, omittedFrames, omittedPaths)
        return AgentTruncationInfo(
            sourceTruncated = sourceTruncated || explicit?.get("sourceTruncated") == true,
            quotaTruncated = quotaTruncated || explicit?.get("quotaTruncated") == true,
            payloadTruncated = payloadTruncated,
            contextCompacted = explicit?.get("contextCompacted") == true,
            returned = returned,
            total = maxOf(total, returned),
            omittedFrames = (omittedFrames + longList(explicit?.get("omittedFrames"))).distinct(),
            omittedPaths = omittedPaths.distinct(),
            continuation = continuation
        )
    }

    fun toJson(info: AgentTruncationInfo): AgentJsonObject = mapOf(
        "sourceTruncated" to info.sourceTruncated,
        "quotaTruncated" to info.quotaTruncated,
        "payloadTruncated" to info.payloadTruncated,
        "contextCompacted" to info.contextCompacted,
        "returned" to info.returned,
        "total" to info.total,
        "omittedFrames" to info.omittedFrames,
        "omittedPaths" to info.omittedPaths,
        "continuation" to info.continuation
    )

    private fun pagingContinuation(
        data: AgentJsonObject,
        returned: Long,
        total: Long
    ): AgentJsonObject? {
        val offset = (data["offset"] as? Number)?.toLong() ?: return null
        if (returned <= 0L || offset + returned >= total) return null
        return buildMap {
            put("offset", offset + returned)
            (data["limit"] as? Number)?.toLong()?.let { put("limit", it) }
        }
    }

    /**
     * A payload trim has two very different causes, and only one of them is
     * fixable by re-reading.
     *
     * When the trim dropped whole *list items*, the page really is re-readable:
     * the items exist, they just did not all survive the byte trim, so
     * re-requesting the same offset with a smaller limit yields fuller entries
     * per call.
     *
     * When the list was complete and the trim instead cut *fields inside* each
     * item — the caps in [AgentResultTruncator] descend together, so deep fields
     * go first — a smaller limit cannot help: it returns fewer of the same
     * partial items. Suggesting it is not merely low-value but wrong, and a model
     * that follows the suggestion spends a turn to receive strictly less. The
     * observed case was a 4-of-4 page whose per-session detail had been trimmed;
     * it was told to retry with limit=2.
     */
    private fun payloadRetryContinuation(
        data: AgentJsonObject,
        returned: Long,
        payloadTruncated: Boolean,
        omittedFrames: List<Long>
    ): AgentJsonObject? {
        if (!payloadTruncated) return null
        val offset = (data["offset"] as? Number)?.toLong() ?: return null
        if (!listItemsWereDropped(data)) {
            // Frames the budget never read are a real, actionable gap; let the
            // detail continuation below claim them instead of declaring the
            // whole result unrecoverable here.
            if (omittedFrames.isNotEmpty()) return null
            // The list survived intact; only its interiors were cut. Narrowing
            // the projection is the only thing that would actually help, and
            // this tool cannot know which fields the caller can spare.
            return mapOf(
                "available" to false,
                "reason" to "narrow_projection_required",
                "detail" to "The item list was complete; fields inside the items were trimmed. " +
                    "Request fewer fields, fewer domains, or a narrower selector rather than a smaller limit."
            )
        }
        val limit = (data["limit"] as? Number)?.toLong() ?: returned
        val pageSize = minOf(limit, returned.coerceAtLeast(1L))
        if (pageSize <= 1L) return null
        return mapOf(
            "offset" to offset,
            "limit" to maxOf(1L, pageSize / 2L),
            "reason" to "retry_with_smaller_limit"
        )
    }

    /**
     * Whether the byte trim removed entire items from a collection.
     *
     * [AgentResultTruncator] leaves two independent traces of that: omitted
     * frame numbers for frame-bearing lists, and a `<key>Returned`/`<key>Total`
     * pair for every collection it shortened. Either one proves items are
     * missing, so no new probing is required here — and the absence of both means
     * the lists are whole and the loss was inside them.
     */
    private fun listItemsWereDropped(data: AgentJsonObject): Boolean {
        if (longList(data["payloadOmittedFrames"]).isNotEmpty()) return true
        return data.keys.any { key ->
            if (!key.endsWith(RETURNED_SUFFIX)) return@any false
            val prefix = key.removeSuffix(RETURNED_SUFFIX)
            val returnedForKey = (data[key] as? Number)?.toLong() ?: return@any false
            val totalForKey = (data["$prefix$TOTAL_SUFFIX"] as? Number)?.toLong()
                ?: return@any false
            returnedForKey < totalForKey
        }
    }

    private fun detailContinuation(
        data: AgentJsonObject,
        omittedFrames: List<Long>
    ): AgentJsonObject? {
        if (omittedFrames.isEmpty()) return null
        return buildMap {
            put("tool", "get_packet_fields")
            put("frames", omittedFrames.take(MAX_CONTINUATION_FRAMES))
            (data["fields"] as? Iterable<*>)
                ?.mapNotNull { it as? String }
                ?.takeIf { it.isNotEmpty() }
                ?.let { put("fields", it) }
            (data["includeDisplayValue"] as? Boolean)?.let { put("includeDisplayValue", it) }
        }
    }

    private fun genericContinuation(
        data: AgentJsonObject,
        omittedFrames: List<Long>,
        omittedPaths: List<String>
    ): AgentJsonObject? {
        val explicit = data["truncation"] as? Map<*, *>
        val truncated = data["truncated"] == true ||
            data["sourceTruncated"] == true ||
            data["omittedByBudget"] == true ||
            data["detailBudgetExhausted"] == true ||
            data["payloadTruncated"] == true ||
            explicit?.get("sourceTruncated") == true ||
            explicit?.get("quotaTruncated") == true ||
            explicit?.get("payloadTruncated") == true ||
            explicit?.get("contextCompacted") == true ||
            omittedFrames.isNotEmpty() ||
            omittedPaths.isNotEmpty()
        if (!truncated) return null
        return mapOf(
            "available" to false,
            "reason" to "no_safe_continuation"
        )
    }

    private fun longList(value: Any?): List<Long> = when (value) {
        is Iterable<*> -> value.mapNotNull { (it as? Number)?.toLong() ?: it?.toString()?.toLongOrNull() }
        is Array<*> -> value.mapNotNull { (it as? Number)?.toLong() ?: it?.toString()?.toLongOrNull() }
        else -> emptyList()
    }

    private fun stringList(value: Any?): List<String> = when (value) {
        is Iterable<*> -> value.mapNotNull { it as? String }
        is Array<*> -> value.mapNotNull { it as? String }
        else -> emptyList()
    }

    private fun mapValue(value: Any?): AgentJsonObject? {
        val map = value as? Map<*, *> ?: return null
        return map.entries.associate { it.key.toString() to it.value }.takeIf { it.isNotEmpty() }
    }

    private const val MAX_CONTINUATION_FRAMES = 48
    private const val RETURNED_SUFFIX = "Returned"
    private const val TOTAL_SUFFIX = "Total"
}
