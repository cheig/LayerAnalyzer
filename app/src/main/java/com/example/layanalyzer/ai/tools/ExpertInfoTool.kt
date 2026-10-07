// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.tools.dto.AgentBaseToolProjections
import com.example.layanalyzer.ai.tools.dto.AgentExpertInfoEntry
import com.example.layanalyzer.ai.tools.dto.AgentExpertSeverity
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.ExpertInfoSummary
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * get_expert_info — the Wireshark Expert Info list, in two shapes.
 *
 * The native engine returns the whole Expert set in one call, so severity
 * filtering, grouping and paging happen in Kotlin.  [ExpertInfoSummary.truncated]
 * is propagated separately from the tool's own paging: a page that ends early
 * because of `limit` is not the same thing as a capture whose Expert list the
 * engine itself cut short, and the model needs to be able to tell them apart.
 *
 * Entry counts here scale with frame count — one frame can raise several Expert
 * items — so a real capture routinely produces more entries than the result byte
 * allowance can hold.  Handing that list to [AgentResultTruncator] would spend
 * the whole allowance on near-duplicate rows and then blindly cut the tail, so
 * this tool instead changes shape when the list will not fit: it returns the
 * distribution across categories plus a drill-down key per category, and the
 * model reads the entries of whichever category matters.  Trimming remains the
 * safety net it was designed to be rather than the normal path.
 */
class ExpertInfoTool(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {

    override val definition = AgentToolDefinition(
        name = "get_expert_info",
        description = "List Wireshark Expert Info entries (errors, warnings, notes, chat) " +
            "with the frame number and drill-down display filter for each one. " +
            "When the matching entries would not fit the result allowance this returns " +
            "mode=summary instead: a per-category distribution with counts, sample frames " +
            "and a ready-to-use display filter for each group. Pass the groupKey of one " +
            "group to read that group's individual entries.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "severities" to mapOf(
                    "type" to "array",
                    "maxItems" to AgentExpertSeverity.wireNames.size,
                    "items" to mapOf(
                        "type" to "string",
                        "enum" to AgentExpertSeverity.wireNames
                    )
                ),
                "mode" to mapOf(
                    "type" to "string",
                    "enum" to listOf(MODE_SUMMARY, MODE_ITEMS)
                ),
                "groupKey" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_GROUP_KEY_LENGTH
                ),
                "offset" to mapOf(
                    "type" to "integer",
                    "minimum" to 0
                ),
                "limit" to mapOf(
                    "type" to "integer",
                    "minimum" to 1,
                    "maximum" to MAX_LIMIT
                ),
                "filter" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_FILTER_LENGTH
                )
            )
        ),
        sensitivity = AgentDataSensitivity.Metadata,
        defaultTimeoutMillis = 30_000L,
        version = "2"
    )

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val requestedSeverities = (arguments["severities"] as? Iterable<*>)
            ?.mapNotNull { AgentExpertSeverity.fromNative(it as? String) }
            ?.distinct()
            .orEmpty()
        val severities = requestedSeverities.toSet()
        val offset = ((arguments["offset"] as? Number)?.toInt() ?: 0).coerceAtLeast(0)
        val limit = minOf(
            (arguments["limit"] as? Number)?.toInt() ?: DEFAULT_LIMIT,
            MAX_LIMIT
        ).coerceAtLeast(1)
        val filter = (arguments["filter"] as? String)?.trim().orEmpty()
        val requestedMode = (arguments["mode"] as? String)?.trim()?.lowercase()
        val groupKey = (arguments["groupKey"] as? String)?.trim()?.takeIf { it.isNotEmpty() }

        // The filter goes through the repository's lease, which validates it,
        // applies it for this read only and restores the user's filter
        // afterwards.  The repository also reuses a deterministic native
        // result when another tool already scanned this scope.
        val reading = context.repository.getExpertInfoSummary(context.snapshot, filter)

        val summary = when (reading) {
            is AgentAnalysisResult.Failure -> throw AgentToolException(reading.error)
            is AgentAnalysisResult.Success -> reading.value
        }

        val (matching, page) = withContext(ioDispatcher) {
            val matching = summary.items.withIndex().filter { (_, item) ->
                if (severities.isEmpty()) return@filter true
                val severity = AgentExpertSeverity.fromNative(item.severity)
                severity != null && severities.contains(severity)
            }.let { indexed ->
                if (requestedSeverities.isEmpty()) {
                    indexed
                } else {
                    val priority = requestedSeverities.withIndex().associate { it.value to it.index }
                    indexed.sortedWith(
                        compareBy<IndexedValue<com.example.layanalyzer.model.ExpertInfoItem>> {
                            priority[AgentExpertSeverity.fromNative(it.value.severity)] ?: Int.MAX_VALUE
                        }.thenBy { it.index }
                    )
                }
            }.map { it.value }
            // A groupKey narrows to one category before paging, so the page is a
            // page of that category rather than of the whole capture.
            val selected = if (groupKey == null) {
                matching
            } else {
                matching.filter { AgentExpertGrouper.groupKeyOf(it) == groupKey }
            }
            selected to selected.drop(offset).take(limit)
                .map(AgentBaseToolProjections::expertEntry)
        }

        val useSummary = shouldSummarize(
            requestedMode = requestedMode,
            groupKey = groupKey,
            page = page,
            context = context
        )
        if (useSummary) {
            return summaryResult(
                context = context,
                summary = summary,
                matching = matching,
                requestedSeverities = requestedSeverities,
                filter = filter
            )
        }

        // Two independent truncation sources: this page not covering every
        // matching item, and the engine having capped its own Expert list.
        val pagedBeyondEnd = offset + page.size < matching.size
        val truncated = pagedBeyondEnd || summary.truncated

        val data = mapOf(
            "mode" to MODE_ITEMS,
            "groupKey" to groupKey,
            "items" to page.map(AgentExpertInfoEntry::toAgentJson),
            "severities" to requestedSeverities.map { it.wireName },
            "offset" to offset,
            "limit" to limit,
            "returned" to page.size,
            "total" to matching.size,
            "truncated" to truncated,
            // Preserved from the native summary so a capped Expert list stays
            // visible even when this page fits comfortably.
            "sourceTruncated" to summary.truncated,
            "errorPackets" to summary.errorPackets,
            "warningPackets" to summary.warningPackets,
            "totalItems" to summary.totalItems
        )

        return context.success(
            data = data,
            returnedCount = page.size.toLong(),
            totalCount = maxOf(matching.size, summary.totalItems).toLong(),
            truncated = truncated
        )
    }

    /**
     * Decide the shape before committing to it.
     *
     * An explicit `mode` from the model wins, and so does a `groupKey`: having
     * named one category, the model is asking for its entries and a distribution
     * would not answer that.  Otherwise the estimate decides, which keeps small
     * captures on exactly the path they were on before this tool grew a second
     * shape — including the host's own bootstrap call.
     */
    private fun shouldSummarize(
        requestedMode: String?,
        groupKey: String?,
        page: List<AgentExpertInfoEntry>,
        context: AgentToolContext
    ): Boolean {
        if (!context.policy.evidenceNarrowingEnabled) return false
        if (requestedMode == MODE_ITEMS) return false
        if (requestedMode == MODE_SUMMARY) return true
        if (groupKey != null) return false
        return !itemsFitAllowance(page, context.resultByteAllowance)
    }

    /**
     * Whether the projected entries fit the bytes still available.
     *
     * Follows [com.example.layanalyzer.ai.agent.AgentPolicy.detailByteFit]:
     * reserve a quarter of the allowance for the payload envelope — the counters,
     * echoed arguments and truncation block that travel with every result — and
     * measure the rows against the rest.  The rows are measured rather than
     * estimated because they are already built at this point, so the check costs
     * one encode and cannot drift from what the model would actually receive.
     */
    private fun itemsFitAllowance(page: List<AgentExpertInfoEntry>, allowance: Int): Boolean {
        if (page.isEmpty()) return true
        val rowBudget = allowance.toLong() * 3L / 4L
        val rowBytes = AgentResultTruncator
            .encode(mapOf("items" to page.map(AgentExpertInfoEntry::toAgentJson)))
            .toByteArray(Charsets.UTF_8).size
        return rowBytes <= rowBudget
    }

    /**
     * The distribution, plus everything needed to drill into one category.
     *
     * `coverageComplete` states that every matching entry was examined even
     * though only groups came back — the same contract
     * `query_packet_field_aggregate` uses for a complete scan with bounded
     * samples.  Without it the host would read "returned 6 of 228" as partial
     * coverage and cap the report's completeness for a read that in fact saw
     * everything.
     */
    private fun summaryResult(
        context: AgentToolContext,
        summary: ExpertInfoSummary,
        matching: List<com.example.layanalyzer.model.ExpertInfoItem>,
        requestedSeverities: List<AgentExpertSeverity>,
        filter: String
    ): AgentToolResult {
        val grouping = AgentExpertGrouper.group(matching)
        val groupsOmitted = grouping.groupsTotal - grouping.groups.size
        val data = mapOf(
            "mode" to MODE_SUMMARY,
            "filter" to filter,
            "severities" to requestedSeverities.map { it.wireName },
            "groups" to grouping.groups.map(AgentExpertGroup::toAgentJson),
            "groupsTotal" to grouping.groupsTotal,
            "groupsReturned" to grouping.groups.size,
            "matchedItems" to matching.size,
            "errorPackets" to summary.errorPackets,
            "warningPackets" to summary.warningPackets,
            "totalItems" to summary.totalItems,
            // Every matching entry was counted into a group, so the distribution
            // is complete even when only the top groups are listed.
            "coverageComplete" to (groupsOmitted <= 0 && !summary.truncated),
            "sampled" to true,
            "sourceTruncated" to summary.truncated,
            "returned" to grouping.groups.size,
            "total" to grouping.groupsTotal,
            "truncated" to (groupsOmitted > 0 || summary.truncated),
            "continuation" to mapOf(
                "tool" to definition.name,
                "mode" to MODE_ITEMS,
                "hint" to "Pass groupKey to read the entries of one group.",
                "availableGroupKeys" to grouping.groups.map { it.groupKey }
            )
        )
        return context.success(
            data = data,
            returnedCount = grouping.groups.size.toLong(),
            totalCount = grouping.groupsTotal.toLong(),
            truncated = groupsOmitted > 0 || summary.truncated
        )
    }

    private companion object {
        const val DEFAULT_LIMIT = 50
        const val MAX_LIMIT = 100
        const val MAX_FILTER_LENGTH = 2048
        const val MAX_GROUP_KEY_LENGTH = 160
        const val MODE_SUMMARY = "summary"
        const val MODE_ITEMS = "items"
    }
}
