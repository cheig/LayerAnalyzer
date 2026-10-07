package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.tools.dto.AgentSearchModeArgument
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.data.SearchQueryValidator
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.PacketSearchMode
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * search_packets — locate frames by number, text, hex or field presence.
 *
 * The result is deliberately thin: a hit count and a page of frame numbers.
 * A search that returned summaries or details would let one call pull an
 * unbounded amount of capture data into the model's context, and would spend
 * detail budget the model never asked to spend.  Reading the hits is a separate
 * decision, made with [PacketSummaryQueryTool] or [PacketFieldsTool].
 *
 * `field` mode asks the engine whether a named field is *present*; it is not a
 * display filter and is never compiled as an expression.  A model that wants
 * filter semantics has `filter`, which the host compiles and validates.
 */
class PacketSearchTool(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {

    override val definition = AgentToolDefinition(
        name = "search_packets",
        description = "Find frames matching a query by frame number, packet text, hex bytes, " +
            "or the presence of a protocol field. Returns matching frame numbers only; " +
            "read them separately if you need their contents.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "required" to listOf("mode", "query"),
            "properties" to mapOf(
                "mode" to mapOf(
                    "type" to "string",
                    "enum" to AgentSearchModeArgument.wireNames
                ),
                "query" to mapOf(
                    "type" to "string",
                    "minLength" to 1,
                    "maxLength" to MAX_QUERY_LENGTH
                ),
                "filter" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_FILTER_LENGTH
                ),
                "offset" to mapOf(
                    "type" to "integer",
                    "minimum" to 0
                ),
                "limit" to mapOf(
                    "type" to "integer",
                    "minimum" to 1,
                    "maximum" to MAX_LIMIT
                )
            )
        ),
        sensitivity = AgentDataSensitivity.Metadata,
        defaultTimeoutMillis = 30_000L
    )

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val mode = AgentSearchModeArgument.fromWire(arguments["mode"] as? String)
            ?: throw AgentToolException(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "That search mode is not supported.",
                details = mapOf("field" to "arguments.mode", "allowed" to AgentSearchModeArgument.wireNames)
            )
        val query = (arguments["query"] as? String)?.trim().orEmpty()
        if (query.isEmpty()) {
            throw AgentToolException(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "The search query is empty.",
                details = mapOf("field" to "arguments.query")
            )
        }
        validateQuery(mode.mode, query)

        val filter = (arguments["filter"] as? String)?.trim().orEmpty()
        val offset = ((arguments["offset"] as? Number)?.toInt() ?: 0).coerceAtLeast(0)
        val limit = context.summaryLimit((arguments["limit"] as? Number)?.toInt() ?: DEFAULT_LIMIT)

        val reading = context.repository.queryWithTemporaryFilter(context.snapshot, filter) { reader ->
            withContext(ioDispatcher) {
                context.ensureStillValid(context.snapshot)
                val matches = reader.searchPacketFrames(mode.mode, query)
                context.ensureStillValid(context.snapshot)
                // The native search hands back every hit at once.  Page here and
                // let the rest go: only the retained slice reaches the payload,
                // and the full list becomes garbage as soon as this returns.
                SearchReading(
                    total = matches.size,
                    page = matches.asSequence().drop(offset).take(limit).toList()
                )
            }
        }

        val value = when (reading) {
            is AgentAnalysisResult.Failure -> throw AgentToolException(reading.error)
            is AgentAnalysisResult.Success -> reading.value
        }

        val truncated = offset + value.page.size < value.total

        val data = mapOf(
            "frameNumbers" to value.page,
            "mode" to mode.wireName,
            "filter" to filter,
            "offset" to offset,
            "limit" to limit,
            "returned" to value.page.size,
            "total" to value.total,
            "truncated" to truncated,
            // An explicit flag so "no packet matched" is never confused with
            // "the search failed"; both would otherwise show an empty list.
            "matched" to (value.total > 0)
        )

        return context.success(
            data = data,
            returnedCount = value.page.size.toLong(),
            totalCount = value.total.toLong(),
            truncated = truncated
        )
    }

    /**
     * Per-mode input checks, run before the query reaches the engine.
     *
     * Hex reuses [SearchQueryValidator] so a model and the user get identical
     * rules, and field names reuse [ProtocolFieldProjector]'s character set so
     * `field` mode cannot smuggle filter syntax through a search argument.
     */
    private fun validateQuery(mode: PacketSearchMode, query: String) {
        when (mode) {
            PacketSearchMode.Hex -> SearchQueryValidator.validateHex(query)?.let { reason ->
                throw AgentToolException(
                    code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                    userMessage = reason,
                    details = mapOf("field" to "arguments.query", "mode" to "hex")
                )
            }

            PacketSearchMode.Number -> {
                val frame = query.toLongOrNull()
                if (frame == null || frame < 1L) {
                    throw AgentToolException(
                        code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                        userMessage = "Number search expects a positive frame number.",
                        details = mapOf("field" to "arguments.query", "mode" to "number")
                    )
                }
            }

            PacketSearchMode.Field -> {
                if (!ProtocolFieldProjector.isValidFieldName(query)) {
                    throw AgentToolException(
                        code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                        userMessage = "Field search expects a protocol field name, " +
                            "not an expression.",
                        details = mapOf("field" to "arguments.query", "mode" to "field")
                    )
                }
            }

            // Text is matched literally by the engine; there is no syntax to check.
            PacketSearchMode.Text -> Unit
        }
    }

    private data class SearchReading(
        val total: Int,
        val page: List<Long>
    )

    private companion object {
        const val DEFAULT_LIMIT = 50
        const val MAX_LIMIT = 100
        const val MAX_QUERY_LENGTH = 1024
        const val MAX_FILTER_LENGTH = 2048
    }
}
