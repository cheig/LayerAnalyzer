// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentToolDefinition
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

/**
 * Fixed whitelist of tools a model may call.
 *
 * The set is supplied once at construction.  There is deliberately no
 * `register()` method: nothing from a capture file, the network or a model
 * response can add a tool at runtime.  Lookup is exact — no reflection, no
 * fuzzy matching, no fallback — so an unknown name simply fails.
 */
class AgentToolRegistry(tools: List<AgentTool>) {
    private val byName: Map<String, AgentTool>

    init {
        val duplicates = tools.groupBy { it.definition.name }
            .filterValues { it.size > 1 }
            .keys
            .sorted()
        require(duplicates.isEmpty()) {
            "Duplicate Agent tool names: ${duplicates.joinToString()}"
        }
        tools.forEach { tool ->
            val name = tool.definition.name
            require(NAME_PATTERN.matches(name)) {
                "Agent tool name must be stable snake_case: $name"
            }
        }
        byName = tools.associateBy { it.definition.name }
    }

    constructor(vararg tools: AgentTool) : this(tools.toList())

    val size: Int
        get() = byName.size

    /** Names in registration order; useful for logs and tests. */
    val toolNames: List<String>
        get() = byName.keys.toList()

    /**
     * The only tool metadata that may be sent to a model.  Kotlin class names,
     * file paths and JNI entry points are never part of a definition.
     */
    fun definitions(): List<AgentToolDefinition> = byName.values.map { tool ->
        tool.definition.copy(inputSchema = providerSchema(tool.definition.inputSchema))
    }

    fun contains(name: String): Boolean = byName.containsKey(name)

    fun find(name: String): AgentTool? = byName[name]

    /**
     * Resolve a model-supplied tool name.  The error intentionally does not
     * echo the requested string, so a crafted name from an injected prompt
     * cannot be reflected back into the transcript.
     */
    fun resolve(name: String): Result<AgentTool> {
        val tool = byName[name]
        return if (tool != null) {
            Result.success(tool)
        } else {
            Result.failure(UnknownToolException(unknownToolError()))
        }
    }

    private fun unknownToolError() = AgentError(
        code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
        userMessage = "That analysis tool is not available.",
        retryable = false,
        details = mapOf(
            "reason" to "unknown_tool",
            "availableTools" to byName.keys.sorted()
        )
    )

    class UnknownToolException(val agentError: AgentError) :
        IllegalArgumentException(agentError.userMessage)

    companion object {
        private val NAME_PATTERN = Regex("^[a-z][a-z0-9]*(_[a-z0-9]+)*$")

        private fun providerSchema(value: Map<String, Any?>): Map<String, Any?> =
            value.entries
                .filterNot { (key, _) -> key.startsWith("x-host") }
                .associate { (key, nested) ->
                    key to when (nested) {
                        is Map<*, *> -> providerSchema(
                            nested.entries.associate { it.key.toString() to it.value }
                        )
                        is Iterable<*> -> nested.map { item ->
                            if (item is Map<*, *>) providerSchema(
                                item.entries.associate { it.key.toString() to it.value }
                            ) else item
                        }
                        else -> nested
                    }
                }

        /**
         * The Phase 0 tool set: a capture overview, filter validation and Expert
         * Info.  Together they let an Agent orient itself in a capture, check
         * any filter it wants to use and read the engine's own findings, without
         * any tool that returns packet bytes or payload.
         *
         * The list is fixed here rather than assembled by a caller so every
         * Agent entry point starts from the same audited surface.
         */
        fun phase0(
            ioDispatcher: CoroutineDispatcher = Dispatchers.IO
        ): AgentToolRegistry = AgentToolRegistry(
            CaptureOverviewTool(ioDispatcher),
            ValidateDisplayFilterTool(),
            ExpertInfoTool(ioDispatcher)
        )

        /**
         * Phase 0 plus the AI-09 packet tools: summaries, search and field
         * projection.
         *
         * These three complete the progressive-narrowing path the Agent design
         * is built around — overview, then candidate frames, then a handful of
         * fields from a handful of frames.  None of them returns packet bytes, a
         * payload or a full protocol tree, so the surface stays as narrow as
         * Phase 0's while being able to answer far more.
         */
        fun phase1(
            ioDispatcher: CoroutineDispatcher = Dispatchers.IO
        ): AgentToolRegistry = AgentToolRegistry(
            CaptureOverviewTool(ioDispatcher),
            ValidateDisplayFilterTool(),
            ExpertInfoTool(ioDispatcher),
            PacketSummaryQueryTool(ioDispatcher),
            PacketSearchTool(ioDispatcher),
            PacketFieldsTool(ioDispatcher)
        )

        /**
         * Phase 1 plus the AI-10 aggregate tools: statistics, communication
         * analysis and follow-stream metadata.
         *
         * These three answer the "what does this capture look like as a whole"
         * questions that would otherwise take dozens of summary pages to
         * approximate — protocol mix, top talkers, traffic over time, call
         * outcomes, stream sizes.  All three are aggregates or metadata: none
         * returns a payload, a SIP body or reassembled stream text.
         */
        fun phase2(
            ioDispatcher: CoroutineDispatcher = Dispatchers.IO
        ): AgentToolRegistry = AgentToolRegistry(
            CaptureOverviewTool(ioDispatcher),
            ValidateDisplayFilterTool(),
            ExpertInfoTool(ioDispatcher),
            PacketSummaryQueryTool(ioDispatcher),
            PacketSearchTool(ioDispatcher),
            PacketFieldsTool(ioDispatcher),
            StatisticsTool(ioDispatcher),
            CommunicationAnalysisTool(ioDispatcher),
            FollowStreamMetadataTool(ioDispatcher)
        )

        /**
         * Phase 2 plus bounded field aggregation, Radio queries, the cross-layer
         * timeline and the terminal report handoff.
         *
         * [SubmitReportTool] is what makes every turn in this set have one
         * shape.  Without it the final report is free text competing with the
         * tool channel, and a model that answers in prose mid-investigation
         * loses the whole run to a formatting slip.
         */
        fun phase3(
            ioDispatcher: CoroutineDispatcher = Dispatchers.IO
        ): AgentToolRegistry = AgentToolRegistry(
            DeclareAnalysisPlanTool(),
            DelegateInvestigationTool(),
            SubmitReportTool(),
            CaptureOverviewTool(ioDispatcher),
            ValidateDisplayFilterTool(),
            ExpertInfoTool(ioDispatcher),
            PacketSummaryQueryTool(ioDispatcher),
            PacketSearchTool(ioDispatcher),
            PacketFieldsTool(ioDispatcher),
            StatisticsTool(ioDispatcher),
            CommunicationAnalysisTool(ioDispatcher),
            FollowStreamMetadataTool(ioDispatcher),
            PacketFieldAggregateTool(ioDispatcher),
            RadioEventsTool(ioDispatcher),
            UnifiedNetworkTimelineTool(ioDispatcher)
        )
    }
}
