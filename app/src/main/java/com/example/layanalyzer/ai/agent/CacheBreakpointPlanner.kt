// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole

/** Adds transient Anthropic message breakpoints to one planned request copy. */
internal object CacheBreakpointPlanner {
    private const val MAX_BREAKPOINTS = 4
    private const val MAX_MESSAGE_BREAKPOINTS = 3
    internal const val MAX_BLOCK_GAP = 15

    /**
     * Mark complete tool-turn ends without mutating [messages].
     *
     * [additionalSystemBlocks] accounts for provider blocks, such as Anthropic's
     * response-schema instruction, that are rendered after System messages and
     * before the conversation. It affects spacing only, never breakpoint count.
     */
    fun mark(
        messages: List<AgentModelMessage>,
        additionalSystemBlocks: Int = 0
    ): List<AgentModelMessage> {
        require(additionalSystemBlocks >= 0) {
            "additionalSystemBlocks must not be negative."
        }
        val requestCopy = messages.map { message ->
            if (message.role == AgentModelMessageRole.System || message.cacheControl == null) {
                message
            } else {
                message.copy(cacheControl = null)
            }
        }
        val systemLayout = systemLayout(requestCopy, additionalSystemBlocks)
        val messageBreakpointLimit = minOf(
            MAX_MESSAGE_BREAKPOINTS,
            (MAX_BREAKPOINTS - systemLayout.breakpointCount).coerceAtLeast(0)
        )
        if (messageBreakpointLimit == 0) return requestCopy

        val completeTurnEnds = completeToolTurnEnds(requestCopy)
        if (completeTurnEnds.isEmpty()) return requestCopy
        val blockPositions = messageEndBlockPositions(
            messages = requestCopy,
            initialPosition = systemLayout.finalBlockPosition
        )
        val candidates = completeTurnEnds.mapNotNull { messageIndex ->
            blockPositions[messageIndex]?.let { position ->
                BreakpointCandidate(messageIndex, position)
            }
        }
        val selected = selectCandidates(
            candidates = candidates,
            limit = messageBreakpointLimit,
            precedingBreakpointPosition = systemLayout.lastBreakpointPosition
        ).mapTo(hashSetOf()) { it.messageIndex }
        if (selected.isEmpty()) return requestCopy

        return requestCopy.mapIndexed { index, message ->
            if (index in selected) message.withCacheBreakpoint() else message
        }
    }

    private fun systemLayout(
        messages: List<AgentModelMessage>,
        additionalSystemBlocks: Int
    ): SystemLayout {
        var blockPosition = 0
        var breakpointCount = 0
        var lastBreakpointPosition: Int? = null
        messages.forEach { message ->
            if (message.role != AgentModelMessageRole.System || message.content.trim().isBlank()) {
                return@forEach
            }
            blockPosition += 1
            if (message.cacheControl != null) {
                breakpointCount += 1
                lastBreakpointPosition = blockPosition
            }
        }
        blockPosition += additionalSystemBlocks
        return SystemLayout(
            finalBlockPosition = blockPosition,
            breakpointCount = breakpointCount,
            lastBreakpointPosition = lastBreakpointPosition
        )
    }

    private fun messageEndBlockPositions(
        messages: List<AgentModelMessage>,
        initialPosition: Int
    ): Map<Int, Int> = buildMap {
        var blockPosition = initialPosition
        messages.forEachIndexed { index, message ->
            if (message.role == AgentModelMessageRole.System) return@forEachIndexed
            val blockCount = contentBlockCount(message)
            blockPosition += blockCount
            if (blockCount > 0) put(index, blockPosition)
        }
    }

    private fun contentBlockCount(message: AgentModelMessage): Int = when (message.role) {
        AgentModelMessageRole.System -> 0
        AgentModelMessageRole.User -> 1
        AgentModelMessageRole.Assistant ->
            message.toolCalls.size + if (message.content.isNotBlank()) 1 else 0
        AgentModelMessageRole.Tool -> 1
        AgentModelMessageRole.Unknown -> 0
    }

    /** Return the last Tool message of each complete assistant/tool group. */
    private fun completeToolTurnEnds(messages: List<AgentModelMessage>): List<Int> = buildList {
        var index = 0
        while (index < messages.size) {
            val assistant = messages[index]
            if (assistant.role != AgentModelMessageRole.Assistant || assistant.toolCalls.isEmpty()) {
                index += 1
                continue
            }
            val expectedIds = assistant.toolCalls.map { it.toolCallId }
            val expectedSet = expectedIds.toSet()
            var cursor = index + 1
            var lastToolIndex = -1
            var invalidGroup = expectedIds.any(String::isBlank) || expectedSet.size != expectedIds.size
            val seenIds = linkedSetOf<String>()
            while (cursor < messages.size && messages[cursor].role == AgentModelMessageRole.Tool) {
                val toolCallId = messages[cursor].toolCallId.orEmpty()
                if (toolCallId !in expectedSet || !seenIds.add(toolCallId)) invalidGroup = true
                lastToolIndex = cursor
                cursor += 1
            }
            if (!invalidGroup && lastToolIndex >= 0 && seenIds == expectedSet) {
                add(lastToolIndex)
            }
            index = cursor.coerceAtLeast(index + 1)
        }
    }

    private fun selectCandidates(
        candidates: List<BreakpointCandidate>,
        limit: Int,
        precedingBreakpointPosition: Int?
    ): List<BreakpointCandidate> {
        if (candidates.isEmpty() || limit <= 0) return emptyList()
        if (precedingBreakpointPosition == null) return candidates.takeLast(limit)

        val validChains = mutableListOf<List<BreakpointCandidate>>()
        fun visit(startIndex: Int, chain: List<BreakpointCandidate>) {
            if (chain.isNotEmpty()) validChains += chain
            if (chain.size >= limit) return
            val precedingPosition = chain.lastOrNull()?.blockPosition
                ?: precedingBreakpointPosition
            for (index in startIndex until candidates.size) {
                val candidate = candidates[index]
                if (candidate.blockPosition - precedingPosition > MAX_BLOCK_GAP) break
                visit(index + 1, chain + candidate)
            }
        }
        visit(0, emptyList())
        return validChains.maxWithOrNull(
            compareBy<List<BreakpointCandidate>> { it.last().messageIndex }
                .thenBy { it.size }
                .thenBy { chain -> chain.sumOf { it.messageIndex } }
        ).orEmpty()
    }

    private data class SystemLayout(
        val finalBlockPosition: Int,
        val breakpointCount: Int,
        val lastBreakpointPosition: Int?
    )

    private data class BreakpointCandidate(
        val messageIndex: Int,
        val blockPosition: Int
    )
}
