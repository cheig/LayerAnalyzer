package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole

/**
 * Prepares a finished run's transcript for replay as the next run's history.
 *
 * Export-side sanitisation means everything downstream — the ViewModel's
 * committed transcript, the saved-session file, the next run's prompt — holds
 * exactly what may be sent to a model, with no consumer needing to re-clean.
 *
 * Rules:
 *  - System messages are dropped outright: the next run assembles a fresh
 *    system block from its own snapshot, and a stale one would describe a
 *    superseded product context.
 *  - Vendor reasoning content is stripped: thinking blocks are valid only
 *    inside the request chain that produced them, and several providers reject
 *    them on replay.  The *empty-string* marker that host-authored tool-call
 *    turns use to distinguish themselves from model turns is preserved —
 *    thinking-mode Chat Completions adapters require it on every replayed
 *    assistant tool turn.
 *  - Cache breakpoints are cleared: they are a transient rendering decision
 *    owned by [CacheBreakpointPlanner], which re-plans them on each request.
 *  - Provider response-item ids are cleared: they reference server state from
 *    the HTTP session that created them and are meaningless in a later run.
 *
 * Everything else — tool call ids, tool results, `untrustedCaptureData`,
 * structured content — travels verbatim: old call ids are self-consistent
 * inside the replayed history (every tool_use has its tool_result beside it),
 * and new calls mint fresh ids, so nothing collides.
 */
internal object ConversationHistorySanitizer {

    fun sanitize(messages: List<AgentModelMessage>): List<AgentModelMessage> =
        messages
            .filter { it.role != AgentModelMessageRole.System }
            .map(::sanitizeMessage)

    private fun sanitizeMessage(message: AgentModelMessage): AgentModelMessage {
        var next = message
        if (next.reasoningContent != null) {
            // Keep only the empty-string host marker; drop vendor thinking.
            next = next.copy(reasoningContent = next.reasoningContent?.takeIf(String::isBlank))
        }
        if (next.cacheControl != null) {
            next = next.copy(cacheControl = null)
        }
        if (next.toolCalls.any { it.responseItemId != null }) {
            next = next.copy(
                toolCalls = next.toolCalls.map { call -> call.copy(responseItemId = null) }
            )
        }
        return next
    }
}
