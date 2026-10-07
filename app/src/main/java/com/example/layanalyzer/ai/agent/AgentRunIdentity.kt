// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import java.util.UUID

/**
 * The two identifiers that define one analysis run, minted by the caller
 * rather than by the agent.
 *
 * A `conversationId` lives for as long as the user keeps asking about one
 * line of inquiry: a first question, every follow-up and every retry share
 * it, and it is the primary key of the saved-session history file.  A
 * `runId` is created once per question, follow-up or retry; it identifies
 * one AgentLoop execution, one billable model trajectory and one diagnostics
 * run, and it doubles as the `diagnosticId` the user can quote from an
 * error card.
 *
 * Both are `UUID.randomUUID()`-based so they are unique across processes:
 * the previous process-local counter could mint `agent-1` again after a
 * relaunch and silently overwrite the earlier saved session file.
 */
data class AgentRunIdentity(
    val conversationId: String,
    val runId: String
) {
    companion object {
        /** A brand-new conversation: new conversationId and new runId. */
        fun newConversation(): AgentRunIdentity = AgentRunIdentity(
            conversationId = "conv_${UUID.randomUUID()}",
            runId = "run_${UUID.randomUUID()}"
        )

        /**
         * A follow-up question or a retry within [conversationId]: the
         * conversation stays, only the run changes, so history keeps a
         * single record and billing can tell the attempts apart.
         */
        fun follow(conversationId: String): AgentRunIdentity {
            require(conversationId.isNotBlank()) { "conversationId must not be blank." }
            return AgentRunIdentity(
                conversationId = conversationId,
                runId = "run_${UUID.randomUUID()}"
            )
        }
    }
}
