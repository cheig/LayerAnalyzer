package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import kotlinx.coroutines.delay

/**
 * A fully offline [AiModelClient] that replays a [MockModelScript].
 *
 * It exists so the whole Agent stack — loop, ViewModel, Compose preview, unit
 * test — can be exercised with no network, no API key and no vendor SDK, and
 * with byte-identical results on every run.
 *
 * What it deliberately does not do: read a capture file, touch the native
 * engine, or invoke a tool.  A scripted `ToolCalls` response only *asks* for a
 * tool; the host's AgentToolRunner still owns whether and how that call runs, so
 * a mock script cannot bypass the registry, the privacy gate or the budget.
 *
 * The class is safe to share between coroutines: the turn cursor and the
 * cancellation flags live behind one lock, and [respond] never launches work
 * into a scope of its own.
 */
class MockAiModelClient(
    private val script: MockModelScript,
    override val id: String = "mock:${script.id}"
) : AiModelClient {

    override val capabilities: AiModelCapabilities
        get() = script.capabilities

    private val lock = Any()
    private var turnIndex: Int = 0
    private val cancelledRequestIds = mutableSetOf<String>()
    private val committedRequestIds = mutableSetOf<String>()
    private val requestLog = mutableListOf<AgentModelRequest>()

    /** Turns answered so far; the next request is served from this index. */
    val servedTurnCount: Int
        get() = synchronized(lock) { turnIndex }

    /** Requests seen so far, in order.  Tests assert trajectories against this. */
    val observedRequests: List<AgentModelRequest>
        get() = synchronized(lock) { requestLog.toList() }

    override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
        val turn = synchronized(lock) {
            requestLog += request
            prepareTurn(request)
        }

        return when (turn) {
            is Turn.Rejected -> turn.response
            is Turn.Scheduled -> serve(request, turn)
        }
    }

    /**
     * Flag [requestId] as cancelled.  Idempotent, and scoped to that one id: a
     * concurrent request with a different id keeps running to completion.
     */
    override fun cancel(requestId: String) {
        synchronized(lock) { cancelledRequestIds += requestId }
    }

    /** Forget every cancellation and replay the script from the first turn. */
    fun reset() {
        synchronized(lock) {
            turnIndex = 0
            cancelledRequestIds.clear()
            committedRequestIds.clear()
            requestLog.clear()
        }
    }

    /**
     * Pick the turn for this request, or reject it outright.  Runs under [lock]
     * and does not advance the cursor: the turn is only committed once its delay
     * has elapsed, so a cancelled turn stays available for a retry and the
     * script's determinism survives.
     */
    private fun prepareTurn(request: AgentModelRequest): Turn {
        if (request.requestId.isBlank()) {
            return Turn.Rejected(
                failure("blank_request_id", mapOf("scriptId" to script.id))
            )
        }
        if (request.requestId in committedRequestIds) {
            // A committed id must never be replayed: it would answer a repeated
            // turn with the *next* scripted response and quietly desynchronise
            // the trajectory the script is asserting.
            return Turn.Rejected(
                failure(
                    reason = "duplicate_request_id",
                    details = mapOf("scriptId" to script.id, "turnIndex" to turnIndex)
                )
            )
        }

        val index = turnIndex
        val scheduled = script.responseAt(index)
            ?: return Turn.Rejected(
                // Exhaustion is reported, not papered over by repeating the last
                // response — a loop that asks for one turn too many is a bug the
                // script should surface, not absorb.
                failure(
                    reason = "script_exhausted",
                    details = mapOf(
                        "scriptId" to script.id,
                        "turnIndex" to index,
                        "turnCount" to script.turnCount
                    )
                )
            )

        script.expectationAt(index)?.violation(request)?.let { violation ->
            return Turn.Rejected(
                failure(
                    reason = "unexpected_request",
                    details = mapOf(
                        "scriptId" to script.id,
                        "turnIndex" to index,
                        "violation" to violation.reason,
                        "expected" to violation.expected,
                        "actual" to violation.actual
                    )
                )
            )
        }

        return Turn.Scheduled(index, scheduled)
    }

    /**
     * Wait out the scripted delay, then commit the turn.
     *
     * The wait is sliced so an explicit [cancel] lands promptly while still
     * using a cancellable [delay] throughout — never `Thread.sleep`, which would
     * block the caller's dispatcher and ignore coroutine cancellation.  A
     * cancelled coroutine propagates `CancellationException` from `delay`; an
     * explicit `cancel(requestId)` instead returns a structured CANCELLED
     * failure, because that path has no exception to carry.
     */
    private suspend fun serve(
        request: AgentModelRequest,
        turn: Turn.Scheduled
    ): AgentModelResponse {
        var remaining = turn.scheduled.delayMillis
        while (true) {
            if (isCancelled(request.requestId)) {
                return AgentModelResponse.Failure(AiModelErrors.cancelled(request.requestId))
            }
            if (remaining <= 0L) break
            val slice = minOf(remaining, CANCEL_POLL_MILLIS)
            delay(slice)
            remaining -= slice
        }

        synchronized(lock) {
            // Another coroutine may have advanced the cursor while this turn was
            // waiting, so commit only the turn that was actually scheduled.
            if (turnIndex != turn.index) {
                return AgentModelResponse.Failure(
                    AiModelErrors.contract(
                        reason = "concurrent_turn_conflict",
                        details = mapOf(
                            "scriptId" to script.id,
                            "expectedTurnIndex" to turn.index,
                            "actualTurnIndex" to turnIndex
                        )
                    )
                )
            }
            turnIndex = turn.index + 1
            committedRequestIds += request.requestId
        }
        return turn.scheduled.response
    }

    private fun isCancelled(requestId: String): Boolean =
        synchronized(lock) { requestId in cancelledRequestIds }

    private fun failure(
        reason: String,
        details: Map<String, Any?> = emptyMap()
    ): AgentModelResponse.Failure = AgentModelResponse.Failure(
        AiModelErrors.contract(reason, details)
    )

    private sealed interface Turn {
        data class Scheduled(val index: Int, val scheduled: MockScriptedResponse) : Turn
        data class Rejected(val response: AgentModelResponse) : Turn
    }

    companion object {
        /** Cancellation is observed at least this often during a scripted delay. */
        private const val CANCEL_POLL_MILLIS = 20L

        /** Build a client for one of the named built-in demo scripts. */
        fun of(scriptId: String): MockAiModelClient =
            MockAiModelClient(MockModelScriptLibrary.require(scriptId))
    }
}
