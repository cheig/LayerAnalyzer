// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.DisplayFilterResult
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.FollowStreamResult
import com.example.layanalyzer.model.PacketSearchMode
import com.example.layanalyzer.model.PacketSummary
import com.example.layanalyzer.model.ProtocolNode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Raised by a synchronous JNI reader when its native cancel generation wins. */
internal class NativeOperationCancelledException : CancellationException(
    "Native operation cancelled."
)

/** Read/write operations the coordinator is allowed to perform on a capture. */
interface CaptureSessionDataSource {
    fun currentSessionHandle(): Long
    fun currentFile(): FileSessionInfo?
    fun getFrameCount(): Int
    fun getVisibleFrameCount(): Int
    fun getAppliedDisplayFilter(): String
    fun applyDisplayFilter(
        filter: String,
        expectedSessionHandle: Long = currentSessionHandle()
    ): DisplayFilterResult
    fun validateDisplayFilter(filter: String): Result<Unit>
    fun cancelLongRunningOperations()
}

/** Read-only surface exposed to Agent analysis operations. */
interface AgentReadSession {
    fun currentSessionHandle(): Long
    fun currentFile(): FileSessionInfo?
    fun getFrameCount(): Int
    fun getVisibleFrameCount(): Int
    fun getAppliedDisplayFilter(): String
    fun getPacketSummaries(start: Int, count: Int): List<PacketSummary>

    /**
     * Optional Native Scoped Query capability (AI-22).  Implementations built
     * against an older JNI library return null so callers can use the legacy
     * filter lease without probing native symbols directly.
     */
    fun queryPacketSummariesScoped(
        filter: String,
        start: Int,
        count: Int
    ): ScopedPacketSummaryQuery? = null

    /**
     * Summaries whose `time` is the raw capture timestamp in seconds, rather
     * than the string the user's selected time format produces.  Agent tools
     * report both an absolute and a relative time, so they need the underlying
     * value; formatting it for display and then parsing it back would lose
     * precision and change meaning with a UI preference.
     */
    fun getRawPacketSummaries(start: Int, count: Int): List<PacketSummary>

    /** Absolute timestamp of the first frame, used as the relative-time origin. */
    fun getFirstPacketTimestamp(): Double

    fun getPacketDetails(frameNumber: Long): ProtocolNode?

    /** Frame numbers matching a search, in frame order. */
    fun searchPacketFrames(mode: PacketSearchMode, query: String): List<Long>
    fun getExpertInfoSummary(): ExpertInfoSummary
    fun buildCaptureStatistics(bucketSeconds: Double = 1.0): CaptureStatistics
    fun buildCommunicationAnalysis(): CommunicationAnalysis

    /**
     * Reassemble the stream carrying [frameNumber].
     *
     * The result still holds the stream's text/ascii/hex, because that is what
     * the native call produces and the UI's Follow Stream view needs.  Agent
     * callers must project metadata off it and drop the records; see
     * [AgentAnalysisRepository.getFollowStreamMetadata], which is the only
     * Agent-side path to this operation.
     */
    fun followStream(frameNumber: Long, protocol: String): FollowStreamResult
}

/** JSON contract returned by NativeEngine.queryPacketSummaries. */
data class ScopedPacketSummaryQuery(
    val success: Boolean,
    val error: String? = null,
    val items: List<PacketSummary> = emptyList(),
    val offset: Int = 0,
    val returned: Int = items.size,
    val total: Int = 0,
    val truncated: Boolean = false,
    val cancelled: Boolean = false,
    val queryVersion: String = ""
)

/** Identity captured while an open operation is being completed. */
data class CaptureSessionToken(
    val sessionHandle: Long,
    val sessionGeneration: Long
) {
    val generation: Long
        get() = sessionGeneration
}

enum class CaptureFingerprintState {
    Unavailable,
    Preparing,
    Ready,
    Failed
}

enum class CaptureFilterOwner {
    None,
    User,
    Agent,

    /**
     * A non-Agent caller borrowed the filter for one bounded read — the
     * evidence-frame pcap export today.  It is distinct from [Agent] only for
     * observability: the lease protocol behind it is identical, and the value
     * exists so a temporary filter applied on behalf of the export can be told
     * apart from one an analysis run holds.
     */
    UserExport
}

/**
 * Shared, observable state for the one native capture session.
 *
 * [fileFingerprint] is non-null for source compatibility with the Agent
 * contract, but an empty value is never considered a valid identity.  The
 * explicit [fingerprintState] distinguishes a session that is still being
 * prepared from a session for which hashing failed.
 */
data class CaptureSessionState(
    val sessionHandle: Long = 0L,
    val fileFingerprint: String = "",
    val localPathIdentity: String = "",
    val frameCount: Int = 0,
    val visibleFrameCount: Int = 0,
    val appliedDisplayFilter: String = "",
    val sessionGeneration: Long = 0L,
    val filterRevision: Long = 0L,
    val fingerprintState: CaptureFingerprintState = CaptureFingerprintState.Unavailable,
    val fingerprintError: AgentError? = null,
    /**
     * Bumped whenever a setting that changes dissection facts is applied —
     * Decode As rules and name resolution today.  It is part of the AI-24 tool
     * cache key, so a configuration change invalidates every cached result for
     * this capture without the cache needing to know which setting moved.
     */
    val analysisConfigVersion: Int = 1
) {
    val hasSession: Boolean
        get() = sessionHandle != 0L

    val fingerprint: String
        get() = fileFingerprint

    val generation: Long
        get() = sessionGeneration

    val token: CaptureSessionToken
        get() = CaptureSessionToken(sessionHandle, sessionGeneration)
}

/** The saved native/UI state held by one temporary Agent filter lease. */
data class AgentFilterLease(
    val sessionHandle: Long,
    val sessionGeneration: Long,
    val originalDisplayFilter: String,
    val originalFilterRevision: Long,
    val originalVisibleFrameCount: Int,
    val temporaryDisplayFilter: String,
    val startedAtMillis: Long
) {
    val originalFilter: String
        get() = originalDisplayFilter

    val generation: Long
        get() = sessionGeneration
}

/** Emitted when a failed restore requires the UI to read the native state. */
data class CaptureFilterRefresh(
    val session: CaptureSessionState,
    val reason: AgentErrorCode = AgentErrorCode.FILTER_CONFLICT
)

/** Structured result shared by the Agent repository and filter coordinator. */
sealed interface AgentAnalysisResult<out T> {
    val success: Boolean

    data class Success<T>(val value: T) : AgentAnalysisResult<T> {
        override val success: Boolean = true
    }

    data class Failure(val error: AgentError) : AgentAnalysisResult<Nothing> {
        override val success: Boolean = false
    }

    @Suppress("UNCHECKED_CAST")
    fun getOrNull(): T? = when (this) {
        is Success<*> -> value as T
        is Failure -> null
    }

    fun errorOrNull(): AgentError? = (this as? Failure)?.error
}

/**
 * Serializes all display-filter mutations against the single native Session.
 * Agent queries prefer Native Scoped Query when the loaded JNI library exposes
 * it; [withAgentFilter] remains the serialized compatibility fallback.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CaptureSessionCoordinator(
    private val dataSource: CaptureSessionDataSource,
    private val fingerprintCalculator: CaptureFingerprintCalculator = CaptureFingerprintCalculator(),
    private val fingerprintDispatcher: CoroutineDispatcher = Dispatchers.IO,
    /**
     * Wireshark owns mutable per-session dissection state.  Keeping Agent and
     * filter reads on one dispatcher prevents a long analysis from running on
     * Main and prevents two JNI traversals from interleaving on the same epan
     * session.  The dispatcher is injectable so the seam is directly testable.
     */
    private val nativeDispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(1),
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val maxAgentLeaseMillis: Long = DEFAULT_AGENT_LEASE_MILLIS
) {
    private val stateGuard = Any()
    private val filterMutex = Mutex()
    private val _state = MutableStateFlow(CaptureSessionState())
    val state: StateFlow<CaptureSessionState> = _state.asStateFlow()

    /**
     * How many Agent runs have opened a filter chain without closing it.  While
     * this is above zero, [withAgentFilter] leaves the temporary filter applied
     * between tool calls and defers the restore to [endAgentFilterChain] or the
     * next user filter application, so a many-tool analysis pays one restore
     * scan instead of one per tool call.
     */
    private val agentChainDepth = AtomicInteger(0)

    /**
     * The lease whose original values describe the user's view that a deferred
     * restore must bring back.  Guarded by [filterMutex].  While this is
     * non-null the native session still shows the Agent's last filter, but the
     * published [state] keeps the user's values: Agent applies never touch it,
     * and a user apply can only run after the pending lease has been resolved.
     */
    private var pendingAgentLease: AgentFilterLease? = null

    /** Alias useful to ViewModels that prefer a more explicit name. */
    val sessionState: StateFlow<CaptureSessionState>
        get() = state

    private val _filterOwner = MutableStateFlow(CaptureFilterOwner.None)
    val filterOwner: StateFlow<CaptureFilterOwner> = _filterOwner.asStateFlow()

    private val _filterRefreshEvents = MutableSharedFlow<CaptureFilterRefresh>(extraBufferCapacity = 16)
    val filterRefreshEvents: SharedFlow<CaptureFilterRefresh> = _filterRefreshEvents.asSharedFlow()

    /** Invalidate before a native close or before replacing the current file. */
    fun invalidateSession(): CaptureSessionState = synchronized(stateGuard) {
        val next = CaptureSessionState(
            sessionGeneration = _state.value.sessionGeneration + 1L,
            // Carried across the reset deliberately.  This number is a cache-key
            // component, so it must never go backwards: reusing version 2 for a
            // second, different Decode As configuration on the same capture
            // would make entries written under the first one look current.
            analysisConfigVersion = _state.value.analysisConfigVersion
        )
        _state.value = next
        next
    }

    /** Compatibility name for callers that describe this as a session change. */
    fun beginSessionChange(): CaptureSessionState = invalidateSession()

    /**
     * Publish the native session immediately, while its fingerprint is still
     * being calculated.  Agents remain in Preparing until [prepareFingerprint]
     * completes successfully.
     */
    fun onSessionOpened(info: FileSessionInfo): CaptureSessionToken {
        val handle = dataSource.currentSessionHandle()
        if (handle == 0L) {
            invalidateSession()
            return CaptureSessionToken(0L, state.value.sessionGeneration)
        }

        return synchronized(stateGuard) {
            val next = CaptureSessionState(
                sessionHandle = handle,
                localPathIdentity = identityFor(info.localPath),
                frameCount = info.frameCount.coerceAtLeast(0),
                visibleFrameCount = info.frameCount.coerceAtLeast(0),
                appliedDisplayFilter = "",
                sessionGeneration = _state.value.sessionGeneration + 1L,
                filterRevision = 0L,
                fingerprintState = CaptureFingerprintState.Preparing,
                // Opening a file resets the engine's Decode As rules, so the
                // dissection configuration returns to the default and the
                // baseline version comes back with it.  That is what lets a
                // reopened capture reuse the entries cached for it before.
                // Anything that then diverges from the default calls
                // bumpAnalysisConfigVersion, which only ever moves forward.
                analysisConfigVersion = DEFAULT_ANALYSIS_CONFIG_VERSION
            )
            _state.value = next
            next.token
        }
    }

    /** Convenience operation for non-UI callers such as session restore. */
    suspend fun registerOpenedSession(info: FileSessionInfo): Result<String> {
        val token = onSessionOpened(info)
        return prepareFingerprint(token, File(info.localPath))
    }

    /** Calculate and publish the fingerprint only if the same Session remains current. */
    suspend fun prepareFingerprint(token: CaptureSessionToken, file: File): Result<String> {
        val before = state.value
        if (!isCurrent(token) || before.fingerprintState != CaptureFingerprintState.Preparing) {
            return Result.failure(IllegalStateException("Capture session changed."))
        }

        val result = withContext(fingerprintDispatcher) {
            fingerprintCalculator.calculateResult(file)
        }
        val value = result.getOrNull()
        if (value.isNullOrBlank()) {
            val safeError = AgentError(
                code = AgentErrorCode.INTERNAL_ERROR,
                userMessage = "Unable to prepare the capture identity.",
                retryable = true,
                details = mapOf("stage" to "fingerprint")
            )
            synchronized(stateGuard) {
                if (isCurrentLocked(token)) {
                    _state.value = _state.value.copy(
                        fingerprintState = CaptureFingerprintState.Failed,
                        fingerprintError = safeError,
                        fileFingerprint = ""
                    )
                }
            }
            return Result.failure(result.exceptionOrNull() ?: IllegalStateException("Capture fingerprint is empty."))
        }

        synchronized(stateGuard) {
            if (!isCurrentLocked(token)) {
                return Result.failure(IllegalStateException("Capture session changed."))
            }
            _state.value = _state.value.copy(
                fileFingerprint = value,
                fingerprintState = CaptureFingerprintState.Ready,
                fingerprintError = null
            )
        }
        return Result.success(value)
    }

    fun currentToken(): CaptureSessionToken? = state.value.takeIf { it.hasSession }?.token

    /**
     * Record that a dissection-affecting setting changed.
     *
     * Callers are the Decode As and name-resolution paths in
     * [com.example.layanalyzer.viewmodel.PacketListViewModel].  Bumping the
     * version is what makes every AI-24 cache entry for this capture miss: the
     * facts a cached result described may no longer be the facts the engine
     * would now produce.
     */
    fun bumpAnalysisConfigVersion(): Int = synchronized(stateGuard) {
        val next = _state.value.analysisConfigVersion + 1
        _state.value = _state.value.copy(analysisConfigVersion = next)
        next
    }

    /** Forward the one global native cancellation operation to the source. */
    fun cancelLongRunningOperations() {
        dataSource.cancelLongRunningOperations()
    }

    /**
     * Open one deferred-restore chain for an Agent run.
     *
     * Until the matching [endAgentFilterChain], consecutive [withAgentFilter]
     * reads keep the temporary filter applied in the native session instead of
     * restoring the user's filter after every call.  Chains nest by depth, so
     * an outer run keeps the chain open over any inner delegated work.
     */
    fun beginAgentFilterChain() {
        agentChainDepth.incrementAndGet()
    }

    /**
     * Close one chain opened by [beginAgentFilterChain].
     *
     * When the last chain closes, a pending deferred restore is performed from
     * a NonCancellable block: run teardown fires native cancellations, and the
     * restore must survive them to give the user their filter back.  A session
     * that changed underneath the chain drops the pending restore instead —
     * the new session starts with no filter of its own.
     */
    suspend fun endAgentFilterChain() {
        val remaining = agentChainDepth.updateAndGet { current -> (current - 1).coerceAtLeast(0) }
        if (remaining > 0) return
        withContext(NonCancellable) {
            filterMutex.withLock {
                _filterOwner.value = CaptureFilterOwner.Agent
                try {
                    releasePendingAgentLease()
                } finally {
                    _filterOwner.value = CaptureFilterOwner.None
                }
            }
        }
    }

    /** Restore and clear the deferred lease, if one is waiting. */
    private suspend fun releasePendingAgentLease() {
        val pending = pendingAgentLease ?: return
        pendingAgentLease = null
        restoreLease(pending)
    }

    /** Run a synchronous native session read away from Main. */
    suspend fun <T> withNativeSession(block: suspend () -> T): T =
        withContext(nativeDispatcher) { block() }

    fun isCurrent(token: CaptureSessionToken): Boolean = synchronized(stateGuard) {
        isCurrentLocked(token)
    }

    /**
     * UI-owned filter mutation.  A stale expected token is rejected before
     * touching the native Session, even if a new file has already opened.
     */
    suspend fun applyUserFilter(
        filter: String,
        expectedSession: CaptureSessionToken? = currentToken()
    ): DisplayFilterResult = try {
        withContext(nativeDispatcher) {
            filterMutex.withLock {
            _filterOwner.value = CaptureFilterOwner.User
            try {
                if (expectedSession == null || !isCurrent(expectedSession)) {
                    dropPendingAgentLeaseWithoutRestore()
                    return@withLock DisplayFilterResult(false, 0, SESSION_CHANGED_MESSAGE)
                }
                val normalized = filter.trim()
                // The user request may need to stop an older UI analysis, but
                // doing it here (after the Agent lease mutex) prevents a queued
                // UI filter from cancelling the Agent operation it is waiting on.
                dataSource.cancelLongRunningOperations()
                val result = runCatching {
                    dataSource.applyDisplayFilter(normalized, expectedSession.sessionHandle)
                }.getOrElse {
                    DisplayFilterResult(false, safeVisibleCount(0), "Unable to apply display filter.")
                }
                if (!isCurrent(expectedSession)) {
                    dropPendingAgentLeaseWithoutRestore()
                    return@withLock DisplayFilterResult(false, 0, SESSION_CHANGED_MESSAGE)
                }
                if (result.success) {
                    updateUserFilterState(expectedSession, normalized, result.filteredCount)
                    // The user's apply just overwrote whatever the Agent left in
                    // the native session, so the deferred restore is moot.
                    dropPendingAgentLeaseWithoutRestore()
                } else {
                    // The native session is still showing the Agent's last
                    // filter; bring the user's previous view back before the
                    // failure is reported.
                    withContext(NonCancellable) {
                        releasePendingAgentLease()
                    }
                }
                result
            } finally {
                _filterOwner.value = CaptureFilterOwner.None
            }
            }
        }
    } catch (_: CancellationException) {
        DisplayFilterResult(false, 0, "Filter operation cancelled.")
    } catch (_: Throwable) {
        DisplayFilterResult(false, safeVisibleCount(0), "Unable to apply display filter.")
    }

    /** Validation is serialized as well, so close/filter operations have one entry point. */
    suspend fun validateDisplayFilter(
        filter: String,
        expectedSession: CaptureSessionToken? = currentToken()
    ): Result<Unit> = try {
        withContext(nativeDispatcher) {
            filterMutex.withLock {
            if (expectedSession == null || !isCurrent(expectedSession)) {
                return@withLock Result.failure(IllegalStateException(SESSION_CHANGED_MESSAGE))
            }
            val result = runCatching {
                dataSource.validateDisplayFilter(filter.trim())
            }.getOrElse { Result.failure(it) }
            if (!isCurrent(expectedSession)) {
                Result.failure(IllegalStateException(SESSION_CHANGED_MESSAGE))
            } else {
                result
            }
            }
        }
    } catch (cancelled: CancellationException) {
        Result.failure(cancelled)
    } catch (error: Throwable) {
        Result.failure(error)
    }

    /**
     * Execute one bounded read while temporarily applying an Agent filter.
     * Restoration is attempted from NonCancellable and only against the same
     * native Session and filter revision that created the lease.
     */
    suspend fun <T> withAgentFilter(
        snapshot: AgentCaptureSnapshot,
        temporaryFilter: String,
        block: suspend (AgentFilterLease) -> T
    ): AgentAnalysisResult<T> = withFilterLease(
        temporaryFilter = temporaryFilter,
        owner = CaptureFilterOwner.Agent,
        checkSession = { snapshotError(snapshot) },
        block = block
    )

    /**
     * Run a bounded read under a temporary display filter, then put the user's
     * view back, without requiring an Agent snapshot.
     *
     * The evidence-frame export needs exactly the guarantee Agent reads get —
     * one serialized filter swap whose restore survives cancellation — but it
     * is not an analysis run.  Building an [AgentCaptureSnapshot] to enter
     * [withAgentFilter] would leak the Agent concept into the export layer, and
     * save/restoring the filter by hand would bypass [filterMutex] and
     * [pendingAgentLease] and strand the user's view.  This entry point exists
     * so that path goes through the one lease protocol instead.
     *
     * [reason] is published as [filterOwner] for the duration of the lease; it
     * is observability only and does not change the restore semantics.  The
     * only precondition is an open session: with no snapshot to compare
     * against, a missing session fails closed before any native step rather
     * than filtering whichever capture happens to be open.
     */
    suspend fun <T> withTemporaryFilter(
        temporaryFilter: String,
        reason: CaptureFilterOwner = CaptureFilterOwner.UserExport,
        block: suspend (AgentFilterLease) -> T
    ): AgentAnalysisResult<T> = withFilterLease(
        temporaryFilter = temporaryFilter,
        owner = reason,
        checkSession = { if (state.value.hasSession) null else noCaptureError() },
        block = block
    )

    /**
     * The single implementation of the temporary-filter lease protocol shared
     * by [withAgentFilter] and [withTemporaryFilter].
     *
     * [checkSession] is the only sanctioned difference between the two public
     * entry points.  It runs at the same points the Agent snapshot check used
     * to, so a session that goes away mid-lease is detected before a result is
     * published.  Everything else — [filterMutex], the deferred
     * [pendingAgentLease], [agentChainDepth], [executeBounded] and the
     * NonCancellable [restoreLease] — is deliberately shared: a second restore
     * path is how the user's filter gets stranded, so there must not be one.
     */
    private suspend fun <T> withFilterLease(
        temporaryFilter: String,
        owner: CaptureFilterOwner,
        checkSession: () -> AgentError?,
        block: suspend (AgentFilterLease) -> T
    ): AgentAnalysisResult<T> = try {
        withContext(nativeDispatcher) {
            filterMutex.withLock {
            _filterOwner.value = owner
            var outcome: AgentAnalysisResult<T>? = null
            var lease: AgentFilterLease? = null
            var temporaryApplied = false
            try {
                val initialError = checkSession()
                if (initialError != null) {
                    outcome = AgentAnalysisResult.Failure(initialError)
                } else {
                    val current = state.value
                    val normalized = temporaryFilter.trim()
                    val newLease = AgentFilterLease(
                        sessionHandle = current.sessionHandle,
                        sessionGeneration = current.sessionGeneration,
                        originalDisplayFilter = current.appliedDisplayFilter,
                        originalFilterRevision = current.filterRevision,
                        // The published state, not the live native count: in a
                        // chain this lease is created while the native session
                        // still shows the previous Agent filter, and the restore
                        // is verified against the user's view the state holds.
                        originalVisibleFrameCount = current.visibleFrameCount.coerceAtLeast(0),
                        temporaryDisplayFilter = normalized,
                        startedAtMillis = clock()
                    )
                    lease = newLease

                    val validation = runCatching {
                        dataSource.validateDisplayFilter(normalized)
                    }.getOrElse { Result.failure(it) }
                    val afterValidationError = checkSession()
                    if (afterValidationError != null) {
                        outcome = AgentAnalysisResult.Failure(afterValidationError)
                    } else if (validation.isFailure) {
                        outcome = AgentAnalysisResult.Failure(invalidFilterError())
                    } else {
                        val applied = runCatching {
                            dataSource.applyDisplayFilter(normalized, newLease.sessionHandle)
                        }.getOrElse {
                            DisplayFilterResult(false, safeVisibleCount(0), null)
                        }
                        val afterApplyError = checkSession()
                        if (afterApplyError != null) {
                            temporaryApplied = applied.success
                            outcome = AgentAnalysisResult.Failure(afterApplyError)
                        } else if (!applied.success) {
                            // Syntax was already validated, so a failed apply is
                            // a cancelled native scan, not a bad filter.
                            outcome = AgentAnalysisResult.Failure(
                                if (isCancelledApply(applied)) cancelledError() else invalidFilterError()
                            )
                        } else {
                            temporaryApplied = true
                            outcome = try {
                                val value = executeBounded(agentLeaseTimeoutMillis(current.frameCount)) {
                                    block(newLease)
                                }
                                val afterError = checkSession()
                                if (afterError != null) {
                                    AgentAnalysisResult.Failure(afterError)
                                } else {
                                    AgentAnalysisResult.Success(value)
                                }
                            } catch (_: TimeoutCancellationException) {
                                AgentAnalysisResult.Failure(timeoutError())
                            } catch (_: LeaseTimeoutException) {
                                AgentAnalysisResult.Failure(timeoutError())
                            } catch (_: CancellationException) {
                                AgentAnalysisResult.Failure(cancelledError())
                            } catch (_: Throwable) {
                                AgentAnalysisResult.Failure(internalError())
                            }
                        }
                    }
                }
            } finally {
                val leaseToRestore = lease
                if (temporaryApplied && leaseToRestore != null) {
                    if (agentChainDepth.get() > 0) {
                        // An open chain keeps the temporary filter applied so
                        // the next Agent read applies over it and the restore
                        // scan runs once at chain end.  Overwriting a pending
                        // lease is safe: Agent applies never touch the published
                        // state, so every lease in a chain carries the same
                        // original user view.
                        pendingAgentLease = leaseToRestore
                    } else {
                        val restorationError = withContext(NonCancellable) {
                            restoreLease(leaseToRestore)
                        }
                        if (restorationError != null) {
                            outcome = AgentAnalysisResult.Failure(restorationError)
                        }
                    }
                }
                _filterOwner.value = CaptureFilterOwner.None
            }
            outcome ?: AgentAnalysisResult.Failure(internalError())
            }
        }
    } catch (_: CancellationException) {
        AgentAnalysisResult.Failure(cancelledError())
    } catch (_: Throwable) {
        AgentAnalysisResult.Failure(internalError())
    }

    /** Validate a snapshot without exposing the native repository. */
    fun snapshotError(snapshot: AgentCaptureSnapshot): AgentError? {
        val current = state.value
        if (!current.hasSession || snapshot.sessionHandle == 0L) return noCaptureError()
        val expectedGeneration = snapshot.sessionGeneration.takeIf { it > 0L }
            ?: snapshot.generation
        if (current.sessionHandle != snapshot.sessionHandle ||
            current.sessionGeneration != expectedGeneration
        ) {
            return sessionChangedError()
        }
        if (current.fingerprintState == CaptureFingerprintState.Preparing) {
            return AgentError(
                code = AgentErrorCode.INTERNAL_ERROR,
                userMessage = "Capture identity is still being prepared.",
                retryable = true,
                details = mapOf("stage" to "fingerprint", "state" to "preparing")
            )
        }
        if (current.fingerprintState == CaptureFingerprintState.Failed) {
            return current.fingerprintError ?: internalError()
        }
        if (current.fileFingerprint.isBlank() || current.fileFingerprint != snapshot.fileFingerprint) {
            return sessionChangedError()
        }
        return null
    }

    private suspend fun restoreLease(lease: AgentFilterLease): AgentError? {
        val current = state.value
        if (!current.hasSession ||
            current.sessionHandle != lease.sessionHandle ||
            current.sessionGeneration != lease.sessionGeneration
        ) {
            return sessionChangedError()
        }
        if (current.filterRevision != lease.originalFilterRevision) {
            syncActualFilterState(lease)
            return filterConflictError()
        }

        // The native apply scans every frame and honours the one process-wide
        // cancellation token, so an unrelated cancel (parallel tool teardown,
        // a UI stop, run cleanup) can abort the restore.  A cancelled apply
        // leaves the session's filter untouched, which is exactly retryable:
        // wait out the cancel storm and try again before declaring the user's
        // view unrestorable.
        var restored: DisplayFilterResult? = null
        var restorationFailure: Throwable? = null
        var attempt = 0
        while (true) {
            val outcome = runCatching {
                dataSource.applyDisplayFilter(lease.originalDisplayFilter, lease.sessionHandle)
            }
            restored = outcome.getOrNull()
            restorationFailure = outcome.exceptionOrNull()
            val succeeded = restored?.success == true
            val retryable = restorationFailure != null ||
                (restored != null && isCancelledApply(restored!!))
            if (succeeded || !retryable) break
            attempt += 1
            if (attempt >= RESTORE_ATTEMPTS) break
            delay(RESTORE_RETRY_DELAY_MILLIS)
        }
        if (restorationFailure != null) {
            syncActualFilterState(lease)
            return filterConflictError()
        }
        val actualFilter = runCatching { dataSource.getAppliedDisplayFilter().trim() }.getOrDefault("")
        val actualCount = runCatching { dataSource.getVisibleFrameCount() }.getOrDefault(-1)
        val stillCurrent = isCurrent(CaptureSessionToken(lease.sessionHandle, lease.sessionGeneration))
        if (!stillCurrent) return sessionChangedError()

        if (restored == null || !restored!!.success ||
            actualFilter != lease.originalDisplayFilter.trim() ||
            actualCount != lease.originalVisibleFrameCount
        ) {
            syncActualFilterState(lease)
            return filterConflictError()
        }

        synchronized(stateGuard) {
            if (isCurrentLocked(CaptureSessionToken(lease.sessionHandle, lease.sessionGeneration))) {
                _state.value = _state.value.copy(visibleFrameCount = actualCount)
            }
        }
        return null
    }

    /** Drop a deferred restore whose session is gone or whose view was replaced. */
    private fun dropPendingAgentLeaseWithoutRestore() {
        pendingAgentLease = null
    }

    /**
     * Native applyDisplayFilter reports a cancelled scan as a failure carrying
     * this cancellation text, with the session's filter left unchanged.
     */
    private fun isCancelledApply(result: DisplayFilterResult): Boolean =
        !result.success && result.error?.contains("cancel", ignoreCase = true) == true

    /**
     * withTimeout alone cannot pre-empt a blocking JNI call.  The watcher runs
     * independently and advances the native cancellation generation at the
     * deadline; the JNI loop then returns and normal finally restoration runs.
     */
    private suspend fun <T> executeBounded(
        timeoutMillis: Long = maxAgentLeaseMillis,
        block: suspend () -> T
    ): T = coroutineScope {
        val boundedTimeoutMillis = timeoutMillis.coerceAtLeast(1L)
        val timedOut = AtomicBoolean(false)
        val parentCancellation = coroutineContext[Job]?.invokeOnCompletion { cause ->
            if (cause is TimeoutCancellationException) timedOut.set(true)
        }
        val watcher = launch(Dispatchers.Default) {
            delay(boundedTimeoutMillis)
            timedOut.set(true)
            runCatching { dataSource.cancelLongRunningOperations() }
        }
        try {
            val value = withTimeout(boundedTimeoutMillis) { block() }
            if (timedOut.get()) throw LeaseTimeoutException()
            value
        } catch (cancelled: NativeOperationCancelledException) {
            // A JNI cancellation is normally a user/run cancellation.  If the
            // deadline watcher fired first, preserve the more useful timeout
            // classification for the Agent runner.
            if (timedOut.get()) throw LeaseTimeoutException()
            throw cancelled
        } finally {
            watcher.cancel()
            parentCancellation?.dispose()
        }
    }

    /**
     * Communication and Expert traversals grow with frame count. Keep the
     * default lease for ordinary captures, but do not reintroduce the old
     * fixed 30-second failure for packet-dense files.
     */
    private fun agentLeaseTimeoutMillis(frameCount: Int): Long {
        if (maxAgentLeaseMillis < DEFAULT_AGENT_LEASE_MILLIS) return maxAgentLeaseMillis
        val target = when {
            frameCount >= VERY_LARGE_CAPTURE_FRAME_THRESHOLD -> 180_000L
            frameCount >= MEDIUM_CAPTURE_FRAME_THRESHOLD -> 150_000L
            frameCount >= LARGE_CAPTURE_FRAME_THRESHOLD -> 120_000L
            else -> DEFAULT_AGENT_LEASE_MILLIS
        }
        return maxOf(maxAgentLeaseMillis, target)
    }

    private fun syncActualFilterState(lease: AgentFilterLease) {
        val current = state.value
        if (!current.hasSession ||
            current.sessionHandle != lease.sessionHandle ||
            current.sessionGeneration != lease.sessionGeneration
        ) return

        val actualFilter = runCatching { dataSource.getAppliedDisplayFilter().trim() }.getOrDefault("")
        val actualCount = runCatching { dataSource.getVisibleFrameCount() }.getOrDefault(0)
        val updated = synchronized(stateGuard) {
            val latest = _state.value
            if (!latest.hasSession ||
                latest.sessionHandle != lease.sessionHandle ||
                latest.sessionGeneration != lease.sessionGeneration
            ) return@synchronized null
            latest.copy(
                appliedDisplayFilter = actualFilter,
                visibleFrameCount = actualCount,
                filterRevision = latest.filterRevision + 1L
            ).also { _state.value = it }
        } ?: return
        _filterRefreshEvents.tryEmit(
            CaptureFilterRefresh(updated, AgentErrorCode.FILTER_CONFLICT)
        )
    }

    private fun updateUserFilterState(
        expected: CaptureSessionToken,
        filter: String,
        visibleCount: Int
    ) {
        synchronized(stateGuard) {
            if (!isCurrentLocked(expected)) return
            _state.value = _state.value.copy(
                appliedDisplayFilter = filter,
                visibleFrameCount = visibleCount,
                filterRevision = _state.value.filterRevision + 1L
            )
        }
    }

    private fun safeVisibleCount(fallback: Int): Int =
        runCatching { dataSource.getVisibleFrameCount() }.getOrDefault(fallback)

    private fun isCurrentLocked(token: CaptureSessionToken): Boolean =
        _state.value.hasSession &&
            _state.value.sessionHandle == token.sessionHandle &&
            _state.value.sessionGeneration == token.sessionGeneration

    private fun identityFor(path: String): String =
        runCatching { File(path).canonicalFile.absolutePath }
            .getOrElse { File(path).absoluteFile.path }

    private fun invalidFilterError() = AgentError(
        code = AgentErrorCode.INVALID_DISPLAY_FILTER,
        userMessage = "The display filter is invalid.",
        retryable = false,
        details = mapOf("stage" to "validation")
    )

    private fun noCaptureError() = AgentError(
        code = AgentErrorCode.NO_CAPTURE,
        userMessage = "No capture is open.",
        retryable = false
    )

    private fun sessionChangedError() = AgentError(
        code = AgentErrorCode.SESSION_CHANGED,
        userMessage = "The capture session changed while the query was running.",
        retryable = true
    )

    private fun filterConflictError() = AgentError(
        code = AgentErrorCode.FILTER_CONFLICT,
        userMessage = "The capture filter could not be restored safely.",
        retryable = true
    )

    private fun timeoutError() = AgentError(
        code = AgentErrorCode.TOOL_TIMEOUT,
        userMessage = "The analysis query timed out.",
        retryable = true
    )

    private fun cancelledError() = AgentError(
        code = AgentErrorCode.CANCELLED,
        userMessage = "The analysis query was cancelled.",
        retryable = true
    )

    private fun internalError() = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The analysis query failed.",
        retryable = true
    )

    private companion object {
        const val DEFAULT_AGENT_LEASE_MILLIS = 120_000L
        const val LARGE_CAPTURE_FRAME_THRESHOLD = 2_000
        const val MEDIUM_CAPTURE_FRAME_THRESHOLD = 5_000
        const val VERY_LARGE_CAPTURE_FRAME_THRESHOLD = 10_000
        const val SESSION_CHANGED_MESSAGE = "Capture session changed."

        /**
         * A cancelled restore is retried before it is reported, so a burst of
         * unrelated native cancellations cannot strand the user's filter.
         */
        const val RESTORE_ATTEMPTS = 3
        const val RESTORE_RETRY_DELAY_MILLIS = 200L

        /**
         * The version a freshly opened capture starts at, matching
         * [CaptureSessionState.analysisConfigVersion]'s own default.
         */
        const val DEFAULT_ANALYSIS_CONFIG_VERSION = 1
    }

    private class LeaseTimeoutException : Exception()
}
