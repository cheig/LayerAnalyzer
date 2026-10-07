package com.example.layanalyzer.data

import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.FollowStreamResult
import com.example.layanalyzer.model.PacketSummary
import com.example.layanalyzer.model.ProtocolNode
import com.example.layanalyzer.model.RadioEventType
import com.example.layanalyzer.model.RadioQueryResult
import com.example.layanalyzer.model.RadioSeverity
import com.example.layanalyzer.model.UnifiedNetworkTimeline
import com.example.layanalyzer.model.resolveDisplayFilter
import com.example.layanalyzer.data.radio.RadioRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.util.LinkedHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Per-direction counters for one follow-stream direction.
 *
 * [direction] is the engine's own label ("client" / "server" or an address
 * pair), not free capture text.
 */
data class FollowStreamDirectionMetadata(
    val direction: String,
    val frameCount: Int,
    val byteCount: Long,
    val firstFrame: Long?,
    val lastFrame: Long?
)

/** Inputs read together before deriving IMS registration state. */
data class ImsRegistrationSourceData(
    val communication: CommunicationAnalysis,
    val statistics: CaptureStatistics,
    val expertInfo: ExpertInfoSummary,
    val frameCount: Int,
    val visibleFrameCount: Int,
    val appliedDisplayFilter: String
)

/** The two expensive facts plus session metadata used by get_capture_overview. */
data class CaptureOverviewSourceData(
    val file: FileSessionInfo?,
    val statistics: CaptureStatistics,
    val expertInfo: ExpertInfoSummary,
    val frameCount: Int,
    val visibleFrameCount: Int,
    val appliedDisplayFilter: String
)

/**
 * Everything an Agent may learn about a reassembled stream.
 *
 * This type is the security boundary for AI-10's Follow Stream requirement: it
 * has no field for text, ascii or hex, so a [FollowStreamResult] converted
 * through [from] cannot carry stream contents any further, no matter what the
 * caller does with the result.  [containsPayload] records only that bytes
 * existed.
 */
data class FollowStreamMetadata(
    val protocol: String,
    val streamId: Int,
    val directionKnown: Boolean,
    val directions: List<FollowStreamDirectionMetadata>,
    val frameCount: Int,
    val byteCount: Long,
    val firstFrame: Long?,
    val lastFrame: Long?,
    val containsPayload: Boolean,
    val scope: String,
    val error: String? = null
) {
    companion object {
        /**
         * Project metadata and discard the bodies.
         *
         * Every value here is a count, a frame number or an engine-supplied
         * label; [FollowStreamRecord.text], `.ascii` and `.hex` are read only
         * through [FollowStreamRecord.payload], which is a boolean.
         */
        fun from(result: FollowStreamResult, requestedProtocol: String): FollowStreamMetadata {
            val records = result.records
            val directions = records.groupBy { it.direction }.map { (direction, group) ->
                FollowStreamDirectionMetadata(
                    direction = direction,
                    frameCount = group.size,
                    byteCount = group.sumOf { it.length.toLong() },
                    firstFrame = group.minOfOrNull { it.frameNumber },
                    lastFrame = group.maxOfOrNull { it.frameNumber }
                )
            }
            return FollowStreamMetadata(
                protocol = result.protocol.ifBlank { requestedProtocol },
                streamId = result.streamId,
                directionKnown = result.directionKnown,
                directions = directions,
                frameCount = records.size,
                byteCount = records.sumOf { it.length.toLong() },
                firstFrame = records.minOfOrNull { it.frameNumber },
                lastFrame = records.maxOfOrNull { it.frameNumber },
                containsPayload = records.any { it.payload },
                scope = result.scope,
                error = result.error
            )
        }
    }
}

/** One bounded page returned by the Agent packet-summary query. */
data class AgentPacketSummaryPage(
    val offset: Int,
    val page: List<PacketSummary>,
    val total: Int,
    val captureStartTime: Double,
    val truncated: Boolean,
    /** Stable provenance value: `native_scoped` or `filter_lease`. */
    val queryMode: String
)

/** Coverage facts for a bounded local scan over one temporary filter lease. */
data class AgentPacketScanStats(
    val matchedPackets: Int,
    val scannedPackets: Int,
    val complete: Boolean,
    /** Filter string actually visible while the temporary lease was active. */
    val appliedFilter: String = ""
)

/**
 * Agent-facing read boundary.  The native PacketRepository is deliberately
 * kept private to this class; callers receive only typed read results and
 * structured errors.
 */
class AgentAnalysisRepository(
    private val dataSource: AgentReadSession,
    private val coordinator: CaptureSessionCoordinator,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val radioRepository: RadioRepository = RadioRepository()
) {
    private val agentGeneration = AtomicLong(0L)
    /**
     * Small in-process cache for deterministic native facts.  AgentToolCache
     * caches final JSON per tool call; this cache sits below that seam so a
     * statistics pass can be reused by communication/IMS/timeline reads even
     * when their projections or arguments differ.  The key includes every
     * dissection input that can change the result.
     */
    private val analysisCache = object : LinkedHashMap<NativeAnalysisCacheKey, CachedNativeAnalysis>(
        MAX_ANALYSIS_CACHE_ENTRIES,
        0.75f,
        true
    ) {
        override fun removeEldestEntry(
            eldest: MutableMap.MutableEntry<NativeAnalysisCacheKey, CachedNativeAnalysis>?
        ): Boolean = size > MAX_ANALYSIS_CACHE_ENTRIES
    }

    private data class NativeAnalysisCacheKey(
        val sessionHandle: Long,
        val sessionGeneration: Long,
        val fingerprint: String,
        val analysisConfigVersion: Int,
        val scope: AnalysisScope,
        val filter: String,
        val bucketSecondsBits: Long
    )

    private data class CachedNativeAnalysis(
        val statistics: CaptureStatistics? = null,
        val communication: CommunicationAnalysis? = null,
        val expertInfo: ExpertInfoSummary? = null
    )

    private fun analysisKey(
        snapshot: AgentCaptureSnapshot,
        filter: String,
        bucketSeconds: Double = 1.0
    ): NativeAnalysisCacheKey = NativeAnalysisCacheKey(
        sessionHandle = snapshot.sessionHandle,
        sessionGeneration = snapshot.sessionGeneration,
        fingerprint = snapshot.fileFingerprint,
        analysisConfigVersion = snapshot.analysisConfigVersion,
        scope = snapshot.scope,
        filter = effectiveFilter(snapshot, filter),
        bucketSecondsBits = bucketSeconds.toBits()
    )

    private fun cached(key: NativeAnalysisCacheKey): CachedNativeAnalysis? =
        synchronized(analysisCache) { analysisCache[key] }

    private fun cache(
        key: NativeAnalysisCacheKey,
        update: (CachedNativeAnalysis?) -> CachedNativeAnalysis
    ) {
        synchronized(analysisCache) {
            analysisCache[key] = update(analysisCache[key])
        }
    }

    fun currentAgentGeneration(): Long = agentGeneration.get()

    /**
     * Snapshot the capture as this run sees it.
     *
     * [displayFilterOverride] (EVL-CONTEXT-03) replaces the session's applied
     * display filter inside the snapshot when one was passed — see
     * [resolveDisplayFilter] for the exact substitution contract.  The
     * [AnalysisScope] is not affected.
     */
    suspend fun createSnapshot(
        scope: AnalysisScope,
        displayFilterOverride: String? = null,
        evidenceFrameCount: Int? = null
    ): AgentAnalysisResult<AgentCaptureSnapshot> {
        val activeError = ensureActiveOrError()
        if (activeError != null) return AgentAnalysisResult.Failure(activeError)

        val current = coordinator.state.value
        val stateError = coordinator.snapshotError(
            AgentCaptureSnapshot(
                sessionHandle = current.sessionHandle,
                fileFingerprint = current.fileFingerprint,
                frameCount = current.frameCount,
                displayFilter = resolveDisplayFilter(
                    current.appliedDisplayFilter,
                    displayFilterOverride
                ),
                scope = scope,
                startedAtMillis = clock(),
                analysisGeneration = 0L,
                sessionGeneration = current.sessionGeneration,
                agentGeneration = 0L,
                evidenceFrameCount = evidenceFrameCount
            )
        )
        if (stateError != null) return AgentAnalysisResult.Failure(stateError)

        val generation = agentGeneration.incrementAndGet()
        val snapshot = AgentCaptureSnapshot(
            sessionHandle = current.sessionHandle,
            fileFingerprint = current.fileFingerprint,
            frameCount = current.frameCount,
            displayFilter = resolveDisplayFilter(
                current.appliedDisplayFilter,
                displayFilterOverride
            ),
            scope = scope,
            startedAtMillis = clock(),
            analysisGeneration = generation,
            sessionGeneration = current.sessionGeneration,
            agentGeneration = generation,
            analysisConfigVersion = current.analysisConfigVersion,
            evidenceFrameCount = evidenceFrameCount
        )
        val afterError = coordinator.snapshotError(snapshot)
        if (afterError != null) return AgentAnalysisResult.Failure(afterError)
        val cancellation = ensureActiveOrError()
        if (cancellation != null) return AgentAnalysisResult.Failure(cancellation)
        return AgentAnalysisResult.Success(snapshot)
    }

    suspend fun validateDisplayFilter(
        snapshot: AgentCaptureSnapshot,
        filter: String
    ): AgentAnalysisResult<Unit> {
        val before = assertSnapshotValid(snapshot)
        if (before != null) return AgentAnalysisResult.Failure(before)
        val validation = coordinator.validateDisplayFilter(filter, snapshotToken(snapshot))
        if (validation.isFailure) {
            val after = assertSnapshotValid(snapshot)
            return AgentAnalysisResult.Failure(
                if (after != null) after else invalidFilterError()
            )
        }
        val after = assertSnapshotValid(snapshot)
        return if (after == null) {
            AgentAnalysisResult.Success(Unit)
        } else {
            AgentAnalysisResult.Failure(after)
        }
    }

    /**
     * Query packet-list rows without mutating the user's native filter state.
     * New JNI libraries use Native Scoped Query; an unavailable or failed
     * capability falls back to the existing serialized Filter Lease path.
     */
    suspend fun queryPacketSummaries(
        snapshot: AgentCaptureSnapshot,
        filter: String,
        offset: Int,
        limit: Int
    ): AgentAnalysisResult<AgentPacketSummaryPage> {
        val before = assertSnapshotValid(snapshot)
        if (before != null) return AgentAnalysisResult.Failure(before)

        val boundedOffset = offset.coerceAtLeast(0)
        val boundedLimit = limit.coerceIn(1, MAX_SCOPED_QUERY_LIMIT)
        val scopedFilter = effectiveFilter(snapshot, filter)
        val nativeResult = try {
            val cancellationHandle = currentCoroutineContext()[Job]?.invokeOnCompletion {
                coordinator.cancelLongRunningOperations()
            }
            try {
                coordinator.withNativeSession {
                    dataSource.queryPacketSummariesScoped(
                        filter = scopedFilter,
                        start = boundedOffset,
                        count = boundedLimit
                    )
                }
            } finally {
                cancellationHandle?.dispose()
            }
        } catch (_: CancellationException) {
            return AgentAnalysisResult.Failure(
                assertSnapshotValid(snapshot) ?: cancelledError()
            )
        } catch (_: Throwable) {
            // Older JNI libraries do not export the symbol. Other native
            // failures also use the proven Filter Lease compatibility path.
            null
        }

        if (nativeResult?.cancelled == true) {
            return AgentAnalysisResult.Failure(
                assertSnapshotValid(snapshot) ?: cancelledError()
            )
        }
        if (nativeResult?.success == true) {
            val after = assertSnapshotValid(snapshot)
            if (after != null) return AgentAnalysisResult.Failure(after)
            val page = nativeResult.items.take(boundedLimit)
            val total = nativeResult.total.coerceAtLeast(page.size)
            val actualOffset = nativeResult.offset.coerceAtLeast(0)
            return AgentAnalysisResult.Success(
                AgentPacketSummaryPage(
                    offset = actualOffset,
                    page = page,
                    total = total,
                    captureStartTime = coordinator.withNativeSession {
                        dataSource.getFirstPacketTimestamp()
                    },
                    truncated = nativeResult.truncated ||
                        actualOffset.toLong() + page.size < total.toLong(),
                    queryMode = QUERY_MODE_NATIVE_SCOPED
                )
            )
        }

        return queryWithTemporaryFilter(snapshot, filter) { reader ->
            val total = reader.getVisibleFrameCount()
            val page = if (boundedOffset >= total) {
                emptyList()
            } else {
                reader.getRawPacketSummaries(
                    boundedOffset,
                    minOf(boundedLimit, total - boundedOffset)
                )
            }
            AgentPacketSummaryPage(
                offset = boundedOffset,
                page = page,
                total = total,
                captureStartTime = reader.getFirstPacketTimestamp(),
                truncated = boundedOffset.toLong() + page.size < total.toLong(),
                queryMode = QUERY_MODE_FILTER_LEASE
            )
        }
    }

    /**
     * Visit filtered packet summaries in bounded pages while holding the same
     * Agent filter lease.  The callback may dissect one packet and retain only
     * bounded counters/sample frame numbers; it must not retain the returned
     * [PacketSummary] page or a protocol tree.
     *
     * This is the Kotlin fallback for field aggregation.  New native batch
     * capabilities can replace this method later without changing the tool's
     * JSON contract or filter/session validation.
     */
    suspend fun scanFilteredPackets(
        snapshot: AgentCaptureSnapshot,
        filter: String,
        pageSize: Int = MAX_SCOPED_QUERY_LIMIT,
        onPacket: (AgentReadSession, PacketSummary) -> Unit
    ): AgentAnalysisResult<AgentPacketScanStats> {
        var scanError: AgentError? = null
        val result = queryWithTemporaryFilter(snapshot, filter) { reader ->
            val matched = reader.getVisibleFrameCount().coerceAtLeast(0)
            val boundedPageSize = pageSize.coerceIn(1, MAX_SCOPED_QUERY_LIMIT)
            var offset = 0
            var scanned = 0
            var complete = true

            while (offset < matched) {
                currentCoroutineContext().ensureActive()
                val snapshotError = assertSnapshotValid(snapshot)
                if (snapshotError != null) {
                    scanError = snapshotError
                    complete = false
                    break
                }
                val page = reader.getRawPacketSummaries(
                    offset,
                    minOf(boundedPageSize, matched - offset)
                )
                if (page.isEmpty()) {
                    complete = false
                    break
                }
                page.forEach { summary ->
                    onPacket(reader, summary)
                    scanned += 1
                }
                offset += page.size
                if (page.size < minOf(boundedPageSize, matched - (offset - page.size))) {
                    complete = false
                    break
                }
            }
            AgentPacketScanStats(
                matchedPackets = matched,
                scannedPackets = scanned,
                complete = complete && scanned >= matched,
                appliedFilter = reader.getAppliedDisplayFilter().trim()
            )
        }
        if (scanError != null) return AgentAnalysisResult.Failure(scanError!!)
        return result
    }

    /**
     * Open one deferred-restore chain for an Agent run.  While a chain is open
     * the coordinator keeps each tool's temporary filter applied between tool
     * calls and restores the user's filter once, at chain end or when the user
     * next applies a filter — instead of paying a restore scan per tool call.
     * The matching [endAgentFilterChain] must run even when the run fails or
     * is cancelled; the coordinator performs that restore NonCancellable.
     */
    fun beginAgentFilterChain() {
        coordinator.beginAgentFilterChain()
    }

    suspend fun endAgentFilterChain() {
        coordinator.endAgentFilterChain()
    }

    /**
     * Run a typed read under an AgentFilterLease.  [operation] receives only
     * the read-only Agent surface, never the mutable PacketRepository.
     */
    suspend fun <T> queryWithTemporaryFilter(
        snapshot: AgentCaptureSnapshot,
        filter: String,
        operation: suspend (AgentReadSession) -> T
    ): AgentAnalysisResult<T> {
        val before = assertSnapshotValid(snapshot)
        if (before != null) return AgentAnalysisResult.Failure(before)

        val effectiveFilter = effectiveFilter(snapshot, filter)
        val leased = coordinator.withAgentFilter(snapshot, effectiveFilter) {
            operation(dataSource)
        }
        if (leased is AgentAnalysisResult.Failure) {
            val afterFailure = assertSnapshotValid(snapshot)
            return if (afterFailure != null) {
                AgentAnalysisResult.Failure(afterFailure)
            } else {
                leased
            }
        }

        val after = assertSnapshotValid(snapshot)
        return if (after != null) {
            AgentAnalysisResult.Failure(after)
        } else {
            @Suppress("UNCHECKED_CAST")
            AgentAnalysisResult.Success((leased as AgentAnalysisResult.Success<T>).value)
        }
    }

    suspend fun getPacketDetails(
        snapshot: AgentCaptureSnapshot,
        frame: Long
    ): AgentAnalysisResult<ProtocolNode?> {
        val before = assertSnapshotValid(snapshot)
        if (before != null) return AgentAnalysisResult.Failure(before)
        if (frame < 1L || frame > snapshot.frameCount.toLong()) {
            return AgentAnalysisResult.Failure(
                AgentError(
                    code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                    userMessage = "The requested frame is outside the capture.",
                    details = mapOf("field" to "frame")
                )
            )
        }
        return checked(snapshot) { dataSource.getPacketDetails(frame) }
    }

    suspend fun getStatistics(
        snapshot: AgentCaptureSnapshot,
        bucketSeconds: Double = 1.0
    ): AgentAnalysisResult<CaptureStatistics> = getStatistics(snapshot, "", bucketSeconds)

    /**
     * Statistics for a caller-supplied filter, on top of the snapshot's scope.
     *
     * [getStatistics] reads the scope as it stands; this variant is what the
     * get_statistics tool uses so a model can narrow a statistics pass the same
     * way it narrows a summary query.
     */
    suspend fun getStatistics(
        snapshot: AgentCaptureSnapshot,
        filter: String,
        bucketSeconds: Double
    ): AgentAnalysisResult<CaptureStatistics> {
        val boundedBucket = bucketSeconds.coerceAtLeast(0.001)
        val key = analysisKey(snapshot, filter, boundedBucket)
        cached(key)?.statistics?.let { return cachedSuccess(snapshot, it) }
        return queryWithTemporaryFilter(snapshot, filter) { reader ->
            val value = cached(key)?.statistics
                ?: reader.buildCaptureStatistics(boundedBucket).also { statistics ->
                    cache(key) { existing ->
                        (existing ?: CachedNativeAnalysis()).copy(statistics = statistics)
                    }
                }
            value
        }
    }

    /** Expert facts share the same keyed cache as the other deterministic reads. */
    suspend fun getExpertInfoSummary(
        snapshot: AgentCaptureSnapshot,
        filter: String = ""
    ): AgentAnalysisResult<ExpertInfoSummary> {
        val key = analysisKey(snapshot, filter)
        cached(key)?.expertInfo?.let { return cachedSuccess(snapshot, it) }
        return queryWithTemporaryFilter(snapshot, filter) { reader ->
            val value = cached(key)?.expertInfo
                ?: reader.getExpertInfoSummary().also { expertInfo ->
                    cache(key) { existing ->
                        (existing ?: CachedNativeAnalysis()).copy(expertInfo = expertInfo)
                    }
                }
            value
        }
    }

    /** Read overview sources in one lease while populating the shared cache. */
    suspend fun getCaptureOverviewSourceData(
        snapshot: AgentCaptureSnapshot,
        bucketSeconds: Double = 1.0
    ): AgentAnalysisResult<CaptureOverviewSourceData> {
        val boundedBucket = bucketSeconds.coerceAtLeast(0.001)
        val key = analysisKey(snapshot, "", boundedBucket)
        return queryWithTemporaryFilter(snapshot, "") { reader ->
            val existing = cached(key)
            val statistics = existing?.statistics
                ?: reader.buildCaptureStatistics(boundedBucket).also { value ->
                    cache(key) { current ->
                        (current ?: CachedNativeAnalysis()).copy(statistics = value)
                    }
                }
            val expertInfo = existing?.expertInfo
                ?: reader.getExpertInfoSummary().also { value ->
                    cache(key) { current ->
                        (current ?: CachedNativeAnalysis()).copy(expertInfo = value)
                    }
                }
            CaptureOverviewSourceData(
                file = reader.currentFile(),
                statistics = statistics,
                expertInfo = expertInfo,
                frameCount = reader.getFrameCount(),
                visibleFrameCount = reader.getVisibleFrameCount(),
                appliedDisplayFilter = reader.getAppliedDisplayFilter()
            )
        }
    }

    suspend fun getCommunicationAnalysis(
        snapshot: AgentCaptureSnapshot
    ): AgentAnalysisResult<CommunicationAnalysis> = getCommunicationAnalysis(snapshot, "")

    /**
     * Aggregated communication analysis under an optional extra filter.
     *
     * [CommunicationAnalyzer.aggregate] runs here rather than in the tool so the
     * calls/streams/sessions a model sees are grouped by exactly the same logic
     * the Communication dialog uses.
     */
    suspend fun getCommunicationAnalysis(
        snapshot: AgentCaptureSnapshot,
        filter: String
    ): AgentAnalysisResult<CommunicationAnalysis> {
        val key = analysisKey(snapshot, filter)
        cached(key)?.communication?.let { return cachedSuccess(snapshot, it) }
        return queryWithTemporaryFilter(snapshot, filter) { reader ->
            val value = cached(key)?.communication
                ?: CommunicationAnalyzer.aggregate(reader.buildCommunicationAnalysis()).also { communication ->
                    cache(key) { existing ->
                        (existing ?: CachedNativeAnalysis()).copy(communication = communication)
                    }
                }
            value
        }
    }

    suspend fun getRadioEvents(
        snapshot: AgentCaptureSnapshot,
        startTime: Double? = null,
        endTime: Double? = null,
        eventTypes: Set<RadioEventType> = emptySet(),
        minimumSeverity: RadioSeverity = RadioSeverity.Info,
        limit: Int = 100
    ): AgentAnalysisResult<RadioQueryResult> = queryWithTemporaryFilter(snapshot, "") {
        radioRepository.queryEvents(
            startTime = startTime,
            endTime = endTime,
            types = eventTypes,
            minimumSeverity = minimumSeverity,
            limit = limit
        )
    }

    /** Read all local layers under one filter lease for the unified timeline. */
    suspend fun getUnifiedNetworkTimeline(
        snapshot: AgentCaptureSnapshot,
        filter: String = "",
        startTime: Double? = null,
        endTime: Double? = null,
        eventTypes: Set<RadioEventType> = emptySet(),
        minimumSeverity: RadioSeverity = RadioSeverity.Info,
        radioLimit: Int = 100
    ): AgentAnalysisResult<UnifiedNetworkTimeline> = queryWithTemporaryFilter(
        snapshot,
        filter
    ) { reader ->
        val radio = radioRepository.queryEvents(
            startTime = startTime,
            endTime = endTime,
            types = eventTypes,
            minimumSeverity = minimumSeverity,
            limit = radioLimit
        )
        val key = analysisKey(snapshot, filter)
        val cached = cached(key)
        val communication = cached?.communication
            ?: CommunicationAnalyzer.aggregate(reader.buildCommunicationAnalysis()).also { value ->
                cache(key) { existing ->
                    (existing ?: CachedNativeAnalysis()).copy(communication = value)
                }
            }
        val statistics = cached?.statistics
            ?: reader.buildCaptureStatistics().also { value ->
                cache(key) { existing ->
                    (existing ?: CachedNativeAnalysis()).copy(statistics = value)
                }
            }
        val expertInfo = cached?.expertInfo
            ?: reader.getExpertInfoSummary().also { value ->
                cache(key) { existing ->
                    (existing ?: CachedNativeAnalysis()).copy(expertInfo = value)
                }
            }
        UnifiedNetworkTimelineBuilder.build(
            radio = radio,
            communication = communication,
            statistics = statistics,
            expertInfo = expertInfo
        )
    }

    /**
     * Read the three local sources used by IMS registration diagnosis under one
     * filter lease.  Their timestamps and frame ranges therefore describe the
     * same scope instead of accidentally combining SIP from one filter with
     * TCP or Expert evidence from another.
     */
    suspend fun getImsRegistrationSourceData(
        snapshot: AgentCaptureSnapshot,
        filter: String
    ): AgentAnalysisResult<ImsRegistrationSourceData> = queryWithTemporaryFilter(
        snapshot,
        filter
    ) { reader ->
        val key = analysisKey(snapshot, filter)
        val cached = cached(key)
        val communication = cached?.communication
            ?: CommunicationAnalyzer.aggregate(reader.buildCommunicationAnalysis()).also { value ->
                cache(key) { existing ->
                    (existing ?: CachedNativeAnalysis()).copy(communication = value)
                }
            }
        val statistics = cached?.statistics
            ?: reader.buildCaptureStatistics().also { value ->
                cache(key) { existing ->
                    (existing ?: CachedNativeAnalysis()).copy(statistics = value)
                }
            }
        val expertInfo = cached?.expertInfo
            ?: reader.getExpertInfoSummary().also { value ->
                cache(key) { existing ->
                    (existing ?: CachedNativeAnalysis()).copy(expertInfo = value)
                }
            }
        ImsRegistrationSourceData(
            communication = communication,
            statistics = statistics,
            expertInfo = expertInfo,
            frameCount = reader.getFrameCount(),
            visibleFrameCount = reader.getVisibleFrameCount(),
            appliedDisplayFilter = reader.getAppliedDisplayFilter()
        )
    }

    /**
     * Follow-stream *metadata* for the stream carrying [frame].
     *
     * The native call reassembles the whole conversation, so the reassembled
     * text is present in memory for as long as this function runs.  The
     * projection to [FollowStreamMetadata] happens inside the lease, and the
     * [FollowStreamResult] — with its text, ascii and hex — goes out of scope
     * here.  Nothing outside this function ever sees the stream contents, which
     * is what keeps the AI-10 requirement ("never write the body to a Tool
     * Result, log or cache") a property of the code rather than a convention
     * every caller has to remember.
     */
    suspend fun getFollowStreamMetadata(
        snapshot: AgentCaptureSnapshot,
        frame: Long,
        protocol: String
    ): AgentAnalysisResult<FollowStreamMetadata> {
        if (frame < 1L || frame > snapshot.frameCount.toLong()) {
            return AgentAnalysisResult.Failure(
                AgentError(
                    code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                    userMessage = "The requested frame is outside the capture.",
                    details = mapOf("field" to "frame")
                )
            )
        }
        return queryWithTemporaryFilter(snapshot, "") { reader ->
            FollowStreamMetadata.from(reader.followStream(frame, protocol), protocol)
        }
    }

    /** Cancel native work and invalidate every snapshot from the old run. */
    fun cancelLongRunningOperations() {
        agentGeneration.incrementAndGet()
        coordinator.cancelLongRunningOperations()
    }

    /** Public for tools that need a pre/post guard around a long custom read. */
    suspend fun assertSnapshotValid(snapshot: AgentCaptureSnapshot): AgentError? {
        val cancellation = ensureActiveOrError()
        if (cancellation != null) return cancellation
        val sessionError = coordinator.snapshotError(snapshot)
        if (sessionError != null) return sessionError
        val expectedAgentGeneration = snapshot.agentGeneration.takeIf { it > 0L }
            ?: snapshot.analysisGeneration
        if (expectedAgentGeneration > 0L && agentGeneration.get() != expectedAgentGeneration) {
            return AgentError(
                code = AgentErrorCode.CANCELLED,
                userMessage = "The analysis run was cancelled or superseded.",
                retryable = true,
                details = mapOf("stage" to "agent_generation")
            )
        }
        return null
    }

    private suspend fun <T> checked(
        snapshot: AgentCaptureSnapshot,
        operation: suspend () -> T
    ): AgentAnalysisResult<T> {
        val before = assertSnapshotValid(snapshot)
        if (before != null) return AgentAnalysisResult.Failure(before)
        return try {
            val value = coordinator.withNativeSession { operation() }
            val after = assertSnapshotValid(snapshot)
            if (after != null) AgentAnalysisResult.Failure(after)
            else AgentAnalysisResult.Success(value)
        } catch (_: CancellationException) {
            AgentAnalysisResult.Failure(assertSnapshotValid(snapshot) ?: cancelledError())
        } catch (_: Throwable) {
            AgentAnalysisResult.Failure(assertSnapshotValid(snapshot) ?: internalError())
        }
    }

    private suspend fun ensureActiveOrError(): AgentError? = try {
        currentCoroutineContext().ensureActive()
        null
    } catch (_: CancellationException) {
        cancelledError()
    }

    private fun snapshotToken(snapshot: AgentCaptureSnapshot): CaptureSessionToken =
        CaptureSessionToken(
            snapshot.sessionHandle,
            snapshot.sessionGeneration.takeIf { it > 0L } ?: snapshot.generation
        )

    private fun effectiveFilter(snapshot: AgentCaptureSnapshot, requested: String): String {
        val query = requested.trim()
        val base = if (snapshot.scope == AnalysisScope.CurrentFilter) snapshot.displayFilter.trim() else ""
        return when {
            base.isBlank() -> query
            query.isBlank() -> base
            else -> "($base) && ($query)"
        }
    }

    private suspend fun <T> cachedSuccess(
        snapshot: AgentCaptureSnapshot,
        value: T
    ): AgentAnalysisResult<T> {
        val error = assertSnapshotValid(snapshot)
        return if (error != null) AgentAnalysisResult.Failure(error)
        else AgentAnalysisResult.Success(value)
    }

    private fun invalidFilterError() = AgentError(
        code = AgentErrorCode.INVALID_DISPLAY_FILTER,
        userMessage = "The display filter is invalid.",
        details = mapOf("stage" to "validation")
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
        const val MAX_SCOPED_QUERY_LIMIT = 100
        const val QUERY_MODE_NATIVE_SCOPED = "native_scoped"
        const val QUERY_MODE_FILTER_LEASE = "filter_lease"
        const val MAX_ANALYSIS_CACHE_ENTRIES = 8
    }
}
