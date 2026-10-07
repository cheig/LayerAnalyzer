// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.tools.dto.AgentBaseToolProjections
import com.example.layanalyzer.ai.tools.dto.AgentCaptureOverview
import com.example.layanalyzer.ai.tools.dto.AgentScopeArgument
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.data.CaptureHealthAnalyzer
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.FileSessionInfo
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * get_capture_overview — the health snapshot an Agent reads first.
 *
 * The tool runs one statistics pass and one Expert pass inside a single filter
 * lease, then projects both through [AgentBaseToolProjections].  The complete
 * [CaptureStatistics] object and the [FileSessionInfo] are never returned as-is,
 * so the capture's local path cannot reach a model.
 */
class CaptureOverviewTool(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {

    override val definition = AgentToolDefinition(
        name = "get_capture_overview",
        description = "Summarise the capture: size, time range, protocol hierarchy, " +
            "DNS/TCP/TLS/HTTP health indicators and Expert Info counts. " +
            "Call this before any targeted analysis.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "scope" to mapOf(
                    "type" to "string",
                    "enum" to AgentScopeArgument.wireNames
                ),
                "statisticsBucketSeconds" to mapOf(
                    "type" to "number",
                    "minimum" to MIN_BUCKET_SECONDS,
                    "maximum" to MAX_BUCKET_SECONDS
                )
            )
        ),
        sensitivity = AgentDataSensitivity.Aggregate,
        defaultTimeoutMillis = 30_000L
    )

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val scope = AgentScopeArgument.fromWire(arguments["scope"] as? String)
            ?: AgentScopeArgument.of(context.snapshot.scope)
        val bucketSeconds = (arguments["statisticsBucketSeconds"] as? Number)
            ?.toDouble()
            ?.coerceIn(MIN_BUCKET_SECONDS, MAX_BUCKET_SECONDS)
            ?: DEFAULT_BUCKET_SECONDS

        // A complete-file read must ignore the user's filter, and a
        // current-filter read must reuse exactly the filter recorded when the
        // run started.  Re-scoping the snapshot lets the repository's own lease
        // logic pick the right temporary filter without the tool ever applying
        // one itself.
        val scopedSnapshot = context.snapshot.scopedTo(scope)

        // Read both expensive facts in one lease and populate the repository's
        // shared cache so subsequent tools do not dissect this scope again.
        val value = when (val result = context.repository.getCaptureOverviewSourceData(
            scopedSnapshot,
            bucketSeconds
        )) {
            is AgentAnalysisResult.Failure -> throw AgentToolException(result.error)
            is AgentAnalysisResult.Success -> result.value.toOverviewReading()
        }

        val overview = withContext(ioDispatcher) { value.toOverview(scope) }
        return context.success(
            data = overview.toAgentJson(),
            returnedCount = overview.returned.toLong(),
            totalCount = overview.total.toLong(),
            truncated = overview.truncated
        )
    }

    private data class OverviewReading(
        val file: FileSessionInfo?,
        val statistics: CaptureStatistics,
        val expert: ExpertInfoSummary,
        val frameCount: Int,
        val visibleFrameCount: Int,
        val displayFilter: String
    )

    private fun com.example.layanalyzer.data.CaptureOverviewSourceData.toOverviewReading() =
        OverviewReading(
            file = file,
            statistics = statistics,
            expert = expertInfo,
            frameCount = frameCount,
            visibleFrameCount = visibleFrameCount,
            displayFilter = appliedDisplayFilter
        )

    private fun OverviewReading.toOverview(scope: AgentScopeArgument): AgentCaptureOverview {
        // CaptureHealthAnalyzer needs a file record; when the session cannot
        // supply one the placeholder carries an empty path so nothing about the
        // device filesystem is ever derived from it.
        val fileInfo = file ?: FileSessionInfo(
            displayName = "",
            sizeBytes = 0L,
            fileType = "unknown",
            frameCount = frameCount,
            localPath = "",
            encapsulation = "unknown"
        )
        val summary = CaptureHealthAnalyzer.summarize(
            file = fileInfo,
            statistics = statistics,
            expert = expert,
            scope = scope.scope
        )
        val hierarchy = AgentBaseToolProjections.protocolHierarchy(statistics)
        val (errorCount, warningCount) = AgentBaseToolProjections.expertCounts(expert)
        val duration = (statistics.endTime - statistics.startTime).coerceAtLeast(0.0)

        return AgentCaptureOverview(
            fileType = fileInfo.fileType,
            encapsulation = fileInfo.encapsulation,
            frameCount = frameCount,
            visibleFrameCount = visibleFrameCount,
            startTime = statistics.startTime,
            endTime = statistics.endTime,
            durationSeconds = duration,
            scope = scope.wireName,
            displayFilter = displayFilter,
            protocolHierarchy = hierarchy,
            protocolHierarchyTotal = statistics.protocolHierarchy.size,
            health = AgentBaseToolProjections.health(statistics, summary),
            expertErrorCount = errorCount,
            expertWarningCount = warningCount,
            capturedByteCount = statistics.capturedByteCount,
            truncatedPacketCount = statistics.truncatedPacketCount,
            returned = statistics.packetCount,
            total = frameCount,
            truncated = statistics.protocolHierarchy.size > hierarchy.size || expert.truncated
        )
    }

    private companion object {
        const val MIN_BUCKET_SECONDS = 0.1
        const val MAX_BUCKET_SECONDS = 60.0
        const val DEFAULT_BUCKET_SECONDS = 1.0
    }
}

/**
 * A copy of this snapshot that reads the requested scope.  Only the scope
 * changes: the session handle, fingerprint and every generation are preserved,
 * so the repository still rejects the read if the capture was swapped.
 */
internal fun AgentCaptureSnapshot.scopedTo(scope: AgentScopeArgument): AgentCaptureSnapshot =
    if (this.scope == scope.scope) this else copy(scope = scope.scope)

/**
 * Abort the surrounding read if the session moved on.  Native scans are long
 * enough that a capture can be closed midway, and a partial result from an old
 * session must never be projected into a tool payload.
 */
internal suspend fun AgentToolContext.ensureStillValid(snapshot: AgentCaptureSnapshot) {
    repository.assertSnapshotValid(snapshot)?.let { error -> throw AgentToolException(error) }
}
