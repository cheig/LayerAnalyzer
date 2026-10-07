package com.example.layanalyzer.ai.audit

import com.example.layanalyzer.ai.tools.AgentToolAuditEntry
import com.example.layanalyzer.ai.tools.AgentToolAuditLog
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentReport

/** A single tool step in the exportable, redacted audit trail. */
data class AgentToolRunRecord(
    val toolName: String,
    val normalizedArgumentsHash: String,
    val durationMillis: Long,
    val returned: Long,
    val total: Long,
    val errorCode: AgentErrorCode? = null,
    val truncated: Boolean = false,
    val resultBytes: Int = 0,
    val queryMode: String? = null,
    val sampled: Boolean = false
)

/**
 * The minimal, in-memory audit record for an Agent run.
 *
 * The record intentionally has no raw arguments, tool data, model request or
 * response.  It is held only until a user explicitly exports it.
 */
data class AgentRunRecord(
    val sessionId: String,
    val captureFingerprint: String,
    val modelId: String,
    val promptVersion: String,
    val playbookVersion: String? = null,
    val analysisScope: String,
    val displayFilterApplied: Boolean,
    val startedAtMillis: Long,
    val completedAtMillis: Long,
    val toolCalls: List<AgentToolRunRecord> = emptyList(),
    val totalSteps: Int = toolCalls.size,
    val totalDurationMillis: Long = (completedAtMillis - startedAtMillis).coerceAtLeast(0L),
    val cancelReason: String? = null,
    val evidenceCount: Int = 0,
    // EVL-COVERAGE-03: the run's evidence-coverage receipt as three counts
    // only. The frame-number sets stay in the trace's in-memory object and
    // are never serialized here — counts and stable ids are the audit
    // boundary. `evidenceFlaggedCount` is the run's evidence set size
    // (cited + uncited by construction), `evidenceCitedCount` the frames the
    // accepted report cites, `citationOutsideFlagged` the cited frames that
    // were never in the evidence set. All zero when the loop produced no
    // coverage receipt (no evidence path, cancelled before a report).
    val evidenceFlaggedCount: Int = 0,
    val evidenceCitedCount: Int = 0,
    val citationOutsideFlagged: Int = 0,
    val completeness: String? = null
)

/** Builds [AgentRunRecord]s from the existing hash-only tool audit boundary. */
class AgentRunAuditRecorder : AgentToolAuditLog {
    private val lock = Any()
    private var metadata: Metadata? = null
    private val entries = mutableListOf<AgentToolRunRecord>()

    fun start(
        sessionId: String,
        snapshot: AgentCaptureSnapshot,
        modelId: String,
        promptVersion: String,
        playbookVersion: String?,
        startedAtMillis: Long
    ) {
        synchronized(lock) {
            metadata = Metadata(
                sessionId = sessionId,
                captureFingerprint = snapshot.captureFingerprint,
                modelId = modelId,
                promptVersion = promptVersion,
                playbookVersion = playbookVersion,
                analysisScope = snapshot.scope.name,
                displayFilterApplied = snapshot.displayFilter.isNotBlank(),
                startedAtMillis = startedAtMillis
            )
            entries.clear()
        }
    }

    override fun record(entry: AgentToolAuditEntry) {
        synchronized(lock) {
            if (metadata == null) return
            entries += AgentToolRunRecord(
                toolName = entry.toolName,
                normalizedArgumentsHash = entry.normalizedArgumentsHash,
                durationMillis = entry.durationMillis,
                returned = entry.returnedCount,
                total = entry.totalCount,
                errorCode = entry.errorCode,
                truncated = entry.truncated,
                resultBytes = entry.resultBytes,
                queryMode = entry.queryMode,
                sampled = entry.sampled
            )
        }
    }

    fun finish(
        completedAtMillis: Long,
        report: AgentReport? = null,
        cancelReason: String? = null,
        evidenceFlaggedCount: Int = 0,
        evidenceCitedCount: Int = 0,
        citationOutsideFlagged: Int = 0
    ): AgentRunRecord? = synchronized(lock) {
        val current = metadata ?: return null
        val capturedEntries = entries.toList()
        AgentRunRecord(
            sessionId = current.sessionId,
            captureFingerprint = current.captureFingerprint,
            modelId = current.modelId,
            promptVersion = current.promptVersion,
            playbookVersion = current.playbookVersion,
            analysisScope = current.analysisScope,
            displayFilterApplied = current.displayFilterApplied,
            startedAtMillis = current.startedAtMillis,
            completedAtMillis = completedAtMillis,
            toolCalls = capturedEntries,
            totalSteps = capturedEntries.size,
            totalDurationMillis = (completedAtMillis - current.startedAtMillis).coerceAtLeast(0L),
            cancelReason = cancelReason,
            evidenceCount = report?.findings?.sumOf { it.evidence.size } ?: 0,
            evidenceFlaggedCount = evidenceFlaggedCount,
            evidenceCitedCount = evidenceCitedCount,
            citationOutsideFlagged = citationOutsideFlagged,
            completeness = report?.completeness?.name
        )
    }

    private data class Metadata(
        val sessionId: String,
        val captureFingerprint: String,
        val modelId: String,
        val promptVersion: String,
        val playbookVersion: String?,
        val analysisScope: String,
        val displayFilterApplied: Boolean,
        val startedAtMillis: Long
    )
}
