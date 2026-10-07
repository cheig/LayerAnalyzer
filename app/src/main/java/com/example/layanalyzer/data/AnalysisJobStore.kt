// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.ai.agent.AgentRunIdentity
import com.example.layanalyzer.ai.serialization.AgentConversationCodec
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AnalysisScope
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale
import java.security.MessageDigest

/** Where a run was when the process died; drives the resume decision. */
enum class AnalysisCheckpoint {
    Queued,
    Preparing,
    /** A model request is in flight; its server-side state is unknown. */
    ModelRequestStarted,
    /** A model response has been folded into the trajectory. */
    ModelResponseCommitted,
    /** A deterministic local tool call is executing. */
    ToolStarted,
    /** A deterministic local tool call's result is committed. */
    ToolResultCommitted,
    /** A decoded report passed host validation. */
    ReportValidated,
    Terminal
}

/** How an interrupted run may be resumed, given its last checkpoint. */
enum class AnalysisResumePolicy {
    /** Last write was ModelRequestStarted: never auto-resume, billing is unknown. */
    ManualConfirm,
    /** A committed/local boundary: safe to resume with a fresh run. */
    SafeToResume,
    /** The capture file is gone or changed; nothing to resume. */
    CaptureUnavailable
}

/**
 * One durable checkpoint record for one in-flight run.
 *
 * Only the normalized transcript and bookkeeping live here — never the full
 * model request messages (that quadratic bloat is what the per-session 32 MiB
 * cap already strains under), and never the native session handle, which
 * cannot outlive the process.  Resume is therefore "a new run under the same
 * conversation, seeded with this context", not "continue the same model call".
 */
data class AnalysisJobCheckpoint(
    val conversationId: String,
    val runId: String,
    val requestId: String? = null,
    val captureFingerprint: String,
    val captureLocalPath: String,
    val captureDisplayName: String = "",
    val captureSizeBytes: Long = 0L,
    val analysisConfigVersion: Int = 1,
    val scope: AnalysisScope = AnalysisScope.CompleteFile,
    val displayFilter: String = "",
    val privacyMode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata,
    val modelId: String = "",
    val promptVersion: String = "",
    val playbookVersion: String? = null,
    val phase: String = "Queued",
    val checkpoint: AnalysisCheckpoint = AnalysisCheckpoint.Queued,
    val turn: Int = 0,
    val completedSteps: Int = 0,
    val completedToolCallIds: List<String> = emptyList(),
    val question: String = "",
    val transcript: List<AgentConversationItem> = emptyList(),
    val lastErrorCode: String? = null,
    val lastNetworkFailureKind: String? = null,
    val lastFailureStage: String? = null,
    val interrupted: Boolean = false,
    val startedAtMillis: Long = 0L,
    val updatedAtMillis: Long = 0L
) {
    /** What a restart is allowed to do with this record. */
    fun resumePolicy(currentFingerprint: String): AnalysisResumePolicy = when {
        captureFingerprint.isNotBlank() &&
            currentFingerprint.isNotBlank() &&
            captureFingerprint != currentFingerprint -> AnalysisResumePolicy.CaptureUnavailable
        checkpoint == AnalysisCheckpoint.ModelRequestStarted -> AnalysisResumePolicy.ManualConfirm
        else -> AnalysisResumePolicy.SafeToResume
    }
}

/**
 * Durable per-run checkpoints under `filesDir/agent_jobs`.
 *
 * One file per active run, named by a hash of the runId, written atomically at
 * each atomic boundary.  A file whose phase is not terminal when the process
 * next starts is proof the run was killed, so [markInterruptedOnStartup] flips
 * it to interrupted — the disk equivalent of the diagnostics log's
 * RunAbandoned back-fill, and keyed by the same runId.  Terminal runs delete
 * their file, so a leftover file always means an unfinished run.
 */
class AnalysisJobStore(
    private val directory: File,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    constructor(context: android.content.Context) : this(
        File(context.applicationContext.filesDir, DIRECTORY_NAME)
    )

    private val guard = Any()

    /** The exact directory a clear action is allowed to remove. */
    val storageDirectory: File
        get() = directory

    /** Write or overwrite the checkpoint for this run. Never throws. */
    fun write(checkpoint: AnalysisJobCheckpoint): Boolean = synchronized(guard) {
        runCatching {
            if (!directory.isDirectory) check(directory.mkdirs()) { "mkdir failed" }
            writeJsonAtomically(
                fileFor(checkpoint.runId),
                encode(checkpoint.copy(updatedAtMillis = clock())).toString(),
                TEMP_SUFFIX
            )
        }.isSuccess
    }

    /** Remove the checkpoint once a run reaches a terminal state. */
    fun delete(runId: String): Boolean = synchronized(guard) {
        if (runId.isBlank()) return false
        fileFor(runId).delete()
    }

    /** Every readable checkpoint, newest first. */
    fun list(): List<AnalysisJobCheckpoint> = synchronized(guard) {
        jobFiles().mapNotNull { decodeOrNull(it) }
            .sortedByDescending { it.updatedAtMillis }
    }

    /** The single non-terminal, non-interrupted run, if the last process left one. */
    fun activeJob(): AnalysisJobCheckpoint? = synchronized(guard) {
        jobFiles().mapNotNull { decodeOrNull(it) }
            .firstOrNull { !it.interrupted && it.checkpoint != AnalysisCheckpoint.Terminal }
    }

    /**
     * Mark every non-terminal record interrupted.  Called once at process
     * start: a checkpoint file that survives to a new process is, by
     * definition, a run that never wrote its terminal state.
     */
    fun markInterruptedOnStartup(): Int = synchronized(guard) {
        var marked = 0
        jobFiles().forEach { file ->
            val checkpoint = decodeOrNull(file) ?: return@forEach
            if (!checkpoint.interrupted && checkpoint.checkpoint != AnalysisCheckpoint.Terminal) {
                val flipped = checkpoint.copy(
                    interrupted = true,
                    phase = "Interrupted",
                    updatedAtMillis = clock()
                )
                if (runCatching {
                    writeJsonAtomically(file, encode(flipped).toString(), TEMP_SUFFIX)
                }.isSuccess) marked += 1
            }
        }
        marked
    }

    fun clear(): Int = synchronized(guard) {
        var removed = 0
        directory.listFiles()
            ?.filter { it.isFile && (it.name.endsWith(FILE_SUFFIX) || it.name.endsWith(TEMP_SUFFIX)) }
            ?.forEach { if (it.delete()) removed += 1 }
        removed
    }

    // ------------------------------------------------------------------ codec

    private fun jobFiles(): List<File> = directory.listFiles()
        ?.filter { it.isFile && it.name.endsWith(FILE_SUFFIX) }
        .orEmpty()

    private fun fileFor(runId: String): File {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(runId.toByteArray(Charsets.UTF_8))
        val name = digest.take(16).joinToString(separator = "") { byte ->
            "%02x".format(Locale.ROOT, byte)
        }
        return File(directory, "$name$FILE_SUFFIX")
    }

    private fun decodeOrNull(file: File): AnalysisJobCheckpoint? = runCatching {
        if (!file.isFile) return null
        decode(JSONObject(file.readText()))
    }.getOrNull()

    private fun encode(job: AnalysisJobCheckpoint): JSONObject = JSONObject()
        .put("schema", SCHEMA_NAME)
        .put("schemaVersion", SCHEMA_VERSION)
        .put("conversationId", job.conversationId)
        .put("runId", job.runId)
        .put("requestId", job.requestId ?: JSONObject.NULL)
        .put("captureFingerprint", job.captureFingerprint)
        .put("captureLocalPath", job.captureLocalPath)
        .put("captureDisplayName", job.captureDisplayName)
        .put("captureSizeBytes", job.captureSizeBytes)
        .put("analysisConfigVersion", job.analysisConfigVersion)
        .put("scope", job.scope.name)
        .put("displayFilter", job.displayFilter)
        .put("privacyMode", job.privacyMode.name)
        .put("modelId", job.modelId)
        .put("promptVersion", job.promptVersion)
        .put("playbookVersion", job.playbookVersion ?: JSONObject.NULL)
        .put("phase", job.phase)
        .put("checkpoint", job.checkpoint.name)
        .put("turn", job.turn)
        .put("completedSteps", job.completedSteps)
        .put("completedToolCallIds", JSONArray().apply { job.completedToolCallIds.forEach { put(it) } })
        .put("question", job.question)
        .put("transcript", AgentConversationCodec.conversationToArray(job.transcript))
        .put("lastErrorCode", job.lastErrorCode ?: JSONObject.NULL)
        .put("lastNetworkFailureKind", job.lastNetworkFailureKind ?: JSONObject.NULL)
        .put("lastFailureStage", job.lastFailureStage ?: JSONObject.NULL)
        .put("interrupted", job.interrupted)
        .put("startedAtMillis", job.startedAtMillis)
        .put("updatedAtMillis", job.updatedAtMillis)

    private fun decode(json: JSONObject): AnalysisJobCheckpoint {
        val schema = json.optString("schema").takeIf { it.isNotBlank() }
        require(schema == null || schema == SCHEMA_NAME) { "Unexpected job schema." }
        val conversationId = json.optString("conversationId").takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("A job checkpoint needs a conversation id.")
        val runId = json.optString("runId").takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("A job checkpoint needs a run id.")
        return AnalysisJobCheckpoint(
            conversationId = conversationId,
            runId = runId,
            requestId = json.optString("requestId").takeIf { it.isNotBlank() },
            captureFingerprint = json.optString("captureFingerprint"),
            captureLocalPath = json.optString("captureLocalPath"),
            captureDisplayName = json.optString("captureDisplayName"),
            captureSizeBytes = json.optLong("captureSizeBytes"),
            analysisConfigVersion = json.optInt("analysisConfigVersion", 1),
            scope = json.optString("scope")
                .let { raw -> AnalysisScope.entries.firstOrNull { it.name == raw } }
                ?: AnalysisScope.CompleteFile,
            displayFilter = json.optString("displayFilter"),
            privacyMode = json.optString("privacyMode")
                .let { raw -> AgentPrivacyMode.entries.firstOrNull { it.name == raw } }
                ?: AgentPrivacyMode.RedactedMetadata,
            modelId = json.optString("modelId"),
            promptVersion = json.optString("promptVersion"),
            playbookVersion = json.optString("playbookVersion").takeIf { it.isNotBlank() },
            phase = json.optString("phase").ifBlank { "Queued" },
            checkpoint = json.optString("checkpoint")
                .let { raw -> AnalysisCheckpoint.entries.firstOrNull { it.name == raw } }
                ?: AnalysisCheckpoint.Queued,
            turn = json.optInt("turn", 0),
            completedSteps = json.optInt("completedSteps", 0),
            completedToolCallIds = json.optJSONArray("completedToolCallIds").let { array ->
                if (array == null) emptyList() else (0 until array.length()).map { array.getString(it) }
            },
            question = json.optString("question"),
            transcript = AgentConversationCodec.conversationFromArray(json.optJSONArray("transcript")),
            lastErrorCode = json.optString("lastErrorCode").takeIf { it.isNotBlank() },
            lastNetworkFailureKind = json.optString("lastNetworkFailureKind").takeIf { it.isNotBlank() },
            lastFailureStage = json.optString("lastFailureStage").takeIf { it.isNotBlank() },
            interrupted = json.optBoolean("interrupted", false),
            startedAtMillis = json.optLong("startedAtMillis"),
            updatedAtMillis = json.optLong("updatedAtMillis")
        )
    }

    companion object {
        const val DIRECTORY_NAME = "agent_jobs"
        private const val SCHEMA_NAME = "AgentAnalysisJob"
        private const val SCHEMA_VERSION = 1
        private const val FILE_SUFFIX = ".json"
        private const val TEMP_SUFFIX = ".tmp"
    }
}
