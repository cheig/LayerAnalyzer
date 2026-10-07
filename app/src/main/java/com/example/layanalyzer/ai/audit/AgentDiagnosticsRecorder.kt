package com.example.layanalyzer.ai.audit

import android.content.Context
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentErrorCode
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

/** One tool step as the diagnostics log records it. */
data class AgentDiagnosticsToolEvent(
    val toolName: String,
    val normalizedArgumentsHash: String,
    val durationMillis: Long,
    val returnedCount: Long,
    val totalCount: Long,
    val truncated: Boolean,
    val cacheHit: Boolean,
    val errorCode: AgentErrorCode? = null,
    val resultBytes: Int = 0,
    val queryMode: String? = null,
    val sampled: Boolean = false
)

/** One completed run as the diagnostics log records it. */
data class AgentDiagnosticsRun(
    val sessionId: String,
    val captureFingerprint: String,
    val modelId: String,
    val promptVersion: String,
    val playbookVersion: String?,
    val startedAtMillis: Long,
    val completedAtMillis: Long,
    val totalSteps: Int,
    val totalDurationMillis: Long,
    val cancelReason: String?,
    val evidenceCount: Int,
    val removedEvidenceCount: Int,
    // EVL-COVERAGE-03: evidence-coverage receipt counters, counts only —
    // zero defaults keep old constructor callers and old log lines valid.
    val evidenceFlaggedCount: Int = 0,
    val evidenceCitedCount: Int = 0,
    val citationOutsideFlagged: Int = 0,
    val truncationEvents: Int,
    val cacheHits: Int,
    val memoryPressureEvents: Int,
    val toolEvents: List<AgentDiagnosticsToolEvent>
)

/**
 * Append-only diagnostics handle for one run.
 *
 * Events are written as they happen, so a process death still leaves the
 * completed prefix of a run available for export.  The handle owns sequence
 * numbers and metadata; callers only provide already-structured values.
 */
class AgentDiagnosticsSession internal constructor(
    private val recorder: AgentDiagnosticsRecorder,
    val runId: String,
    val sessionId: String,
    val conversationId: String = "",
    private var captureFingerprint: String,
    private var modelId: String,
    private val promptVersion: String,
    private var playbookVersion: String?,
    startedAtMillis: Long
) {
    private val guard = Any()
    private var sequence = 0L
    private var terminal = false

    val isFinished: Boolean
        get() = synchronized(guard) { terminal }

    init {
        record(
            type = AgentDiagnosticsEventType.RunStarted,
            status = "started",
            attributes = mapOf("startedAtMillis" to startedAtMillis.toString())
        )
    }

    /** Update metadata after the model and capture snapshot have been resolved. */
    fun configure(
        captureFingerprint: String? = null,
        modelId: String? = null,
        playbookVersion: String? = null,
        attributes: Map<String, String> = emptyMap()
    ) {
        synchronized(guard) {
            captureFingerprint?.let { this.captureFingerprint = it }
            modelId?.let { this.modelId = it }
            playbookVersion?.let { this.playbookVersion = it }
        }
        record(
            type = AgentDiagnosticsEventType.Configuration,
            attributes = attributes
        )
    }

    fun record(
        type: AgentDiagnosticsEventType,
        captureFingerprint: String? = null,
        modelId: String? = null,
        playbookVersion: String? = null,
        phase: String? = null,
        turn: Int? = null,
        step: Int? = null,
        toolName: String? = null,
        argumentsHash: String? = null,
        durationMillis: Long? = null,
        status: String? = null,
        failure: AgentDiagnosticsFailure? = null,
        attributes: Map<String, String> = emptyMap()
    ) {
        val event = synchronized(guard) {
            if (terminal) return
            captureFingerprint?.let { this.captureFingerprint = it }
            modelId?.let { this.modelId = it }
            playbookVersion?.let { this.playbookVersion = it }
            sequence += 1
            AgentDiagnosticsEvent(
                runId = runId,
                sessionId = sessionId,
                conversationId = conversationId,
                sequence = sequence,
                timestampMillis = recorder.now(),
                type = type,
                captureFingerprint = this.captureFingerprint,
                modelId = this.modelId,
                promptVersion = promptVersion,
                playbookVersion = this.playbookVersion,
                phase = phase,
                turn = turn,
                step = step,
                toolName = toolName,
                argumentsHash = argumentsHash,
                durationMillis = durationMillis,
                status = status,
                failure = failure,
                attributes = attributes
            )
        }
        recorder.append(event)
    }

    fun recordFailure(
        type: AgentDiagnosticsEventType,
        boundary: String,
        error: com.example.layanalyzer.model.AgentError? = null,
        throwable: Throwable? = null,
        phase: String? = null,
        turn: Int? = null,
        step: Int? = null,
        toolName: String? = null,
        status: String? = "failed",
        attributes: Map<String, String> = emptyMap()
    ) {
        val failure = when {
            throwable != null -> throwable.toDiagnosticsFailure(
                boundary = boundary,
                errorCode = error?.code ?: AgentErrorCode.INTERNAL_ERROR,
                retryable = error?.retryable ?: false
            ).copy(reason = error?.let { it.toDiagnosticsFailure(boundary).reason }
                ?: "unexpected_exception")
            error != null -> error.toDiagnosticsFailure(boundary)
            else -> AgentDiagnosticsFailure(boundary = boundary)
        }
        record(
            type = type,
            phase = phase,
            turn = turn,
            step = step,
            toolName = toolName,
            status = status,
            failure = failure,
            attributes = attributes
        )
    }

    fun finish(
        status: String,
        error: com.example.layanalyzer.model.AgentError? = null,
        throwable: Throwable? = null,
        attributes: Map<String, String> = emptyMap()
    ) {
        val failure = when {
            throwable != null -> throwable.toDiagnosticsFailure(
                boundary = "run",
                errorCode = error?.code ?: AgentErrorCode.INTERNAL_ERROR,
                retryable = error?.retryable ?: false
            )
            error != null -> error.toDiagnosticsFailure("run")
            else -> null
        }
        val event = synchronized(guard) {
            if (terminal) return
            sequence += 1
            AgentDiagnosticsEvent(
                runId = runId,
                sessionId = sessionId,
                conversationId = conversationId,
                sequence = sequence,
                timestampMillis = recorder.now(),
                type = AgentDiagnosticsEventType.RunFinished,
                captureFingerprint = captureFingerprint,
                modelId = modelId,
                promptVersion = promptVersion,
                playbookVersion = playbookVersion,
                status = status,
                failure = failure,
                attributes = attributes
            ).also { terminal = true }
        }
        recorder.append(event)
    }
}

/**
 * Rotating, local-only performance and error log for Agent runs.
 *
 * The recorder is a *diagnostics* log, not a transcript.  It answers "which
 * step was slow", "what failed", "how often did the cache help" and "how much
 * evidence did the validator remove" — and it is structurally unable to answer
 * "what did the capture contain" or "what did the model say", because nothing
 * that could carry those is ever passed to it.  Tool arguments arrive already
 * hashed, results arrive as counts, and there is no field for prose.
 *
 * The capture fingerprint is truncated on write: enough to correlate the runs
 * of one file with each other, not enough to serve as the file's identity if
 * the log is shared.
 */
class AgentDiagnosticsRecorder(
    private val directory: File?,
    private val maxFileBytes: Long = DEFAULT_MAX_FILE_BYTES,
    private val maxFiles: Int = DEFAULT_MAX_FILES,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    constructor(
        context: Context,
        clock: () -> Long = { System.currentTimeMillis() }
    ) : this(File(context.applicationContext.filesDir, DIRECTORY_NAME), clock = clock)

    private val guard = Any()

    /** The exact directory a clear action is allowed to remove. */
    val storageDirectory: File?
        get() = directory

    internal fun now(): Long = clock()

    /** Start a durable event stream before snapshot creation or model setup. */
    fun beginRun(
        sessionId: String,
        runId: String? = null,
        conversationId: String = "",
        modelId: String = "",
        promptVersion: String = "",
        playbookVersion: String? = null,
        startedAtMillis: Long = clock()
    ): AgentDiagnosticsSession {
        // A caller that knows the run identity (Phase 1 ID model) passes it in
        // and it is used verbatim, so the runId the user sees on an error card
        // is the same string the log is grouped by.  The derived form only
        // remains for legacy callers.
        val resolvedRunId = runId?.takeIf { it.isNotBlank() }
            ?: "$sessionId-${startedAtMillis}-${UUID.randomUUID().toString().take(8)}"
        directory?.let { root -> synchronized(guard) { markAbandonedRuns(root) } }
        return AgentDiagnosticsSession(
            recorder = this,
            runId = resolvedRunId,
            sessionId = sessionId,
            conversationId = conversationId,
            captureFingerprint = "",
            modelId = modelId,
            promptVersion = promptVersion,
            playbookVersion = playbookVersion,
            startedAtMillis = startedAtMillis
        )
    }

    /**
     * Append one run.  Failure to write is swallowed: a full disk must never
     * turn a completed analysis into a failed one.
     */
    fun record(run: AgentDiagnosticsRun) {
        val root = directory ?: return
        synchronized(guard) {
            runCatching {
                appendJson(root, encode(run))
            }
        }
    }

    internal fun append(event: AgentDiagnosticsEvent) {
        val root = directory ?: return
        synchronized(guard) {
            runCatching { appendJson(root, encode(event)) }
        }
    }

    /** Convenience overload building the record from an [AgentRunRecord]. */
    fun record(
        record: AgentRunRecord,
        cacheHitHashes: Set<String> = emptySet(),
        removedEvidenceCount: Int = 0,
        memoryPressureEvents: Int = 0
    ) {
        record(
            AgentDiagnosticsRun(
                sessionId = record.sessionId,
                captureFingerprint = record.captureFingerprint,
                modelId = record.modelId,
                promptVersion = record.promptVersion,
                playbookVersion = record.playbookVersion,
                startedAtMillis = record.startedAtMillis,
                completedAtMillis = record.completedAtMillis,
                totalSteps = record.totalSteps,
                totalDurationMillis = record.totalDurationMillis,
                cancelReason = record.cancelReason,
                evidenceCount = record.evidenceCount,
                removedEvidenceCount = removedEvidenceCount,
                evidenceFlaggedCount = record.evidenceFlaggedCount,
                evidenceCitedCount = record.evidenceCitedCount,
                citationOutsideFlagged = record.citationOutsideFlagged,
                truncationEvents = record.toolCalls.count { it.truncated },
                cacheHits = record.toolCalls.count { it.normalizedArgumentsHash in cacheHitHashes },
                memoryPressureEvents = memoryPressureEvents,
                toolEvents = record.toolCalls.map { call ->
                    AgentDiagnosticsToolEvent(
                        toolName = call.toolName,
                        normalizedArgumentsHash = call.normalizedArgumentsHash,
                        durationMillis = call.durationMillis,
                        returnedCount = call.returned,
                        totalCount = call.total,
                        truncated = call.truncated,
                        cacheHit = call.normalizedArgumentsHash in cacheHitHashes,
                        errorCode = call.errorCode,
                        resultBytes = call.resultBytes,
                        queryMode = call.queryMode,
                        sampled = call.sampled
                    )
                }
            )
        )
    }

    /**
     * Build the text a user-initiated export shares.
     *
     * Everything written was already hash-only, but the export goes one step
     * further and drops the argument hashes as well: they are useful locally
     * for matching a repeated call, and useless to anyone reading a shared
     * file, so there is no reason to let them leave the device.
     */
    fun exportRedacted(): String {
        val root = directory ?: return EMPTY_EXPORT
        val lines = synchronized(guard) { logFiles(root).flatMap { it.readLines() } }
        if (lines.isEmpty()) return EMPTY_EXPORT
        val runs = JSONArray()
        val events = JSONArray()
        lines.forEach { line ->
            val entry = runCatching { JSONObject(line) }.getOrNull() ?: return@forEach
            when (entry.optString("schema")) {
                RUN_SCHEMA -> {
                    entry.remove("captureRef")
                    entry.put("modelId", sanitizeDiagnosticsText(entry.optString("modelId"), 160) ?: JSONObject.NULL)
                    entry.put("promptVersion", sanitizeDiagnosticsText(entry.optString("promptVersion"), 160) ?: JSONObject.NULL)
                    entry.put("playbookVersion", sanitizeDiagnosticsText(entry.optString("playbookVersion"), 160) ?: JSONObject.NULL)
                    entry.put("cancelReason", sanitizeDiagnosticsText(entry.optString("cancelReason"), 160) ?: JSONObject.NULL)
                    entry.optJSONArray("tools")?.let { tools ->
                        for (index in 0 until tools.length()) {
                            tools.optJSONObject(index)?.let { tool ->
                                tool.remove("argumentsHash")
                                tool.put(
                                    "toolName",
                                    sanitizeDiagnosticsText(tool.optString("toolName"), 120) ?: "unknown"
                                )
                            }
                        }
                    }
                    runs.put(entry)
                }
                EVENT_SCHEMA -> {
                    entry.remove("captureRef")
                    entry.remove("argumentsHash")
                    entry.put("modelId", sanitizeDiagnosticsText(entry.optString("modelId"), 160) ?: JSONObject.NULL)
                    entry.put("promptVersion", sanitizeDiagnosticsText(entry.optString("promptVersion"), 160) ?: JSONObject.NULL)
                    entry.put("playbookVersion", sanitizeDiagnosticsText(entry.optString("playbookVersion"), 160) ?: JSONObject.NULL)
                    events.put(entry)
                }
            }
        }
        return JSONObject()
            .put("schema", EXPORT_SCHEMA)
            .put("schemaVersion", SCHEMA_VERSION)
            .put("exportedAtMillis", clock())
            .put("runs", runs)
            .put("events", events)
            .toString(2)
    }

    fun totalBytes(): Long = directory?.let { root -> logFiles(root).sumOf { it.length() } } ?: 0L

    /** Remove every rotated log.  Only this recorder's own files. */
    fun clear(): Int = synchronized(guard) {
        val root = directory ?: return 0
        var removed = 0
        logFiles(root).forEach { if (it.delete()) removed += 1 }
        removed
    }

    // ----------------------------------------------------------------- codec

    private fun appendJson(root: File, value: JSONObject) {
        if (!root.isDirectory && !root.mkdirs()) return
        val line = value.toString() + "\n"
        val current = File(root, ACTIVE_FILE)
        val lineBytes = line.toByteArray(Charsets.UTF_8).size.toLong()
        if (current.isFile && current.length() > 0L &&
            current.length() + lineBytes > maxFileBytes
        ) {
            rotate(root, current)
        }
        current.appendText(line)
        enforceFileCap(root)
    }

    private fun encode(run: AgentDiagnosticsRun): JSONObject = JSONObject()
        .put("schema", RUN_SCHEMA)
        .put("schemaVersion", SCHEMA_VERSION)
        .put("sessionId", run.sessionId)
        .put("captureRef", shortReference(run.captureFingerprint))
        .put("modelId", sanitizeDiagnosticsText(run.modelId, 160) ?: JSONObject.NULL)
        .put("promptVersion", sanitizeDiagnosticsText(run.promptVersion, 160) ?: JSONObject.NULL)
        .put("playbookVersion", sanitizeDiagnosticsText(run.playbookVersion, 160) ?: JSONObject.NULL)
        .put("startedAtMillis", run.startedAtMillis)
        .put("completedAtMillis", run.completedAtMillis)
        .put("totalSteps", run.totalSteps)
        .put("totalDurationMillis", run.totalDurationMillis)
        .put("cancelReason", sanitizeDiagnosticsText(run.cancelReason, 160) ?: JSONObject.NULL)
        .put("evidenceCount", run.evidenceCount)
        .put("removedEvidenceCount", run.removedEvidenceCount)
        // EVL-COVERAGE-03: the coverage receipt as three integers. The
        // frame-number sets behind them never leave the in-memory trace.
        .put("evidenceFlaggedCount", run.evidenceFlaggedCount)
        .put("evidenceCitedCount", run.evidenceCitedCount)
        .put("citationOutsideFlagged", run.citationOutsideFlagged)
        .put("truncationEvents", run.truncationEvents)
        .put("cacheHits", run.cacheHits)
        .put("memoryPressureEvents", run.memoryPressureEvents)
        .put("tools", JSONArray().apply {
            run.toolEvents.forEach { event ->
                put(
                    JSONObject()
                        .put("toolName", sanitizeDiagnosticsText(event.toolName, 120) ?: "unknown")
                        .put("argumentsHash", sanitizeDiagnosticsText(event.normalizedArgumentsHash, 160) ?: "")
                        .put("durationMillis", event.durationMillis)
                        .put("returned", event.returnedCount)
                        .put("total", event.totalCount)
                        .put("truncated", event.truncated)
                        .put("cacheHit", event.cacheHit)
                        .put("errorCode", event.errorCode?.name ?: JSONObject.NULL)
                        .put("resultBytes", event.resultBytes)
                        .put("queryMode", event.queryMode ?: JSONObject.NULL)
                        .put("sampled", event.sampled)
                )
            }
        })

    private fun encode(event: AgentDiagnosticsEvent): JSONObject = JSONObject()
        .put("schema", EVENT_SCHEMA)
        .put("schemaVersion", SCHEMA_VERSION)
        .put("runId", event.runId)
        .put("sessionId", event.sessionId)
        .put("conversationId", event.conversationId.takeIf { it.isNotBlank() } ?: JSONObject.NULL)
        .put("sequence", event.sequence)
        .put("timestampMillis", event.timestampMillis)
        .put("eventType", event.type.name)
        .put("captureRef", shortReference(event.captureFingerprint))
        .put("modelId", sanitizeDiagnosticsText(event.modelId, 160) ?: JSONObject.NULL)
        .put("promptVersion", sanitizeDiagnosticsText(event.promptVersion, 160) ?: JSONObject.NULL)
        .put("playbookVersion", sanitizeDiagnosticsText(event.playbookVersion, 160) ?: JSONObject.NULL)
        .put("phase", sanitizeDiagnosticsText(event.phase, 80) ?: JSONObject.NULL)
        .put("turn", event.turn ?: JSONObject.NULL)
        .put("step", event.step ?: JSONObject.NULL)
        .put("toolName", sanitizeDiagnosticsText(event.toolName, 120) ?: JSONObject.NULL)
        .put("argumentsHash", sanitizeDiagnosticsText(event.argumentsHash, 160) ?: JSONObject.NULL)
        .put("durationMillis", event.durationMillis ?: JSONObject.NULL)
        .put("status", sanitizeDiagnosticsText(event.status, 80) ?: JSONObject.NULL)
        .put("failure", encode(event.failure))
        .put("attributes", JSONObject().apply {
            event.attributes.forEach { (key, value) ->
                put(
                    sanitizeDiagnosticsText(key, 80) ?: "unknown",
                    encodeAttributeValue(key, value)
                )
            }
        })

    private fun encodeAttributeValue(key: String, value: String): String =
        if (key in NUMERIC_ATTRIBUTE_KEYS && value.toDoubleOrNull() != null) {
            value
        } else {
            sanitizeDiagnosticsText(value) ?: ""
        }

    private fun encode(failure: AgentDiagnosticsFailure?): Any = failure?.let {
        JSONObject()
            .put("boundary", sanitizeDiagnosticsText(it.boundary, 120) ?: "unknown")
            .put("errorCode", it.errorCode?.name ?: JSONObject.NULL)
            .put("retryable", it.retryable ?: JSONObject.NULL)
            .put("reason", sanitizeDiagnosticsText(it.reason) ?: JSONObject.NULL)
            .put("providerStatus", it.providerStatus ?: JSONObject.NULL)
            .put("providerCode", sanitizeDiagnosticsText(it.providerCode, 120) ?: JSONObject.NULL)
            .put("providerType", sanitizeDiagnosticsText(it.providerType, 120) ?: JSONObject.NULL)
            .put("providerMessage", sanitizeDiagnosticsText(it.providerMessage) ?: JSONObject.NULL)
            .put("failureStage", sanitizeDiagnosticsText(it.failureStage, 40) ?: JSONObject.NULL)
            .put("networkFailureKind", sanitizeDiagnosticsText(it.networkFailureKind, 40) ?: JSONObject.NULL)
            .put("bytesReceived", it.bytesReceived ?: JSONObject.NULL)
            .put("responseLimitBytes", it.responseLimitBytes ?: JSONObject.NULL)
            .put("exception", encode(it.exception))
    } ?: JSONObject.NULL

    private fun encode(exception: AgentDiagnosticsException?): Any = exception?.let {
        JSONObject()
            .put("type", sanitizeDiagnosticsText(it.type, 160) ?: "UnknownThrowable")
            .put("message", sanitizeDiagnosticsText(it.message) ?: JSONObject.NULL)
            .put("stack", sanitizeDiagnosticsText(it.stack, 4_096) ?: JSONObject.NULL)
            .put("causes", JSONArray(it.causes.map { cause -> sanitizeDiagnosticsText(cause, 160) }))
    } ?: JSONObject.NULL

    /** First bytes only: correlates runs of one capture without identifying it. */
    private fun shortReference(fingerprint: String): String =
        fingerprint.take(SHORT_REFERENCE_CHARS)

    private fun logFiles(root: File): List<File> = root.listFiles()
        ?.filter { it.isFile && it.name.startsWith(FILE_PREFIX) }
        ?.sortedBy { it.name }
        .orEmpty()

    private fun rotate(root: File, current: File) {
        if (!current.isFile) return
        val rotated = File(root, "$FILE_PREFIX-${clock()}$FILE_SUFFIX")
        if (!current.renameTo(rotated)) current.delete()
    }

    private fun enforceFileCap(root: File) {
        val files = logFiles(root).filter { it.name != ACTIVE_FILE }
        if (files.size <= maxFiles) return
        files.sortedBy { it.lastModified() }
            .take(files.size - maxFiles)
            .forEach { it.delete() }
    }

    /** Mark a previous process-dead run before starting a new one. */
    private fun markAbandonedRuns(root: File) {
        val state = linkedMapOf<String, AbandonedRunState>()
        logFiles(root).flatMap { it.readLines() }.forEach { line ->
            val entry = runCatching { JSONObject(line) }.getOrNull() ?: return@forEach
            if (entry.optString("schema") != EVENT_SCHEMA) return@forEach
            val runId = entry.optString("runId").takeIf { it.isNotBlank() } ?: return@forEach
            val current = state.getOrPut(runId) {
                AbandonedRunState(
                    sessionId = entry.optString("sessionId"),
                    conversationId = entry.optString("conversationId"),
                    maxSequence = 0L,
                    terminal = false,
                    captureRef = entry.optString("captureRef"),
                    modelId = entry.optString("modelId"),
                    promptVersion = entry.optString("promptVersion"),
                    playbookVersion = entry.optString("playbookVersion")
                )
            }
            current.maxSequence = maxOf(current.maxSequence, entry.optLong("sequence", 0L))
            if (entry.optString("eventType") == AgentDiagnosticsEventType.RunFinished.name ||
                entry.optString("eventType") == AgentDiagnosticsEventType.RunAbandoned.name
            ) {
                current.terminal = true
            }
        }
        state.filterValues { it.maxSequence > 0L && !it.terminal }.forEach { (runId, old) ->
            appendJson(
                root,
                JSONObject()
                    .put("schema", EVENT_SCHEMA)
                    .put("schemaVersion", SCHEMA_VERSION)
                    .put("runId", runId)
                    .put("sessionId", old.sessionId)
                    .put("conversationId",
                        old.conversationId.takeIf { it.isNotBlank() } ?: JSONObject.NULL)
                    .put("sequence", old.maxSequence + 1L)
                    .put("timestampMillis", clock())
                    .put("eventType", AgentDiagnosticsEventType.RunAbandoned.name)
                    .put("captureRef", old.captureRef)
                    .put("modelId", old.modelId)
                    .put("promptVersion", old.promptVersion)
                    .put("playbookVersion", old.playbookVersion)
                    .put("status", "abandoned")
                    .put("failure", JSONObject()
                        .put("boundary", "process")
                        .put("reason", "process_restart_before_terminal_event"))
                    .put("attributes", JSONObject())
            )
        }
    }

    private data class AbandonedRunState(
        val sessionId: String,
        val conversationId: String,
        var maxSequence: Long,
        var terminal: Boolean,
        val captureRef: String,
        val modelId: String,
        val promptVersion: String,
        val playbookVersion: String
    )

    companion object {
        const val DIRECTORY_NAME = "agent_logs"
        private const val FILE_PREFIX = "agent-diagnostics"
        private const val FILE_SUFFIX = ".jsonl"
        private const val ACTIVE_FILE = "$FILE_PREFIX$FILE_SUFFIX"
        private const val RUN_SCHEMA = "AgentDiagnosticsRun"
        private const val EVENT_SCHEMA = "AgentDiagnosticsEvent"
        private const val EXPORT_SCHEMA = "AgentDiagnosticsExport"
        private const val SCHEMA_VERSION = 2
        private const val SHORT_REFERENCE_CHARS = 8
        private const val DEFAULT_MAX_FILE_BYTES = 256L * 1024
        private const val DEFAULT_MAX_FILES = 3
        private val NUMERIC_ATTRIBUTE_KEYS = setOf(
            "actualInputTokens",
            "cachedInputTokens",
            "cacheCreationTokens",
            "outputTokens",
            "estimatedInputTokens",
            "estimatorRatio",
            "fallbackContextTokens",
            "maxContextTokens",
            "maxOutputTokens",
            "requestedOutputTokens",
            "responseLimitBytes",
            "bytesReceived",
            // OPT-EVAL-04-01 RunMetrics quality metrics (rate and 0/1 flag).
            "citationRejectionRate",
            "revisionTriggered",
            // OPT-VAL-04-03 polarity double-track counts (integers).
            "negativePolarityDeclared",
            "negativePolarityConflict",
            // OPT-VAL-01-02 playbook check-coverage gap count (integer).
            "planCoverageGaps",
            // OPT-VAL-02-03 baseline signal-coverage gap count (integer).
            "signalCoverageGaps",
            // OPT-VAL-03-01 removed question-alignment entries (integer).
            "alignmentFailures"
        )
        private val EMPTY_EXPORT = JSONObject()
            .put("schema", EXPORT_SCHEMA)
            .put("schemaVersion", SCHEMA_VERSION)
            .put("runs", JSONArray())
            .put("events", JSONArray())
            .toString(2)
    }
}

/** Snapshot-derived context a caller may attach without exposing a handle. */
fun AgentCaptureSnapshot.diagnosticsReference(): String = captureFingerprint.take(8)
