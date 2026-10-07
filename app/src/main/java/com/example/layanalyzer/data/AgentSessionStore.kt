package com.example.layanalyzer.data

import android.content.Context
import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.ai.serialization.AgentConversationCodec
import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.model.AGENT_SESSION_SCHEMA_VERSION
import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRound
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentSavedSession
import com.example.layanalyzer.model.AgentSavedSessionSummary
import com.example.layanalyzer.model.AgentSavedToolStep
import com.example.layanalyzer.model.AgentTokenUsage
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AnalysisScope
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale
import java.util.UUID
import java.security.MessageDigest

/**
 * Automatic local persistence for Agent analyses, including the conversation itself.
 *
 * A saved session holds the whole analysis: the validated report, the visible
 * transcript, and the model exchanges behind it — tool arguments, tool result
 * payloads and vendor reasoning included, unredacted.  That is what lets the
 * user reopen an analysis and carry on asking questions instead of reading a
 * summary of what they asked yesterday.  Nothing here is encrypted, so a saved
 * file may expose capture-derived identifiers to anything with access to app
 * storage.  Credentials are the one exception and are never written here.
 *
 * Each conversation is its own file under `filesDir/agent_sessions`, named by a
 * hash of the cross-process `conversationId`.  One file per conversation is
 * what makes the malformed-file requirement cheap to honour: a corrupt entry
 * is skipped and can still be deleted, while every other saved analysis stays
 * readable.  A single combined index would lose them all.
 *
 * Records written before schema 4 are migrated lazily on read: each legacy
 * record becomes exactly one conversation under a *derived* id, keeping its
 * `legacySessionId` for forensics.  Migration writes the new file first and
 * only deletes the legacy file after the rename has succeeded, so a crash can
 * never lose a saved analysis.
 */
class AgentSessionStore(
    private val directory: File,
    private val clock: () -> Long = { System.currentTimeMillis() },
    /** Newest-first cap; an older session is dropped once this is exceeded. */
    private val maxSessions: Int = DEFAULT_MAX_SESSIONS
) {
    constructor(
        context: Context,
        clock: () -> Long = { System.currentTimeMillis() }
    ) : this(File(context.applicationContext.filesDir, DIRECTORY_NAME), clock)

    /**
     * Serialises reads that may migrate against writes and clears.  Without it
     * a `listForCapture` racing a `clear` could resurrect a file the user just
     * deleted, or two concurrent reads could both attempt the same migration.
     */
    private val guard = Any()

    /** The exact directory a clear action is allowed to remove. */
    val storageDirectory: File
        get() = directory

    /**
     * Persist [session], replacing any earlier save with the same conversation.
     *
     * The write goes to a temporary file in the same directory and is then
     * renamed over the target, so a process death mid-write leaves either the
     * previous file or the new one — never a half-written session that would
     * fail to decode on the next launch.
     */
    fun save(session: AgentSavedSession): Result<AgentSavedSession> = runCatching {
        require(session.conversationId.isNotBlank()) { "A saved session needs a conversation id." }
        require(session.captureFingerprint.isNotBlank()) {
            "A saved session needs the fingerprint of the capture it describes."
        }
        if (!directory.isDirectory) {
            check(directory.mkdirs()) { "Unable to create the Agent session directory." }
        }

        val stamped = session.copy(
            savedAtMillis = session.savedAtMillis.takeIf { it > 0L } ?: clock(),
            schemaVersion = AGENT_SESSION_SCHEMA_VERSION
        )
        val encoded = encode(stamped).toString()
        check(encoded.toByteArray(Charsets.UTF_8).size <= MAX_SESSION_BYTES) {
            "Session too large"
        }
        synchronized(guard) {
            writeJsonAtomically(fileFor(stamped.conversationId), encoded, TEMP_SUFFIX)
            enforceSessionCap()
        }
        stamped
    }

    /** Convenience overload that assembles a session from what a run produced. */
    fun save(
        report: AgentReport,
        userQuestion: String,
        runRecord: AgentRunRecord?,
        captureFingerprint: String,
        conversationId: String,
        captureDisplayName: String = "",
        analysisConfigVersion: Int = 1,
        cacheHits: Set<String> = emptySet(),
        autoSaved: Boolean = false,
        messages: List<AgentConversationItem> = emptyList(),
        modelInteractions: List<AgentModelInteraction> = emptyList(),
        toolActivities: List<AgentToolActivity> = emptyList(),
        analysisPlan: AgentAnalysisPlan? = null,
        completedPlanSteps: Int = 0,
        completedSteps: Int = 0,
        privacyMode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata,
        tokenUsage: AgentTokenUsage? = null,
        sessionGeneration: Long = 0L,
        latestRunId: String = "",
        runIds: List<String> = emptyList(),
        createdAtMillis: Long = 0L,
        conversationTranscript: List<AgentModelMessage> = emptyList(),
        rounds: List<AgentConversationRound> = emptyList()
    ): Result<AgentSavedSession> {
        val now = clock()
        return save(
            AgentSavedSession(
                conversationId = conversationId,
                captureFingerprint = captureFingerprint,
                captureDisplayName = captureDisplayName,
                userQuestion = userQuestion,
                report = report,
                modelId = report.provenance.modelId.ifBlank { runRecord?.modelId.orEmpty() },
                promptVersion = report.provenance.promptVersion
                    .ifBlank { runRecord?.promptVersion.orEmpty() },
                playbookVersion = report.provenance.playbookVersion ?: runRecord?.playbookVersion,
                analysisConfigVersion = analysisConfigVersion,
                analysisScope = report.provenance.scope,
                displayFilter = report.provenance.displayFilter,
                toolSteps = runRecord?.toolCalls.orEmpty().map { call ->
                    AgentSavedToolStep(
                        toolName = call.toolName,
                        normalizedArgumentsHash = call.normalizedArgumentsHash,
                        durationMillis = call.durationMillis,
                        returnedCount = call.returned,
                        totalCount = call.total,
                        truncated = call.truncated,
                        errorCode = call.errorCode?.name,
                        cacheHit = call.normalizedArgumentsHash in cacheHits
                    )
                },
                savedAtMillis = now,
                autoSaved = autoSaved,
                messages = messages,
                modelInteractions = modelInteractions,
                toolActivities = toolActivities,
                analysisPlan = analysisPlan,
                completedPlanSteps = completedPlanSteps,
                completedSteps = completedSteps,
                privacyMode = privacyMode,
                tokenUsage = tokenUsage,
                sessionGeneration = sessionGeneration,
                latestRunId = latestRunId,
                runIds = runIds,
                createdAtMillis = createdAtMillis.takeIf { it > 0L } ?: now,
                updatedAtMillis = now,
                conversationTranscript = conversationTranscript,
                rounds = rounds
            )
        )
    }

    /**
     * Only the conversations that belong to [captureFingerprint], newest first.
     *
     * A blank fingerprint returns nothing: without an open capture there is no
     * "current" history to show.  Matching is exact equality, and because the
     * fingerprint is a content hash, the same file reopened from a different
     * path still finds its history.
     */
    fun listForCapture(captureFingerprint: String): List<AgentSavedSessionSummary> {
        if (captureFingerprint.isBlank()) return emptyList()
        return listAll().filter { it.captureFingerprint == captureFingerprint }
    }

    /**
     * Every readable saved session, newest first.
     *
     * A file that fails to decode is skipped rather than propagated: one
     * corrupt session must not hide the rest, and the user still needs the list
     * in order to clear it.  Decoding may lazily migrate a legacy record, but a
     * read never runs the session cap: a list refresh must not delete data.
     */
    fun listAll(): List<AgentSavedSessionSummary> =
        synchronized(guard) {
            // Migrate first: a migrated file and its not-yet-deleted legacy
            // duplicate must collapse to one row before summarising, otherwise
            // a crash in the migration window would list one conversation twice.
            val sessions = sessionFiles().mapNotNull { file -> decodeAndMigrate(file) }
            sessions
                .distinctBy { it.conversationId }
                .map { session ->
                    AgentSavedSessionSummary(
                        conversationId = session.conversationId,
                        captureFingerprint = session.captureFingerprint,
                        captureDisplayName = session.captureDisplayName,
                        userQuestion = session.userQuestion,
                        summary = session.report.summary,
                        findingCount = session.findingCount,
                        savedAtMillis = session.savedAtMillis,
                        sizeBytes = fileFor(session.conversationId).length(),
                        modelId = session.modelId,
                        autoSaved = session.autoSaved,
                        messageCount = session.messages.size,
                        isResumable = session.isResumable
                    )
                }
                .sortedByDescending { it.savedAtMillis }
        }

    /** Number of saved conversations belonging to [captureFingerprint]. */
    fun countForCapture(captureFingerprint: String): Int =
        listForCapture(captureFingerprint).size

    /** On-disk bytes of the saved conversations belonging to [captureFingerprint]. */
    fun bytesForCapture(captureFingerprint: String): Long =
        listForCapture(captureFingerprint).sumOf { it.sizeBytes }

    fun load(conversationId: String): AgentSavedSession? {
        if (conversationId.isBlank()) return null
        return synchronized(guard) {
            decodeAndMigrate(fileFor(conversationId))
                // A record migrated before this process saw it lives under its
                // derived conversation id; fall back to a legacy-id scan so a
                // caller holding only the old id can still reach it.
                ?: sessionFiles().firstNotNullOfOrNull { file ->
                    decodeAndMigrate(file)?.takeIf { it.legacySessionId == conversationId }
                }
        }
    }

    fun delete(conversationId: String): Boolean {
        if (conversationId.isBlank()) return false
        return synchronized(guard) {
            val existing = load(conversationId)
            if (existing != null) {
                // Delete every file that can hold this conversation: the hashed
                // name of the (possibly derived) conversation id, the hashed
                // name of the legacy id it was migrated from, and the raw name
                // the caller passed in.
                buildSet {
                    add(fileFor(existing.conversationId))
                    existing.legacySessionId?.let { add(fileFor(it)) }
                    add(fileFor(conversationId))
                }.fold(false) { removed, file -> file.delete() || removed }
            } else {
                fileFor(conversationId).delete()
            }
        }
    }

    /**
     * Remove every saved session.
     *
     * Only files this store owns are deleted, and only from its own directory:
     * a stray file dropped in by something else is left alone rather than being
     * swept up by a recursive delete.  Legacy (pre-migration) files share the
     * same suffix, so a partial migration cannot leave orphans behind.
     */
    fun clear(): Int = synchronized(guard) {
        var removed = 0
        directory.listFiles()
            ?.filter { it.isFile && (it.name.endsWith(FILE_SUFFIX) || it.name.endsWith(TEMP_SUFFIX)) }
            ?.forEach { if (it.delete()) removed += 1 }
        removed
    }

    fun totalBytes(): Long = synchronized(guard) { sessionFiles().sumOf { it.length() } }

    fun count(): Int = synchronized(guard) { sessionFiles().size }

    // ------------------------------------------------------------------ codec

    private fun sessionFiles(): List<File> = directory.listFiles()
        ?.filter { it.isFile && it.name.endsWith(FILE_SUFFIX) }
        .orEmpty()

    /**
     * File name is a hash of the conversation id rather than the id itself, so
     * a hostile or merely awkward id can never escape the directory or collide
     * with the temporary-file suffix.
     */
    private fun fileFor(conversationId: String): File {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(conversationId.toByteArray(Charsets.UTF_8))
        val name = digest.take(16).joinToString(separator = "") { byte ->
            "%02x".format(Locale.ROOT, byte)
        }
        return File(directory, "$name$FILE_SUFFIX")
    }

    /**
     * Decode [file], migrating a pre-schema-4 record in place when found.
     *
     * Migration is idempotent: the new conversation id is *derived* from the
     * legacy content rather than random, so a repeated read, a crash between
     * the write and the delete, or a `load` racing a `list` all converge on
     * the same target.  The new file is written before the old one is deleted;
     * if the rename failed the legacy file is left untouched and simply
     * decoded again next time.
     */
    private fun decodeAndMigrate(file: File): AgentSavedSession? {
        if (!file.isFile) return null
        val raw = runCatching { decode(JSONObject(file.readText())) }.getOrNull() ?: return null
        if (raw.conversationId.isNotBlank()) return raw

        val legacyId = raw.legacySessionId ?: return null
        val derivedId = "conv_" + UUID.nameUUIDFromBytes(
            "legacy:$legacyId:${raw.captureFingerprint}:${raw.savedAtMillis}"
                .toByteArray(Charsets.UTF_8)
        )
        val migrated = raw.copy(
            conversationId = derivedId,
            createdAtMillis = raw.savedAtMillis,
            updatedAtMillis = raw.savedAtMillis,
            schemaVersion = AGENT_SESSION_SCHEMA_VERSION
        )
        val target = fileFor(derivedId)
        if (target.isFile) {
            // A previous migration wrote the new file but died before deleting
            // the legacy one.  Finish the job; never overwrite a different
            // conversation that happens to share the name.
            val existing = runCatching {
                decode(JSONObject(target.readText()))
            }.getOrNull()
            if (existing?.legacySessionId == legacyId) {
                file.delete()
                return existing
            }
            return raw
        }
        return runCatching {
            writeJsonAtomically(target, encode(migrated).toString(), TEMP_SUFFIX)
            // The cap evicts by lastModified; keep the migrated file's age so
            // an old record is not suddenly treated as the newest.
            target.setLastModified(migrated.savedAtMillis.takeIf { it > 0L } ?: clock())
            if (!file.delete()) {
                // The legacy file surviving is safe: the next read finds the
                // migrated target first and finishes the deletion above.
            }
            migrated
        }.getOrElse { raw }
    }

    private fun encode(session: AgentSavedSession): JSONObject = JSONObject()
        .put("schema", SCHEMA_NAME)
        .put("schemaVersion", AGENT_SESSION_SCHEMA_VERSION)
        .put("conversationId", session.conversationId)
        .put("legacySessionId", session.legacySessionId ?: JSONObject.NULL)
        .put("latestRunId", session.latestRunId)
        .put("runIds", JSONArray().apply { session.runIds.forEach { put(it) } })
        .put("createdAtMillis", session.createdAtMillis)
        .put("updatedAtMillis", session.updatedAtMillis)
        .put("captureFingerprint", session.captureFingerprint)
        .put("captureDisplayName", session.captureDisplayName)
        .put("userQuestion", session.userQuestion)
        .put("report", JSONObject(AgentJsonCodec.encodeReport(session.report)))
        .put("modelId", session.modelId)
        .put("promptVersion", session.promptVersion)
        .put("playbookVersion", session.playbookVersion ?: JSONObject.NULL)
        .put("analysisConfigVersion", session.analysisConfigVersion)
        .put("analysisScope", session.analysisScope.name)
        .put("displayFilter", session.displayFilter)
        .put("savedAtMillis", session.savedAtMillis)
        .put("autoSaved", session.autoSaved)
        .put("toolSteps", JSONArray().apply {
            session.toolSteps.forEach { step ->
                put(
                    JSONObject()
                        .put("toolName", step.toolName)
                        .put("toolVersion", step.toolVersion)
                        .put("normalizedArgumentsHash", step.normalizedArgumentsHash)
                        .put("durationMillis", step.durationMillis)
                        .put("returnedCount", step.returnedCount)
                        .put("totalCount", step.totalCount)
                        .put("truncated", step.truncated)
                        .put("errorCode", step.errorCode ?: JSONObject.NULL)
                        .put("cacheHit", step.cacheHit)
                )
            }
        })
        // Schema 3: everything needed to put the user back in the conversation.
        .put("messages", AgentConversationCodec.conversationToArray(session.messages))
        .put(
            "modelInteractions",
            AgentConversationCodec.interactionsToArray(session.modelInteractions)
        )
        .put("toolActivities", AgentConversationCodec.activitiesToArray(session.toolActivities))
        .put("completedSteps", session.completedSteps)
        .put("completedPlanSteps", session.completedPlanSteps)
        .put("privacyMode", session.privacyMode.name)
        .put("sessionGeneration", session.sessionGeneration)
        .apply {
            session.analysisPlan?.let { put("analysisPlan", AgentConversationCodec.planToObject(it)) }
            session.tokenUsage?.let { put("tokenUsage", AgentConversationCodec.usageToObject(it)) }
        }
        // Schema 5: the sanitized prior-rounds transcript, so a follow-up after
        // a process restart replays the full history instead of a summary.
        .put(
            "conversationTranscript",
            AgentConversationCodec.messagesToArray(session.conversationTranscript)
        )
        // Schema 6: the reports of rounds before the current one, so a reopened
        // conversation still shows every round's conclusion.
        .put("rounds", AgentConversationCodec.roundsToArray(session.rounds))

    /**
     * Decode one stored session.
     *
     * Unknown fields are ignored so a file written by a newer minor build still
     * loads, but a higher [AGENT_SESSION_SCHEMA_VERSION] is rejected: a future
     * format may carry different privacy semantics, and guessing at them is
     * exactly the mistake versioning exists to prevent.  A missing version is
     * treated as version 1, which is what pre-versioned local data would be.
     *
     * A record whose `conversationId` is blank is a legacy (pre-schema-4) file:
     * it decodes with an empty conversation id and its old `sessionId` moved to
     * `legacySessionId`, and [decodeAndMigrate] rewrites it on first read.
     */
    private fun decode(json: JSONObject): AgentSavedSession {
        val version = when (val raw = json.opt("schemaVersion")) {
            null, JSONObject.NULL -> 1
            is Number -> raw.toInt()
            is String -> raw.toIntOrNull() ?: throw IllegalArgumentException("Bad schema version.")
            else -> throw IllegalArgumentException("Bad schema version.")
        }
        require(version in 1..AGENT_SESSION_SCHEMA_VERSION) {
            "Unsupported saved-session schema version."
        }
        val schema = json.optString("schema").takeIf { it.isNotBlank() }
        require(schema == null || schema == SCHEMA_NAME) { "Unexpected saved-session schema." }

        // Schema 4 names the key conversationId; schema 1-3 called it sessionId.
        val conversationId = json.optString("conversationId").takeIf { it.isNotBlank() } ?: ""
        val legacySessionId = json.optString("legacySessionId").takeIf { it.isNotBlank() }
            ?: json.optString("sessionId").takeIf { it.isNotBlank() }
        if (conversationId.isBlank() && legacySessionId.isNullOrBlank()) {
            throw IllegalArgumentException("A saved session needs an id.")
        }
        val fingerprint = json.optString("captureFingerprint").takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("A saved session needs a capture fingerprint.")
        val report = AgentJsonCodec
            .decodeReport(json.getJSONObject("report").toString())
            .getOrNull()
            ?: throw IllegalArgumentException("The saved report could not be read.")

        return AgentSavedSession(
            conversationId = conversationId,
            captureFingerprint = fingerprint,
            captureDisplayName = json.optString("captureDisplayName"),
            userQuestion = json.optString("userQuestion"),
            report = report,
            modelId = json.optString("modelId"),
            promptVersion = json.optString("promptVersion"),
            playbookVersion = json.optString("playbookVersion").takeIf { it.isNotBlank() },
            analysisConfigVersion = json.optInt("analysisConfigVersion", 1),
            analysisScope = json.optString("analysisScope")
                .let { raw -> AnalysisScope.entries.firstOrNull { it.name == raw } }
                ?: AnalysisScope.CompleteFile,
            displayFilter = json.optString("displayFilter"),
            toolSteps = json.optJSONArray("toolSteps").let { array ->
                if (array == null) emptyList() else (0 until array.length()).mapNotNull { index ->
                    val item = array.optJSONObject(index) ?: return@mapNotNull null
                    AgentSavedToolStep(
                        toolName = item.optString("toolName"),
                        toolVersion = item.optString("toolVersion").ifBlank { "1" },
                        normalizedArgumentsHash = item.optString("normalizedArgumentsHash"),
                        durationMillis = item.optLong("durationMillis"),
                        returnedCount = item.optLong("returnedCount"),
                        totalCount = item.optLong("totalCount"),
                        truncated = item.optBoolean("truncated", false),
                        errorCode = item.optString("errorCode").takeIf { it.isNotBlank() },
                        cacheHit = item.optBoolean("cacheHit", false)
                    )
                }
            },
            savedAtMillis = json.optLong("savedAtMillis"),
            autoSaved = json.optBoolean("autoSaved", false),
            schemaVersion = version,
            // Absent in schema 1 and 2; such a session decodes to an empty
            // transcript and is offered as a read-only report, not a resume.
            messages = AgentConversationCodec.conversationFromArray(
                json.optJSONArray("messages")
            ),
            modelInteractions = AgentConversationCodec.interactionsFromArray(
                json.optJSONArray("modelInteractions")
            ),
            toolActivities = AgentConversationCodec.activitiesFromArray(
                json.optJSONArray("toolActivities")
            ),
            analysisPlan = json.optJSONObject("analysisPlan")
                ?.let { AgentConversationCodec.planFromObject(it) },
            completedPlanSteps = json.optInt("completedPlanSteps", 0),
            completedSteps = json.optInt("completedSteps", 0),
            privacyMode = json.optString("privacyMode")
                .let { raw -> AgentPrivacyMode.entries.firstOrNull { it.name == raw } }
                ?: AgentPrivacyMode.RedactedMetadata,
            tokenUsage = json.optJSONObject("tokenUsage")
                ?.let { AgentConversationCodec.usageFromObject(it) },
            sessionGeneration = json.optLong("sessionGeneration"),
            legacySessionId = legacySessionId,
            latestRunId = json.optString("latestRunId"),
            runIds = json.optJSONArray("runIds").let { array ->
                if (array == null) emptyList() else (0 until array.length()).map { array.getString(it) }
            },
            createdAtMillis = json.optLong("createdAtMillis"),
            updatedAtMillis = json.optLong("updatedAtMillis"),
            // Absent in schema 4 and earlier; such a session has no replayable
            // history and follow-ups degrade to the prior-context summary path.
            conversationTranscript = AgentConversationCodec.messagesFromArray(
                json.optJSONArray("conversationTranscript")
            ),
            // Absent in schema 5 and earlier; such a session has no per-round
            // report history and shows only its final report.
            rounds = AgentConversationCodec.roundsFromArray(
                json.optJSONArray("rounds")
            )
        )
    }

    private fun enforceSessionCap() {
        val files = sessionFiles()
        if (files.size <= maxSessions) return
        files.sortedBy { it.lastModified() }
            .take(files.size - maxSessions)
            .forEach { it.delete() }
    }

    companion object {
        const val DIRECTORY_NAME = "agent_sessions"
        private const val SCHEMA_NAME = "AgentSavedSession"
        private const val FILE_SUFFIX = ".json"
        private const val TEMP_SUFFIX = ".tmp"
        private const val DEFAULT_MAX_SESSIONS = 100

        /**
         * Per-session ceiling.
         *
         * Generous because a saved session now carries every model request, and
         * each request repeats the whole conversation so far including full tool
         * results — growth is quadratic in turns, and a long analysis of a large
         * capture runs to megabytes.  The old 512 KiB limit would have silently
         * failed to save exactly the long conversations worth keeping.  This is
         * still a bound rather than no limit at all, so one runaway session
         * cannot fill the device.
         */
        private const val MAX_SESSION_BYTES = 32 * 1024 * 1024
    }
}
