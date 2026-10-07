// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

/**
 * Contracts for the three local Agent stores added by AI-24: saved sessions,
 * the deterministic tool cache and the diagnostics log.
 *
 * Saved sessions retain a complete analysis conversation so that reopening one
 * returns the user to the screen they left, able to ask a follow-up.  That is a
 * deliberate reversal of this file's original rule: the transcript, the model
 * exchanges, tool arguments, tool result payloads and vendor reasoning are all
 * written to disk, unredacted, under `filesDir/agent_sessions`.  A saved file
 * may therefore contain capture-derived identifiers and payload fragments.
 *
 * What still never lands here is credential material: no API key and no gateway
 * token.  Those live in the keystore-backed secret store, and nothing in this
 * file should ever be extended to carry them.
 *
 * The tool cache and diagnostics log below are unchanged — they remain
 * hash-only and sensitivity-tiered.
 */

/** The version written into every saved-session file. */
const val AGENT_SESSION_SCHEMA_VERSION: Int = 6

/**
 * One finished round of a multi-turn conversation and its report.
 *
 * When a follow-up commits a new report, the report that was on screen is
 * archived here rather than overwritten, so every round's conclusion stays
 * reachable.  Ordered oldest first; the newest round is always the session's
 * [AgentSavedSession.report] itself.
 */
data class AgentConversationRound(
    /** The question that produced this round's report. */
    val question: String,
    val report: AgentReport,
    /** When the round reached its terminal outcome. */
    val completedAtMillis: Long = 0L
) {
    /**
     * Content-derived identity for de-duplication across a storage round trip:
     * decoded rounds rebuild the same id, so an archive step can recognise the
     * round it already holds without persisting a separate key field.
     */
    val stableId: String
        get() {
            val payload = listOf(
                question,
                completedAtMillis.toString(),
                report.summary,
                report.findings.joinToString("|") { it.title }
            ).joinToString("\u0000")
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(payload.toByteArray(Charsets.UTF_8))
            return digest.take(12).joinToString("") {
                "%02x".format(java.util.Locale.ROOT, it)
            }
        }
}

/**
 * One tool step retained with a saved session.
 *
 * This is the minimal trajectory the task calls for: enough to tell the user
 * which analysis steps produced the report and whether any of them were
 * truncated, and not enough to reconstruct what was read.
 */
data class AgentSavedToolStep(
    val toolName: String,
    val toolVersion: String = "1",
    val normalizedArgumentsHash: String = "",
    val durationMillis: Long = 0L,
    val returnedCount: Long = 0L,
    val totalCount: Long = 0L,
    val truncated: Boolean = false,
    val errorCode: String? = null,
    val cacheHit: Boolean = false
)

/**
 * A report persisted automatically after an analysis run.
 *
 * [captureFingerprint] is what later decides whether the report may still drive navigation: a restored
 * session whose fingerprint does not match the open capture is read-only,
 * because its frame numbers refer to a file that is no longer loaded.
 *
 * [messages] and [modelInteractions] are what make a saved session resumable.
 * [userQuestion] and [report] remain the *last* turn's question and conclusion
 * so that the list UI and older readers keep working, but the transcript is the
 * authoritative record of the conversation.
 */
data class AgentSavedSession(
    /**
     * Cross-process unique conversation key and the file's primary identity.
     * One conversation covers a first question plus every follow-up and retry.
     */
    val conversationId: String,
    val captureFingerprint: String,
    val userQuestion: String,
    val report: AgentReport,
    val modelId: String = "",
    val promptVersion: String = "",
    val playbookVersion: String? = null,
    val analysisConfigVersion: Int = 1,
    val analysisScope: AnalysisScope = AnalysisScope.CompleteFile,
    val displayFilter: String = "",
    val toolSteps: List<AgentSavedToolStep> = emptyList(),
    val savedAtMillis: Long = 0L,
    /** Legacy recovery marker retained only for compatibility with older files. */
    val autoSaved: Boolean = false,
    val schemaVersion: Int = AGENT_SESSION_SCHEMA_VERSION,
    /** Display name of the capture at save time; shown in the saved list. */
    val captureDisplayName: String = "",
    /**
     * The visible transcript, in order.  Empty for a session written before
     * schema 3, which is what [isResumable] detects.
     */
    val messages: List<AgentConversationItem> = emptyList(),
    /** Full model exchanges backing the transcript's tool and detail views. */
    val modelInteractions: List<AgentModelInteraction> = emptyList(),
    /** Tool activity rows, so a resumed run shows the steps it already ran. */
    val toolActivities: List<AgentToolActivity> = emptyList(),
    /** The plan declared for the last turn, redisplayed on resume. */
    val analysisPlan: AgentAnalysisPlan? = null,
    /** Plan steps completed, kept in step with [analysisPlan]. */
    val completedPlanSteps: Int = 0,
    /** Tool steps completed across the conversation. */
    val completedSteps: Int = 0,
    /** The privacy mode the conversation ran under; a follow-up must match it. */
    val privacyMode: AgentPrivacyMode = AgentPrivacyMode.RedactedMetadata,
    /** Provider totals for the last turn, redisplayed on resume. */
    val tokenUsage: AgentTokenUsage? = null,
    /**
     * The capture session generation this conversation was framed against.
     *
     * Restored alongside [captureFingerprint] so a resumed follow-up applies the
     * same "did the capture change underneath us" rule as a live one.
     */
    val sessionGeneration: Long = 0L,
    /**
     * The `sessionId` this record had before schema 4, kept for forensics and
     * for [AgentSessionStore.load] fallback lookups.  Null for records written
     * by schema 4 or later.  Never used as a new file's key.
     */
    val legacySessionId: String? = null,
    /** The most recent run that contributed to this conversation. */
    val latestRunId: String = "",
    /** Every run that contributed, oldest first. Empty for migrated records. */
    val runIds: List<String> = emptyList(),
    /** When this conversation was first saved. */
    val createdAtMillis: Long = 0L,
    /** When this conversation was last saved; [savedAtMillis] mirrors it. */
    val updatedAtMillis: Long = 0L,
    /**
     * Sanitized (export-sanitized) model transcript of prior rounds, appended
     * per round.  Empty = not replayable (v4 and earlier files); follow-ups
     * automatically degrade to the summary path.
     */
    val conversationTranscript: List<AgentModelMessage> = emptyList(),
    /**
     * Reports of rounds *before* the one [report] belongs to, oldest first.
     * Empty for v5 and earlier files.  The current report is deliberately not
     * duplicated here; it stays the session's single authoritative conclusion.
     */
    val rounds: List<AgentConversationRound> = emptyList()
) {
    /** True when this report's evidence may be opened against [fingerprint]. */
    fun matchesCapture(fingerprint: String): Boolean =
        fingerprint.isNotBlank() && fingerprint == captureFingerprint

    /**
     * Whether reopening this session can restore a conversation rather than
     * just a report.  Sessions written before schema 3 have no transcript, so
     * they stay view-only however new the reader is.
     */
    val isResumable: Boolean
        get() = messages.isNotEmpty()

    val findingCount: Int
        get() = report.findings.size

    val evidenceCount: Int
        get() = report.findings.sumOf { it.evidence.size }
}

/**
 * A saved session as the list UI sees it, without decoding the whole report.
 *
 * The Agent page lists potentially dozens of saved analyses; reading only the
 * header keeps that list cheap and keeps a malformed report body from breaking
 * the row that would let the user delete it.
 */
data class AgentSavedSessionSummary(
    val conversationId: String,
    val captureFingerprint: String,
    val captureDisplayName: String,
    val userQuestion: String,
    val summary: String,
    val findingCount: Int,
    val savedAtMillis: Long,
    val sizeBytes: Long,
    val modelId: String = "",
    /** Legacy recovery marker retained only for compatibility with older files. */
    val autoSaved: Boolean = false,
    /** Turns in the saved transcript; 0 for a pre-schema-3 session. */
    val messageCount: Int = 0,
    /** True when opening this row restores a conversation rather than a report. */
    val isResumable: Boolean = false
)

/**
 * Whether a cached tool result may be written to disk.
 *
 * The mapping is the security rule of AI-24 section 3 expressed as a type:
 * Aggregate/Metadata may persist, Identifier is memory-only until an encrypted
 * store passes product review, and Payload/Credential are never cached at all.
 */
enum class AgentCacheTier {
    /** Written to the on-disk cache and reused across app restarts. */
    Disk,

    /** Kept only for the lifetime of the process. */
    MemoryOnly,

    /** Never stored, in memory or on disk. */
    Never;

    companion object {
        fun of(sensitivity: AgentDataSensitivity): AgentCacheTier = when (sensitivity) {
            AgentDataSensitivity.Aggregate,
            AgentDataSensitivity.Metadata -> Disk

            AgentDataSensitivity.Identifier -> MemoryOnly

            // Payload and Credential never reach a cache.  Unknown joins them:
            // a sensitivity the host does not recognise is treated as the most
            // sensitive one rather than as harmless aggregate data.
            AgentDataSensitivity.Payload,
            AgentDataSensitivity.Credential,
            AgentDataSensitivity.Unknown -> Never
        }
    }
}

/**
 * Every component of the deterministic cache key, per AI-24 section 3.
 *
 * The key is a data class rather than a pre-joined string so that adding a
 * component is a compile error at each construction site instead of a silently
 * weaker key.  [analysisConfigVersion] carries the dissection-affecting
 * configuration — Decode As rules and name resolution — so changing either one
 * invalidates every entry without the cache needing to know what changed.
 */
data class AgentToolCacheKey(
    val captureFingerprint: String,
    val analysisConfigVersion: Int,
    val toolName: String,
    val normalizedArgumentsHash: String,
    val nativeBuildMarker: String,
    val toolVersion: String,
    /**
     * The run's analysis scope and applied display filter.
     *
     * Not in the task's five-part list, but required for correctness: a tool
     * reads through the snapshot's scope, so get_statistics over the whole file
     * and the same call under a `sip` filter are different questions with
     * identical arguments.  Section 4's rule - anything that changes analysis
     * facts must invalidate - is what puts it in the key.
     */
    val scopeKey: String = ""
) {
    /**
     * Stable storage identity.  Components are joined with a separator that
     * cannot appear in a hex hash or an enum name, so two different keys can
     * never concatenate into the same string.
     */
    fun canonical(): String = listOf(
        captureFingerprint,
        analysisConfigVersion.toString(),
        toolName,
        normalizedArgumentsHash,
        nativeBuildMarker,
        toolVersion,
        scopeKey
    ).joinToString(separator = SEPARATOR)

    private companion object {
        /** A newline cannot occur in a hex hash, a tool name or an enum name. */
        const val SEPARATOR = "\n"
    }
}

/**
 * A cached tool result together with everything needed to replay it faithfully.
 *
 * A cache hit must produce the same [AgentToolResult] semantics as a fresh run,
 * so truncation, counts and the declared sensitivity are stored beside the
 * data.  Provenance is deliberately *not* stored: a hit re-derives it from the
 * live snapshot, because the fingerprint, scope and filter of the run using the
 * entry are what the report must cite, not those of the run that filled it.
 */
data class AgentCachedToolResult(
    val key: AgentToolCacheKey,
    val data: AgentJsonObject,
    val sensitivity: AgentDataSensitivity,
    val returnedCount: Long,
    val totalCount: Long,
    val truncated: Boolean,
    val queryMode: String? = null,
    val createdAtMillis: Long = 0L,
    val sizeBytes: Int = 0,
    /** Duration of the original execution, kept for diagnostics only. */
    val originalDurationMillis: Long = 0L
)

/** Local disk usage and last-cleanup time shown by the settings screen. */
data class AgentLocalDataUsage(
    val savedSessionCount: Int = 0,
    val savedSessionBytes: Long = 0L,
    val cacheEntryCount: Int = 0,
    val cacheBytes: Long = 0L,
    val diagnosticsBytes: Long = 0L,
    val lastClearedAtMillis: Long? = null
) {
    val totalBytes: Long
        get() = savedSessionBytes + cacheBytes + diagnosticsBytes

    val isEmpty: Boolean
        get() = savedSessionCount == 0 && cacheEntryCount == 0 && diagnosticsBytes == 0L
}

/** Which local Agent data a clear action should remove. */
enum class AgentLocalDataCategory {
    SavedSessions,
    Cache,
    Diagnostics
}
