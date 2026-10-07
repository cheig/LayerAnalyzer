// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.privacy

import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentPrivacyMode

/**
 * The enforcement point for AI-11.
 *
 * Two things pass through here on their way out of the device: tool results, via
 * [redactIfNeeded], and model-authored report prose, via [sanitizeReportText].
 * Both are called from code the model cannot influence — the tool runner and the
 * report validator — because a privacy rule a model could decline to follow is
 * not a rule.  Nothing in this object reads a prompt, a tool argument or a
 * capture field to decide what to do.
 */
object AgentPrivacyPolicy {

    /**
     * Whether results at [sensitivity] must be redacted under [privacyMode].
     *
     * Nothing leaves the device in [AgentPrivacyMode.LocalOnly], so processing
     * there would only obscure the user's own evidence. Every remote-capable
     * mode still walks the result. [AgentPrivacyMode.UnredactedMetadata] keeps
     * metadata and identifiers unchanged while the redactor continues to block
     * payload and credential fields. [AgentPrivacyMode.Unknown] remains the
     * strictest cloud mode so a future value cannot silently open a hole.
     *
     * [sensitivity] deliberately does not gate this.  A tool declaring
     * `Aggregate` is stating an intent, and AI-11 section 2 requires that a
     * mislabelled result still be judged field by field, so every cloud-bound
     * result is walked and the field table decides what actually changes.
     */
    @Suppress("UNUSED_PARAMETER")
    fun shouldRedact(
        sensitivity: AgentDataSensitivity,
        privacyMode: AgentPrivacyMode
    ): Boolean = privacyMode != AgentPrivacyMode.LocalOnly

    /**
     * Redact one tool result for [privacyMode], reusing the run's alias map.
     *
     * Returns [data] unchanged when the mode is local-only. Unredacted metadata
     * still passes through the structural payload and credential guards.
     */
    fun redactIfNeeded(
        data: AgentJsonObject,
        sensitivity: AgentDataSensitivity,
        privacyMode: AgentPrivacyMode,
        snapshot: AgentCaptureSnapshot,
        redactor: AgentPayloadRedactor = AgentPayloadRedactor.of(privacyMode, snapshot)
    ): AgentJsonObject {
        if (!shouldRedact(sensitivity, privacyMode)) return data
        return redactor.redact(data, sensitivity)
    }

    /**
     * Strip anything from model-authored text that a renderer could turn into an
     * executable action.
     *
     * The threat is indirect: capture text is attacker-controlled, a model may
     * repeat it, and a Markdown renderer will happily make `[tap
     * here](intent://…)` tappable.  AI-11 allows exactly two things to become
     * clickable — a frame number and a display filter the host validated — so
     * everything else is reduced to inert text here rather than filtered in the
     * UI, where a second renderer would have to remember to do it again.
     *
     * This changes prose only.  Structured evidence fields keep their own
     * validation paths, so a display filter is never mangled by this function.
     */
    fun sanitizeReportText(text: String): String {
        if (text.isEmpty()) return text
        var result = text

        // Fenced code blocks first: a shell fence's contents would otherwise be
        // scanned line-by-line by the rules below and partially survive.
        result = FENCED_BLOCK.replace(result) { match ->
            val body = match.groupValues[2].trim()
            if (body.isEmpty()) "" else "$CODE_PREFIX${body.replace(Regex("\\s+"), " ")}"
        }

        // A Markdown link keeps its label and loses its target entirely, so
        // there is nothing left for a renderer to navigate to.
        result = MARKDOWN_LINK.replace(result) { match ->
            match.groupValues[1].ifBlank { LINK_REMOVED }
        }
        result = MARKDOWN_IMAGE.replace(result) { match ->
            match.groupValues[1].ifBlank { LINK_REMOVED }
        }

        result = DANGEROUS_URI.replace(result, BLOCKED_URI)
        result = LOCAL_PATH.replace(result, BLOCKED_PATH)
        result = WINDOWS_PATH.replace(result, BLOCKED_PATH)

        return result
    }

    /** Apply [sanitizeReportText] to a value only when it is prose. */
    fun sanitizeReportValue(value: String?): String? = value?.let(::sanitizeReportText)

    /** Marker left where a link target was removed. */
    const val LINK_REMOVED = "[link removed]"

    /** Marker left in place of a scheme a renderer could act on. */
    const val BLOCKED_URI = "[blocked-uri]"

    /** Marker left in place of a local filesystem path. */
    const val BLOCKED_PATH = "[blocked-path]"

    /** Prefix marking text that arrived as a code fence and was flattened. */
    private const val CODE_PREFIX = "code: "

    /**
     * Schemes a renderer or the OS could act on.
     *
     * Three families are deliberately absent.  `http`/`https` are inert as plain
     * text and blanking them would make a report about web traffic unreadable.
     * `sip`/`sips`/`tel` are this app's own domain vocabulary — an IMS report is
     * largely made of them, they arrive here already replaced by
     * [AgentPayloadRedactor] with aliases pointing at reserved ranges, and
     * blanking them would erase the very identities the analysis is about.
     *
     * In every case the rule is the same: this function guarantees the text
     * carries no actionable *target*, and the UI remains responsible for
     * linkifying nothing but frame numbers and validated display filters.
     */
    private val DANGEROUS_URI = Regex(
        "(?i)\\b(intent|android-app|file|content|javascript|vbscript|data|adb|jar|smb|market)" +
            ":(//)?[^\\s)\\]\"'<>]*"
    )

    /** `[label](target)` — the label survives, the target does not. */
    private val MARKDOWN_LINK = Regex("\\[([^\\]]*)]\\(([^)]*)\\)")

    /** `![alt](src)` — same treatment; an image src is a network call. */
    private val MARKDOWN_IMAGE = Regex("!\\[([^\\]]*)]\\(([^)]*)\\)")

    /** A fenced block, with its optional language tag. */
    private val FENCED_BLOCK = Regex("```([A-Za-z0-9_+-]*)\\s*\\n?([\\s\\S]*?)```")

    /** Android and Unix locations that identify the device's own storage. */
    private val LOCAL_PATH = Regex(
        "(?i)(?<![A-Za-z0-9])/(?:data|sdcard|storage|system|proc|root|home|var|etc|tmp)(?:/[^\\s)\\]\"'<>,]*)?"
    )

    /** `C:\Users\...` and friends. */
    private val WINDOWS_PATH = Regex("(?i)\\b[A-Z]:\\\\[^\\s)\\]\"'<>,]*")
}
