// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

/**
 * Shared declarative-text validation for scenario content, used by verified
 * scenario package decoding and user-authored scenario saves alike.
 *
 * Free-text fields are descriptive prose for prompts and review UIs.  They
 * must never look like executable content: no URLs, no code fences, no
 * script keywords.  The host never evaluates them, but keeping them plainly
 * declarative means crafted content cannot smuggle instructions that a
 * downstream reviewer might act on.
 */
object ScenarioTextRules {

    /** Length limit applied when decoding verified scenario packages. */
    const val PACKAGE_MAX_TEXT_LENGTH = 500

    /**
     * Stricter length limits for user-authored scenarios only.  These are a
     * user-layer boundary, not a global tightening: package decoding keeps
     * [PACKAGE_MAX_TEXT_LENGTH] so every verified package that loads today
     * keeps loading unchanged.
     */
    const val USER_MAX_TITLE_LENGTH = 80
    const val USER_MAX_HINT_LENGTH = 80
    const val USER_MAX_TEXT_LENGTH = 300

    /**
     * Rejects text that exceeds [maxLength] or looks like executable content.
     * Package decoding calls this with the default package limit; user-layer
     * saves pass one of the [USER_MAX_TEXT_LENGTH]-family limits per field.
     *
     * Rejections throw [PlaybookValidationException] with the stable reason
     * codes [ScenarioValidationCodes.TEXT_TOO_LONG] (arg `max`) and
     * [ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT] so callers report
     * codes rather than parse the English message; the rule itself is
     * unchanged.
     */
    fun requireDeclarativeText(text: String, maxLength: Int = PACKAGE_MAX_TEXT_LENGTH) {
        if (text.length > maxLength) {
            throw PlaybookValidationException(
                path = null,
                code = ScenarioValidationCodes.TEXT_TOO_LONG,
                args = mapOf("max" to maxLength.toString()),
                errorMessage = "Declarative text exceeds $maxLength characters."
            )
        }
        FORBIDDEN_TEXT_PATTERNS.forEach { pattern ->
            if (pattern.containsMatchIn(text)) {
                throw PlaybookValidationException(
                    path = null,
                    code = ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT,
                    errorMessage = "Declarative text contains forbidden content."
                )
            }
        }
    }

    private val FORBIDDEN_TEXT_PATTERNS = listOf(
        Regex("https?://", RegexOption.IGNORE_CASE),
        Regex("```"),
        Regex("<script", RegexOption.IGNORE_CASE),
        Regex("\\beval\\(", RegexOption.IGNORE_CASE),
        Regex("\\bexec\\(", RegexOption.IGNORE_CASE)
    )
}
