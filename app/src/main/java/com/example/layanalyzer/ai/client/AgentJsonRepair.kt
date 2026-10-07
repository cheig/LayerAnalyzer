// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

/**
 * Last-resort structural repair for a final report that failed to parse.
 *
 * This exists because a model that hand-writes several thousand characters of
 * nested JSON inside free text occasionally drops one delimiter, and losing a
 * complete analysis to a missing quote is a worse outcome than accepting a
 * narrowly repaired one.  It is a safety net, not the mechanism: the report is
 * meant to arrive as a schema-validated tool call, and this code should be
 * reached only when a provider ignores that contract.
 *
 * The repair is deliberately **structural only**.  It inserts delimiters that
 * JSON grammar requires and never edits, deletes, reorders or invents content,
 * so a repaired document either carries exactly the data the model emitted or
 * fails to parse and is discarded.  There is no rule here that could turn a
 * malformed document into a valid one with different meaning.
 *
 * Two rules, in order:
 *  1. A key whose closing quote is missing (`"recommendations [` → `"recommendations":[`).
 *     Restricted to strings in key position — the character before the opening
 *     quote must be `{` or `,` — so a `[` inside an ordinary string value is
 *     left alone.
 *  2. A closing delimiter that does not match the innermost open container, or a
 *     container still open at end of input, gets the closers it is missing.
 *
 * Deliberately **not** repaired: an unterminated string.  Appending the closing
 * quote would silently absorb whatever followed — `{"summary":"oops}` would
 * become the value `oops}` — which changes the data rather than restoring it.
 * A truncated string is a truncated response, and the caller reports it as one.
 */
internal object AgentJsonRepair {

    /**
     * Repair [source], or return null when nothing was changed.
     *
     * A null result means "no repair applies", which callers should treat as the
     * original parse failure rather than retrying.
     */
    fun repair(source: String): AgentJsonRepairResult? {
        val notes = mutableListOf<String>()
        val keysClosed = closeUnclosedKeys(source, notes)
        val balanced = balanceContainers(keysClosed, notes)
        if (notes.isEmpty() || balanced == source) return null
        return AgentJsonRepairResult(json = balanced, repairs = notes.toList())
    }

    /** Rule 1: restore `":` on a key whose closing quote was dropped. */
    private fun closeUnclosedKeys(source: String, notes: MutableList<String>): String {
        val out = StringBuilder(source.length + 8)
        var index = 0
        var inString = false
        var escaped = false
        var stringStart = -1
        var inKeyPosition = false
        while (index < source.length) {
            val ch = source[index]
            if (!inString) {
                if (ch == '"') {
                    inString = true
                    stringStart = out.length
                    inKeyPosition = isKeyPosition(out)
                }
                out.append(ch)
                index += 1
                continue
            }
            when {
                escaped -> {
                    escaped = false
                    out.append(ch)
                }
                ch == '\\' -> {
                    escaped = true
                    out.append(ch)
                }
                ch == '"' -> {
                    inString = false
                    out.append(ch)
                }
                // A value-opening delimiter after a space, inside what claims to
                // be a key, means the key was never closed.
                inKeyPosition && (ch == '[' || ch == '{') && out.lastOrNull() == ' ' -> {
                    val key = out.substring(stringStart + 1, out.length - 1)
                    if (key.isNotEmpty() && key.all { it.isLetterOrDigit() || it == '_' } &&
                        !key.first().isDigit()
                    ) {
                        out.setLength(out.length - 1)
                        out.append("\":").append(ch)
                        notes += "closed_key"
                        inString = false
                    } else {
                        out.append(ch)
                    }
                }
                else -> out.append(ch)
            }
            index += 1
        }
        return out.toString()
    }

    /** Rule 2: insert closers the container stack proves are missing. */
    private fun balanceContainers(source: String, notes: MutableList<String>): String {
        val out = StringBuilder(source.length + 8)
        val stack = ArrayDeque<Char>()
        var inString = false
        var escaped = false
        for (ch in source) {
            if (inString) {
                out.append(ch)
                when {
                    escaped -> escaped = false
                    ch == '\\' -> escaped = true
                    ch == '"' -> inString = false
                }
                continue
            }
            when (ch) {
                '"' -> {
                    inString = true
                    out.append(ch)
                }
                '{', '[' -> {
                    stack.addLast(ch)
                    out.append(ch)
                }
                '}', ']' -> {
                    val expected = if (ch == '}') '{' else '['
                    while (stack.isNotEmpty() && stack.last() != expected) {
                        val inner = stack.removeLast()
                        out.append(if (inner == '{') '}' else ']')
                        notes += "closed_container"
                    }
                    if (stack.isNotEmpty()) stack.removeLast()
                    out.append(ch)
                }
                else -> out.append(ch)
            }
        }
        // A response that ended mid-string was cut off, not mangled. Closing the
        // quote here would fold the remaining delimiters into the string value
        // and hand back altered data, so the document is left to fail instead.
        if (inString) return source
        while (stack.isNotEmpty()) {
            val open = stack.removeLast()
            out.append(if (open == '{') '}' else ']')
            notes += "closed_container_at_end"
        }
        return out.toString()
    }

    /**
     * Whether a string opening at the end of [out] sits in key position.
     *
     * Only `{` and `,` can precede a key, so a string following `:` — an
     * ordinary value — is never treated as a candidate for rule 1.
     */
    private fun isKeyPosition(out: StringBuilder): Boolean {
        var index = out.length - 1
        while (index >= 0 && out[index].isWhitespace()) index -= 1
        if (index < 0) return false
        return out[index] == '{' || out[index] == ','
    }
}

/** A repaired document and the structural edits that produced it. */
internal data class AgentJsonRepairResult(
    val json: String,
    val repairs: List<String>
)
