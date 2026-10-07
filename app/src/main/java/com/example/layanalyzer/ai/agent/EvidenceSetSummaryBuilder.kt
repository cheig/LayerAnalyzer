package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AnalysisWorkspace
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote

/**
 * Builds the textual "evidence set summary" prompt section from a capture
 * workspace's evidence set (EVL-CONTEXT-01).
 *
 * The section gives the model a compact, provenance-carrying view of the
 * evidence the analysis must stay grounded in:
 *
 * - the frame numbers of the evidence set (at most [MAX_LISTED_FRAMES] listed
 *   explicitly, the remainder declared as "N more frames not listed"),
 * - per-item provenance: each item's [EvidenceSource] and, for
 *   [EvidenceSource.AgentFinding] items, its `sourceFindingId`,
 * - per-item note summary: the workspace note joined by `frameNumber`,
 *   redacted and capped at [MAX_NOTE_SUMMARY_CHARS] characters.
 *
 * ### Fail-closed evidence semantics
 *
 * Nothing in the section is ever cut silently.  A note summary that exceeds
 * its cap is cut with an explicit `[note truncated]` marker, and a section
 * that exceeds [MAX_SECTION_CHARS] characters loses whole item lines and
 * appends an explicit `[truncated: ...]` declaration stating how many items
 * survived.  An empty evidence set yields `null` so the caller can omit the
 * section entirely instead of presenting an empty one.
 *
 * ### Redaction
 *
 * [AgentPayloadRedactor]-style redaction does not fit here: that redactor
 * walks structured tool-result JSON keyed by field names, while note text is
 * free-form prose.  The suitable existing API is the underlying free-text
 * pass, `MetadataRedactor.redact(String)`, so the builder takes it as an
 * injected function ([noteRedactor]) and never sees unredacted note text.
 * The parameter is deliberately not optional — a caller without a redactor
 * cannot accidentally emit raw note content into a prompt.  This file stays
 * pure JVM: no Android classes, no logging of note text.
 */
object EvidenceSetSummaryBuilder {

    /** How many frame numbers are listed explicitly before the "more" declaration. */
    const val MAX_LISTED_FRAMES = 40

    /** Hard cap for one redacted note summary, marker included. */
    const val MAX_NOTE_SUMMARY_CHARS = 120

    /** Hard cap for the whole section, truncation declaration included. */
    const val MAX_SECTION_CHARS = 2000

    private const val NOTE_TRUNCATED_MARKER = "[note truncated]"
    private const val NO_NOTE_TEXT = "none"

    /**
     * Builds the evidence-set summary section, or `null` when the workspace
     * has no evidence items (the caller then omits the section).
     *
     * [noteRedactor] must be the free-text redaction pass (for example
     * `metadataRedactor::redact`); it is applied before any length capping so
     * a cap can never expose a redacted suffix.
     */
    fun build(
        workspace: AnalysisWorkspace,
        noteRedactor: (String) -> String
    ): String? {
        if (workspace.evidenceItems.isEmpty()) return null

        val items = workspace.evidenceItems.sortedBy { it.frameNumber }
        val frames = items.map { it.frameNumber }.distinct()
        val header = buildHeader(frames)

        val itemLines = items.map { buildItemLine(it, latestNoteFor(it.frameNumber, workspace.notes), noteRedactor) }
        val full = join(header, itemLines)
        if (full.length <= MAX_SECTION_CHARS) return full

        // Over the cap: drop whole item lines from the end until the section
        // — truncation declaration included — fits, then declare the cut.
        var kept = itemLines.size
        while (true) {
            val candidate = join(header, itemLines.take(kept)) +
                truncatedDeclaration(keptItems = kept, totalItems = items.size) + "\n"
            if (candidate.length <= MAX_SECTION_CHARS || kept == 0) return candidate
            kept--
        }
    }

    private fun buildHeader(frames: List<Long>): String {
        val sb = StringBuilder()
        sb.append("Evidence set summary (").append(frames.size).append(" frame(s)):\n")
        sb.append("Frames: ")
        sb.append(frames.take(MAX_LISTED_FRAMES).joinToString(", "))
        val unlisted = frames.size - MAX_LISTED_FRAMES
        if (unlisted > 0) {
            sb.append(" and ").append(unlisted).append(" more frames not listed")
        }
        sb.append("\n")
        sb.append("Items:\n")
        return sb.toString()
    }

    private fun buildItemLine(
        item: EvidenceItem,
        note: WorkspaceNote?,
        noteRedactor: (String) -> String
    ): String {
        val sb = StringBuilder()
        sb.append("- frame ").append(item.frameNumber).append(": source=").append(item.source.name)
        if (item.source == EvidenceSource.AgentFinding) {
            sb.append(" (findingId=").append(item.sourceFindingId ?: "unknown").append(")")
        }
        sb.append("; note: ")
        sb.append(note?.let { summarizeNote(it, noteRedactor) } ?: NO_NOTE_TEXT)
        return sb.toString()
    }

    /**
     * Redacts and caps one note summary.  Whitespace is collapsed first so a
     * multi-line note cannot break the one-line-per-item shape, then the text
     * is redacted, then cut to [MAX_NOTE_SUMMARY_CHARS] with an explicit
     * marker — never a silent cut.
     */
    private fun summarizeNote(note: WorkspaceNote, noteRedactor: (String) -> String): String {
        val redacted = noteRedactor(note.text.replace(Regex("\\s+"), " ").trim())
        if (redacted.length <= MAX_NOTE_SUMMARY_CHARS) return redacted
        val keep = MAX_NOTE_SUMMARY_CHARS - NOTE_TRUNCATED_MARKER.length
        return redacted.take(keep) + NOTE_TRUNCATED_MARKER
    }

    /** Latest note wins when a frame carries more than one note. */
    private fun latestNoteFor(frameNumber: Long, notes: List<WorkspaceNote>): WorkspaceNote? =
        notes.filter { it.frameNumber == frameNumber }.maxByOrNull { it.updatedAtMillis }

    private fun join(header: String, itemLines: List<String>): String =
        header + itemLines.joinToString("\n", postfix = if (itemLines.isEmpty()) "" else "\n")

    private fun truncatedDeclaration(keptItems: Int, totalItems: Int): String =
        "[truncated: evidence set summary exceeded the $MAX_SECTION_CHARS character limit; " +
            "$keptItems of $totalItems items shown]"
}
