package com.example.layanalyzer.data

import com.example.layanalyzer.model.AgentSavedFinding
import com.example.layanalyzer.model.EvidenceExportMode
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote

/**
 * The Markdown body of the `## 证据帧` section of `report.md` (EVL-EXPORT-04).
 *
 * The table is the human-readable counterpart of the machine-readable
 * `provenance` entry that [EvidenceExportManifestFields.provenanceObject] writes
 * into `frames.json`: one row per evidence frame, telling the reader where the
 * frame came from, which note is attached to it and which saved finding put it
 * there.
 *
 * The whole decision is pure and free of any Android dependency, so the
 * ViewModel — which needs a `Context` and therefore cannot be instantiated in a
 * JVM test — is reduced to one call. Every mode branch is exhaustive: there is
 * no branch that treats an unhandled mode as "original", and a required
 * redaction that cannot be performed is refused rather than silently skipped.
 * Note text and finding titles are user- or model-controlled, so they are
 * flattened into a single line and their `|` escaped before they are placed in a
 * cell, or the table would lose its column structure.
 */
object EvidenceExportReportSections {
    /** Body written when the export carries no evidence frames at all. */
    const val NO_EVIDENCE_FRAMES = "本次导出不含证据帧"

    /** Cell text for an absent note or an unresolved finding title. */
    const val PLACEHOLDER = "—"

    private const val HEADER = "| 帧号 | 来源 | 关联备注 | 来源结论标题 |"
    private const val SEPARATOR = "| --- | --- | --- | --- |"

    /**
     * Renders the evidence-frame table, or [NO_EVIDENCE_FRAMES] when [items] is
     * empty — an empty table with a header and no rows would read as a bug
     * rather than as "this export has no evidence".
     *
     * Rows are ascending by `frameNumber` and the ordering is total, so a
     * shuffled [items] yields an identical body. The note text is joined from
     * [notes] by `frameNumber`, because [EvidenceItem] deliberately does not
     * carry it; a frame without a matching note gets [PLACEHOLDER]. The title is
     * resolved from [findings] by `sourceFindingId`; evidence that did not come
     * from a finding, or whose finding is gone, gets [PLACEHOLDER] rather than
     * failing the whole export.
     */
    fun evidenceFramesTable(
        items: List<EvidenceItem>,
        notes: List<WorkspaceNote>,
        findings: List<AgentSavedFinding>,
        mode: EvidenceExportMode,
        redactor: MetadataRedactor?
    ): String {
        if (items.isEmpty()) return NO_EVIDENCE_FRAMES

        val notesByFrame = HashMap<Long, WorkspaceNote>(notes.size)
        notes.forEach { note -> notesByFrame[note.frameNumber] = note }

        val ordered = items.sortedWith(
            compareBy(
                { item -> item.frameNumber },
                { item -> item.source.name },
                { item -> item.sourceFindingId.orEmpty() },
                { item -> item.addedAtMillis }
            )
        )

        val rows = ordered.joinToString("\n") { item ->
            val note = notesByFrame[item.frameNumber]
            "| ${item.frameNumber} | ${sourceLabel(item.source)} | " +
                "${cell(noteCell(note, mode, redactor))} | " +
                "${cell(titleCell(item, findings))} |"
        }
        return "$HEADER\n$SEPARATOR\n$rows"
    }

    /** The localised label for an evidence origin; exhaustive over [EvidenceSource]. */
    private fun sourceLabel(source: EvidenceSource): String = when (source) {
        EvidenceSource.Manual -> "手动"
        EvidenceSource.AgentFinding -> "来自结论"
    }

    /**
     * The note column for one frame: [PLACEHOLDER] when there is no note or the
     * mode forbids note text, the redacted text in [EvidenceExportMode.Redacted],
     * and the verbatim text in [EvidenceExportMode.Original].
     */
    private fun noteCell(
        note: WorkspaceNote?,
        mode: EvidenceExportMode,
        redactor: MetadataRedactor?
    ): String {
        if (note == null) return PLACEHOLDER
        return when (mode) {
            EvidenceExportMode.MetadataOnly -> PLACEHOLDER
            EvidenceExportMode.Redacted -> redactorOrFail(mode, redactor).redact(note.text)
            EvidenceExportMode.Original -> note.text
        }
    }

    /**
     * The origin-finding title for one frame: only evidence that came from a
     * finding can resolve one, and a finding that is no longer present yields
     * [PLACEHOLDER] instead of an exception.
     */
    private fun titleCell(item: EvidenceItem, findings: List<AgentSavedFinding>): String {
        if (item.source != EvidenceSource.AgentFinding) return PLACEHOLDER
        val findingId = item.sourceFindingId ?: return PLACEHOLDER
        val title = findings.firstOrNull { it.findingId == findingId }?.title ?: return PLACEHOLDER
        return title.ifBlank { PLACEHOLDER }
    }

    /**
     * Flattens user- or model-controlled text so it cannot break a table row: a
     * line break becomes a space and `|` is escaped as `\|`.
     */
    private fun cell(value: String): String = value
        .replace("\r\n", " ")
        .replace('\n', ' ')
        .replace('\r', ' ')
        .replace("|", "\\|")

    /**
     * Fail-closed redaction guard: a mode that promises redaction must never
     * fall back to emitting the raw value when the redactor is missing.
     */
    private fun redactorOrFail(mode: EvidenceExportMode, redactor: MetadataRedactor?): MetadataRedactor =
        redactor ?: throw IllegalArgumentException(
            "Evidence export mode $mode requires a MetadataRedactor;" +
                " refusing to emit unredacted metadata."
        )
}
