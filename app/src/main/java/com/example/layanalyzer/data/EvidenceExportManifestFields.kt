// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.EvidenceExportMode
import com.example.layanalyzer.model.EvidenceExportScope
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.WorkspaceNote
import org.json.JSONArray
import org.json.JSONObject

/**
 * The provenance fields an evidence export writes into its manifest (EVL-EXPORT-03).
 *
 * These fields describe, in a machine-readable way, *what* was exported: which
 * scope was requested, which evidence filter actually took effect, the
 * de-duplicated evidence frame count, one entry per evidence frame with its
 * origin, and whether an attached capture holds the evidence frames only.
 *
 * The construction is deliberately pure and free of any Android dependency, so
 * the ViewModel — which needs a `Context` and therefore cannot be unit-tested on
 * the JVM — is reduced to wiring. Every decision here is exhaustive over
 * [EvidenceExportMode]: there is no branch that treats an unhandled mode as
 * "original", and redaction that is required but cannot be performed is refused
 * rather than silently skipped, matching the fail-closed evidence semantics.
 */
object EvidenceExportManifestFields {
    /** Manifest key: the requested export scope, always present. */
    const val KEY_EXPORT_SCOPE = "exportScope"

    /** Manifest key: the evidence filter that took effect, or JSON null. */
    const val KEY_EVIDENCE_FILTER = "evidenceFilter"

    /** Manifest key: the de-duplicated evidence frame count, always present. */
    const val KEY_EVIDENCE_FRAME_COUNT = "evidenceFrameCount"

    /** Manifest key: one object per evidence frame, ascending by frame number. */
    const val KEY_EVIDENCE_ITEMS = "evidenceItems"

    /** Manifest key: whether the attached pcap holds evidence frames only. */
    const val KEY_PCAP_EVIDENCE_ONLY = "pcapIncludesEvidenceFramesOnly"

    /**
     * Writes the five provenance fields into [manifest] and returns it.
     *
     * [evidenceFilter] is the filter that actually took effect (the compiled
     * evidence filter for [EvidenceExportScope.EvidenceFrames]); it is redacted
     * or nulled according to [mode]. When [EvidenceExportPlan.applyEvidenceTemporaryFilter]
     * is `false` the export never applied an evidence filter, so the field is
     * JSON `null` regardless of [mode] — reporting a filter that was not used
     * would be a lie.
     */
    fun applyTo(
        manifest: JSONObject,
        scope: EvidenceExportScope,
        plan: EvidenceExportPlan,
        evidenceFilter: String?,
        items: List<EvidenceItem>,
        notes: List<WorkspaceNote>,
        mode: EvidenceExportMode,
        redactor: MetadataRedactor?
    ): JSONObject {
        manifest.put(KEY_EXPORT_SCOPE, scope.name)
        manifest.put(
            KEY_EVIDENCE_FILTER,
            if (plan.applyEvidenceTemporaryFilter) {
                evidenceFilterValue(evidenceFilter, mode, redactor)
            } else {
                JSONObject.NULL
            }
        )
        manifest.put(KEY_EVIDENCE_FRAME_COUNT, evidenceFrameCount(items))
        manifest.put(KEY_EVIDENCE_ITEMS, evidenceItemsArray(items, notes, mode, redactor))
        manifest.put(KEY_PCAP_EVIDENCE_ONLY, plan.pcapIncludesEvidenceFramesOnly)
        return manifest
    }

    /**
     * The value to place under [KEY_EVIDENCE_FILTER].
     *
     * A `null` [filter] means no filter took effect and becomes JSON `null`. The
     * three modes are exhaustive and mutually exclusive:
     * - [EvidenceExportMode.Original] returns the filter verbatim;
     * - [EvidenceExportMode.Redacted] returns `redactor.redact(filter)` and
     *   throws when no redactor was supplied, rather than leaking the raw filter;
     * - [EvidenceExportMode.MetadataOnly] returns JSON `null`.
     */
    fun evidenceFilterValue(
        filter: String?,
        mode: EvidenceExportMode,
        redactor: MetadataRedactor?
    ): Any? {
        if (filter == null) return JSONObject.NULL
        return when (mode) {
            EvidenceExportMode.Original -> filter
            EvidenceExportMode.Redacted -> redactorOrFail(mode, redactor).redact(filter)
            EvidenceExportMode.MetadataOnly -> JSONObject.NULL
        }
    }

    /**
     * The de-duplicated number of evidence frames, i.e. `workspace.evidenceFrames.size`.
     *
     * Frame numbers are collapsed into a set first so a duplicated
     * [EvidenceItem] cannot inflate the count.
     */
    fun evidenceFrameCount(items: List<EvidenceItem>): Int =
        items.mapTo(LinkedHashSet()) { it.frameNumber }.size

    /**
     * One JSON object per evidence frame, sorted ascending by `frameNumber`.
     *
     * Each entry carries `frameNumber`, `source`, `sourceFindingId` (JSON `null`
     * for [com.example.layanalyzer.model.EvidenceSource.Manual]), `addedAtMillis`,
     * and — when the frame has a note — `note`. The note text is not stored on
     * [EvidenceItem], so it is joined from [notes] by `frameNumber`; a note whose
     * frame is not in the evidence set is ignored.
     *
     * Under [EvidenceExportMode.MetadataOnly] the `note` key is **omitted**
     * entirely (not written as an empty string), and a frame without a note
     * likewise omits the key. The ordering is total — ties on `frameNumber`
     * break on source, finding id and timestamp — so shuffling [items] yields an
     * identical array.
     */
    fun evidenceItemsArray(
        items: List<EvidenceItem>,
        notes: List<WorkspaceNote>,
        mode: EvidenceExportMode,
        redactor: MetadataRedactor?
    ): JSONArray {
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

        return JSONArray().apply {
            ordered.forEach { item ->
                put(provenanceObject(item, notesByFrame[item.frameNumber], mode, redactor))
            }
        }
    }

    /**
     * The provenance object for one evidence frame, shared by the manifest's
     * [KEY_EVIDENCE_ITEMS] entry and the `frames.json` frame element so the two
     * can never drift apart (EVL-EXPORT-04).
     *
     * The object always carries `frameNumber`, `source`, `sourceFindingId`
     * (JSON `null` for [com.example.layanalyzer.model.EvidenceSource.Manual]) and
     * `addedAtMillis`. When [note] is present a `note` key is added, unless the
     * mode forbids note text — under [EvidenceExportMode.MetadataOnly] the key is
     * omitted entirely rather than written as an empty string, and a frame
     * without a note likewise omits it. [EvidenceExportMode.Redacted] requires a
     * redactor and fails closed when none is supplied.
     */
    fun provenanceObject(
        item: EvidenceItem,
        note: WorkspaceNote?,
        mode: EvidenceExportMode,
        redactor: MetadataRedactor?
    ): JSONObject {
        val entry = JSONObject()
            .put("frameNumber", item.frameNumber)
            .put("source", item.source.name)
            .put("sourceFindingId", item.sourceFindingId ?: JSONObject.NULL)
            .put("addedAtMillis", item.addedAtMillis)
        if (note != null) {
            noteValue(note, mode, redactor)?.let { value -> entry.put("note", value) }
        }
        return entry
    }

    /**
     * The `note` value for one frame, or `null` when the key must be omitted.
     *
     * Exhaustive over [EvidenceExportMode]: [EvidenceExportMode.MetadataOnly]
     * never emits note text, [EvidenceExportMode.Redacted] requires a redactor,
     * and [EvidenceExportMode.Original] passes the note through.
     */
    private fun noteValue(
        note: WorkspaceNote,
        mode: EvidenceExportMode,
        redactor: MetadataRedactor?
    ): Any? = when (mode) {
        EvidenceExportMode.MetadataOnly -> null
        EvidenceExportMode.Redacted -> redactorOrFail(mode, redactor).redact(note.text)
        EvidenceExportMode.Original -> note.text
    }

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
