package com.example.layanalyzer.ui.components

import com.example.layanalyzer.data.EvidenceFrameViewDecision
import com.example.layanalyzer.data.EvidenceFrameViewRejection
import com.example.layanalyzer.model.AgentSavedFinding
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote

/**
 * How the evidence list is partitioned for display.
 *
 * The same evidence set is shown three ways without duplicating or dropping any
 * frames: [All] shows every frame, [Manual] only user-added frames, and
 * [FromFindings] only frames whose provenance is an approved Agent conclusion.
 */
internal enum class EvidenceGroup { All, Manual, FromFindings }

/**
 * One rendered row of the rebuilt evidence page.
 *
 * Every field is derived from the workspace by [EvidenceWorkbench.rows]; the
 * composable layer only maps it to UI.  The note text is kept verbatim (no
 * truncation here) so the UI can elide it with `maxLines`.
 */
internal data class EvidenceRow(
    val frameNumber: Long,
    val source: EvidenceSource,
    val sourceFindingTitle: String?,
    val noteText: String?,
    val isStale: Boolean
)

/**
 * Which empty-state (if any) the evidence list must render.
 *
 * The split between [NoEvidence] and [GroupEmpty] is load-bearing: an empty
 * *whole* evidence set should invite the user to add frames (long-press in the
 * packet detail screen), whereas an empty *group* only means the active filter
 * hid everything and must NOT nudge the user to re-annotate.  [None] means the
 * current group has rows to show.  This is a pure classifier — no clock, no
 * input mutation, no Android — so it stays unit testable on the JVM.
 */
internal enum class EvidenceEmptyState { None, NoEvidence, GroupEmpty }

/**
 * Why the evidence page's "analyze with this evidence" entry cannot start a run.
 *
 * The priority order is fixed and tested: [AgentRunning] always wins, then an
 * [EvidenceFrameViewDecision.Apply] is accepted, and a rejection maps one-to-one
 * onto its structural reason. The UI resolves these to localised copy.
 */
internal enum class EvidenceAnalyzeBlockReason {
    /** A run is already in flight; a second concurrent submit is refused. */
    AgentRunning,

    /** The workspace has no evidence frames to analyze. */
    EmptySet,

    /** More distinct frames than the compiled-filter frame limit. */
    TooManyFrames,

    /** More merged ranges than the compiled-filter range limit. */
    TooManyRanges,

    /** A non-positive frame number, or the engine rejected the compiled filter. */
    InvalidFilter
}

/**
 * Whether the evidence page's analyze entry may start a run, plus everything the
 * caller needs to submit it.
 *
 * `enabled == (reason == null)`.  When [enabled] is true, [filter] is the
 * verbatim compiled display filter and [frameCount] is the number of frames it
 * selects — the caller must hand both to the agent submit.  When [enabled] is
 * false, [reason] is non-null, [filter] is `null`, and the entry is greyed out
 * with an explanatory message; it must never emit a submittable filter.
 */
internal data class EvidenceAnalyzeActionState(
    val enabled: Boolean,
    val reason: EvidenceAnalyzeBlockReason? = null,
    val actual: Int? = null,
    val limit: Int? = null,
    val filter: String? = null,
    val frameCount: Int = 0
)

/**
 * Pure, Android-free logic for the evidence workbench.
 *
 * All writes to the evidence set still go through `evidenceItems` in the
 * workspace; this object only projects that data into display rows.  It never
 * reads the clock, mutates inputs, or touches Android APIs so it stays unit
 * testable on the JVM.
 */
internal object EvidenceWorkbench {

    fun rows(
        items: List<EvidenceItem>,
        notes: List<WorkspaceNote>,
        findings: List<AgentSavedFinding>,
        frameCount: Int,
        group: EvidenceGroup
    ): List<EvidenceRow> {
        val filtered = when (group) {
            EvidenceGroup.All -> items
            EvidenceGroup.Manual -> items.filter { it.source == EvidenceSource.Manual }
            EvidenceGroup.FromFindings -> items.filter { it.source == EvidenceSource.AgentFinding }
        }

        // Defensive de-duplication: a frame number should appear at most once.
        // Keep the entry with the smallest addedAtMillis; never drop a distinct
        // frame number.
        val byFrame = LinkedHashMap<Long, EvidenceItem>()
        for (item in filtered) {
            val existing = byFrame[item.frameNumber]
            if (existing == null || item.addedAtMillis < existing.addedAtMillis) {
                byFrame[item.frameNumber] = item
            }
        }

        // Latest note per frame wins; missing frames simply have no note.
        val bestNoteByFrame = LinkedHashMap<Long, WorkspaceNote>()
        for (note in notes) {
            val existing = bestNoteByFrame[note.frameNumber]
            if (existing == null || note.updatedAtMillis > existing.updatedAtMillis) {
                bestNoteByFrame[note.frameNumber] = note
            }
        }
        val noteTextByFrame = bestNoteByFrame.mapValues { it.value.text }

        // First finding per sourceId (matches firstOrNull semantics). A blank
        // title is dropped so the UI falls back to a generic badge.
        val findingBySourceId = LinkedHashMap<String, AgentSavedFinding>()
        for (finding in findings) {
            if (!findingBySourceId.containsKey(finding.sourceId)) {
                findingBySourceId[finding.sourceId] = finding
            }
        }

        return byFrame.values.sortedBy { it.frameNumber }.map { item ->
            val sourceFindingTitle = if (item.source == EvidenceSource.AgentFinding && item.sourceFindingId != null) {
                findingBySourceId[item.sourceFindingId]?.title?.takeIf { it.isNotBlank() }
            } else {
                null
            }
            val isStale = frameCount > 0 &&
                (item.frameNumber < 1L || item.frameNumber > frameCount.toLong())
            EvidenceRow(
                frameNumber = item.frameNumber,
                source = item.source,
                sourceFindingTitle = sourceFindingTitle,
                noteText = noteTextByFrame[item.frameNumber],
                isStale = isStale
            )
        }
    }

    fun staleCount(rows: List<EvidenceRow>): Int = rows.count { it.isStale }

    /**
     * Classifies the empty-state the evidence list should show, from the rows of
     * the [All] group ([allRows]) and the rows of the currently selected group
     * ([visibleRows]).
     *
     * Contract (pinned by tests):
     * - [visibleRows] is non-empty → [EvidenceEmptyState.None];
     * - [visibleRows] is empty and [allRows] is also empty → [EvidenceEmptyState.NoEvidence]
     *   (the whole evidence set is empty → show the "long-press a frame to add
     *   evidence" guidance);
     * - [visibleRows] is empty but [allRows] is non-empty → [EvidenceEmptyState.GroupEmpty]
     *   (evidence exists, the active group just filtered it all out → show "no
     *   evidence frames in this group", never the add-evidence guidance).
     *
     * A stale frame is still a frame: it keeps [visibleRows] non-empty, so it can
     * never be mistaken for an empty state.  Pure function — does not read the
     * clock, mutate inputs, or touch Android.
     */
    fun emptyState(allRows: List<EvidenceRow>, visibleRows: List<EvidenceRow>): EvidenceEmptyState {
        if (visibleRows.isNotEmpty()) return EvidenceEmptyState.None
        return if (allRows.isEmpty()) EvidenceEmptyState.NoEvidence else EvidenceEmptyState.GroupEmpty
    }

    /**
     * Frame numbers currently visible in [rows], in row order, de-duplicated and
     * deterministic.
     *
     * [rows] is already emitted in ascending frame order, so this is the set of
     * frames the user can "select all" over for the active group. A `LinkedHashSet`
     * preserves that order and collapses any accidental duplicate (rows should
     * already be unique by frame number, but the contract is fail-safe).
     */
    fun visibleFrames(rows: List<EvidenceRow>): List<Long> {
        val seen = LinkedHashSet<Long>()
        for (row in rows) seen.add(row.frameNumber)
        return seen.toList()
    }

    /**
     * Decides whether the evidence page's "analyze with this evidence" entry may
     * start a run, from the already-compiled frame-filter [decision] and the agent
     * running flag.
     *
     * Priority (this order is the contract and is pinned by tests):
     * 1. [isAgentRunning] → blocked with [EvidenceAnalyzeBlockReason.AgentRunning];
     *    if [decision] is an [EvidenceFrameViewDecision.Apply] its `filter` /
     *    `frameCount` are still forwarded (they are harmless to carry), otherwise
     *    `filter` is `null` and `frameCount` is `0`.
     * 2. [EvidenceFrameViewDecision.Apply] → enabled, carrying the verbatim filter
     *    and frame count.
     * 3. [EvidenceFrameViewDecision.Reject] → blocked; the reason maps one-to-one
     *    from [EvidenceFrameViewRejection] and `actual` / `limit` are forwarded;
     *    `filter` is `null`.
     *
     * Invariant: `enabled == true` implies `reason == null && filter != null &&
     * filter.isNotBlank()`; `enabled == false` implies `reason != null` and never
     * yields a submittable filter.  The call is fail-closed — a rejection can never
     * be silently coerced into an enabled submission.
     */
    fun analyzeAction(
        decision: EvidenceFrameViewDecision,
        isAgentRunning: Boolean
    ): EvidenceAnalyzeActionState {
        if (isAgentRunning) {
            val carried = if (decision is EvidenceFrameViewDecision.Apply) {
                decision.filter to decision.frameCount
            } else {
                null to 0
            }
            return EvidenceAnalyzeActionState(
                enabled = false,
                reason = EvidenceAnalyzeBlockReason.AgentRunning,
                filter = carried.first,
                frameCount = carried.second
            )
        }

        return when (decision) {
            is EvidenceFrameViewDecision.Apply -> EvidenceAnalyzeActionState(
                enabled = true,
                reason = null,
                filter = decision.filter,
                frameCount = decision.frameCount
            )

            is EvidenceFrameViewDecision.Reject -> EvidenceAnalyzeActionState(
                enabled = false,
                reason = when (decision.reason) {
                    EvidenceFrameViewRejection.EmptySet -> EvidenceAnalyzeBlockReason.EmptySet
                    EvidenceFrameViewRejection.TooManyFrames -> EvidenceAnalyzeBlockReason.TooManyFrames
                    EvidenceFrameViewRejection.TooManyRanges -> EvidenceAnalyzeBlockReason.TooManyRanges
                    EvidenceFrameViewRejection.InvalidFilter -> EvidenceAnalyzeBlockReason.InvalidFilter
                },
                actual = decision.actual,
                limit = decision.limit,
                filter = null
            )
        }
    }
}
