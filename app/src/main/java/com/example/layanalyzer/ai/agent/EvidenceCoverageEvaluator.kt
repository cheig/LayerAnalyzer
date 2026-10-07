// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentReport

/**
 * Result of the evidence-coverage accounting for one report (EVL-COVERAGE-01).
 *
 * Pure set bookkeeping between the frames the workspace flagged as evidence
 * and the frame numbers the report's citations carry. It answers only
 * "flagged evidence set vs. report citations" — whether a citation is *real*
 * or *verifiable* is [EvidenceValidator]'s fact check and is deliberately not
 * repeated here.
 */
data class EvidenceCoverage(
    /** Flagged frames the report actually cites through some finding's evidence. */
    val citedFrames: Set<Long>,
    /** Flagged frames no citation names, i.e. gathered evidence left unused. */
    val uncitedFrames: Set<Long>,
    /** Frames the report cites that were never flagged into the evidence set. */
    val citationOutsideFlagged: Set<Long>
) {
    companion object {
        /**
         * Every host-authored uncited-frame limitation starts with this prefix
         * (EVL-COVERAGE-02), mirroring [ReportCoverageValidator]
         * `.SIGNAL_GAP_LIMITATION_MARKER`: a stable, machine-readable marker
         * that names the channel and keeps the line recognizable as host
         * bookkeeping rather than model prose.
         */
        const val UNCITED_FRAMES_LIMITATION_MARKER = "Uncited evidence frames "

        /** How many uncited frame numbers one limitation line lists verbatim. */
        const val MAX_LISTED_UNCITED_FRAMES = 10
    }

    /** True when the evidence set and the citations agree in both directions. */
    val clean: Boolean
        get() = uncitedFrames.isEmpty() && citationOutsideFlagged.isEmpty()

    /**
     * Host-authored limitation prose for the uncited flagged frames
     * (EVL-COVERAGE-02), the finalization record a clean submit leaves behind
     * when the run gathered evidence the report never cited.
     *
     * Style follows the [ReportCoverageValidator] host-authored limitations:
     * English, machine-readable, stable ids only — the sorted frame numbers,
     * capped at [MAX_LISTED_UNCITED_FRAMES] with the remainder declared as a
     * count — and never any frame content. Null when every flagged frame was
     * cited or the evidence set was empty, so a clean run appends nothing and
     * keeps its report bytes unchanged. Pure prose minting: deciding *when*
     * the line is appended (after validation, at loop finalization) belongs
     * to the loop, not here.
     */
    fun uncitedFramesLimitation(): String? {
        val ordered = uncitedFrames.sorted()
        if (ordered.isEmpty()) return null
        val listed = ordered.take(MAX_LISTED_UNCITED_FRAMES)
        val overflow = ordered.size - listed.size
        val truncation = if (overflow > 0) ", ..." else ""
        val overflowNote = if (overflow > 0) {
            "; $overflow more uncited ${if (overflow == 1) "frame" else "frames"} not listed"
        } else {
            ""
        }
        return "$UNCITED_FRAMES_LIMITATION_MARKER${listed.joinToString(", ")}$truncation " +
            "were returned by this run's tools but cited by no finding$overflowNote."
    }
}

/**
 * Computes the coverage relation between the flagged evidence set and the
 * frame numbers a report's citations carry (EVL-COVERAGE-01).
 *
 * Pure function: no Android dependency, no Context, no I/O. Like
 * [ReportCoverageValidator] this is gap data only — deciding what to do with
 * the gaps (limitation prose, revision trigger, rejection) belongs to the
 * loop and the validator, not here. It performs no fact verification of its
 * own; [EvidenceValidator] already owns the "citation actually returned by a
 * tool of this run" judgement, and duplicating it would risk the two layers
 * disagreeing.
 *
 * [flagged] accepts any collection — workspace evidence entries can carry a
 * repeated frame number, so duplicates are collapsed into a set first. Frame
 * numbers are stable ids only; no capture payload ever enters the result.
 */
object EvidenceCoverageEvaluator {

    fun evaluate(flagged: Collection<Long>, report: AgentReport): EvidenceCoverage {
        val flaggedFrames = flagged.toSet()
        val citedFrames = report.findings
            .flatMap { it.evidence }
            .mapNotNull { it.frameNumber }
            .toSet()
        return EvidenceCoverage(
            citedFrames = flaggedFrames intersect citedFrames,
            uncitedFrames = flaggedFrames - citedFrames,
            citationOutsideFlagged = citedFrames - flaggedFrames
        )
    }
}
