// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.EvidenceExportMode
import com.example.layanalyzer.model.EvidenceExportScope

/**
 * What one evidence-package export must do, derived from the requested
 * [EvidenceExportMode] and [EvidenceExportScope].
 *
 * This is the pure decision table behind the export flow (EVL-EXPORT-02): the
 * ViewModel reads it and wires the native calls, so the branching rules are
 * unit-tested without an Android or native dependency. The fields are
 * independent booleans rather than an enum because the request can attach a
 * capture while *not* filtering it, and [pcapIncludesEvidenceFramesOnly] is a
 * property of the combination, not of either input alone.
 */
data class EvidenceExportPlan(
    /** `mode == Original`: the export writes a pcap into the package. */
    val attachCapture: Boolean,

    /** `scope == EvidenceFrames`: the native filter is swapped for the evidence filter. */
    val applyEvidenceTemporaryFilter: Boolean,

    /** `scope == EvidenceFrames`: the visible frame count is checked against the evidence set. */
    val verifyEvidenceFrameCount: Boolean,

    /**
     * `attachCapture && scope == EvidenceFrames`: the pcap holds only evidence
     * frames, not the user's current view. `true` implies [attachCapture].
     */
    val pcapIncludesEvidenceFramesOnly: Boolean
)

/**
 * Builds the [EvidenceExportPlan] for a request. Deliberately side-effect free
 * so it can be called from anywhere and asserted exhaustively in tests.
 *
 * Rules:
 * - [EvidenceExportScope.CurrentView] never enters the temporary-filter lease;
 *   the export keeps the exact behaviour it has today.
 * - [EvidenceExportScope.EvidenceFrames] always enters the lease and always
 *   verifies the frame count, whether or not the mode produces a pcap. Applying
 *   the evidence filter is the only way the count can mean "the evidence set",
 *   so skipping it for metadata-only exports would make the check meaningless.
 * - A pcap is attached only in [EvidenceExportMode.Original].
 */
object EvidenceExportPlanner {
    fun planFor(
        mode: EvidenceExportMode,
        scope: EvidenceExportScope
    ): EvidenceExportPlan {
        val attachCapture = mode == EvidenceExportMode.Original
        val evidenceScope = scope == EvidenceExportScope.EvidenceFrames
        return EvidenceExportPlan(
            attachCapture = attachCapture,
            applyEvidenceTemporaryFilter = evidenceScope,
            verifyEvidenceFrameCount = evidenceScope,
            pcapIncludesEvidenceFramesOnly = attachCapture && evidenceScope
        )
    }
}
