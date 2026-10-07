// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.EvidenceExportScope

/**
 * Decides whether an export scope may be offered to the user, given the result
 * of compiling the workspace evidence set into a display filter.
 *
 * This is the UI-facing half of the evidence-loop export flow (decision 7):
 * [EvidenceFrameFilter.compileOrNull] produces structural facts, and this policy
 * turns them into a stability contract the UI can localise. No Android or
 * resource dependency leaks into the data layer — [ScopeAvailability.reasonCode]
 * is a stable enum and [ScopeAvailability.detail] carries the English
 * [EvidenceFrameFilter.CompileResult.Rejected.message] for diagnostics only.
 *
 * Failure semantics are fail-closed and match the compiler: an empty evidence
 * set, or a compilation that was rejected, makes the evidence-frame scope
 * *unavailable*. There is deliberately no path that reports a rejected or empty
 * evidence set as available, so a caller can never silently fall back to the
 * current view while claiming to export evidence frames.
 */
object EvidenceExportScopePolicy {
    /**
     * Why a scope is unavailable. Stable and resource-free so the UI layer maps
     * each code to a localised string.
     */
    enum class ReasonCode {
        /** The workspace has no evidence frames to export. */
        NoEvidenceFrames,

        /** The evidence set could not be compiled into a filter (see the reject reason). */
        FilterRejected
    }

    /**
     * Availability verdict for a single [EvidenceExportScope].
     *
     * [available] `false` always implies a non-null [reasonCode]. The limit
     * fields are only meaningful for [ReasonCode.FilterRejected] rejections that
     * are limit-based; they are `null` otherwise (including the non-limit
     * [EvidenceFrameFilter.RejectReason.InvalidFilter]).
     */
    data class ScopeAvailability(
        val available: Boolean,
        val reasonCode: ReasonCode? = null,
        /** Display-ready English diagnostic from the compiler; never shown verbatim. */
        val detail: String? = null,
        /** The offending count when the rejection is limit-based, else `null`. */
        val actual: Int? = null,
        /** The configured limit when the rejection is limit-based, else `null`. */
        val limit: Int? = null,
        /** Structural reject reason, carried through for the UI/next stage. */
        val rejectReason: EvidenceFrameFilter.RejectReason? = null
    )

    /**
     * Deterministic, side-effect-free evaluation.
     *
     * - [EvidenceExportScope.CurrentView] is always available: it describes the
     *   live filter scope, which needs no evidence compilation.
     * - [EvidenceExportScope.EvidenceFrames] is available only for
     *   [EvidenceFrameFilter.CompileResult.Compiled]. [EvidenceFrameFilter.CompileResult.Empty]
     *   and [EvidenceFrameFilter.CompileResult.Rejected] both yield
     *   `available = false` with a populated [ScopeAvailability.reasonCode].
     *
     * [framesCompileResult] is expected to come from
     * `EvidenceFrameFilter.compileOrNull(workspace.evidenceFrames)`; it is passed
     * in rather than computed here so the policy stays pure and independently
     * testable.
     */
    fun evaluate(
        scope: EvidenceExportScope,
        framesCompileResult: EvidenceFrameFilter.CompileResult
    ): ScopeAvailability = when (scope) {
        EvidenceExportScope.CurrentView -> ScopeAvailability(available = true)

        EvidenceExportScope.EvidenceFrames -> when (framesCompileResult) {
            EvidenceFrameFilter.CompileResult.Empty -> ScopeAvailability(
                available = false,
                reasonCode = ReasonCode.NoEvidenceFrames
            )

            is EvidenceFrameFilter.CompileResult.Compiled -> ScopeAvailability(available = true)

            is EvidenceFrameFilter.CompileResult.Rejected -> ScopeAvailability(
                available = false,
                reasonCode = ReasonCode.FilterRejected,
                detail = framesCompileResult.message,
                actual = framesCompileResult.actual,
                limit = framesCompileResult.limit,
                rejectReason = framesCompileResult.reason
            )
        }
    }
}
