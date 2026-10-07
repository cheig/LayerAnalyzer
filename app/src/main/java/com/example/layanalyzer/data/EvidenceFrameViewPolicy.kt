package com.example.layanalyzer.data

/**
 * Turns a compiled evidence filter into a UI decision for the "show evidence
 * frames only" action (EVL-UI-04).
 *
 * This is the view-layer half of the evidence-frame flow: [EvidenceFrameFilter]
 * produces the structural facts, and this policy maps them to one of two
 * mutually exclusive outcomes — apply a display filter, or reject with a reason
 * the UI can localise. No Android or resource dependency leaks in; the decision
 * is structural and the UI resolves strings from [EvidenceFrameViewRejection].
 *
 * Failure semantics are fail-closed and mirror the compiler: an empty evidence
 * set, or a compilation that was rejected, yields [EvidenceFrameViewDecision.Reject].
 * There is deliberately no path that reports a rejected or empty evidence set as
 * [EvidenceFrameViewDecision.Apply], so a caller can never silently fall back to
 * the current view while claiming to frame the packet list with the evidence.
 *
 * The core invariant: [decide] can only produce [EvidenceFrameViewDecision.Apply]
 * for [EvidenceFrameFilter.CompileResult.Compiled]. [Empty] and [Rejected] always
 * become [Reject], never an application. This is what keeps an over-limit or
 * invalid evidence set from being silently truncated into a smaller filter.
 */
enum class EvidenceFrameViewRejection {
    /** The workspace has no evidence frames to frame. */
    EmptySet,

    /** More distinct frames than [EvidenceFrameFilter.MAX_FRAMES]. */
    TooManyFrames,

    /** More merged ranges than [EvidenceFrameFilter.MAX_RANGES]. */
    TooManyRanges,

    /** A non-positive frame number, or the engine rejected the compiled filter. */
    InvalidFilter
}

/**
 * What the "show evidence frames only" action should do with a compiled filter.
 *
 * [Apply.filter] is passed through verbatim from the compiler — this policy
 * never rewrites, truncates or re-joins the expression. [Reject.actual] /
 * [Reject.limit] are only meaningful for the limit-based rejections and are
 * `null` for [EvidenceFrameViewRejection.EmptySet] and
 * [EvidenceFrameViewRejection.InvalidFilter].
 */
sealed interface EvidenceFrameViewDecision {
    data class Apply(val filter: String, val frameCount: Int) : EvidenceFrameViewDecision

    data class Reject(
        val reason: EvidenceFrameViewRejection,
        val actual: Int? = null,
        val limit: Int? = null
    ) : EvidenceFrameViewDecision
}

internal object EvidenceFrameViewPolicy {
    /**
     * Deterministic, side-effect-free evaluation of a compile result.
     *
     * - [EvidenceFrameFilter.CompileResult.Compiled] →
     *   [EvidenceFrameViewDecision.Apply] carrying the original filter and frame
     *   count, unchanged.
     * - [EvidenceFrameFilter.CompileResult.Empty] →
     *   [EvidenceFrameViewDecision.Reject] with [EvidenceFrameViewRejection.EmptySet].
     * - [EvidenceFrameFilter.CompileResult.Rejected] →
     *   [EvidenceFrameViewDecision.Reject] whose [EvidenceFrameViewRejection] maps
     *   from the compiler's [EvidenceFrameFilter.RejectReason]; [actual] / [limit]
     *   are forwarded (both `null` for [EvidenceFrameFilter.RejectReason.InvalidFilter]).
     */
    fun decide(compiled: EvidenceFrameFilter.CompileResult): EvidenceFrameViewDecision = when (compiled) {
        EvidenceFrameFilter.CompileResult.Empty ->
            EvidenceFrameViewDecision.Reject(EvidenceFrameViewRejection.EmptySet)

        is EvidenceFrameFilter.CompileResult.Compiled ->
            EvidenceFrameViewDecision.Apply(filter = compiled.filter, frameCount = compiled.frameCount)

        is EvidenceFrameFilter.CompileResult.Rejected -> when (compiled.reason) {
            EvidenceFrameFilter.RejectReason.TooManyFrames ->
                EvidenceFrameViewDecision.Reject(
                    reason = EvidenceFrameViewRejection.TooManyFrames,
                    actual = compiled.actual,
                    limit = compiled.limit
                )

            EvidenceFrameFilter.RejectReason.TooManyRanges ->
                EvidenceFrameViewDecision.Reject(
                    reason = EvidenceFrameViewRejection.TooManyRanges,
                    actual = compiled.actual,
                    limit = compiled.limit
                )

            EvidenceFrameFilter.RejectReason.InvalidFilter ->
                EvidenceFrameViewDecision.Reject(
                    reason = EvidenceFrameViewRejection.InvalidFilter,
                    actual = compiled.actual,
                    limit = compiled.limit
                )
        }
    }
}
