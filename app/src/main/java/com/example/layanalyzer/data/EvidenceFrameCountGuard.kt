// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

/**
 * Result of comparing the evidence set size with the frame count the native
 * session actually shows under the evidence filter.
 *
 * [Mismatch] carries both numbers so the UI layer can localise the message; the
 * data layer never produces display text.
 */
sealed interface EvidenceFrameCountVerification {
    /** The lease selected exactly the expected number of frames. */
    data object Match : EvidenceFrameCountVerification

    /** The lease selected a different number of frames; this capture must not be exported. */
    data class Mismatch(val expected: Int, val actual: Int) : EvidenceFrameCountVerification
}

/**
 * Compares the frame count the export *expects* — the de-duplicated size of the
 * evidence set, [EvidenceFrameFilter.CompileResult.Compiled.frameCount] — with
 * the count the native session *reports* under the temporary evidence filter.
 *
 * This is the execution-side half of the fail-closed evidence semantics: a
 * mismatch means the filter did not select the evidence set, so the capture is
 * not the evidence package's capture and must be refused rather than shipped.
 * Either direction is a failure — fewer frames silently dropped evidence, more
 * frames silently widened it.
 *
 * A non-positive [expected] never matches, even against an identical [actual].
 * The compile step refuses an empty evidence set before this runs, so a zero
 * expectation can only be a caller bug; treating it as a pass would let a
 * degenerate "export nothing" through, so it is refused like any mismatch.
 */
object EvidenceFrameCountGuard {
    fun verify(expected: Int, actual: Int): EvidenceFrameCountVerification =
        if (expected > 0 && expected == actual) {
            EvidenceFrameCountVerification.Match
        } else {
            EvidenceFrameCountVerification.Mismatch(expected = expected, actual = actual)
        }
}
