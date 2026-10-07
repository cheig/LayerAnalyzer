package com.example.layanalyzer.data

import kotlin.coroutines.cancellation.CancellationException

/**
 * Compiles a set of evidence frame numbers into a Wireshark display filter.
 *
 * The output is meant to be handed to the native engine as a temporary filter
 * (see the evidence-loop export flow). Frames are collapsed into runs so the
 * expression length scales with the number of *runs*, not the number of frames:
 * a 50-frame burst compresses from ~900 characters to ~40 per decision 6 of the
 * evidence-loop design.
 *
 * Syntax mirrors [com.example.layanalyzer.ai.tools.FollowStreamMetadataTool]:
 * single frames use `frame.number==12` (no surrounding spaces) and runs use
 * `(frame.number>=10 && frame.number<=14)`. Multiple segments are joined with
 * `" || "`.
 *
 * Failure semantics are fail-closed: this compiler never silently drops or
 * truncates an input frame. A frame number that cannot describe a real packet
 * (anything `<= 0`, since frame numbers are 1-based) makes the whole compilation
 * fail rather than yielding a filter that would quietly omit evidence.
 *
 * Upper bounds are enforced by [compileOrNull] / [compileValidated] (decision 7 of
 * the evidence-loop design): above [MAX_FRAMES] or [MAX_RANGES] the compilation is
 * *rejected*, never truncated. The original [compile] entry point is intentionally
 * left unbounded and unchanged for the FILTER-01 contract and its existing tests.
 */
object EvidenceFrameFilter {
    /** Merged-range upper bound. Exceeding it rejects the compilation; never truncates. */
    const val MAX_RANGES = 256

    /** Frame-count upper bound, measured after de-duplication. */
    const val MAX_FRAMES = 20_000

    /**
     * Outcome of a bounded compilation. The four states are deliberately
     * distinguishable: empty input, success, a limit rejection, and an invalid
     * filter. Callers must not treat [Rejected] as an empty or partial result.
     */
    sealed interface CompileResult {
        /** Input was empty; there is nothing to select. */
        data object Empty : CompileResult

        /** Compilation succeeded; [filter] passed the configured checks. */
        data class Compiled(
            val filter: String,
            val rangeCount: Int,
            val frameCount: Int
        ) : CompileResult

        /**
         * Compilation was refused. [message] is a display-ready English string that
         * includes the concrete values; [actual] / [limit] are exposed structurally
         * so a UI layer can localise without the data layer depending on Android
         * resources. They are `null` when the rejection is not limit-based
         * (i.e. [RejectReason.InvalidFilter]).
         */
        data class Rejected(
            val reason: RejectReason,
            val message: String,
            val actual: Int? = null,
            val limit: Int? = null
        ) : CompileResult
    }

    /** Why a compilation was refused. */
    enum class RejectReason {
        /** More distinct frames than [MAX_FRAMES]. */
        TooManyFrames,

        /** More merged ranges than [MAX_RANGES]. */
        TooManyRanges,

        /** A non-positive frame number, or the engine rejected the compiled filter. */
        InvalidFilter
    }

    /**
     * Compiles [frames] into a display filter, or `null` when there is nothing
     * to select.
     *
     * Runs are built after sorting and de-duplicating. A run of one frame emits
     * `frame.number==n`; a run of two or more emits
     * `(frame.number>=start && frame.number<=end)`; segments are joined with
     * `" || "`. The order of [frames] does not matter.
     *
     * @return `null` if [frames] is empty; otherwise the display filter.
     * @throws IllegalArgumentException if any frame number is `<= 0`. Non-positive
     *   values are not silently ignored: dropping them would produce a filter
     *   that selects fewer frames than the caller intended, which is unsafe for
     *   evidence export.
     */
    fun compile(frames: Collection<Long>): String? {
        if (frames.isEmpty()) return null

        val sorted = frames.sorted()
        val distinct = ArrayList<Long>(sorted.size)
        var previous = Long.MIN_VALUE
        for (frame in sorted) {
            require(frame > 0L) { "Evidence frame numbers must be positive, got $frame." }
            if (frame != previous) {
                distinct.add(frame)
                previous = frame
            }
        }

        val segments = ArrayList<String>()
        var start = distinct[0]
        var end = distinct[0]
        for (index in 1 until distinct.size) {
            val frame = distinct[index]
            if (frame == end + 1L) {
                end = frame
            } else {
                segments.add(segment(start, end))
                start = frame
                end = frame
            }
        }
        segments.add(segment(start, end))
        return segments.joinToString(" || ")
    }

    /**
     * Bounded, non-throwing variant of the compiler (decision 7).
     *
     * Checks are applied in this fixed order, and the order is part of the
     * contract:
     *
     * 1. **Positivity** — any frame `<= 0` yields
     *    [CompileResult.Rejected] with [RejectReason.InvalidFilter]. Unlike
     *    [compile], this variant **never throws** [IllegalArgumentException].
     * 2. **[MAX_FRAMES]** — the de-duplicated frame count is compared first.
     * 3. **[MAX_RANGES]** — only then is the merged-range count compared.
     *
     * A count exactly equal to a limit is accepted; `limit + 1` is rejected.
     * When a rejection happens, no truncated or partial [CompileResult.Compiled]
     * is ever produced — callers cannot accidentally consume a smaller evidence
     * set than they asked for. Silent truncation is unacceptable for evidence
     * export, so refusal is the only failure mode.
     *
     * @return [CompileResult.Empty] for an empty collection, otherwise a
     *   [CompileResult.Compiled] or [CompileResult.Rejected]. This function does
     *   not itself validate the filter against the engine; use [compileValidated]
     *   when the result is going to be applied.
     */
    fun compileOrNull(frames: Collection<Long>): CompileResult {
        if (frames.isEmpty()) return CompileResult.Empty

        val sorted = frames.sorted()
        val distinct = ArrayList<Long>(sorted.size)
        var previous = Long.MIN_VALUE
        for (frame in sorted) {
            if (frame <= 0L) {
                return CompileResult.Rejected(
                    reason = RejectReason.InvalidFilter,
                    message = "The evidence set contains a non-positive frame number" +
                        " ($frame); nothing was compiled."
                )
            }
            if (frame != previous) {
                distinct.add(frame)
                previous = frame
            }
        }

        val frameCount = distinct.size
        if (frameCount > MAX_FRAMES) {
            return CompileResult.Rejected(
                reason = RejectReason.TooManyFrames,
                message = "The evidence set has $frameCount frames, above the" +
                    " $MAX_FRAMES-frame limit; nothing was compiled.",
                actual = frameCount,
                limit = MAX_FRAMES
            )
        }

        val ranges = collectRanges(distinct)
        val rangeCount = ranges.size
        if (rangeCount > MAX_RANGES) {
            return CompileResult.Rejected(
                reason = RejectReason.TooManyRanges,
                message = "The evidence set has $rangeCount ranges, above the" +
                    " $MAX_RANGES-range limit; nothing was compiled.",
                actual = rangeCount,
                limit = MAX_RANGES
            )
        }

        return CompileResult.Compiled(
            filter = ranges.joinToString(" || ") { segment(it.first, it.second) },
            rangeCount = rangeCount,
            frameCount = frameCount
        )
    }

    /**
     * Compile **and** validate against the engine (decision 8). This is the only
     * sanctioned entry point for callers that need a display filter they can
     * actually apply: a compiled expression must never reach the engine without
     * first passing [validate], which is why validation is folded into the same
     * call rather than left to the caller.
     *
     * Semantics:
     * - [CompileResult.Empty] and [CompileResult.Rejected] are returned as-is;
     *   [validate] is not invoked for them.
     * - On [CompileResult.Compiled] the filter is passed to [validate]. A failure
     *   result — or a validator that *throws* — becomes
     *   [CompileResult.Rejected] with [RejectReason.InvalidFilter]. Validation is
     *   fail-closed: exceptions are converted rather than propagated, so a broken
     *   validator cannot leak a filter through.
     * - Only a successful validation returns the [CompileResult.Compiled].
     *
     * [CancellationException] is re-thrown rather than swallowed, to preserve
     * cooperative cancellation; all other throwables are treated as rejection.
     *
     * The coordinator's `withTemporaryFilter` / `withAgentFilter` validate again
     * internally. That duplication is cheap and intentional: the guarantee here
     * is defence in depth, not that validation happens exactly once. The point is
     * that no path applies a compiled filter unvalidated.
     *
     * [validate] is injected so this logic stays unit-testable without an Android
     * or native dependency; production callers pass
     * `NativeEngine.validateDisplayFilter` (via the coordinator).
     */
    suspend fun compileValidated(
        frames: Collection<Long>,
        validate: suspend (String) -> Result<Unit>
    ): CompileResult {
        val compiled = compileOrNull(frames)
        if (compiled !is CompileResult.Compiled) return compiled

        val validation = try {
            validate(compiled.filter)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            return rejectedByValidation()
        }

        return validation.fold(
            onSuccess = { compiled },
            onFailure = { error ->
                if (error is CancellationException) throw error
                rejectedByValidation()
            }
        )
    }

    private fun rejectedByValidation(): CompileResult.Rejected = CompileResult.Rejected(
        reason = RejectReason.InvalidFilter,
        message = "The compiled evidence filter failed engine validation; nothing was compiled."
    )

    /** Folds sorted, de-duplicated frames into `(start, end)` runs. Non-empty input. */
    private fun collectRanges(distinct: List<Long>): List<Pair<Long, Long>> {
        val ranges = ArrayList<Pair<Long, Long>>()
        var start = distinct[0]
        var end = distinct[0]
        for (index in 1 until distinct.size) {
            val frame = distinct[index]
            if (frame == end + 1L) {
                end = frame
            } else {
                ranges.add(start to end)
                start = frame
                end = frame
            }
        }
        ranges.add(start to end)
        return ranges
    }

    private fun segment(start: Long, end: Long): String =
        if (start == end) {
            "frame.number==$start"
        } else {
            "(frame.number>=$start && frame.number<=$end)"
        }
}
