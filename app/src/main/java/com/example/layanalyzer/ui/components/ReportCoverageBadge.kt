package com.example.layanalyzer.ui.components

import com.example.layanalyzer.ai.agent.EvidenceCoverage
import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.model.AgentReport

/**
 * EVL-UI-07: the report's evidence-coverage receipt as the badge renders it.
 *
 * The counts come from the run record (EVL-COVERAGE-03) and the uncited frame
 * numbers from the host-authored limitation the run appended to its report
 * (EVL-COVERAGE-02). Nothing here reaches for the workspace evidence set: the
 * loop that minted the limitation only knows the frames its own tools returned,
 * and pairing the badge with a different set would print numbers that contradict
 * the very limitation the user reads underneath it.
 */
internal data class ReportCoverageBadgeModel(
    val citedCount: Int,
    val flaggedCount: Int,
    /** Frame numbers the host limitation names verbatim (at most MAX_LISTED_UNCITED_FRAMES). */
    val uncitedFrames: List<Long>,
    /** Uncited frames the host limitation declared but did not list. */
    val uncitedOverflow: Int
) {
    val totalUncited: Int get() = uncitedFrames.size + uncitedOverflow
    val complete: Boolean get() = totalUncited == 0
}

internal object ReportCoverageBadge {

    /**
     * Builds the badge for [report] from the run that produced it, or null when
     * no trustworthy coverage can be shown (fail-closed).
     *
     * Every guard below exists to keep the badge from ever printing a number the
     * host limitation does not also state: a missing run record, a degenerate
     * receipt, a fingerprint that belongs to another capture, or a listed-frame
     * count that disagrees with the run's own counters all suppress the whole
     * badge rather than fabricating one.
     */
    fun from(run: AgentRunRecord?, report: AgentReport): ReportCoverageBadgeModel? {
        // No run record means no coverage receipt: never invent the numbers.
        if (run == null) return null

        val flaggedCount = run.evidenceFlaggedCount
        if (flaggedCount <= 0) return null
        val citedCount = run.evidenceCitedCount
        if (citedCount !in 0..flaggedCount) return null

        // A run record whose capture fingerprint disagrees with the report's
        // belongs to another capture; the two can never be paired. Blank on
        // either side means "unknown", not "mismatch".
        val runFingerprint = run.captureFingerprint.trim()
        val reportFingerprint = report.provenance.captureFingerprint.trim()
        if (runFingerprint.isNotEmpty() &&
            reportFingerprint.isNotEmpty() &&
            runFingerprint != reportFingerprint
        ) {
            return null
        }

        // A clean run appends no host line; the empty accounting below is the
        // expected shape, not a failure to parse.
        val parsed = parseUncitedFrames(report.limitations)
        val listed = parsed?.listed ?: emptyList()
        val overflow = parsed?.overflow ?: 0

        // The decisive consistency check: the host limitation and the badge must
        // agree on how many frames were left uncited. If they do not, nothing
        // is shown — better no badge than a self-contradicting one.
        if (listed.size + overflow != flaggedCount - citedCount) return null

        return ReportCoverageBadgeModel(
            citedCount = citedCount,
            flaggedCount = flaggedCount,
            uncitedFrames = listed,
            uncitedOverflow = overflow
        )
    }

    private data class ParsedUncitedFrames(val listed: List<Long>, val overflow: Int)

    /**
     * The first line in [limitations] that is a host-authored uncited-frame
     * limitation, decoded back into the listed frame numbers and the declared
     * overflow; null when no such line is present.
     *
     * Lines that are not host-authored (the model's own prose) and lines that
     * merely resemble the shape are skipped, never guessed at. Only the exact
     * producer output round-trips — the tests pin this against
     * [EvidenceCoverage.uncitedFramesLimitation] itself.
     */
    private fun parseUncitedFrames(limitations: List<String>): ParsedUncitedFrames? {
        for (raw in limitations) {
            val line = raw.trim()
            if (!line.startsWith(EvidenceCoverage.UNCITED_FRAMES_LIMITATION_MARKER)) continue
            if (!line.endsWith(".")) continue
            val rest = line
                .removeSuffix(".")
                .removePrefix(EvidenceCoverage.UNCITED_FRAMES_LIMITATION_MARKER)
            val middleIndex = rest.indexOf(UNCITED_MIDDLE)
            if (middleIndex < 0) continue

            val listedPart = rest.substring(0, middleIndex)
            val tail = rest.substring(middleIndex + UNCITED_MIDDLE.length).trim()
            val overflow = if (tail.isEmpty()) {
                0
            } else {
                val match = UNCITED_OVERFLOW_NOTE.matchEntire(tail) ?: continue
                match.groupValues[1].toIntOrNull() ?: continue
            }

            val withoutTruncation = listedPart.removeSuffix(UNCITED_TRUNCATION_SUFFIX).trim()
            val frames = if (withoutTruncation.isEmpty()) {
                emptyList()
            } else {
                val parsedFrames = withoutTruncation.split(",").map { it.trim().toLongOrNull() }
                if (parsedFrames.any { it == null }) continue
                parsedFrames.filterNotNull()
            }
            return ParsedUncitedFrames(frames, overflow)
        }
        return null
    }
}

private const val UNCITED_MIDDLE = " were returned by this run's tools but cited by no finding"
private const val UNCITED_TRUNCATION_SUFFIX = ", ..."
private val UNCITED_OVERFLOW_NOTE = Regex("^;\\s*(\\d+)\\s+more uncited frames? not listed$")
