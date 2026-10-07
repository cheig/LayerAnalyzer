// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

/**
 * One sample the muxer will hand to `MediaMuxer`: a byte range of the ES file,
 * the timestamp it goes out with, and the flags.
 *
 * [offset] and [length] are a *range*, never a copy of the bytes -- QA-03's
 * budget for a ten-minute 720p export is under 50 MB of extra memory, and
 * holding the elementary stream in memory would blow it on its own. The mux
 * loop reads that range out of the file as it writes it.
 *
 * [flags] is a `MediaCodec.BufferInfo` flags value, so it can be handed over
 * unchanged: [KEY_FRAME_FLAG] is `MediaCodec.BUFFER_FLAG_KEY_FRAME`, and a
 * sample that is not a key frame carries 0.
 */
data class VideoSample(
    val offset: Long,
    val length: Int,
    val ptsUs: Long,
    val flags: Int
) {
    val isKeyFrame: Boolean get() = flags and VideoSamplePlan.KEY_FRAME_FLAG != 0
}

/**
 * The `.vidx` records turned into a sample timeline, by a pure function over
 * the entries -- no file is read, nothing is muxed, and the monotonic-PTS
 * repair is a value here rather than a side effect of the write loop, which is
 * the only reason a JVM unit test can pin it.
 *
 * Two things happen on the way from a record to a sample, and the card fixes
 * both:
 *
 *  1. **Key-frame flags.** `flags & 0x01` is a key frame (`kVidxFlagKey` on the
 *     C++ side, bit 0x01 in the file). The other two bits the format defines
 *     (`0x02` corrupt, `0x04` parameter sets) are *not* muxer flags and are
 *     dropped: a corrupt access unit is still written, per NAT-03's
 *     `dropCorrupt=false` default, and MediaMuxer has no "corrupt" flag to set.
 *  2. **Monotonic presentation times.** `MediaMuxer` rejects a non-monotonic
 *     timestamp, and NAT-03 writes PTS as they arrived without reordering them
 *     (B-frames make the arrival order non-monotonic on purpose, and QA-01
 *     compares those bytes against the reference). So a PTS that is equal to or
 *     smaller than the previous *written* one becomes `previous + 1` and is
 *     counted. The comparison is against the repaired value, not the raw one,
 *     because the repaired one is what the muxer saw; that is what makes a run
 *     of three decreasing timestamps come out `previous+1`, `previous+2`,
 *     `previous+3` instead of all landing on the same microsecond.
 *
 * [Rejected] is the fail-closed answer, and its [Rejected.reason] tokens are
 * public so a caller (and the instrumented test) can assert on them the way
 * `AacExporter`'s tokens are asserted on.
 */
sealed interface VideoSamplePlan {

    /**
     * @param samples the timeline, in the order the records were in -- the
     *   order they go into the file, since MPEG4Writer needs chronological
     *   timestamps, not sorted input
     * @param nonMonotonicPtsCount how many timestamps needed the `+1` repair
     * @param durationMs the last written PTS in milliseconds. This is the
     *   presentation span of the stream: NAT-03 numbers PTS from the first
     *   access unit's own timestamp, so the first sample is at 0. `MediaMuxer`
     *   adds the last sample's own length on top of it, so an extractor can
     *   report up to one frame more than this -- see `VideoMuxerTest`, which
     *   asserts exactly that being within one frame.
     */
    data class Ok(
        val samples: List<VideoSample>,
        val nonMonotonicPtsCount: Int,
        val durationMs: Long
    ) : VideoSamplePlan

    /** [reason] is one of the `REASON_*` tokens; the index cannot be muxed. */
    data class Rejected(val reason: String) : VideoSamplePlan

    companion object {
        /**
         * `MediaCodec.BUFFER_FLAG_KEY_FRAME`, spelled out for the same reason
         * [VideoMuxFormat.MIME_H264] is: the pure half of this feature must not
         * touch an `android.*` class. It is numerically the same value as
         * [VidxFile.FLAG_KEY], which is a coincidence of the file format and
         * is why the record's flags are masked before being stored here.
         */
        const val KEY_FRAME_FLAG = 0x01

        /** The index declares no access units at all: nothing to mux. */
        const val REASON_EMPTY_INDEX = "emptyIndex"

        /**
         * A record that describes no sample: a zero or negative length, or a
         * negative offset. The `.vidx` reader reports these faithfully (they
         * are what the file said) and refuses them here, because a zero-length
         * sample is not a frame and `writeSampleData` rejects it.
         */
        const val REASON_BAD_RECORD = "badRecord"

        /**
         * A record whose byte range does not fit in the ES file, i.e. the
         * index and the stream disagree about how big the stream is. That is a
         * truncated or stale pair, and writing the part of it that does fit
         * would produce an MP4 whose last frames are garbage -- so nothing is
         * written.
         */
        const val REASON_SHORT_STREAM = "shortStream"

        /**
         * The plan for [entries] read out of an ES file of [streamBytes] octets.
         *
         * [streamBytes] is passed in rather than read here so this stays a pure
         * function of its arguments; [RtpVideoMuxer] hands it `File.length()`.
         */
        fun of(entries: List<VidxEntry>, streamBytes: Long): VideoSamplePlan {
            if (entries.isEmpty()) return Rejected(REASON_EMPTY_INDEX)

            val samples = ArrayList<VideoSample>(entries.size)
            // The first record is never repaired: `previous` starts below every
            // value a pts can hold, so even a first PTS of 0 is written as 0.
            var previous = Long.MIN_VALUE
            var repaired = 0

            for (entry in entries) {
                if (entry.offset < 0L || entry.length <= 0) {
                    return Rejected(REASON_BAD_RECORD)
                }
                // Written as a subtraction so a huge offset cannot overflow into
                // a range the check would accept.
                if (entry.offset > streamBytes ||
                    entry.length.toLong() > streamBytes - entry.offset
                ) {
                    return Rejected(REASON_SHORT_STREAM)
                }

                var ptsUs = entry.ptsUs
                if (ptsUs <= previous) {
                    ptsUs = previous + 1
                    repaired++
                }
                previous = ptsUs

                val flags = if (entry.flags and VidxFile.FLAG_KEY != 0) KEY_FRAME_FLAG else 0
                samples += VideoSample(
                    offset = entry.offset,
                    length = entry.length,
                    ptsUs = ptsUs,
                    flags = flags
                )
            }

            return Ok(
                samples = samples,
                nonMonotonicPtsCount = repaired,
                durationMs = samples.last().ptsUs / MICROS_PER_MILLI
            )
        }

        private const val MICROS_PER_MILLI = 1_000L
    }
}
