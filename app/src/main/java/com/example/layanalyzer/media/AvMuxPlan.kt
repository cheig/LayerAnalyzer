// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

/**
 * One AAC access unit, as `MediaExtractor` reported it out of the `.m4a`
 * `AacExporter` wrote (RTP5-KT-04).
 *
 * [index] is the sample's position in the extractor's own order -- the order it
 * is read back in, which is the order the file stores it in. The muxer needs it
 * because `MediaExtractor` has no random access to a sample: the merged plan
 * says "write audio sample 17 here", and the writer reaches it by advancing
 * [index] times. [length] is what the reader actually returned, which is also
 * what sizes the sample buffer; [ptsUs] is the extractor's own timestamp, and
 * it starts at zero because `AacExporter` hands the first PCM block a timestamp
 * of zero.
 */
data class AacSample(
    val index: Int,
    val ptsUs: Long,
    val length: Int
)

/**
 * One step of the merged write sequence: the order the two tracks' samples are
 * handed to `MediaMuxer`.
 *
 * A sealed type rather than a tagged struct, because the two tracks do not
 * carry the same thing: a video step is a byte *range* of the elementary stream
 * ([VideoSample], read from the ES as it is written), while an audio step is a
 * sample *index* into the `.m4a` ([Audio], reached by advancing the extractor).
 * Flattening them would need a field that means two different things.
 */
sealed interface AvMuxStep {
    /** The presentation time this step is written with, in microseconds. */
    val ptsUs: Long

    /** A video access unit out of the elementary stream. */
    data class Video(val sample: VideoSample) : AvMuxStep {
        override val ptsUs: Long get() = sample.ptsUs
    }

    /** The [index]-th AAC access unit of the `.m4a`. */
    data class Audio(
        val index: Int,
        val length: Int,
        override val ptsUs: Long
    ) : AvMuxStep
}

/**
 * The two tracks merged into one time-ordered write sequence, by a pure function
 * over the samples -- nothing here reads a file, opens a codec or touches
 * `MediaMuxer`, which is the only reason a JVM unit test can pin the alignment
 * and the interleaving.
 *
 * ## The alignment rule (the card's "两路都以首包的 firstAbsEpochUs 为基准")
 *
 * Both tracks are anchored on their own first packet's `firstAbsEpochUs`, and
 * the sign convention is fixed here once and for all:
 *
 * ```
 * offsetUs = audioStartEpochUs - videoStartEpochUs
 * ```
 *
 * so a **positive** offset means the audio started *after* the video and a
 * **negative** one means it started *before*. The video track is the zero of the
 * file's timeline (NAT-03 numbers an access unit's PTS from the first one, so
 * the first video sample is at 0), and an audio sample whose own timeline
 * position is `t` is written at `t + offsetUs`.
 *
 * Worked example, video first: video anchor 1 000 000 µs, audio anchor
 * 1 500 000 µs ⇒ `offsetUs = +500 000`. The `.m4a`'s first sample (its own time
 * 0) is written at PTS 500 000 -- the audio starts half a second into the video,
 * which is when its first packet arrived. The card's "偏移量作为音频轨第一个样本
 * 的 PTS" is exactly this, and it is why [Ok.firstAudioPtsUs] equals
 * [Ok.offsetUs] whenever the `.m4a`'s own timeline starts at zero -- which is
 * what `AacExporter` writes, since it hands its first PCM block a timestamp of
 * zero. (Every sample is placed at *its own* time plus the offset rather than
 * the whole track being shifted so that its first sample lands on the offset:
 * the two are the same statement when that first time is zero, and the former
 * stays correct if a device's extractor ever reported a priming delay instead,
 * where moving the track would move the audio itself.)
 *
 * ## The negative offset, which the card does not cover
 *
 * When the audio started first, the raw offset is negative and `MediaMuxer`
 * refuses a negative presentation time (`MPEG4Writer` rejects a sample whose
 * timestamp is not strictly increasing from its track's start). The card fixes
 * the audio track's first PTS **as the offset**, which argues against moving the
 * video track to make room, so this plan takes the other branch and **drops the
 * leading audio samples that would fall before the video's zero, and counts
 * them** in [Ok.droppedAudioSamples]. Every remaining sample keeps its position
 * on the shared timeline, so nothing is stretched and the audio stays where it
 * belongs; only the part that began before the video has anything to be shown
 * against is gone. [Ok.firstAudioPtsUs] is then the first *written* sample's
 * presentation time, which is the smallest one that is not negative -- not the
 * raw offset.
 *
 * Worked example, audio first: video anchor 2 000 000 µs, audio anchor
 * 1 700 000 µs ⇒ `offsetUs = -300 000`. With 48 kHz AAC (1024 samples a frame,
 * 21 333 µs each) the sample times are 0, 21 333, 42 666, …; the sample at
 * 298 662 is still negative at -1 338, and the one at 319 995 lands at +19 995.
 * So 15 samples are dropped and `firstAudioPtsUs` is 19 995. No written sample
 * is ever negative, by construction: a sample is dropped exactly when
 * `sample.ptsUs + offsetUs < 0`.
 *
 * ## Interleaving
 *
 * `MediaMuxer`'s `MPEG4Writer` wants samples handed over in time order; writing
 * a whole track and then the other produces a file that plays badly or not at
 * all. Both inputs are therefore required to be strictly increasing (which they
 * are: `VideoSamplePlan` repairs the video's timestamps, and `MediaExtractor`
 * hands audio out in the sample table's order), and a two-way merge keeps that
 * order. **On a tie the video step goes first**: the video track is the file's
 * timeline, so at the instant both tracks have something, the frame is what the
 * timestamp names -- and it keeps the opening of a combined file identical to
 * the opening of the video-only file KT-01 writes.
 *
 * ## Refusals
 *
 * The whole plan is refused rather than partly written, and [Rejected.reason]'s
 * tokens are public so a caller (and the instrumented test) can assert on them:
 * an empty track, a track whose timestamps are not strictly increasing (the
 * merge's precondition), an offset too large to be an offset at all, and an
 * audio track that the negative-offset rule would empty completely.
 */
sealed interface AvMuxPlan {

    /**
     * @param steps the merged write sequence
     * @param offsetUs `audioStartEpochUs - videoStartEpochUs`, as the card words
     *   it -- reported raw, so a caller can log the real gap even when part of
     *   the audio had to be dropped
     * @param droppedAudioSamples how many leading audio samples the
     *   negative-offset rule removed; zero for a non-negative offset
     * @param firstAudioPtsUs the presentation time of the first audio sample
     *   that is written, never negative
     * @param videoSamples how many video access units are in [steps]
     * @param audioSamples how many audio samples are in [steps] (the kept ones,
     *   i.e. the `.m4a`'s count minus [droppedAudioSamples])
     * @param durationMs the largest written presentation time in milliseconds,
     *   over both tracks. `MediaMuxer` adds the last sample's own span on top of
     *   it, so a player can report up to one frame more.
     */
    data class Ok(
        val steps: List<AvMuxStep>,
        val offsetUs: Long,
        val droppedAudioSamples: Int,
        val firstAudioPtsUs: Long,
        val videoSamples: Int,
        val audioSamples: Int,
        val durationMs: Long
    ) : AvMuxPlan

    /** [reason] is one of the `REASON_*` tokens; the pair cannot be muxed. */
    data class Rejected(val reason: String) : AvMuxPlan

    companion object {
        /** The video side has no samples at all: there is nothing to combine. */
        const val REASON_EMPTY_VIDEO = "emptyVideo"

        /** The audio side has no samples at all: the `.m4a` is empty. */
        const val REASON_EMPTY_AUDIO = "emptyAudio"

        /** The video samples are not strictly increasing, so the merge is illegal. */
        const val REASON_UNSORTED_VIDEO = "unsortedVideo"

        /** The audio samples are not strictly increasing, same reason. */
        const val REASON_UNSORTED_AUDIO = "unsortedAudio"

        /**
         * The two anchors are absurdly far apart. An hour is not a call's
         * audio-to-video gap, and the value that produces it is a broken anchor:
         * a stream whose `firstAbsEpochUs` never made it out of the native
         * layer reads as 0, which would put the audio (or the video) some 55
         * years away from the other and write a file with a duration nothing can
         * play. Refusing is the fail-closed answer.
         */
        const val REASON_IMPLAUSIBLE_OFFSET = "implausibleOffset"

        /**
         * The negative-offset rule dropped every audio sample: the whole track
         * sits before the video's first frame, so there is no audio track left
         * to add.
         */
        const val REASON_AUDIO_ALL_DROPPED = "audioAllDropped"

        /**
         * An audio sample time that is not a time: one whose shift by the offset
         * is still negative after the drop rule had already kept it, which means
         * the `.m4a`'s own timestamp was absurd enough (hundreds of millennia) to
         * overflow the addition. Refusing is the fail-closed answer, because the
         * one thing this plan promises is that no written sample is negative.
         */
        const val REASON_AUDIO_TIME_RANGE = "audioTimeRange"

        /** An hour in microseconds: the largest offset that can be an offset. */
        const val MAX_TRACK_OFFSET_US = 3_600_000_000L

        private const val MICROS_PER_MILLI = 1_000L

        /**
         * The plan for [videoSamples] and [audioSamples] anchored on
         * [videoStartEpochUs] and [audioStartEpochUs].
         *
         * @param videoSamples KT-01's samples, already repaired by
         *   [VideoSamplePlan.of] -- this function does not repair them again,
         *   because the video track is the zero the audio is placed against and
         *   moving its first sample off zero would move that zero
         * @param audioSamples the `.m4a`'s samples in extractor order, whose
         *   times are relative to the audio's own first sample
         */
        fun of(
            videoSamples: List<VideoSample>,
            audioSamples: List<AacSample>,
            videoStartEpochUs: Long,
            audioStartEpochUs: Long
        ): AvMuxPlan {
            if (videoSamples.isEmpty()) return Rejected(REASON_EMPTY_VIDEO)
            if (audioSamples.isEmpty()) return Rejected(REASON_EMPTY_AUDIO)
            if (!videoSamples.isStrictlyIncreasing { it.ptsUs }) {
                return Rejected(REASON_UNSORTED_VIDEO)
            }
            if (!audioSamples.isStrictlyIncreasing { it.ptsUs }) {
                return Rejected(REASON_UNSORTED_AUDIO)
            }

            val offsetUs = audioStartEpochUs - videoStartEpochUs
            if (offsetUs > MAX_TRACK_OFFSET_US || offsetUs < -MAX_TRACK_OFFSET_US) {
                return Rejected(REASON_IMPLAUSIBLE_OFFSET)
            }

            // The negative-offset rule. `audioSamples` is strictly increasing, so
            // the samples it removes are a prefix and the comparison is a
            // subtraction rather than an addition -- an anchor of
            // `Long.MIN_VALUE` cannot overflow into a plausible-looking time.
            var dropped = 0
            while (dropped < audioSamples.size && audioSamples[dropped].ptsUs < -offsetUs) {
                dropped++
            }
            if (dropped == audioSamples.size) return Rejected(REASON_AUDIO_ALL_DROPPED)

            val kept = audioSamples.subList(dropped, audioSamples.size)
            // The shift, computed once for every kept sample. A time that is not a
            // time -- an `stts` claiming hundreds of millennia, or a shift that
            // overflowed the addition -- is refused here rather than written,
            // because "no written sample is negative" is a promise this function
            // makes and this addition is the one place that could break it.
            val shifted = ArrayList<Long>(kept.size)
            for (sample in kept) {
                val ptsUs = sample.ptsUs + offsetUs
                if (ptsUs < 0L) return Rejected(REASON_AUDIO_TIME_RANGE)
                shifted += ptsUs
            }

            val steps = ArrayList<AvMuxStep>(videoSamples.size + kept.size)
            var videoIndex = 0
            var audioIndex = 0
            while (videoIndex < videoSamples.size && audioIndex < kept.size) {
                val video = videoSamples[videoIndex]
                val audio = kept[audioIndex]
                val audioPtsUs = shifted[audioIndex]
                // Video first on a tie: see the class comment.
                if (video.ptsUs <= audioPtsUs) {
                    steps += AvMuxStep.Video(video)
                    videoIndex++
                } else {
                    steps += AvMuxStep.Audio(audio.index, audio.length, audioPtsUs)
                    audioIndex++
                }
            }
            while (videoIndex < videoSamples.size) {
                steps += AvMuxStep.Video(videoSamples[videoIndex++])
            }
            while (audioIndex < kept.size) {
                val audio = kept[audioIndex]
                steps += AvMuxStep.Audio(audio.index, audio.length, shifted[audioIndex])
                audioIndex++
            }

            return Ok(
                steps = steps,
                offsetUs = offsetUs,
                droppedAudioSamples = dropped,
                firstAudioPtsUs = shifted.first(),
                videoSamples = videoSamples.size,
                audioSamples = kept.size,
                durationMs = steps.maxOf { it.ptsUs } / MICROS_PER_MILLI
            )
        }

        private fun <T> List<T>.isStrictlyIncreasing(key: (T) -> Long): Boolean {
            for (index in 1 until size) {
                if (key(this[index]) <= key(this[index - 1])) return false
            }
            return true
        }
    }
}
