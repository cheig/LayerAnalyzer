package com.example.layanalyzer.media

import com.example.layanalyzer.data.VideoParamSets
import java.io.File

/**
 * Outcome of one [AudioVideoMuxer.mux] call (RTP5-KT-04).
 *
 *  - [Ok] the `.mp4` was written and carries the values reported here
 *  - [Failed] everything else: a codec this muxer cannot describe, parameter
 *    sets it does not have, an index or an ES it cannot read, an `.m4a` with no
 *    AAC track, two tracks that cannot be aligned, a muxer that rejected a
 *    sample, a cancelled caller. A [Failed] never leaves a file behind, so a
 *    caller that sees one has nothing to clean up.
 *
 * It is a separate type from [VideoMuxResult] rather than a reuse of it: that
 * one reports one track's frames, and this one has an audio track to report on
 * too -- how many of its samples were written and how many the alignment rule
 * had to drop, which is the whole point of the feature and has nowhere to live
 * in the video-only shape.
 */
sealed interface AvMuxResult {
    /**
     * @param mp4Path the file that was written
     * @param videoFrames how many video access units were handed to the muxer,
     *   i.e. the number of `.vidx` records that became samples
     * @param audioSamples how many AAC samples were written
     * @param droppedAudioSamples how many leading AAC samples fell before the
     *   video's zero and were removed (`AvMuxPlan`)
     * @param offsetUs `audioStartEpochUs - videoStartEpochUs`: the alignment the
     *   two tracks were written with
     * @param durationMs the largest written presentation time in milliseconds;
     *   `MediaMuxer` adds one sample's own span on top, so a player reports up
     *   to one frame more
     * @param nonMonotonicPtsCount how many video timestamps needed the `+1`
     *   repair; it comes from KT-01's [VideoSamplePlan], which is where the
     *   repair happens
     */
    data class Ok(
        val mp4Path: String,
        val videoFrames: Int,
        val audioSamples: Int,
        val droppedAudioSamples: Int,
        val offsetUs: Long,
        val durationMs: Long,
        val nonMonotonicPtsCount: Int
    ) : AvMuxResult

    data class Failed(val message: String) : AvMuxResult
}

/**
 * RTP5-KT-04: the seam between `RtpViewModel` and the combined muxer.
 *
 * It exists for the same reason [VideoMuxer] does: the JVM unit tests of the
 * view model must be able to see *that* the ES, its index and the encoded audio
 * were handed to a muxer, with which codec/size/parameter sets, with which two
 * anchors and towards which path -- and [RtpAudioVideoMuxer] cannot run there at
 * all, because it is built on `MediaMuxer` and `MediaExtractor`.
 *
 * The two anchors travel as parameters rather than being looked up here: the
 * card's rule is that both tracks are anchored on their first packet's
 * `firstAbsEpochUs`, and those two numbers belong to the two `RtpStream`s the
 * caller holds. A muxer that went looking for them itself would be reading
 * state it has no business owning.
 */
interface AudioVideoMuxer {
    suspend fun mux(
        esFile: File,
        vidxFile: File,
        codec: String,
        width: Int,
        height: Int,
        paramSets: VideoParamSets,
        audioFile: File,
        outFile: File,
        videoStartEpochUs: Long,
        audioStartEpochUs: Long
    ): AvMuxResult

    /** Asks a running [mux] to stop and clean up; a no-op when nothing is running. */
    fun cancel()
}

/**
 * The production [AudioVideoMuxer]: a fresh [RtpAudioVideoMuxer] per call.
 *
 * Fresh per call for the same reason [PlatformVideoMuxer] is: the muxer's
 * `cancel` latches, so a shared instance would let one cancelled combination
 * poison every one after it with `cancelled`. The instance a call is running on
 * is remembered only so [cancel] has something to reach.
 */
class PlatformAudioVideoMuxer : AudioVideoMuxer {

    @Volatile
    private var active: RtpAudioVideoMuxer? = null

    override suspend fun mux(
        esFile: File,
        vidxFile: File,
        codec: String,
        width: Int,
        height: Int,
        paramSets: VideoParamSets,
        audioFile: File,
        outFile: File,
        videoStartEpochUs: Long,
        audioStartEpochUs: Long
    ): AvMuxResult {
        val muxer = RtpAudioVideoMuxer()
        active = muxer
        try {
            return muxer.mux(
                esFile = esFile,
                vidxFile = vidxFile,
                codec = codec,
                width = width,
                height = height,
                paramSets = paramSets,
                audioFile = audioFile,
                outFile = outFile,
                videoStartEpochUs = videoStartEpochUs,
                audioStartEpochUs = audioStartEpochUs
            )
        } finally {
            // Only clear it when this call is still the active one, so a cancel
            // that arrives for a newer export is never dropped.
            if (active === muxer) active = null
        }
    }

    override fun cancel() {
        active?.cancel()
    }
}
