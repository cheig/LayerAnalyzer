// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMuxer
import android.util.Log
import com.example.layanalyzer.data.VideoParamSets
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption

/**
 * Wraps an exported H.264/H.265 elementary stream (RTP5-KT-01) together with
 * the AAC track M4-KT-04 produced, into one MP4 (RTP5-KT-04).
 *
 * It is the last stage of the RTP route, after both halves exist:
 *
 * ```
 * ... -> exportRtpVideo -> [.h264 + .vidx] -+
 *                                            +-> RtpAudioVideoMuxer -> [.mp4]
 * ... -> renderRtpAudioFromPcm -> [wav] -> AacExporter -> [.m4a] -+
 * ```
 *
 * ## The route this takes, and why
 *
 * The card words the audio side as "把渲染好的 WAV 经 `AacExporter`（M4-KT-04）
 * 编码成 AAC 轨". `AacExporter` hands back a finished `.m4a`, not raw access units
 * plus a config record, so the muxer opens that `.m4a` with `MediaExtractor` and
 * feeds its AAC track's samples and its track `MediaFormat` -- which carries the
 * `csd-0` (`AudioSpecificConfig`) `MediaMuxer` needs -- into the combined write.
 * The alternative, encoding AAC here with `MediaCodec`, would duplicate
 * `AacExporter`'s ADTS handling and its `csd-0` construction, and would give the
 * tree two places to keep right. The consequence is that this path is a
 * **remux, not a re-encode**: the audio is untouched, byte for byte, and the
 * cost is a second read of a file that is small next to the video.
 *
 * ## What is whose decision
 *
 *  - The alignment and the interleaving are [AvMuxPlan]'s, a pure function. The
 *    card's anchors -- both tracks start at their first packet's
 *    `firstAbsEpochUs` -- arrive here as two numbers, are turned into an offset
 *    and a merged write sequence, and everything the plan refuses (an empty
 *    track, unsorted timestamps, an implausible offset, an audio track that
 *    falls entirely before the video) is refused before a muxer is built.
 *  - The video track's MIME, size fallback and `csd` arrays are
 *    [VideoMuxFormat]'s, unchanged: this muxer describes its video track exactly
 *    the way KT-01's does, and the samples go in Annex-B with their in-band
 *    parameter sets (**C17**).
 *  - The video samples are KT-01's [VideoSamplePlan], monotonic-PTS repair and
 *    all. That repair is deliberately not repeated here: the video track is the
 *    zero the audio is placed against.
 *
 * ## Two passes over the audio
 *
 * `MediaExtractor` has no random access to a sample: samples are read in the
 * file's order. The plan needs every sample's timestamp and length before it can
 * decide the merged order, so the `.m4a` is walked once to collect them (into a
 * scratch buffer, nothing is kept) and then seeked back to zero for the write.
 * The write then consumes the audio in the plan's order, which is the
 * extractor's own order -- the merge preserves each track's relative order --
 * by advancing one sample at a time, so a sample that the negative-offset rule
 * dropped is stepped over rather than read.
 *
 * `MediaMuxer.stop()` is the step that finalises the file, so it is called
 * inside the `try` on the one path that wrote samples and before the `finally`
 * releases the muxer; a stop on a muxer that wrote nothing throws, and a file
 * that was released without a stop is exactly the unplayable `.mp4` this
 * contract exists to prevent.
 */
class RtpAudioVideoMuxer(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {

    /**
     * Latched cancellation flag, set by [cancel] and read before every step, so
     * a cancel takes effect within one sample. Once set it stays set: a
     * cancelled instance refuses further work rather than silently starting
     * over, so a caller that wants to mux again builds a new muxer.
     */
    @Volatile
    private var cancelRequested = false

    /** Asks a running (or about-to-start) [mux] to stop and clean up. */
    fun cancel() {
        cancelRequested = true
    }

    /**
     * Muxes [esFile] and [audioFile] into [outFile] as an MPEG-4 file with one
     * video track and one audio track.
     *
     * @param esFile the Annex-B elementary stream `exportRtpVideo` wrote
     * @param vidxFile the `.vidx` index that goes with it
     * @param codec the canonical codec id of the stream (`H264` or `H265`);
     *   anything else is refused, see [VideoMuxFormat.mimeFor]
     * @param width the video track width, from the stream's SPS; 0 means unknown
     * @param height the video track height; 0 means unknown
     * @param paramSets the video parameter sets from the stream's SDP (RTP5-KT-00)
     * @param audioFile the `.m4a` `AacExporter` wrote (M4-KT-04)
     * @param outFile the `.mp4` to write; its parent directory must exist and
     *   nothing of it survives a call that does not return [AvMuxResult.Ok]
     * @param videoStartEpochUs the video stream's `firstAbsEpochUs`
     * @param audioStartEpochUs the audio stream's `firstAbsEpochUs`
     *
     * No exception escapes: an unusable codec, missing parameter sets, an
     * unreadable index, an `.m4a` with no AAC track, a pair of tracks that
     * cannot be aligned, a muxer that rejects a sample and a cancelled caller
     * all come back as an [AvMuxResult]. On anything but [AvMuxResult.Ok]
     * [outFile] is removed, so a caller never sees half a file.
     */
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
    ): AvMuxResult {
        var succeeded = false
        try {
            val result = withContext(ioDispatcher) {
                runMux(
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
            }
            succeeded = result is AvMuxResult.Ok
            return result
        } catch (error: Exception) {
            // A real device can fail here in ways no amount of checking
            // anticipates (a muxer whose destination disappeared, an extractor
            // that dies on a sample, a codec list that changed under us). It is
            // still an ordinary answer, not a crash. The exception's own message
            // is carried into the result: it is the only thing that says *why*,
            // and it never contains payload bytes.
            Log.w(TAG, "mux failed", error)
            return AvMuxResult.Failed(error.describe())
        } finally {
            if (!succeeded) {
                outFile.delete()
            }
        }
    }

    private fun runMux(
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
        val startedNs = System.nanoTime()
        if (cancelRequested) {
            return AvMuxResult.Failed(CANCELLED)
        }

        val mime = VideoMuxFormat.mimeFor(codec)
            ?: return AvMuxResult.Failed(UNSUPPORTED_CODEC)

        // The card's fallback, and the reason it is not silent: a stream whose
        // SPS could not be read is still worth muxing, but a caller reading the
        // log has to be able to tell a real 1280x720 from a guessed one.
        val dimensions = VideoMuxFormat.dimensions(width, height)
        if (dimensions.usedFallback) {
            Log.w(
                TAG,
                "mux: ${width}x$height is not a usable video size, " +
                    "using ${dimensions.width}x${dimensions.height}"
            )
        }

        val csd = VideoMuxFormat.codecSpecificData(codec, paramSets)
            ?: return AvMuxResult.Failed(MISSING_PARAMETER_SETS)

        if (!esFile.isFile) {
            return AvMuxResult.Failed(UNREADABLE_STREAM)
        }
        if (!audioFile.isFile) {
            return AvMuxResult.Failed(UNREADABLE_AUDIO)
        }

        val entries = try {
            VidxFile.read(vidxFile).entries
        } catch (error: IOException) {
            // VidxFile.read is the authority on the format and fails closed;
            // every way it can fail is the same answer here.
            Log.i(TAG, "mux: unreadable index (${error.javaClass.simpleName})")
            return AvMuxResult.Failed(UNREADABLE_INDEX)
        }

        val videoPlan = when (val built = VideoSamplePlan.of(entries, esFile.length())) {
            is VideoSamplePlan.Rejected -> return AvMuxResult.Failed(built.reason)
            is VideoSamplePlan.Ok -> built
        }

        val extractor = MediaExtractor()
        try {
            try {
                extractor.setDataSource(audioFile.absolutePath)
            } catch (error: Exception) {
                Log.i(TAG, "mux: unreadable audio (${error.javaClass.simpleName})")
                return AvMuxResult.Failed(UNREADABLE_AUDIO)
            }

            val audioTrack = findAudioTrack(extractor)
                ?: return AvMuxResult.Failed(NO_AUDIO_TRACK)
            extractor.selectTrack(audioTrack)
            val audioFormat = try {
                extractor.getTrackFormat(audioTrack)
            } catch (error: Exception) {
                Log.i(TAG, "mux: unusable audio format (${error.javaClass.simpleName})")
                return AvMuxResult.Failed(UNREADABLE_AUDIO)
            }

            val audioSamples = readAudioSamples(extractor)
                ?: return AvMuxResult.Failed(AUDIO_SAMPLE_UNREADABLE)

            val plan = when (
                val built = AvMuxPlan.of(
                    videoSamples = videoPlan.samples,
                    audioSamples = audioSamples,
                    videoStartEpochUs = videoStartEpochUs,
                    audioStartEpochUs = audioStartEpochUs
                )
            ) {
                is AvMuxPlan.Rejected -> return AvMuxResult.Failed(built.reason)
                is AvMuxPlan.Ok -> built
            }

            // Back to the first sample: the second pass reads the audio in the
            // plan's order, one `advance()` at a time. An `.m4a`'s first sample
            // is a sync sample, so seeking to zero lands on it.
            extractor.seekTo(0L, MediaExtractor.SEEK_TO_CLOSEST_SYNC)

            return writeAll(
                extractor = extractor,
                plan = plan,
                videoPlan = videoPlan,
                videoFormat = MediaFormat
                    .createVideoFormat(mime, dimensions.width, dimensions.height)
                    .apply {
                        setInteger(VideoMuxFormat.KEY_TIME_SCALE, VideoMuxFormat.TIME_SCALE)
                        setByteBuffer(CSD_0, csd.csd0.asDirectBuffer())
                        // H.264 only: H.265 concatenates its three sets into
                        // csd-0 and has no second entry.
                        csd.csd1?.let { setByteBuffer(CSD_1, it.asDirectBuffer()) }
                    },
                audioFormat = audioFormat,
                esFile = esFile,
                outFile = outFile,
                startedNs = startedNs
            )
        } finally {
            runCatching { extractor.release() }
        }
    }

    /**
     * The second pass: open the muxer, add both tracks, and hand every step of
     * the merged plan over in the order the plan fixed.
     */
    private fun writeAll(
        extractor: MediaExtractor,
        plan: AvMuxPlan.Ok,
        videoPlan: VideoSamplePlan.Ok,
        videoFormat: MediaFormat,
        audioFormat: MediaFormat,
        esFile: File,
        outFile: File,
        startedNs: Long
    ): AvMuxResult {
        // The muxer writes the file from its constructor on, so it is the one
        // resource that can leave a `.mp4` behind without ever having written a
        // sample. `mux`'s `finally` deletes the path on every failing path.
        val muxer = try {
            MediaMuxer(outFile.absolutePath, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
        } catch (error: Exception) {
            Log.w(TAG, "mux: cannot open the mp4 destination")
            return AvMuxResult.Failed(MUXER_UNAVAILABLE)
        }

        val audioSteps = plan.steps.filterIsInstance<AvMuxStep.Audio>()
        // One buffer per track, sized to the largest sample of that track and
        // reused sample after sample; `writeSampleData` is synchronous and the
        // writer copies the sample into its own queue, which is what makes the
        // reuse safe and what keeps a long export inside QA-03's memory budget.
        val videoBuffer = ByteBuffer.allocateDirect(videoPlan.samples.maxOf { it.length })
        val audioBuffer = ByteBuffer.allocateDirect(audioSteps.maxOf { it.length })
        val videoInfo = MediaCodec.BufferInfo()
        val audioInfo = MediaCodec.BufferInfo()

        var videoWritten = 0
        var audioWritten = 0
        // The extractor's own cursor: it is always positioned on the sample
        // whose index this holds, and a sample is only read when a step asks
        // for it, so the ones the alignment dropped are stepped over unread.
        var audioCursor = 0

        try {
            val videoTrack = muxer.addTrack(videoFormat)
            val audioTrack = muxer.addTrack(audioFormat)
            muxer.start()

            FileChannel.open(esFile.toPath(), StandardOpenOption.READ).use { channel ->
                for (step in plan.steps) {
                    if (cancelRequested) {
                        return AvMuxResult.Failed(CANCELLED)
                    }
                    when (step) {
                        is AvMuxStep.Video -> {
                            if (!readFully(
                                    channel,
                                    videoBuffer,
                                    step.sample.offset,
                                    step.sample.length
                                )
                            ) {
                                // The plan already checked every range against
                                // the file's length, so this is the file
                                // changing under us. Nothing more is written for
                                // a stream that cannot be read to its end.
                                return AvMuxResult.Failed(TRUNCATED_SAMPLE)
                            }
                            // Annex-B, unchanged: see the class comment and C17.
                            videoInfo.set(0, step.sample.length, step.ptsUs, step.sample.flags)
                            if (!writeSample(muxer, videoTrack, videoBuffer, videoInfo)) {
                                return AvMuxResult.Failed(MUXER_REJECTED_SAMPLE)
                            }
                            videoWritten++
                        }

                        is AvMuxStep.Audio -> {
                            if (step.index < audioCursor) {
                                // The merge preserves each track's order, so
                                // this cannot happen; failing closed rather than
                                // reading the wrong sample keeps a bug here from
                                // becoming an MP4 with the audio shuffled.
                                return AvMuxResult.Failed(AUDIO_SAMPLE_UNREADABLE)
                            }
                            while (audioCursor < step.index) {
                                if (!extractor.advance()) {
                                    return AvMuxResult.Failed(AUDIO_SAMPLE_UNREADABLE)
                                }
                                audioCursor++
                            }
                            val size = extractor.readSampleData(audioBuffer, 0)
                            if (size != step.length) {
                                return AvMuxResult.Failed(AUDIO_SAMPLE_UNREADABLE)
                            }
                            audioBuffer.position(0)
                            audioBuffer.limit(size)
                            // The plan's presentation time, not the extractor's:
                            // that is the whole alignment.
                            audioInfo.set(0, size, step.ptsUs, 0)
                            if (!writeSample(muxer, audioTrack, audioBuffer, audioInfo)) {
                                return AvMuxResult.Failed(MUXER_REJECTED_SAMPLE)
                            }
                            audioWritten++
                        }
                    }
                }
            }

            // The step that finalises the file. `stop()` is called here, on the
            // one path that wrote samples, and never in the `finally`: a stop on
            // a muxer that has written nothing throws, and a stop that ran after
            // a failure would leave a file that looks finished.
            muxer.stop()
            Log.i(
                TAG,
                "mux: $videoWritten video + $audioWritten audio samples " +
                    "dropped=${plan.droppedAudioSamples} offset=${plan.offsetUs}us " +
                    "duration=${plan.durationMs}ms " +
                    "take=${(System.nanoTime() - startedNs) / 1_000_000}ms"
            )
            return AvMuxResult.Ok(
                mp4Path = outFile.absolutePath,
                videoFrames = videoWritten,
                audioSamples = audioWritten,
                droppedAudioSamples = plan.droppedAudioSamples,
                offsetUs = plan.offsetUs,
                durationMs = plan.durationMs,
                nonMonotonicPtsCount = videoPlan.nonMonotonicPtsCount
            )
        } finally {
            // Every path out -- success, fail-closed, cancel, or an exception on
            // its way here -- releases the muxer exactly once, after the `stop()`
            // above when there was one. The muxer is released without `stop()` on
            // the failing paths, which is what leaves the file unusable; `mux`
            // deletes it.
            runCatching { muxer.release() }
        }
    }

    /** Hands one sample to the muxer, answering false when it is refused. */
    private fun writeSample(
        muxer: MediaMuxer,
        trackIndex: Int,
        buffer: ByteBuffer,
        info: MediaCodec.BufferInfo
    ): Boolean = try {
        muxer.writeSampleData(trackIndex, buffer, info)
        true
    } catch (error: Exception) {
        Log.w(TAG, "mux: the muxer rejected a sample")
        false
    }

    /**
     * The index of the `.m4a`'s AAC track, or null when the file has none.
     *
     * The MIME is `AacExporter.MIME_AAC` and not a second literal: that constant
     * is what `AacExporter` encoded with and what `MediaExtractor` reports for
     * the track of the file it writes, so the two halves cannot drift.
     */
    private fun findAudioTrack(extractor: MediaExtractor): Int? {
        for (index in 0 until extractor.trackCount) {
            val mime = runCatching {
                extractor.getTrackFormat(index).getString(MediaFormat.KEY_MIME)
            }.getOrNull()
            if (mime == AacExporter.MIME_AAC) return index
        }
        return null
    }

    /**
     * The `.m4a`'s samples in the extractor's own order, or null when one of
     * them cannot be read.
     *
     * The bytes are read into a scratch buffer and dropped: what the plan needs
     * is each sample's timestamp and length, and `readSampleData` is the only
     * way to get them that works on every API level this app supports
     * (`getSampleSize` arrived in API 28, `minSdk` is 26). The second pass reads
     * the audio again for real.
     */
    private fun readAudioSamples(extractor: MediaExtractor): List<AacSample>? {
        val scratch = ByteBuffer.allocateDirect(MAX_AAC_SAMPLE_BYTES)
        val samples = ArrayList<AacSample>()
        while (true) {
            val size = extractor.readSampleData(scratch, 0)
            if (size < 0) break
            samples += AacSample(
                index = samples.size,
                ptsUs = extractor.sampleTime,
                length = size
            )
            if (!extractor.advance()) break
        }
        return samples
    }

    /**
     * Fills [buffer] with the [length] octets of `esFile` starting at [offset],
     * leaving it ready to hand to `writeSampleData`: position 0, limit `length`.
     *
     * A positional read into a direct buffer, so the sample is never copied
     * through a `ByteArray` and the buffer's own position is never left
     * mid-stream. Returns false on a short read, which for a regular file means
     * the file ended early.
     */
    private fun readFully(
        channel: FileChannel,
        buffer: ByteBuffer,
        offset: Long,
        length: Int
    ): Boolean {
        buffer.clear()
        buffer.limit(length)
        var position = offset
        while (buffer.hasRemaining()) {
            val read = channel.read(buffer, position)
            if (read <= 0) return false
            position += read
        }
        buffer.flip()
        return true
    }

    /** A direct copy of [this]: `MediaMuxer` reads both `csd` entries by pointer. */
    private fun ByteArray.asDirectBuffer(): ByteBuffer =
        ByteBuffer.allocateDirect(size).also { buffer ->
            buffer.put(this)
            buffer.position(0)
        }

    /** `ExceptionClass: message`, trimmed to something a UI can show. */
    private fun Exception.describe(): String {
        val message = message?.replace('\n', ' ')?.trim().orEmpty()
        return if (message.isEmpty()) {
            javaClass.simpleName
        } else {
            "${javaClass.simpleName}: ${message.take(MAX_REASON_CHARS)}"
        }
    }

    companion object {
        private const val TAG = "RtpAudioVideoMuxer"
        private const val MAX_REASON_CHARS = 160

        /** The `MediaFormat` keys the codec-specific data goes under. */
        const val CSD_0 = "csd-0"
        const val CSD_1 = "csd-1"

        /** Short tokens the contract freezes, as [RtpVideoMuxer] does. */
        const val CANCELLED = "cancelled"

        /** A codec id this muxer has no MP4 sample description for. */
        const val UNSUPPORTED_CODEC = "unsupportedCodec"

        /** SDP parameter sets the video track cannot be described without. */
        const val MISSING_PARAMETER_SETS = "missingParameterSets"

        /** The ES file is missing or unreadable. */
        const val UNREADABLE_STREAM = "unreadableStream"

        /** The `.vidx` is missing, truncated, or not a `.vidx`. */
        const val UNREADABLE_INDEX = "unreadableIndex"

        /** The `.m4a` is missing, unreadable, or not a file `MediaExtractor` can open. */
        const val UNREADABLE_AUDIO = "unreadableAudio"

        /** `MediaExtractor` opened the `.m4a` but found no AAC track in it. */
        const val NO_AUDIO_TRACK = "noAudioTrack"

        /** A sample of the `.m4a` could not be read, or did not read back the same size. */
        const val AUDIO_SAMPLE_UNREADABLE = "audioSampleUnreadable"

        /** The ES ended before a sample's byte range did. */
        const val TRUNCATED_SAMPLE = "truncatedSample"

        /**
         * The largest AAC access unit the first pass will read into its scratch
         * buffer. A 64 kbps AAC frame is well under a kilobyte, so this is the
         * bound that keeps a corrupt `.m4a` from allocating whatever its sample
         * table claims: a sample that does not fit fails the read (and comes
         * back as `audioSampleUnreadable`, or as a `Failed` carrying the
         * platform's own message) rather than being trusted.
         */
        private const val MAX_AAC_SAMPLE_BYTES = 64 * 1024

        private const val MUXER_UNAVAILABLE = "muxerUnavailable"
        private const val MUXER_REJECTED_SAMPLE = "muxerRejectedSample"
    }
}
