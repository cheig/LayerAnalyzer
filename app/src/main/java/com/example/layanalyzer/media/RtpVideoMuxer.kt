// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import android.media.MediaCodec
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
 * Outcome of one [RtpVideoMuxer.mux] call.
 *
 *  - [Ok] the `.mp4` was written and carries the values reported here
 *  - [Failed] everything else: a codec this muxer cannot describe, parameter
 *    sets it does not have, an index it cannot read, an index whose byte ranges
 *    do not fit the elementary stream, a muxer that rejected a sample, a
 *    cancelled caller. A [Failed] never leaves a file behind, so a caller that
 *    sees one has nothing to clean up.
 */
sealed interface VideoMuxResult {
    /**
     * @param mp4Path the file that was written
     * @param frames how many access units were handed to the muxer, i.e. the
     *   number of `.vidx` records that became samples
     * @param durationMs the last sample's presentation time in milliseconds;
     *   `MediaMuxer` adds one sample's own span on top, so a player reports up
     *   to one frame more
     * @param nonMonotonicPtsCount how many timestamps were not strictly
     *   increasing and had to be pushed forward by a microsecond (the card's
     *   "结果里返回 nonMonotonicPtsCount"). It is the last field with a default
     *   of 0 so that the frozen three-argument shape of [Ok] -- `(mp4Path,
     *   frames, durationMs)` -- still compiles for callers written against the
     *   card, including the card's own `VideoMuxResult.Ok(...)` examples.
     */
    data class Ok(
        val mp4Path: String,
        val frames: Int,
        val durationMs: Long,
        val nonMonotonicPtsCount: Int = 0
    ) : VideoMuxResult

    data class Failed(val message: String) : VideoMuxResult
}

/**
 * Wraps an already-exported H.264/H.265 elementary stream in an MP4 (RTP5-KT-01).
 *
 * It is the last stage of the RTP video route, after the ES and its index
 * exist:
 *
 * ```
 * ... -> exportRtpVideo -> [.h264 + .vidx] -> RtpVideoMuxer -> [.mp4]
 * ```
 *
 * It is deliberately the mirror image of [AacExporter], the audio half of the
 * same milestone: the same `ioDispatcher` constructor parameter, the same
 * latched `@Volatile` cancellation, the same `sealed interface` result, the
 * same promise that no exception escapes, and the same rule that a call which
 * does not return [VideoMuxResult.Ok] removes the file it was writing.
 *
 * What it does, and what it deliberately does not:
 *
 *  - The input is described entirely by `.vidx`: how many access units there
 *    are, where each one starts in the ES, how long it is, when it is shown and
 *    whether it is a key frame. The index is read by [VidxFile], the Kotlin
 *    mirror of the C++ writer, and nothing here re-scans the ES for NAL
 *    boundaries -- NAT-03 already did that, and QA-01's byte comparison rests
 *    on the container not second-guessing it.
 *  - **The samples go in as they are, Annex-B, start codes and all** (C17).
 *    `MediaMuxer`'s `MPEG4Writer` converts Annex-B to the length-prefixed form
 *    a sample description box describes, so converting here would corrupt every
 *    sample; `task_rtp_m5_video.md` section 5.2 says otherwise ("把 Annex B 转成
 *    4 字节长度前缀") and `cards/m5.md` is the authority that overrides it, as
 *    README section 2's precedence rule says. **In-band parameter sets are kept
 *    for the same reason**: 5.2 wants them stripped, the card says "**不要**删除
 *    带内的参数集 NAL（保持与 `exportRtpVideo` 的输出一致）", and the exported
 *    stream is what QA-01 compares byte for byte. All this muxer does is say in
 *    `csd-0`/`csd-1` what the stream's parameter sets are (RTP5-KT-00's SDP
 *    values -- it does not go looking in the ES for them either).
 *  - The decisions -- the MIME, the size with its 1280x720 fallback, the `csd`
 *    arrays, the per-sample timeline with its monotonic-PTS repair -- are
 *    [VideoMuxFormat]'s and [VideoSamplePlan]'s, which are pure Kotlin and are
 *    pinned by the JVM unit tests. What is left here is reading byte ranges out
 *    of the file and handing them to [MediaMuxer].
 *  - The elementary stream is never held in memory: the plan is a list of
 *    offsets and lengths and one direct buffer, sized to the largest access
 *    unit, is reused for every sample (QA-03's ten-minute 720p budget is under
 *    50 MB of extra memory).
 *  - `MediaMuxer.stop()` is the step that finalises the file, so it is called
 *    inside the `try` on the one path that wrote samples and before the
 *    `finally` releases the muxer; a stop on a muxer that wrote nothing throws,
 *    and a file that was released without a stop is exactly the unplayable
 *    `.mp4` this contract exists to prevent.
 */
class RtpVideoMuxer(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {

    /**
     * Latched cancellation flag, set by [cancel] and read before every sample,
     * so a cancel takes effect within one access unit. Once set it stays set: a
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
     * Muxes [esFile] into [outFile] as an MPEG-4 file with one video track.
     *
     * @param esFile the Annex-B elementary stream `exportRtpVideo` wrote
     * @param vidxFile the `.vidx` index that goes with it
     * @param codec the canonical codec id of the stream (`H264` or `H265`);
     *   anything else is refused, see [VideoMuxFormat.mimeFor]
     * @param width the track width, from the stream's SPS; 0 means unknown
     * @param height the track height; 0 means unknown
     * @param paramSets the parameter sets from the stream's SDP (RTP5-KT-00)
     * @param outFile the `.mp4` to write; its parent directory must exist and
     *   nothing of it survives a call that does not return [VideoMuxResult.Ok]
     *
     * No exception escapes: an unusable codec, missing parameter sets, an
     * unreadable index, a range that does not fit the stream, a muxer that
     * rejects a sample and a cancelled caller all come back as a
     * [VideoMuxResult]. On anything but [VideoMuxResult.Ok] [outFile] is
     * removed, so a caller never sees half a file.
     */
    suspend fun mux(
        esFile: File,
        vidxFile: File,
        codec: String,
        width: Int,
        height: Int,
        paramSets: VideoParamSets,
        outFile: File,
        onProgress: ((done: Int, total: Int) -> Unit)? = null
    ): VideoMuxResult {
        var succeeded = false
        try {
            val result = withContext(ioDispatcher) {
                runMux(esFile, vidxFile, codec, width, height, paramSets, outFile, onProgress)
            }
            succeeded = result is VideoMuxResult.Ok
            return result
        } catch (error: Exception) {
            // A real device can fail here in ways no amount of checking
            // anticipates (a muxer whose destination disappeared, a size the
            // platform refuses to describe, an index that vanished between the
            // read and the write). It is still an ordinary answer, not a crash.
            // The exception's own message is carried into the result: it is the
            // only thing that says *why*, and it never contains payload bytes.
            Log.w(TAG, "mux failed", error)
            return VideoMuxResult.Failed(error.describe())
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
        outFile: File,
        onProgress: ((done: Int, total: Int) -> Unit)?
    ): VideoMuxResult {
        val startedNs = System.nanoTime()
        if (cancelRequested) {
            return VideoMuxResult.Failed(CANCELLED)
        }

        val mime = VideoMuxFormat.mimeFor(codec)
            ?: return VideoMuxResult.Failed(UNSUPPORTED_CODEC)

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
            ?: return VideoMuxResult.Failed(MISSING_PARAMETER_SETS)

        if (!esFile.isFile) {
            return VideoMuxResult.Failed(UNREADABLE_STREAM)
        }

        val entries = try {
            VidxFile.read(vidxFile).entries
        } catch (error: IOException) {
            // VidxFile.read is the authority on the format and fails closed;
            // every way it can fail is the same answer here.
            Log.i(TAG, "mux: unreadable index (${error.javaClass.simpleName})")
            return VideoMuxResult.Failed(UNREADABLE_INDEX)
        }

        val plan = when (val built = VideoSamplePlan.of(entries, esFile.length())) {
            is VideoSamplePlan.Rejected -> return VideoMuxResult.Failed(built.reason)
            is VideoSamplePlan.Ok -> built
        }

        val format = MediaFormat.createVideoFormat(mime, dimensions.width, dimensions.height)
            .apply {
                setInteger(VideoMuxFormat.KEY_TIME_SCALE, VideoMuxFormat.TIME_SCALE)
                setByteBuffer(CSD_0, csd.csd0.asDirectBuffer())
                // H.264 only: H.265 concatenates its three sets into csd-0 and
                // has no second entry.
                csd.csd1?.let { setByteBuffer(CSD_1, it.asDirectBuffer()) }
            }

        // The muxer writes the file from its constructor on, so it is the one
        // resource that can leave a `.mp4` behind without ever having written a
        // sample. `mux`'s `finally` deletes the path on every failing path.
        val muxer = try {
            MediaMuxer(outFile.absolutePath, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
        } catch (error: Exception) {
            Log.w(TAG, "mux: cannot open the mp4 destination")
            return VideoMuxResult.Failed(MUXER_UNAVAILABLE)
        }

        // One buffer for the whole export, sized to the largest access unit and
        // reused sample after sample; `writeSampleData` is synchronous and the
        // writer copies the sample into its own queue, which is what makes the
        // reuse safe and what keeps a long export inside QA-03's memory budget.
        val buffer = ByteBuffer.allocateDirect(plan.samples.maxOf { it.length })
        val info = MediaCodec.BufferInfo()
        var written = 0
        var lastReported = -1
        val sampleCount = plan.samples.size

        try {
            val trackIndex = muxer.addTrack(format)
            muxer.start()

            FileChannel.open(esFile.toPath(), StandardOpenOption.READ).use { channel ->
                for (sample in plan.samples) {
                    if (cancelRequested) {
                        return VideoMuxResult.Failed(CANCELLED)
                    }
                    if (!readFully(channel, buffer, sample.offset, sample.length)) {
                        // The plan already checked every range against the
                        // file's length, so this is the file changing under us.
                        // Nothing more is written for a stream that cannot be
                        // read to its end.
                        return VideoMuxResult.Failed(TRUNCATED_SAMPLE)
                    }
                    // Annex-B, unchanged: see the class comment and C17.
                    info.set(0, sample.length, sample.ptsUs, sample.flags)
                    try {
                        muxer.writeSampleData(trackIndex, buffer, info)
                    } catch (error: Exception) {
                        Log.w(TAG, "mux: the muxer rejected a sample")
                        return VideoMuxResult.Failed(MUXER_REJECTED_SAMPLE)
                    }
                    written++
                    if (onProgress != null && sampleCount > 0) {
                        val percent = (written * 100 / sampleCount).coerceIn(0, 100)
                        if (percent != lastReported) {
                            lastReported = percent
                            onProgress(percent, 100)
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
                "mux: $codec ${dimensions.width}x${dimensions.height} " +
                    "samples=$written repairedPts=${plan.nonMonotonicPtsCount} " +
                    "duration=${plan.durationMs}ms " +
                    "take=${(System.nanoTime() - startedNs) / 1_000_000}ms"
            )
            return VideoMuxResult.Ok(
                mp4Path = outFile.absolutePath,
                frames = written,
                durationMs = plan.durationMs,
                nonMonotonicPtsCount = plan.nonMonotonicPtsCount
            )
        } finally {
            // Every path out -- success, fail-closed, cancel, or an exception on
            // its way to `mux` -- releases the muxer exactly once, after the
            // `stop()` above when there was one. The muxer is released without
            // `stop()` on the failing paths, which is what leaves the file
            // unusable; `mux` deletes it.
            runCatching { muxer.release() }
        }
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
        private const val TAG = "RtpVideoMuxer"
        private const val MAX_REASON_CHARS = 160

        /** The `MediaFormat` keys the codec-specific data goes under. */
        const val CSD_0 = "csd-0"
        const val CSD_1 = "csd-1"

        /** Short tokens the contract freezes, as `AacExporter` does. */
        const val CANCELLED = "cancelled"

        /** A codec id this muxer has no MP4 sample description for. */
        const val UNSUPPORTED_CODEC = "unsupportedCodec"

        /** SDP parameter sets this codec cannot be described without. */
        const val MISSING_PARAMETER_SETS = "missingParameterSets"

        /** The ES file is missing or unreadable. */
        const val UNREADABLE_STREAM = "unreadableStream"

        /** The `.vidx` is missing, truncated, or not a `.vidx`. */
        const val UNREADABLE_INDEX = "unreadableIndex"

        /** The ES ended before a sample's byte range did. */
        const val TRUNCATED_SAMPLE = "truncatedSample"

        private const val MUXER_UNAVAILABLE = "muxerUnavailable"
        private const val MUXER_REJECTED_SAMPLE = "muxerRejectedSample"
    }
}
