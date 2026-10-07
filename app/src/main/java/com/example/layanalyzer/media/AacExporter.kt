// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaCodecList
import android.media.MediaFormat
import android.media.MediaMuxer
import android.util.Log
import com.example.layanalyzer.data.WavHeader
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer

/**
 * Outcome of one [AacExporter.export] call.
 *
 *  - [Ok] the `.m4a` was written and carries the values reported here
 *  - [Unsupported] this device has no AAC encoder
 *  - [Failed] everything else: a missing, unreadable, truncated or non-16-bit
 *    WAV, an encoder that never answered, a cancelled caller. A [Failed] never
 *    leaves a file behind, so a caller that sees one has nothing to clean up.
 */
sealed interface AacExportResult {
    data class Ok(
        val m4aPath: String,
        val sampleRate: Int,
        val channels: Int,
        val durationMs: Long
    ) : AacExportResult

    /** Device has no AAC encoder; `reason` is a short token. */
    data class Unsupported(val reason: String) : AacExportResult

    data class Failed(val message: String) : AacExportResult
}

/**
 * Compresses an already-rendered WAV into a `.m4a` (MPEG-4 / AAC-LC) with the
 * platform `MediaCodec` encoder and `MediaMuxer` (RTP4-KT-04). It is the last
 * stage of the RTP audio route, after the WAV exists:
 *
 * ```
 * ... -> renderRtpAudioFromPcm -> [wav] -> AacExporter -> [m4a]
 * ```
 *
 * It is deliberately the mirror image of [MediaCodecAudioDecoder]: the same
 * `ioDispatcher` constructor parameter, the same latched `@Volatile`
 * cancellation, the same synchronous `dequeueInputBuffer`/`dequeueOutputBuffer`
 * loop on a timeout, the same `sealed interface` result with the three
 * outcomes, and the same promise that no exception escapes.
 *
 * What it does, and what it deliberately does not:
 *
 *  - The input is described entirely by [WavHeader.parse]: sample rate, channel
 *    count, bit depth and the PCM byte count all come from there, so there is
 *    no second WAV parser and no second opinion about the input. A `parse` that
 *    answers `null` is a rejected request, not an exception.
 *  - The encoder is AAC-LC -- `MediaCodecInfo.CodecProfileLevel.AACObjectLC` --
 *    at [BIT_RATE], at the source's sample rate and channel count. The card
 *    fixes those three; nothing here resamples, downmixes or normalises.
 *  - PCM is read in bounded blocks and handed over as it is read. The WAV is
 *    never read into memory whole.
 *  - `MediaMuxer.stop()` is the step that turns the written samples into a
 *    playable file, so it is called inside the `try` and both the encoder and
 *    the muxer are released in the matching `finally`. On anything but [Ok] --
 *    including a cancel -- the half-written file is removed by [export], so
 *    neither a caller nor the cache ever sees a `.m4a` that cannot be played.
 *  - The one thing it does not own is the destination: the caller picks the
 *    `.m4a` path (the same request directory the WAV came from, under
 *    `RtpMediaCache`), and its parent directory has to exist.
 */
class AacExporter(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {

    /**
     * Latched cancellation flag, set by [cancel] and read by the encode loop at
     * the top of every iteration, so a cancel takes effect within one dequeue
     * timeout (10 ms). Once set it stays set: a cancelled instance refuses
     * further work rather than silently starting over, so a caller that wants
     * to export again builds a new exporter.
     */
    @Volatile
    private var cancelRequested = false

    /** Asks a running (or about-to-start) [export] to stop and clean up. */
    fun cancel() {
        cancelRequested = true
    }

    /**
     * Encodes [wavFile] into [outFile] as an AAC-LC `.m4a`.
     *
     * @param wavFile a 16-bit PCM RIFF/WAVE file, as `renderRtpAudioFromPcm`
     *   writes it
     * @param outFile the `.m4a` to write; its parent directory must exist and
     *   nothing of it survives a call that does not return [AacExportResult.Ok]
     * @param onProgress called once per block of PCM handed to the encoder with
     *   `(done, total)`, both counted in sample frames (so `total` is the WAV's
     *   `frameCount`). The last call on a successful export is
     *   `(total, total)`.
     *
     * No exception escapes: an unsupported device, an input the header refuses,
     * a muxer that rejects a sample and a cancelled caller all come back as an
     * [AacExportResult]. On anything but [AacExportResult.Ok] [outFile] is
     * removed, so a caller never sees half a file.
     */
    suspend fun export(
        wavFile: File,
        outFile: File,
        onProgress: ((done: Int, total: Int) -> Unit)? = null
    ): AacExportResult {
        var succeeded = false
        try {
            val result = withContext(ioDispatcher) {
                runExport(wavFile, outFile, onProgress)
            }
            succeeded = result is AacExportResult.Ok
            return result
        } catch (error: Exception) {
            // A real device can fail here in ways no amount of checking
            // anticipates (an encoder that dies mid-stream, a muxer whose
            // destination disappeared, a codec that rejects a block size). It
            // is still an ordinary answer, not a crash. The exception's own
            // message is carried into the result: it is the only thing that
            // says *why*, and it never contains payload bytes.
            Log.w(TAG, "export failed", error)
            return AacExportResult.Failed(error.describe())
        } finally {
            if (!succeeded) {
                outFile.delete()
            }
        }
    }

    private fun runExport(
        wavFile: File,
        outFile: File,
        onProgress: ((done: Int, total: Int) -> Unit)?
    ): AacExportResult {
        val startedNs = System.nanoTime()
        if (cancelRequested) {
            return AacExportResult.Failed(CANCELLED)
        }

        // The input's one and only description. `WavHeader.parse` refuses a
        // missing file, a file that is not RIFF/WAVE, a file with no usable
        // `fmt ` or `data` chunk and a `data` length that is not a whole number
        // of frames; every one of those is the same answer here.
        if (!wavFile.isFile) {
            return AacExportResult.Failed(UNREADABLE_WAV)
        }
        val header = WavHeader.parse(wavFile)
            ?: return AacExportResult.Failed(UNREADABLE_WAV)
        if (header.bitsPerSample != BITS_PER_SAMPLE) {
            // The card's fail-closed rule: `parse` accepts 8/16/24/32-bit PCM,
            // the encoder takes 16-bit samples, and a bit depth this exporter
            // would have to convert is a request it refuses rather than
            // silently renders wrong.
            Log.i(TAG, "export: ${header.bitsPerSample}-bit PCM is not encodable")
            return AacExportResult.Failed(UNSUPPORTED_PCM)
        }
        if (header.channels !in MIN_CHANNELS..MAX_CHANNELS || header.sampleRate <= 0) {
            Log.i(
                TAG,
                "export: ${header.sampleRate}Hz/${header.channels}ch is not encodable"
            )
            return AacExportResult.Failed(UNSUPPORTED_FORMAT)
        }
        if (header.frameCount <= 0L) {
            return AacExportResult.Failed(EMPTY_INPUT)
        }

        // Where the PCM starts. `WavHeader.parse` is the authority on *whether*
        // this is a 16-bit PCM WAV and on *how much* PCM it holds; what it does
        // not report is the offset of the `data` payload, and an exporter has
        // to read the samples. So the chunk list is walked once more, for the
        // offset alone: no `fmt ` field is read and no length is trusted, which
        // is why this is not a second WAV parser. It is the same walk
        // `WavHeader.parse` and the native `read_pcm_wav` (RtpJni.cpp) already
        // do, and it stops at the same `RIFF` size, so it cannot look past
        // anything `parse` accepted.
        val dataOffset = dataOffsetOf(wavFile)
            ?: return AacExportResult.Failed(UNREADABLE_WAV)

        val format = try {
            MediaFormat.createAudioFormat(MIME_AAC, header.sampleRate, header.channels)
                .apply {
                    setInteger(
                        MediaFormat.KEY_AAC_PROFILE,
                        MediaCodecInfo.CodecProfileLevel.AACObjectLC
                    )
                    setInteger(MediaFormat.KEY_BIT_RATE, BIT_RATE)
                }
        } catch (error: Exception) {
            Log.w(TAG, "export: unusable format for $MIME_AAC")
            return AacExportResult.Unsupported(NO_ENCODER)
        }

        val encoderName = try {
            MediaCodecList(MediaCodecList.REGULAR_CODECS).findEncoderForFormat(format)
        } catch (error: Exception) {
            // The lookup itself throws only for a format the platform cannot
            // describe. From the caller's seat that is the same answer as "no
            // encoder here", and the contract says not to throw.
            Log.w(TAG, "export: encoder lookup failed for $MIME_AAC")
            null
        }
        if (encoderName == null) {
            Log.i(TAG, "export: no $MIME_AAC encoder on this device")
            return AacExportResult.Unsupported(NO_ENCODER)
        }

        val codec = try {
            MediaCodec.createByCodecName(encoderName)
        } catch (error: Exception) {
            Log.w(TAG, "export: ${error.javaClass.simpleName} for $MIME_AAC")
            return AacExportResult.Failed(ENCODER_UNAVAILABLE)
        }

        // The muxer writes the file from its constructor on, so it is the one
        // resource that can leave a `.m4a` behind without ever having been
        // started. `export`'s `finally` deletes the path on every failing path,
        // and a muxer that was built but never `stop()`ped is exactly the
        // "unplayable file" the card warns about -- which is why `stop()` below
        // has to be reached on the success path and nowhere else.
        val muxer = try {
            MediaMuxer(outFile.absolutePath, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
        } catch (error: Exception) {
            Log.w(TAG, "export: cannot open the m4a destination")
            runCatching { codec.release() }
            return AacExportResult.Failed(MUXER_UNAVAILABLE)
        }

        val bytesPerFrame = header.channels * BYTES_PER_SAMPLE
        val progressTotal = header.frameCount
            .coerceAtMost(Int.MAX_VALUE.toLong())
            .toInt()
        val chunk = ByteArray(INPUT_CHUNK_FRAMES * bytesPerFrame)
        val bufferInfo = MediaCodec.BufferInfo()

        var trackIndex = -1
        var muxerStarted = false
        var endQueued = false
        var outputDone = false
        var fedFrames = 0L
        var encodedFrames = 0
        var lastPtsUs = 0L
        var lastProgressNs = System.nanoTime()
        var idleSinceNs = 0L

        try {
            codec.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            codec.start()

            RandomAccessFile(wavFile, "r").use { wav ->
                wav.seek(dataOffset)
                // Exactly the `data` chunk `WavHeader.parse` measured, and no
                // more: the file may carry chunks after it.
                var remainingBytes = header.dataBytes

                while (!outputDone) {
                    if (cancelRequested) {
                        return AacExportResult.Failed(CANCELLED)
                    }
                    // Whether this turn of the loop moved anything: feeding a
                    // block of PCM, handing over end-of-stream, or collecting a
                    // frame of AAC.
                    var progressed = false

                    if (remainingBytes > 0L) {
                        // A full input queue is the ordinary case: the output
                        // drain below frees the slots, one per iteration.
                        val inputIndex = codec.dequeueInputBuffer(DEQUEUE_TIMEOUT_US)
                        if (inputIndex >= 0) {
                            val input = codec.getInputBuffer(inputIndex)
                                ?: return AacExportResult.Failed(NO_INPUT_BUFFER)
                            // The encoder picks the input buffer's size, so the
                            // block is whatever fits: never more than the
                            // buffer, never more than one read's worth, and
                            // never more than the PCM that is left. All three
                            // are in whole sample frames, so a block can never
                            // split a stereo pair.
                            val capacityFrames = input.capacity() / bytesPerFrame
                            val wantFrames = minOf(
                                capacityFrames.toLong(),
                                INPUT_CHUNK_FRAMES.toLong(),
                                remainingBytes / bytesPerFrame
                            )
                            if (wantFrames <= 0L) {
                                return AacExportResult.Failed(NO_INPUT_BUFFER)
                            }
                            val wantBytes = (wantFrames * bytesPerFrame).toInt()
                            val read = runCatching {
                                wav.readFully(chunk, 0, wantBytes)
                                true
                            }.getOrDefault(false)
                            if (!read) {
                                // The header promised more PCM than the file
                                // holds. Nothing is written for a stream that
                                // cannot be read to its end.
                                return AacExportResult.Failed(TRUNCATED_WAV)
                            }

                            input.clear()
                            input.put(chunk, 0, wantBytes)
                            // The block's timestamp is the clock position of
                            // its first sample frame, so the timeline starts at
                            // zero and advances by the audio's own duration.
                            val ptsUs = fedFrames * MICROS_PER_SECOND / header.sampleRate
                            lastPtsUs = ptsUs
                            codec.queueInputBuffer(inputIndex, 0, wantBytes, ptsUs, 0)
                            fedFrames += wantFrames
                            remainingBytes -= wantBytes
                            progressed = true
                            onProgress?.invoke(
                                fedFrames.coerceAtMost(progressTotal.toLong()).toInt(),
                                progressTotal
                            )
                        }
                    } else if (!endQueued) {
                        val inputIndex = codec.dequeueInputBuffer(DEQUEUE_TIMEOUT_US)
                        if (inputIndex >= 0) {
                            codec.queueInputBuffer(
                                inputIndex, 0, 0, lastPtsUs,
                                MediaCodec.BUFFER_FLAG_END_OF_STREAM
                            )
                            endQueued = true
                            progressed = true
                        }
                    }

                    val outputIndex = codec.dequeueOutputBuffer(
                        bufferInfo, DEQUEUE_TIMEOUT_US
                    )
                    when {
                        outputIndex == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                            // What the encoder settled on. For AAC-LC it is the
                            // requested pair, and the track has to be added
                            // before any sample is written, which is why the
                            // muxer is started here rather than earlier.
                            val outputFormat = codec.outputFormat
                            Log.i(
                                TAG,
                                "export: encoder format " +
                                    "${intOrNull(outputFormat, MediaFormat.KEY_SAMPLE_RATE)}Hz/" +
                                    "${intOrNull(outputFormat, MediaFormat.KEY_CHANNEL_COUNT)}ch"
                            )
                            if (!muxerStarted) {
                                trackIndex = muxer.addTrack(outputFormat)
                                muxer.start()
                                muxerStarted = true
                            }
                            progressed = true
                        }

                        outputIndex >= 0 -> {
                            // A config buffer carries codec-specific data -- the
                            // AudioSpecificConfig that goes into the track's
                            // `esds`, not into `mdat` -- so it is not a sample.
                            val isConfig = bufferInfo.flags and
                                MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0
                            if (bufferInfo.size > 0 && !isConfig) {
                                if (!muxerStarted) {
                                    // An encoder that never announced its format
                                    // still has to be muxed, and its
                                    // `outputFormat` carries the same `csd-0`
                                    // the change would have.
                                    trackIndex = muxer.addTrack(codec.outputFormat)
                                    muxer.start()
                                    muxerStarted = true
                                }
                                val output = codec.getOutputBuffer(outputIndex)
                                    ?: return AacExportResult.Failed(NO_OUTPUT_BUFFER)
                                if (!writeSample(muxer, trackIndex, output, bufferInfo)) {
                                    return AacExportResult.Failed(MUXER_REJECTED_SAMPLE)
                                }
                                encodedFrames++
                            }
                            codec.releaseOutputBuffer(outputIndex, false)
                            progressed = true
                            if (bufferInfo.flags and
                                MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0
                            ) {
                                outputDone = true
                            }
                        }

                        else -> {
                            // INFO_TRY_AGAIN_LATER: nothing ready in this
                            // slice. INFO_OUTPUT_BUFFERS_CHANGED is deprecated
                            // and needs no reaction. Both just count as a turn
                            // with no progress.
                        }
                    }

                    val now = System.nanoTime()
                    if (progressed) {
                        lastProgressNs = now
                        idleSinceNs = 0L
                    } else if (remainingBytes <= 0L && endQueued && idleSinceNs == 0L) {
                        // Every block is in and end-of-stream has been handed
                        // over, so the encoder has been asked for every frame it
                        // can still produce. Start timing its silence.
                        idleSinceNs = now
                    }

                    if (now - lastProgressNs > STALL_TIMEOUT_NS) {
                        return AacExportResult.Failed(TIMEOUT)
                    }
                    // Some encoders drop the end-of-stream flag on their last
                    // output buffer. Once nothing is left to feed and the
                    // encoder has gone quiet, there is no more audio coming.
                    if (idleSinceNs != 0L && now - idleSinceNs > POST_EOS_IDLE_NS) {
                        outputDone = true
                    }
                }
            }

            if (encodedFrames == 0) {
                return AacExportResult.Failed(NO_OUTPUT)
            }
            // The step that finalises the file. `stop()` is called here, on the
            // one path that produced samples, and never in the `finally`: a
            // stop on a muxer that has written nothing throws, and a stop that
            // ran after a failure would leave a file that looks finished.
            muxer.stop()
            val durationMs = header.frameCount * 1000L / header.sampleRate
            Log.i(
                TAG,
                "export: ${header.sampleRate}Hz/${header.channels}ch " +
                    "samples=${header.frameCount} aacFrames=$encodedFrames " +
                    "duration=${durationMs}ms take=" +
                    "${(System.nanoTime() - startedNs) / 1_000_000}ms"
            )
            return AacExportResult.Ok(
                m4aPath = outFile.absolutePath,
                sampleRate = header.sampleRate,
                channels = header.channels,
                durationMs = durationMs
            )
        } finally {
            // Every path out -- success, fail-closed, cancel, or an exception
            // on its way to `export` -- releases both resources exactly once.
            // The muxer is released without `stop()` on the failing paths,
            // which is what leaves the file unusable; `export` deletes it.
            runCatching { codec.stop() }
            runCatching { codec.release() }
            runCatching { muxer.release() }
        }
    }

    /**
     * Hands one encoded access unit to the muxer.
     *
     * The ADTS question: `MediaMuxer` builds the track's `esds` from `csd-0`
     * and expects bare access units in `mdat`, while Android's AAC encoder is
     * free to hand out ADTS-framed output. Rather than assume either, each
     * buffer is checked for a header that *declares itself*: the ADTS sync word
     * followed by an `aac_frame_length` that covers the buffer exactly. A bare
     * access unit would have to start with `0xFF 0xFx` **and** carry a matching
     * length to be mistaken for one.
     *
     * Both `BufferInfo.offset` and the buffer's own position are moved past the
     * header, because the two documented ways of telling `writeSampleData`
     * where the sample starts -- the `BufferInfo` offset, and the buffer's
     * position -- then agree on the same bytes.
     */
    private fun writeSample(
        muxer: MediaMuxer,
        trackIndex: Int,
        buffer: ByteBuffer,
        info: MediaCodec.BufferInfo
    ): Boolean {
        // The codec's own limit can be smaller than the sample; widening it to
        // the sample's end is what makes the absolute reads below legal.
        val sampleEnd = info.offset + info.size
        buffer.limit(sampleEnd)
        val headerBytes = adtsHeaderLength(buffer, info.offset, info.size)
        val sample = MediaCodec.BufferInfo().apply {
            set(
                info.offset + headerBytes,
                info.size - headerBytes,
                info.presentationTimeUs,
                info.flags
            )
        }
        buffer.position(info.offset + headerBytes)
        buffer.limit(sampleEnd)
        return try {
            muxer.writeSampleData(trackIndex, buffer, sample)
            true
        } catch (error: Exception) {
            Log.w(TAG, "export: the muxer rejected a sample")
            false
        }
    }

    /**
     * The number of ADTS header octets in front of the access unit held in
     * `buffer[offset, offset + size)`, or 0 when the buffer holds a bare access
     * unit. 7 octets normally, 9 when the header carries a CRC
     * (`protection_absent == 0`) -- but only ever a value whose
     * `aac_frame_length` covers the buffer exactly.
     */
    private fun adtsHeaderLength(buffer: ByteBuffer, offset: Int, size: Int): Int {
        if (size < ADTS_HEADER_BYTES) return 0
        if (buffer.get(offset).toInt() and 0xff != ADTS_SYNC_FIRST) return 0
        val second = buffer.get(offset + 1).toInt() and 0xff
        if (second and 0xf0 != ADTS_SYNC_SECOND_MASK) return 0
        val third = buffer.get(offset + 2).toInt() and 0xff
        val fourth = buffer.get(offset + 3).toInt() and 0xff
        val fifth = buffer.get(offset + 4).toInt() and 0xff
        val seventh = buffer.get(offset + 6).toInt() and 0xff
        // `aac_frame_length`: 13 bits, spanning the last two bits of the third
        // octet, all of the fourth, and the top three of the fifth.
        val declared = ((third and 0x03) shl 11) or (fourth shl 3) or (fifth shr 5)
        if (declared != size) return 0
        // `number_of_raw_data_blocks_in_frame` is the low two bits of the
        // seventh; more than one block means the length above does not describe
        // a single access unit, so it is not a frame this can hand over.
        if (seventh and 0x03 != 0) return 0
        return if (second and 0x01 != 0) {
            ADTS_HEADER_BYTES
        } else {
            ADTS_HEADER_BYTES_WITH_CRC
        }
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
        private const val TAG = "AacExporter"
        private const val MAX_REASON_CHARS = 160

        /** Short tokens the contract freezes, as `MediaCodecAudioDecoder` does. */
        const val NO_ENCODER = "noEncoder"
        const val TIMEOUT = "timeout"
        const val CANCELLED = "cancelled"

        /**
         * The input-shape tokens RTP4-KT-04's test freezes. They are separate
         * from [NO_ENCODER] because they describe the *request*, not the
         * device: the same file is refused on every device there is.
         */
        const val UNREADABLE_WAV = "unreadableWav"
        const val UNSUPPORTED_PCM = "unsupportedPcm"

        private const val UNSUPPORTED_FORMAT = "unsupportedFormat"
        private const val EMPTY_INPUT = "emptyInput"
        private const val TRUNCATED_WAV = "truncatedWav"
        private const val ENCODER_UNAVAILABLE = "encoderUnavailable"
        private const val MUXER_UNAVAILABLE = "muxerUnavailable"
        private const val MUXER_REJECTED_SAMPLE = "muxerRejectedSample"
        private const val NO_INPUT_BUFFER = "noInputBuffer"
        private const val NO_OUTPUT_BUFFER = "noOutputBuffer"
        private const val NO_OUTPUT = "noOutput"

        /**
         * `MediaFormat.MIMETYPE_AUDIO_AAC`, spelled out because it is also the
         * string `MediaExtractor` reports for the track of a file this writes.
         */
        const val MIME_AAC = "audio/mp4a-latm"

        /** The card's bit rate for the AAC-LC encoder. */
        const val BIT_RATE = 64_000

        private const val BITS_PER_SAMPLE = 16
        private const val BYTES_PER_SAMPLE = 2
        private const val MIN_CHANNELS = 1
        private const val MAX_CHANNELS = 2
        private const val MICROS_PER_SECOND = 1_000_000L

        /**
         * How much PCM one input buffer gets. The encoder may hand out a
         * smaller buffer, in which case the block shrinks to fit; this is the
         * ceiling, not an assumption, and it has nothing to do with the
         * encoder's own 1024-sample AAC frame.
         */
        private const val INPUT_CHUNK_FRAMES = 1024

        /** Per-dequeue wait. Short, so [cancel] is noticed promptly. */
        private const val DEQUEUE_TIMEOUT_US = 10_000L

        /** No progress of any kind for this long means the encoder is stuck. */
        private const val STALL_TIMEOUT_NS = 10_000_000_000L

        /** How long a fully fed stream may stay silent before it is finished. */
        private const val POST_EOS_IDLE_NS = 1_000_000_000L

        private const val RIFF_HEADER_BYTES = 12L
        private const val CHUNK_HEADER_BYTES = 8L

        private const val ADTS_SYNC_FIRST = 0xFF
        private const val ADTS_SYNC_SECOND_MASK = 0xF0
        private const val ADTS_HEADER_BYTES = 7
        private const val ADTS_HEADER_BYTES_WITH_CRC = 9

        private fun intOrNull(format: MediaFormat, key: String): Int? =
            if (format.containsKey(key)) format.getInteger(key) else null

        /**
         * The offset of the first octet of the `data` chunk's payload, or null
         * when the file has no `data` chunk inside the size its `RIFF` header
         * declares.
         *
         * This is the same walk `WavHeader.parse` performs and it deliberately
         * reads nothing else: `WavHeader.parse` has already decided that the
         * file is a 16-bit PCM WAV and how long its payload is, so all that is
         * missing to read the samples is where they begin.
         */
        private fun dataOffsetOf(wavFile: File): Long? = runCatching {
            RandomAccessFile(wavFile, "r").use { input ->
                if (input.length() < RIFF_HEADER_BYTES) return@use null
                val riff = ByteArray(RIFF_HEADER_BYTES.toInt())
                input.seek(0L)
                input.readFully(riff)
                if (ascii(riff, 0) != "RIFF" || ascii(riff, 8) != "WAVE") {
                    return@use null
                }

                val riffEnd = 8L + unsignedInt(riff, 4)
                var offset = RIFF_HEADER_BYTES
                while (offset + CHUNK_HEADER_BYTES <= riffEnd) {
                    input.seek(offset)
                    val head = ByteArray(CHUNK_HEADER_BYTES.toInt())
                    input.readFully(head)
                    val chunkSize = unsignedInt(head, 4)
                    val payloadStart = offset + CHUNK_HEADER_BYTES
                    val payloadEnd = payloadStart + chunkSize
                    if (payloadEnd < payloadStart || payloadEnd > riffEnd) {
                        return@use null
                    }
                    if (ascii(head, 0) == "data") return@use payloadStart
                    // Chunks are word-aligned: an odd size is followed by a pad
                    // octet, exactly as `WavHeader.parse` accounts for.
                    offset = payloadEnd + (chunkSize and 1L)
                }
                null
            }
        }.getOrNull()

        private fun ascii(bytes: ByteArray, offset: Int): String =
            String(bytes, offset, 4, Charsets.US_ASCII)

        private fun unsignedInt(bytes: ByteArray, offset: Int): Long =
            (bytes[offset].toLong() and 0xff) or
                ((bytes[offset + 1].toLong() and 0xff) shl 8) or
                ((bytes[offset + 2].toLong() and 0xff) shl 16) or
                ((bytes[offset + 3].toLong() and 0xff) shl 24)
    }
}
