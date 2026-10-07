package com.example.layanalyzer.media

import android.media.MediaCodec
import android.media.MediaCodecList
import android.media.MediaFormat
import android.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.util.ArrayDeque

/**
 * Outcome of one [MediaCodecAudioDecoder.decode] call.
 *
 *  - [Ok] the `.pcmchunks` file was written and carries the values reported here
 *  - [Unsupported] this device has no decoder for the requested `mime`
 *  - [Failed] everything else: a truncated `.frames`, a decoder that never
 *    answered, a cancelled caller
 */
sealed interface MediaCodecDecodeResult {
    data class Ok(
        val pcmChunksPath: String,
        val sampleRate: Int,
        val channels: Int,
        val decodedFrames: Int
    ) : MediaCodecDecodeResult

    /** Device has no decoder for this mime; `reason` is a short token. */
    data class Unsupported(val reason: String) : MediaCodecDecodeResult

    data class Failed(val message: String) : MediaCodecDecodeResult
}

/**
 * Decodes the codec frames RTP4-NAT-06 extracted into `.frames` with the
 * platform `MediaCodec`, and writes the PCM blocks RTP4-NAT-07 renders
 * (RTP4-KT-01). This is the middle stage of the MEDIACODEC route RTP4-KT-02
 * wires up:
 *
 * ```
 * extractRtpCodecFrames -> MediaCodecAudioDecoder -> renderRtpAudioFromPcm
 * ```
 *
 * What it does, and what it deliberately does not:
 *
 *  - Frames are read **at random** from `.frames` with [RandomAccessFile], one
 *    entry at a time. The blob is never read into memory: it can be as large as
 *    the capture's whole payload set.
 *  - `lost` entries are skipped. They carry no frame data (`.fidx` says so with
 *    the `0x01` flag), so there is nothing to hand the decoder; the renderer
 *    turns that slot into a gap.
 *  - Presentation timestamps are `extTs` deltas converted to microseconds. The
 *    zero point is the first frame actually fed, and the RTP clock rate comes
 *    from [timestampRateHz] -- one explicit decision, not a magic number.
 *  - The whole synchronous `MediaCodec` dance runs on [ioDispatcher] (never the
 *    main thread) and is cancellable through [cancel].
 *  - Nothing is decoded, downmixed or resampled beyond what the codec itself
 *    does: the blocks written are the codec's own output, and the renderer owns
 *    the timeline, the gaps and the WAV.
 */
class MediaCodecAudioDecoder(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {

    /**
     * Latched cancellation flag. It is set by [cancel] and read by the decode
     * loop, so a cancel takes effect within one dequeue timeout (10 ms). Once
     * set it stays set: a cancelled instance refuses further work rather than
     * silently starting over, so a caller that wants to decode again builds a
     * new decoder.
     */
    @Volatile
    private var cancelRequested = false

    /** Asks a running (or about-to-start) [decode] to stop and clean up. */
    fun cancel() {
        cancelRequested = true
    }

    /**
     * Decodes [framesFile] according to [fidx] and writes [outFile] in the
     * `.pcmchunks` format (see [PcmChunkWriter]).
     *
     * @param mime codec mime as `extractRtpCodecFrames` reports it
     *   (`audio/amr`, `audio/amr-wb`, `audio/opus`)
     * @param sampleRate decoder sample rate; for Opus this is the output rate,
     *   which is 48 kHz, and the RTP clock is 48 kHz as well
     * @param channels decoder channel count
     * @param csd codec-specific data; empty for AMR, AMR-WB and Opus
     * @param onProgress called once per frame handed to the decoder with
     *   `(done, total)`, where `total` counts the frames that will be fed
     *   (`lost` entries excluded)
     *
     * No exception escapes: an unsupported device, a decoder that rejects the
     * stream and a cancelled caller all come back as a [MediaCodecDecodeResult].
     * On anything but [MediaCodecDecodeResult.Ok] the output file is removed, so
     * a caller never sees half a stream.
     */
    suspend fun decode(
        framesFile: File,
        fidx: FidxFile,
        mime: String,
        sampleRate: Int,
        channels: Int,
        csd: List<ByteArray>,
        outFile: File,
        onProgress: ((done: Int, total: Int) -> Unit)? = null
    ): MediaCodecDecodeResult {
        var succeeded = false
        try {
            val result = withContext(ioDispatcher) {
                runDecode(framesFile, fidx, mime, sampleRate, channels, csd, outFile, onProgress)
            }
            succeeded = result is MediaCodecDecodeResult.Ok
            return result
        } catch (error: Exception) {
            // A real device can fail here in ways no amount of checking
            // anticipates (a codec that dies mid-stream, a codec that wants
            // codec-specific data the caller did not pass, an input buffer that
            // cannot be mapped). It is still an ordinary answer, not a crash.
            // The codec's own message is carried into the result: it is the only
            // thing that says *why*, and it never contains payload bytes.
            Log.w(TAG, "decode failed for $mime", error)
            return MediaCodecDecodeResult.Failed(error.describe())
        } finally {
            if (!succeeded) {
                outFile.delete()
            }
        }
    }

    private fun runDecode(
        framesFile: File,
        fidx: FidxFile,
        mime: String,
        requestedSampleRate: Int,
        requestedChannels: Int,
        csd: List<ByteArray>,
        outFile: File,
        onProgress: ((done: Int, total: Int) -> Unit)?
    ): MediaCodecDecodeResult {
        val startedNs = System.nanoTime()
        if (fidx.entries.isEmpty()) {
            return MediaCodecDecodeResult.Failed(NO_FRAMES)
        }
        if (cancelRequested) {
            return MediaCodecDecodeResult.Failed(CANCELLED)
        }

        val entries = fidx.entries
        // The frames that will be fed, in `.fidx` order, as indices into
        // `entries`: a `lost` entry is a hole in the stream, not a frame.
        val plan = entries.indices.filter { !entries[it].isLost }
        if (plan.isEmpty()) {
            return MediaCodecDecodeResult.Failed(NO_FRAMES)
        }

        val format = try {
            MediaFormat
                .createAudioFormat(mime, requestedSampleRate, requestedChannels)
                .apply {
                    csd.forEachIndexed { index, bytes ->
                        setByteBuffer("csd-$index", ByteBuffer.wrap(bytes))
                    }
                }
        } catch (error: Exception) {
            Log.w(TAG, "decode: unusable format for $mime")
            return MediaCodecDecodeResult.Unsupported(NO_DECODER)
        }

        val decoderName = try {
            MediaCodecList(MediaCodecList.REGULAR_CODECS).findDecoderForFormat(format)
        } catch (error: Exception) {
            // The lookup itself throws only for a format the platform cannot
            // describe. From the caller's seat that is the same answer as "no
            // decoder here", and the contract says not to throw.
            Log.w(TAG, "decode: decoder lookup failed for $mime")
            null
        }
        if (decoderName == null) {
            Log.i(TAG, "decode: no $mime decoder on this device")
            return MediaCodecDecodeResult.Unsupported(NO_DECODER)
        }

        val timestampRateHz = timestampRateHz(mime, requestedSampleRate)
        val codec = try {
            MediaCodec.createByCodecName(decoderName)
        } catch (error: Exception) {
            Log.w(TAG, "decode: ${error.javaClass.simpleName} for $mime")
            return MediaCodecDecodeResult.Failed(DECODER_UNAVAILABLE)
        }

        // The output format can name a sample rate and a channel count different
        // from the requested ones, and when it does the decoder's answer wins.
        // They are read by the writer with its first block, so anything that
        // arrives later cannot go into a header that is already on disk.
        var outSampleRate = requestedSampleRate
        var outChannels = requestedChannels
        var writer: PcmChunkWriter? = null
        var decodedFrames = 0

        // `.fidx` indices whose frame is inside the decoder but whose PCM has
        // not been drained yet, oldest first. AMR, AMR-WB and Opus decoders
        // produce one output buffer per input frame, so the oldest pending index
        // is the one an arriving buffer belongs to.
        val pending = ArrayDeque<Int>()

        try {
            codec.configure(format, null, null, 0)
            codec.start()

            RandomAccessFile(framesFile, "r").use { frames ->
                val framesLength = frames.length()
                val firstExtTs = entries[plan.first()].extTs
                val bufferInfo = MediaCodec.BufferInfo()

                var fed = 0
                var endQueued = false
                var lastPtsUs = 0L
                var lastProgressNs = System.nanoTime()
                var idleSinceNs = 0L
                var outputDone = false

                while (!outputDone) {
                    if (cancelRequested) {
                        return MediaCodecDecodeResult.Failed(CANCELLED)
                    }
                    // Whether this turn of the loop moved anything: feeding a
                    // frame, handing over end-of-stream, or collecting output.
                    var progressed = false

                    if (fed < plan.size) {
                        // A full input queue is the ordinary case: the output
                        // drain below frees the slots, one per iteration.
                        val inputIndex = codec.dequeueInputBuffer(DEQUEUE_TIMEOUT_US)
                        if (inputIndex >= 0) {
                            val entryIndex = plan[fed]
                            val entry = entries[entryIndex]
                            val frameBytes = readFrame(frames, framesLength, entry)
                                ?: return MediaCodecDecodeResult.Failed(TRUNCATED_FRAMES)
                            val input = codec.getInputBuffer(inputIndex)
                                ?: return MediaCodecDecodeResult.Failed(NO_INPUT_BUFFER)
                            if (input.capacity() < frameBytes.size) {
                                return MediaCodecDecodeResult.Failed(FRAME_TOO_LARGE)
                            }
                            input.clear()
                            input.put(frameBytes)
                            // Non-decreasing, so a non-monotonic extTs in the
                            // index cannot make a codec reject the stream.
                            val ptsUs = presentationTimeUs(
                                entry.extTs, firstExtTs, timestampRateHz
                            ).coerceAtLeast(lastPtsUs)
                            lastPtsUs = ptsUs
                            // `size` is the frame length, not the buffer's.
                            codec.queueInputBuffer(inputIndex, 0, frameBytes.size, ptsUs, 0)
                            pending.addLast(entryIndex)
                            fed++
                            progressed = true
                            onProgress?.invoke(fed, plan.size)
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
                            val outputFormat = codec.outputFormat
                            val rate = outputFormat.getInteger(MediaFormat.KEY_SAMPLE_RATE)
                            val count =
                                outputFormat.getInteger(MediaFormat.KEY_CHANNEL_COUNT)
                            if (rate > 0 && count > 0) {
                                Log.i(
                                    TAG,
                                    "decode: output format $mime " +
                                        "${outSampleRate}Hz/${outChannels}ch -> " +
                                        "${rate}Hz/${count}ch"
                                )
                                if (rate != outSampleRate || count != outChannels) {
                                    if (writer != null) {
                                        // The header on disk already says
                                        // otherwise, so this stream cannot be
                                        // described by the file it is half in.
                                        return MediaCodecDecodeResult.Failed(
                                            FORMAT_CHANGED
                                        )
                                    }
                                    // The decoder's values win over the request's.
                                    outSampleRate = rate
                                    outChannels = count
                                }
                            }
                            progressed = true
                        }

                        outputIndex >= 0 -> {
                            // A config buffer carries codec-specific data, not
                            // PCM, and does not belong to any input frame.
                            val isConfig = bufferInfo.flags and
                                MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0
                            if (bufferInfo.size > 0 && !isConfig) {
                                val entryIndex = pending.pollFirst()
                                if (entryIndex == null) {
                                    // More output than input: no `.fidx` entry
                                    // owns these samples, so they cannot be
                                    // written anywhere.
                                    Log.w(TAG, "decode: extra output buffer dropped")
                                } else {
                                    val output = codec.getOutputBuffer(outputIndex)
                                        ?: return MediaCodecDecodeResult.Failed(
                                            NO_OUTPUT_BUFFER
                                        )
                                    output.position(bufferInfo.offset)
                                    output.limit(bufferInfo.offset + bufferInfo.size)
                                    val samples = readPcm(output, bufferInfo.size)
                                    val target = writer
                                        ?: PcmChunkWriter(
                                            outFile, outSampleRate, outChannels
                                        ).also { writer = it }
                                    target.writeChunk(entryIndex, samples)
                                    decodedFrames++
                                }
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
                    } else if (fed == plan.size && endQueued && idleSinceNs == 0L) {
                        // Every frame is in and end-of-stream has been handed
                        // over, so the decoder has been asked for everything it
                        // can still produce. Start timing its silence.
                        idleSinceNs = now
                    }

                    if (now - lastProgressNs > STALL_TIMEOUT_NS) {
                        return MediaCodecDecodeResult.Failed(TIMEOUT)
                    }
                    // Some decoders drop the end-of-stream flag on their last
                    // output buffer. Once the decoder has gone quiet with
                    // nothing left to collect there is no more audio coming.
                    if (idleSinceNs != 0L && now - idleSinceNs > POST_EOS_IDLE_NS) {
                        if (pending.isEmpty()) {
                            outputDone = true
                        } else {
                            // It still owes frames, so this really is a stall.
                            return MediaCodecDecodeResult.Failed(TIMEOUT)
                        }
                    }
                }
            }

            if (decodedFrames == 0) {
                return MediaCodecDecodeResult.Failed(NO_OUTPUT)
            }
            writer?.close()
            Log.i(
                TAG,
                "decode: mime=$mime frames=${plan.size} decoded=$decodedFrames " +
                    "${outSampleRate}Hz/${outChannels}ch take=" +
                    "${(System.nanoTime() - startedNs) / 1_000_000}ms"
            )
            return MediaCodecDecodeResult.Ok(
                pcmChunksPath = outFile.absolutePath,
                sampleRate = outSampleRate,
                channels = outChannels,
                decodedFrames = decodedFrames
            )
        } finally {
            runCatching { writer?.close() }
            runCatching { codec.stop() }
            codec.release()
        }
    }

    /**
     * Reads one frame at its `.fidx` offset, or null when the index points
     * outside the blob (a truncated `.frames` is a rejected request, not a
     * partially decoded result).
     */
    private fun readFrame(
        frames: RandomAccessFile,
        framesLength: Long,
        entry: FidxEntry
    ): ByteArray? = try {
        val length = entry.length
        if (length < 0 || entry.offset < 0 || entry.offset + length > framesLength) {
            null
        } else {
            val bytes = ByteArray(length)
            frames.seek(entry.offset)
            frames.readFully(bytes)
            bytes
        }
    } catch (error: Exception) {
        null
    }

    /**
     * The codec's output as 16-bit PCM.
     *
     * The bytes are assembled by hand instead of going through
     * `asShortBuffer()`, because the byte order of a `MediaCodec` output buffer
     * is not part of the API contract while the order of the 16-bit PCM coming
     * out of an audio codec is: little-endian on every ABI Android ships. The
     * length is `info.size` -- the allocation behind the buffer is usually
     * larger and its tail is not output.
     */
    private fun readPcm(buffer: ByteBuffer, size: Int): ShortArray {
        val bytes = ByteArray(size)
        buffer.get(bytes)
        val samples = ShortArray(bytes.size / BYTES_PER_SAMPLE)
        for (index in samples.indices) {
            samples[index] = (
                (bytes[index * 2].toInt() and 0xff) or
                    (bytes[index * 2 + 1].toInt() shl 8)
                ).toShort()
        }
        return samples
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
        private const val TAG = "MediaCodecAudioDecoder"
        private const val MAX_REASON_CHARS = 160

        /** Short tokens the contract freezes. */
        const val NO_DECODER = "noDecoder"
        const val TIMEOUT = "timeout"
        const val CANCELLED = "cancelled"

        private const val NO_FRAMES = "noFrames"
        private const val NO_OUTPUT = "noOutput"
        private const val TRUNCATED_FRAMES = "truncatedFrames"
        private const val FRAME_TOO_LARGE = "frameTooLarge"
        private const val NO_INPUT_BUFFER = "noInputBuffer"
        private const val NO_OUTPUT_BUFFER = "noOutputBuffer"
        private const val DECODER_UNAVAILABLE = "decoderUnavailable"
        private const val FORMAT_CHANGED = "outputFormatChanged"

        /** Opus' RTP clock, fixed at 48 kHz by RFC 7587 section 4.1. */
        const val OPUS_TIMESTAMP_RATE_HZ = 48_000
        private const val MIME_OPUS = "audio/opus"
        private const val MICROS_PER_SECOND = 1_000_000L
        private const val BYTES_PER_SAMPLE = 2

        /** Per-dequeue wait. Short, so [cancel] is noticed promptly. */
        private const val DEQUEUE_TIMEOUT_US = 10_000L

        /** No progress of any kind for this long means the decoder is stuck. */
        private const val STALL_TIMEOUT_NS = 10_000_000_000L

        /** How long a fully fed stream may stay silent before it is finished. */
        private const val POST_EOS_IDLE_NS = 1_000_000_000L

        /**
         * The RTP clock rate a frame's `extTs` is expressed in.
         *
         * The one place where the two rates differ, and why it is a decision
         * rather than a constant:
         *
         *  - AMR and AMR-WB: RFC 4867 section 4.5.3 fixes the RTP clock at the
         *    codec's own sample rate (8 kHz and 16 kHz), and the decoder outputs
         *    at that same rate -- so the timestamp rate *is* [sampleRate].
         *  - Opus: RFC 7587 section 4.1 fixes the RTP clock at 48 kHz whatever
         *    the audio bandwidth, while [sampleRate] is the decoder's output
         *    rate. They agree at 48 kHz for the platform decoder, and the
         *    timestamp arithmetic has to name the clock, not the output.
         *
         * The delta is in RTP ticks, so feeding this the wrong rate would
         * stretch or compress the whole timeline.
         */
        private fun timestampRateHz(mime: String, sampleRate: Int): Int =
            if (mime.equals(MIME_OPUS, ignoreCase = true)) {
                OPUS_TIMESTAMP_RATE_HZ
            } else {
                sampleRate
            }

        /**
         * `extTs` as microseconds on the renderer's clock.
         *
         * [firstExtTs] is the timestamp of the first frame handed to the
         * decoder, so the pipeline always starts at 0 regardless of where the
         * capture's RTP timestamp started. The product is bounded by the capture
         * length: an hour of 48 kHz audio is 1.7e14 microseconds, three orders
         * of magnitude below [Long.MAX_VALUE], and `.fidx` `extTs` is a 64-bit
         * field, so no wrap-around has to be handled here.
         */
        private fun presentationTimeUs(
            extTs: Long,
            firstExtTs: Long,
            timestampRateHz: Int
        ): Long = (extTs - firstExtTs) * MICROS_PER_SECOND / timestampRateHz
    }
}
