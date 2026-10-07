package com.example.layanalyzer

import android.content.Context
import android.media.AudioFormat
import android.media.MediaCodec
import android.media.MediaCodecList
import android.media.MediaFormat
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.media.FidxEntry
import com.example.layanalyzer.media.FidxFile
import com.example.layanalyzer.media.MediaCodecAudioDecoder
import com.example.layanalyzer.media.MediaCodecDecodeResult
import com.example.layanalyzer.media.isLost
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.sin

/**
 * RTP4-KT-01: the `MediaCodecAudioDecoder` pipeline, on device.
 *
 * WHERE THE AMR / OPUS BITSTREAMS COME FROM
 * =========================================
 * There is no AMR-NB, AMR-WB or Opus capture under
 * `app/src/androidTest/assets/rtp/` -- the checked-in fixtures are
 * `sip_g711a_bidirectional`, `g711u_loss_reorder`, `rtp_no_signal` and `srtp`
 * (see CONTRIBUTING.md) -- and CONTRIBUTING.md forbids hand-editing fixtures, so
 * this file cannot get real frames from a capture. It does **not** work around
 * that by writing a made-up `.frames`: the frames it decodes are produced at run
 * time by the device's own platform **encoder** (`audio/3gpp`, `audio/amr-wb`,
 * `audio/opus`), fed a synthesized tone and drained buffer by buffer. That is a
 * real bitstream from a real encoder, which is what this pipeline exists to
 * decode; it is not a golden value.
 *
 * The pipeline has no container stage -- `.frames` is a bare concatenation of
 * codec frames and `.fidx` says where each one is -- so `MediaMuxer` /
 * `MediaExtractor` are not needed to unwrap one: the encoder's output buffers
 * *are* the frames, ToC byte and all (RTP4-NAT-04 hands `MediaCodec` the same
 * storage format).
 *
 * TWO THINGS THIS DEVICE SAYS ABOUT THE FROZEN CONTRACT
 * ====================================================
 * Both are recorded here because they are cross-task, not KT-01's to fix, and
 * both would otherwise be easy to mistake for a decode bug:
 *
 *  1. **`audio/amr` has no decoder.** RTP4-NAT-06 reports `mime = "audio/amr"`
 *     for AMR-NB. The platform registers its AMR-NB decoder as `audio/3gpp`
 *     (`MediaFormat.MIMETYPE_AUDIO_AMR_NB`); this device's
 *     `/vendor/etc/media_codecs_google_audio.xml` has no `audio/amr` entry at
 *     all, so `findDecoderForFormat` answers null and RTP4-KT-01 correctly
 *     answers `Unsupported("noDecoder")`. The AMR-NB mime alias belongs to
 *     RTP4-NAT-06 / RTP4-KT-02. [CODECS] therefore lists both mimes per codec
 *     and picks whichever this device actually has, so the pipeline itself is
 *     still exercised against a real AMR-NB bitstream.
 *  2. **Opus needs `csd-0`.** RTP4-NAT-06 returns an empty `csd` for Opus
 *     (card item 6: "MediaCodec 的 Opus 解码器不需要 CSD"). On this device the
 *     decoder refuses to start -- `C2SoftOpusDec: process encountered error in
 *     GetOpusHeaderBuffers` -- because the AOSP Opus decoder parses the RFC 7845
 *     OpusHead out of `csd-0`. See
 *     [opusWithoutCodecSpecificDataIsReportedAsAFailure], which pins the
 *     observable result instead of inventing the missing header.
 *
 * A device that has no encoder for a codec cannot produce a bitstream to decode,
 * and one without a decoder cannot decode anything: those cases skip with
 * `Assume` and the reason spelled out, rather than being weakened into an
 * assertion that always passes.
 */
@RunWith(AndroidJUnit4::class)
class MediaCodecDecodeTest {

    // ------------------------------------------------------------ .fidx format

    /**
     * The frozen 33-octet record, checked against bytes this test builds itself.
     *
     * The layout is RTP4-NAT-06's and is mirrored by
     * `layanalyzer::rtp::FidxEntry` on the C++ side: `"FID1"`, `u32 count`, then
     * `u64 offset, u32 len, u32 frame, u64 extTs, f64 arrivalRel, u8 flags` --
     * note `frame` before `extTs`, which is the order the card reverses relative
     * to the task doc. A field-order mistake fails here.
     */
    @Test
    fun fidxFileRoundTripsTheFrozenThirtyThreeOctetRecord() {
        val file = File(freshDir("fidx-roundtrip"), "s3.fidx")
        val buffer = ByteBuffer.allocate(FIDX_HEADER_BYTES + 2 * 33).order(LITTLE_ENDIAN)
        buffer.put("FID1".toByteArray(Charsets.US_ASCII))
        buffer.putInt(2)
        // Record 0.
        buffer.putLong(9_876_543_210L)          // offset
        buffer.putInt(32)                       // len
        buffer.putInt(7)                        // frame
        buffer.putLong(4_294_967_296L)          // extTs: above u32 on purpose
        buffer.putDouble(1.25)                  // arrivalRel
        buffer.put(0x00.toByte())               // flags
        // Record 1.
        buffer.putLong(9_876_543_242L)
        buffer.putInt(0)
        buffer.putInt(9)
        buffer.putLong(160)
        buffer.putDouble(-0.5)
        buffer.put(0x06.toByte())               // sid | late
        file.writeBytes(buffer.array())

        assertEquals(FIDX_HEADER_BYTES + 2 * 33L, file.length())
        val index = FidxFile.read(file)
        assertEquals(2, index.entries.size)

        val first = index.entries[0]
        assertEquals(9_876_543_210L, first.offset)
        assertEquals(32, first.length)
        assertEquals(7L, first.frame)
        assertEquals(4_294_967_296L, first.extTs)
        assertEquals(1.25, first.arrivalRel, 0.0)
        assertEquals(0, first.flags)
        assertFalse(first.isLost)

        val second = index.entries[1]
        assertEquals(9_876_543_242L, second.offset)
        assertEquals(0, second.length)
        assertEquals(9L, second.frame)
        assertEquals(160L, second.extTs)
        assertEquals(-0.5, second.arrivalRel, 0.0)
        assertEquals(FidxFile.FLAG_SID or FidxFile.FLAG_LATE, second.flags)
        assertTrue(second.flags and FidxFile.FLAG_LOST == 0)
        assertFalse(second.isLost)
    }

    /** `lost` is the one flag the decoder acts on, so it is pinned separately. */
    @Test
    fun fidxLostFlagIsBitZero() {
        val file = File(freshDir("fidx-flags"), "s3.fidx")
        writeFidx(
            file,
            listOf(
                FidxEntry(0L, 0, 1L, 160L, 0.0, FidxFile.FLAG_LOST),
                FidxEntry(0L, 4, 2L, 320L, 0.02, FidxFile.FLAG_SID),
                FidxEntry(4L, 4, 3L, 480L, 0.04, FidxFile.FLAG_LOST or FidxFile.FLAG_LATE)
            )
        )

        val entries = FidxFile.read(file).entries
        assertTrue(entries[0].isLost)
        assertFalse(entries[1].isLost)
        assertTrue(entries[2].isLost && entries[2].flags and FidxFile.FLAG_LATE != 0)
    }

    /** Every malformed index it is asked to read must be refused, not guessed. */
    @Test
    fun fidxReadFailsClosedOnBadMagicTruncationAndMissingFiles() {
        val dir = freshDir("fidx-bad")

        val missing = File(dir, "absent.fidx")
        assertTrue(
            "a missing index must be refused",
            throwsIoException { FidxFile.read(missing) }
        )

        val empty = File(dir, "empty.fidx")
        empty.writeBytes(ByteArray(0))
        assertTrue(
            "an empty file must be refused",
            throwsIoException { FidxFile.read(empty) }
        )

        val badMagic = File(dir, "magic.fidx")
        badMagic.writeBytes(
            ByteBuffer.allocate(FIDX_HEADER_BYTES)
                .order(LITTLE_ENDIAN)
                .put("FID2".toByteArray(Charsets.US_ASCII))
                .putInt(0)
                .array()
        )
        assertTrue(
            "a bad magic must be refused",
            throwsIoException { FidxFile.read(badMagic) }
        )

        val truncatedHeader = File(dir, "short-header.fidx")
        truncatedHeader.writeBytes("FID".toByteArray(Charsets.US_ASCII))
        assertTrue(
            "a truncated header must be refused",
            throwsIoException { FidxFile.read(truncatedHeader) }
        )

        // Declares three records but holds one and a half.
        val truncatedBody = File(dir, "short-body.fidx")
        val buffer = ByteBuffer.allocate(FIDX_HEADER_BYTES + 33 + 5)
            .order(LITTLE_ENDIAN)
        buffer.put("FID1".toByteArray(Charsets.US_ASCII))
        buffer.putInt(3)
        buffer.putLong(0L)
        buffer.putInt(1)
        buffer.putInt(1)
        buffer.putLong(160L)
        buffer.putDouble(0.0)
        buffer.put(0x00.toByte())
        buffer.put(ByteArray(5))
        truncatedBody.writeBytes(buffer.array())
        assertTrue(
            "a record count the file cannot hold must be refused",
            throwsIoException { FidxFile.read(truncatedBody) }
        )

        // The converse, which the C++ reader also allows: octets past the
        // declared count are ignored rather than treated as a record.
        val trailing = File(dir, "trailing.fidx")
        val trailingBuffer = ByteBuffer.allocate(FIDX_HEADER_BYTES + 33 + 8)
            .order(LITTLE_ENDIAN)
        trailingBuffer.put("FID1".toByteArray(Charsets.US_ASCII))
        trailingBuffer.putInt(1)
        trailingBuffer.putLong(12L)
        trailingBuffer.putInt(4)
        trailingBuffer.putInt(3)
        trailingBuffer.putLong(480L)
        trailingBuffer.putDouble(0.25)
        trailingBuffer.put(0x00.toByte())
        trailingBuffer.put(ByteArray(8))
        trailing.writeBytes(trailingBuffer.array())
        assertEquals(1, FidxFile.read(trailing).entries.size)
    }

    // -------------------------------------------------------- decoder contract

    /**
     * A mime no platform ships a decoder for must answer `Unsupported`, not
     * throw: the caller routes on that value instead of catching.
     */
    @Test(timeout = 60_000)
    fun unknownMimeIsUnsupportedAndNotAnException() {
        val dir = freshDir("unknown-mime")
        val written = writeFrames(dir, listOf(ByteArray(8)))
        val out = File(dir, "s3.pcmchunks")

        val result = decode(
            written.first,
            written.second,
            mime = "audio/not-a-real-codec",
            sampleRate = 8_000,
            outFile = out
        )

        assertEquals(MediaCodecDecodeResult.Unsupported("noDecoder"), result)
        assertFalse("a refused request may not leave an output file", out.exists())
    }

    /**
     * The `Unsupported` answer is not a guess: it has to agree with the device's
     * own decoder list, in both directions, for every mime this pipeline is
     * pointed at. `audio/amr` is in the list on purpose -- see the class comment
     * about the AMR-NB mime alias.
     */
    @Test(timeout = 120_000)
    fun decoderAvailabilityAndTheUnsupportedAnswerAgree() {
        for (probe in AVAILABILITY_PROBES) {
            val dir = freshDir("availability-${probe.mime.replace('/', '-')}")
            val written = writeFrames(dir, listOf(ByteArray(4)))
            val out = File(dir, "s3.pcmchunks")

            val result = decode(
                written.first, written.second, probe.mime, probe.sampleRate, out
            )
            if (hasDecoder(probe.mime, probe.sampleRate)) {
                assertFalse(
                    "${probe.mime} has a decoder on this device, so it must not " +
                        "answer Unsupported: $result",
                    result is MediaCodecDecodeResult.Unsupported
                )
            } else {
                assertEquals(
                    "${probe.mime} has no decoder on this device, so it must " +
                        "answer Unsupported",
                    MediaCodecDecodeResult.Unsupported("noDecoder"),
                    result
                )
                assertFalse(
                    "a refused request may not leave an output file",
                    out.exists()
                )
            }
        }
    }

    /**
     * `.fidx` is the only thing that says where a frame lives, so an index that
     * points past the end of `.frames` is a rejected request -- never a
     * partially decoded file.
     */
    @Test(timeout = 60_000)
    fun framesOutsideTheBlobAreRejectedAndLeaveNoFile() {
        val codec = CODECS.firstOrNull { decoderMimeFor(it) != null }
        assumeTrue(
            "no AMR-NB, AMR-WB or Opus decoder on this device, so there is " +
                "nothing that could decode",
            codec != null
        )
        val chosen = requireNotNull(codec)
        val decoderMime = requireNotNull(decoderMimeFor(chosen))

        val dir = freshDir("short-frames")
        val framesFile = File(dir, "s3.frames")
        framesFile.writeBytes(ByteArray(4))
        val fidxFile = File(dir, "s3.fidx")
        writeFidx(
            fidxFile,
            listOf(
                FidxEntry(
                    offset = 0L, length = 64, frame = 1L, extTs = 0L,
                    arrivalRel = 0.0, flags = 0
                )
            )
        )
        val out = File(dir, "s3.pcmchunks")

        val result = decode(
            framesFile,
            FidxFile.read(fidxFile),
            decoderMime,
            chosen.sampleRate,
            outFile = out
        )

        assertEquals(MediaCodecDecodeResult.Failed("truncatedFrames"), result)
        assertFalse("a rejected request may not leave an output file", out.exists())
    }

    // ------------------------------------------------------- the real pipeline

    @Test(timeout = 120_000)
    fun amrNbEncodedStreamDecodesToOk() = assertEncodedStreamDecodes(CODECS[0])

    @Test(timeout = 120_000)
    fun amrWbEncodedStreamDecodesToOk() = assertEncodedStreamDecodes(CODECS[1])

    /**
     * The Opus route exactly as RTP4-NAT-06 hands it over: real Opus packets and
     * `csd = []`.
     *
     * The platform Opus decoder needs `csd-0`, and this pins that
     * =========================================================
     * `extractRtpCodecFrames` returns an empty `csd` for Opus (its card item 6
     * says the platform decoder needs none). On this device it does: the codec
     * answers `E C2SoftOpusDec: process encountered error in GetOpusHeaderBuffers`,
     * because the AOSP Opus decoder parses the RFC 7845 OpusHead identification
     * header out of `csd-0` and will not start without it. The task doc's
     * section 3.2 keeps `csd` in the result for exactly this kind of need.
     *
     * So what this asserts is what the pipeline owes its caller today: real
     * frames plus the empty `csd` RTP4-NAT-06 produces must come back as a
     * `Failed` with a non-empty reason -- never `Ok`, never `Unsupported` (a
     * decoder does exist), never an exception, and never a leftover file.
     * Supplying an OpusHead here would be inventing the very value whose absence
     * is the defect. The Opus acceptance case -- `Ok` with decoded frames -- is
     * blocked by the `csd` decision in RTP4-NAT-06 and belongs to that task and
     * to RTP4-QA-01.
     */
    @Test(timeout = 120_000)
    fun opusWithoutCodecSpecificDataIsReportedAsAFailure() {
        val codec = CODECS[2]
        assumeTrue(
            "this device has no Opus encoder (${codec.encoderMimes.first()}), so " +
                "no real Opus bitstream can be produced here",
            hasEncoder(codec)
        )
        val decoderMime = decoderMimeFor(codec)
        assumeTrue(
            "this device has no Opus decoder, so there is nothing to decode with",
            decoderMime != null
        )

        val dir = freshDir("opus-without-csd")
        val encoded = encodeRealFrames(codec, ENCODED_FRAME_COUNT)
        assertTrue("the Opus encoder produced no frames", encoded.isNotEmpty())
        val written = writeFrames(dir, encoded, codec.samplesPerFrame)
        val out = File(dir, "s3.pcmchunks")

        val result = decode(
            written.first, written.second, requireNotNull(decoderMime),
            codec.sampleRate, out
        )

        Log.i(
            TAG,
            "opusWithEmptyCsd: ${encoded.size} real frames decoded with csd=[] -> $result"
        )
        assertFalse(
            "a decoder exists, so this may not answer Unsupported: $result",
            result is MediaCodecDecodeResult.Unsupported
        )
        assertTrue(
            "the empty csd RTP4-NAT-06 returns cannot produce Opus audio here: $result",
            result is MediaCodecDecodeResult.Failed
        )
        assertTrue(
            "the failure must say why: $result",
            (result as MediaCodecDecodeResult.Failed).message.isNotBlank()
        )
        assertFalse("a failed decode may not leave an output file", out.exists())
    }

    /**
     * `cancel()` must stop the loop and remove the half-written file. The cancel
     * is triggered from inside the progress callback, which the loop calls per
     * frame, so it is deterministic: the next turn of the loop sees the flag.
     */
    @Test(timeout = 120_000)
    fun cancelStopsTheLoopAndDeletesThePartialFile() {
        val codec = CODECS.firstOrNull { hasEncoder(it) && decoderMimeFor(it) != null }
        assumeTrue(
            "no codec on this device can both encode a bitstream and decode one, " +
                "so the loop cannot be driven",
            codec != null
        )
        val chosen = requireNotNull(codec)
        val decoderMime = requireNotNull(decoderMimeFor(chosen))

        val dir = freshDir("cancel")
        val encoded = encodeRealFrames(chosen, ENCODED_FRAME_COUNT)
        assertTrue("the encoder produced no frames", encoded.size > CANCEL_AFTER_FRAMES)
        val frames = writeFrames(dir, encoded, chosen.samplesPerFrame)
        val out = File(dir, "s3.pcmchunks")

        val decoder = MediaCodecAudioDecoder()
        var progressCalls = 0
        val result = runBlocking {
            decoder.decode(
                frames.first, frames.second, decoderMime,
                chosen.sampleRate, 1, emptyList(), out
            ) { done, _ ->
                progressCalls++
                if (done >= CANCEL_AFTER_FRAMES) decoder.cancel()
            }
        }

        assertTrue("the progress callback never ran", progressCalls > 0)
        assertEquals(MediaCodecDecodeResult.Failed("cancelled"), result)
        assertFalse("a cancelled decode may not leave an output file", out.exists())
    }

    /** The card's positive path: real bitstream in, `Ok` and a readable file out. */
    private fun assertEncodedStreamDecodes(codec: Codec) {
        assumeTrue(
            "this device has no ${codec.label} encoder (${codec.encoderMimes.first()}), " +
                "so no real ${codec.label} bitstream can be produced here; the " +
                "fixture-based acceptance case is RTP4-QA-01's",
            hasEncoder(codec)
        )
        val decoderMime = decoderMimeFor(codec)
        assumeTrue(
            "this device has no ${codec.label} decoder for any of " +
                "${codec.decoderMimes}, so there is nothing to decode with",
            decoderMime != null
        )

        val dir = freshDir("decode-${codec.label.lowercase()}")
        val encoded = encodeRealFrames(codec, ENCODED_FRAME_COUNT)
        assertTrue("the ${codec.label} encoder produced no frames", encoded.isNotEmpty())
        // One `lost` entry in the middle: it must be skipped, not decoded, and it
        // must not shift the `.fidx` indices the blocks are keyed by.
        val written = writeFrames(dir, encoded, codec.samplesPerFrame, lostAt = 1)
        val entries = written.second.entries
        val fedFrames = entries.count { !it.isLost }
        assertEquals(
            "one lost entry was requested, and it replaces one encoded frame",
            encoded.size - 1,
            fedFrames
        )
        val out = File(dir, "s3.pcmchunks")

        val result = decode(
            written.first, written.second, requireNotNull(decoderMime),
            codec.sampleRate, out
        )
        assertTrue(
            "${codec.label} did not decode (decoder mime $decoderMime): $result",
            result is MediaCodecDecodeResult.Ok
        )
        val ok = result as MediaCodecDecodeResult.Ok

        assertEquals(out.absolutePath, ok.pcmChunksPath)
        assertEquals("every non-lost entry must decode", fedFrames, ok.decodedFrames)
        assertEquals(codec.sampleRate, ok.sampleRate)
        assertEquals(1, ok.channels)
        assertTrue(out.isFile && out.length() > 0L)

        // Read it back the way `parse_pcm_chunks` in jni/RtpJni.cpp does, so a
        // writer that drifted from that contract cannot pass this test.
        val parsed = parsePcmChunks(out, entries.size)
        assertEquals(ok.sampleRate, parsed.sampleRate)
        assertEquals(ok.channels, parsed.channels)
        assertEquals(ok.decodedFrames, parsed.blocks.size)
        assertEquals(
            "a lost entry must not be given a block",
            entries.indices.filter { !entries[it].isLost },
            parsed.blocks.map { it.fidxIndex }
        )
        assertTrue("no block may be empty", parsed.blocks.all { it.values.isNotEmpty() })

        val totalFrames = parsed.blocks.sumOf { it.samples }
        if (codec.exactSamplesPerFrame) {
            assertTrue(
                "${codec.label} decodes one frame to ${codec.samplesPerFrame} samples",
                parsed.blocks.all { it.samples == codec.samplesPerFrame }
            )
        } else {
            // Opus may pick any legal frame duration; what it may not do is
            // produce something that is not one.
            val sizes = parsed.blocks.map { it.samples }.distinct()
            assertEquals("every Opus block must be the same length", 1, sizes.size)
            assertTrue(
                "an Opus packet must decode to a legal frame duration, was " +
                    "${sizes.single()}",
                sizes.single() in OPUS_FRAME_SAMPLES_AT_48K
            )
        }
        val expectedFrames = fedFrames * codec.samplesPerFrame
        val tolerance = expectedFrames * 5L / 100L
        assertTrue(
            "decoded $totalFrames frames, expected about $expectedFrames",
            abs(totalFrames - expectedFrames) <= tolerance
        )
    }

    // ------------------------------------------------------------- test codecs

    private class Codec(
        val label: String,
        /** Platform encoder mime; one element, the mime the encoder is filed under. */
        val encoderMimes: List<String>,
        /**
         * Decoder mimes to try, most faithful to the contract first. AMR-NB is
         * the one codec where the mime RTP4-NAT-06 reports (`audio/amr`) is not
         * the mime the platform files the decoder under (`audio/3gpp`).
         */
        val decoderMimes: List<String>,
        val sampleRate: Int,
        val samplesPerFrame: Int,
        val bitRate: Int,
        val exactSamplesPerFrame: Boolean
    )

    private class Probe(val mime: String, val sampleRate: Int)

    /** One 20 ms tone frame per `samplesPerFrame`, at the codec's own rate. */
    private fun encodeRealFrames(codec: Codec, frameCount: Int): List<ByteArray> {
        val format = encoderFormat(codec)
        val name = MediaCodecList(MediaCodecList.REGULAR_CODECS)
            .findEncoderForFormat(format) ?: return emptyList()

        val encoder = MediaCodec.createByCodecName(name)
        val frames = mutableListOf<ByteArray>()
        try {
            encoder.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            encoder.start()

            val info = MediaCodec.BufferInfo()
            var fed = 0
            var endQueued = false
            var done = false
            var ptsUs = 0L
            val deadlineNs = System.nanoTime() + ENCODE_TIMEOUT_NS

            while (!done) {
                assertTrue(
                    "the ${codec.label} encoder stalled",
                    System.nanoTime() < deadlineNs
                )

                if (fed < frameCount) {
                    val inputIndex = encoder.dequeueInputBuffer(DEQUEUE_TIMEOUT_US)
                    if (inputIndex >= 0) {
                        val input = requireNotNull(encoder.getInputBuffer(inputIndex))
                        input.clear()
                        input.order(LITTLE_ENDIAN)
                        input.asShortBuffer().put(tone(codec))
                        encoder.queueInputBuffer(
                            inputIndex, 0, codec.samplesPerFrame * 2, ptsUs, 0
                        )
                        fed++
                        ptsUs += 1_000_000L * codec.samplesPerFrame / codec.sampleRate
                    }
                } else if (!endQueued) {
                    val inputIndex = encoder.dequeueInputBuffer(DEQUEUE_TIMEOUT_US)
                    if (inputIndex >= 0) {
                        encoder.queueInputBuffer(
                            inputIndex, 0, 0, ptsUs,
                            MediaCodec.BUFFER_FLAG_END_OF_STREAM
                        )
                        endQueued = true
                    }
                }

                val outputIndex = encoder.dequeueOutputBuffer(info, DEQUEUE_TIMEOUT_US)
                if (outputIndex >= 0) {
                    val isConfig = info.flags and
                        MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0
                    if (info.size > 0 && !isConfig) {
                        val output = requireNotNull(encoder.getOutputBuffer(outputIndex))
                        output.position(info.offset)
                        output.limit(info.offset + info.size)
                        val bytes = ByteArray(info.size)
                        output.get(bytes)
                        frames += bytes
                    }
                    encoder.releaseOutputBuffer(outputIndex, false)
                    if (info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0) {
                        done = true
                    }
                }
            }
        } finally {
            runCatching { encoder.stop() }
            encoder.release()
        }
        return frames
    }

    /** A 440 Hz tone, which every one of these codecs can carry. */
    private fun tone(codec: Codec): ShortArray =
        ShortArray(codec.samplesPerFrame) { index ->
            (TONE_AMPLITUDE * sin(2.0 * PI * TONE_HZ * index / codec.sampleRate))
                .toInt()
                .toShort()
        }

    /** Exactly the format [encodeRealFrames] configures, so the probes agree. */
    private fun encoderFormat(codec: Codec): MediaFormat =
        MediaFormat
            .createAudioFormat(codec.encoderMimes.first(), codec.sampleRate, 1)
            .apply {
                setInteger(MediaFormat.KEY_BIT_RATE, codec.bitRate)
                setInteger(MediaFormat.KEY_CHANNEL_MASK, AudioFormat.CHANNEL_IN_MONO)
            }

    private fun hasEncoder(codec: Codec): Boolean = runCatching {
        MediaCodecList(MediaCodecList.REGULAR_CODECS)
            .findEncoderForFormat(encoderFormat(codec)) != null
    }.getOrDefault(false)

    private fun hasDecoder(mime: String, sampleRate: Int): Boolean = runCatching {
        MediaCodecList(MediaCodecList.REGULAR_CODECS).findDecoderForFormat(
            MediaFormat.createAudioFormat(mime, sampleRate, 1)
        ) != null
    }.getOrDefault(false)

    /** The first decoder mime this device actually has for [codec], or null. */
    private fun decoderMimeFor(codec: Codec): String? =
        codec.decoderMimes.firstOrNull { hasDecoder(it, codec.sampleRate) }

    // ----------------------------------------------------------------- helpers

    private fun decode(
        framesFile: File,
        fidx: FidxFile,
        mime: String,
        sampleRate: Int,
        outFile: File
    ): MediaCodecDecodeResult = runBlocking {
        MediaCodecAudioDecoder().decode(
            framesFile, fidx, mime, sampleRate, 1, emptyList(), outFile
        )
    }

    /**
     * Writes a `.frames` blob plus the `.fidx` RTP4-NAT-06 freezes for it, in
     * the field order the card fixes: `u64 offset, u32 len, u32 frame, u64 extTs,
     * f64 arrivalRel, u8 flags`, 33 octets per record.
     *
     * @param lostAt index whose entry is marked `lost` and holds no frame bytes
     * @return the `.frames` file and the index read back through [FidxFile]
     */
    private fun writeFrames(
        dir: File,
        frames: List<ByteArray>,
        samplesPerFrame: Int = 160,
        lostAt: Int = -1
    ): Pair<File, FidxFile> {
        val framesFile = File(dir, "s3.frames")
        val fidxFile = File(dir, "s3.fidx")
        val blob = ByteArrayOutputStream()
        val entries = mutableListOf<FidxEntry>()
        for ((index, frame) in frames.withIndex()) {
            val extTs = FIRST_EXT_TS + index.toLong() * samplesPerFrame
            if (index == lostAt) {
                entries += FidxEntry(
                    offset = blob.size().toLong(),
                    length = 0,
                    frame = FIRST_FRAME + index,
                    extTs = extTs,
                    arrivalRel = index * FRAME_SECONDS,
                    flags = FidxFile.FLAG_LOST
                )
                continue
            }
            entries += FidxEntry(
                offset = blob.size().toLong(),
                length = frame.size,
                frame = FIRST_FRAME + index,
                extTs = extTs,
                arrivalRel = index * FRAME_SECONDS,
                flags = 0
            )
            blob.write(frame)
        }
        framesFile.writeBytes(blob.toByteArray())
        writeFidx(fidxFile, entries)
        return framesFile to FidxFile.read(fidxFile)
    }

    /** The `.fidx` writer, kept out of the production code on purpose. */
    private fun writeFidx(file: File, entries: List<FidxEntry>) {
        val buffer = ByteBuffer
            .allocate(FIDX_HEADER_BYTES + entries.size * 33)
            .order(LITTLE_ENDIAN)
        buffer.put("FID1".toByteArray(Charsets.US_ASCII))
        buffer.putInt(entries.size)
        for (entry in entries) {
            buffer.putLong(entry.offset)
            buffer.putInt(entry.length)
            buffer.putInt(entry.frame.toInt())
            buffer.putLong(entry.extTs)
            buffer.putDouble(entry.arrivalRel)
            buffer.put(entry.flags.toByte())
        }
        file.writeBytes(buffer.array())
    }

    private class PcmChunks(
        val sampleRate: Int,
        val channels: Int,
        val blocks: List<PcmBlock>
    )

    private class PcmBlock(val fidxIndex: Int, val samples: Int, val values: ShortArray)

    /**
     * Reads `.pcmchunks` by the rules `parse_pcm_chunks` in `jni/RtpJni.cpp`
     * enforces, including the ones the renderer fails closed on: an index out of
     * range for the `.fidx` it is paired with, and a duplicate index.
     */
    private fun parsePcmChunks(file: File, fidxCount: Int): PcmChunks {
        val data = file.readBytes()
        assertTrue("a `.pcmchunks` file is at least its 10 octet header", data.size >= 10)
        assertEquals("PCM1", String(data, 0, 4, Charsets.US_ASCII))
        val sampleRate = littleEndianU32(data, 4)
        val channels = littleEndianU16(data, 8)
        assertTrue("channels must be 1 or 2", channels in 1..2)

        var offset = PCM_HEADER_BYTES
        val seen = BooleanArray(fidxCount)
        val blocks = mutableListOf<PcmBlock>()
        while (offset < data.size) {
            assertTrue("truncated block header", data.size - offset >= 8)
            val fidxIndex = littleEndianU32(data, offset)
            val samples = littleEndianU32(data, offset + 4)
            offset += 8
            val payload = samples * channels * 2
            assertTrue("truncated block payload", data.size - offset >= payload)
            assertTrue(
                "fidxIndex $fidxIndex is out of range for $fidxCount entries",
                fidxIndex < fidxCount
            )
            assertFalse("fidxIndex $fidxIndex is duplicated", seen[fidxIndex])
            seen[fidxIndex] = true
            val values = ShortArray(samples * channels) { sample ->
                littleEndianU16(data, offset + sample * 2).toShort()
            }
            offset += payload
            blocks += PcmBlock(fidxIndex, samples, values)
        }
        assertEquals("the file has trailing octets", data.size, offset)
        return PcmChunks(sampleRate, channels, blocks)
    }

    private fun littleEndianU32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)

    private fun littleEndianU16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8)

    private fun throwsIoException(block: () -> Unit): Boolean =
        try {
            block()
            false
        } catch (error: IOException) {
            true
        }

    private fun freshDir(name: String): File {
        val dir = File(cacheDir, "rtp-mediacodec-$name")
        dir.deleteRecursively()
        assertTrue("unable to create ${dir.absolutePath}", dir.mkdirs())
        return dir
    }

    @After
    fun cleanOutputs() {
        cacheDir.listFiles().orEmpty()
            .filter { it.name.startsWith("rtp-mediacodec-") }
            .forEach(File::deleteRecursively)
    }

    private val cacheDir: File
        get() = ApplicationProvider.getApplicationContext<Context>().cacheDir

    private companion object {
        const val TAG = "MediaCodecDecodeTest"

        /** Index matters: the positive tests pick their codec out of this list. */
        val CODECS = listOf(
            Codec(
                label = "AMR-NB",
                encoderMimes = listOf("audio/3gpp"),
                // `audio/amr` is what RTP4-NAT-06 reports and is tried first;
                // `audio/3gpp` is what the platform files this decoder under.
                decoderMimes = listOf("audio/amr", "audio/3gpp"),
                sampleRate = 8_000,
                samplesPerFrame = 160,
                bitRate = 12_200,
                exactSamplesPerFrame = true
            ),
            Codec(
                label = "AMR-WB",
                encoderMimes = listOf("audio/amr-wb"),
                decoderMimes = listOf("audio/amr-wb"),
                sampleRate = 16_000,
                samplesPerFrame = 320,
                bitRate = 23_850,
                exactSamplesPerFrame = true
            ),
            Codec(
                label = "Opus",
                encoderMimes = listOf("audio/opus"),
                decoderMimes = listOf("audio/opus"),
                sampleRate = 48_000,
                samplesPerFrame = 960,
                bitRate = 32_000,
                exactSamplesPerFrame = false
            )
        )

        /** Mimes the `Unsupported` answer is checked against. */
        val AVAILABILITY_PROBES = listOf(
            Probe("audio/amr", 8_000),
            Probe("audio/3gpp", 8_000),
            Probe("audio/amr-wb", 16_000),
            Probe("audio/opus", 48_000)
        )

        /** Legal Opus packet durations at the fixed 48 kHz clock. */
        val OPUS_FRAME_SAMPLES_AT_48K = setOf(120, 240, 480, 960, 1920, 2880)

        const val ENCODED_FRAME_COUNT = 12
        const val CANCEL_AFTER_FRAMES = 2
        const val FIRST_FRAME = 10L
        const val FIRST_EXT_TS = 1_000L
        const val FRAME_SECONDS = 0.02
        const val FIDX_HEADER_BYTES = 8
        const val PCM_HEADER_BYTES = 10

        const val TONE_HZ = 440.0
        const val TONE_AMPLITUDE = 12_000.0

        const val DEQUEUE_TIMEOUT_US = 10_000L
        const val ENCODE_TIMEOUT_NS = 30_000_000_000L

        val LITTLE_ENDIAN = ByteOrder.LITTLE_ENDIAN
    }
}
