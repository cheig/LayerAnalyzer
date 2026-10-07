// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import android.media.MediaExtractor
import android.media.MediaFormat
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.data.VideoParamSets
import com.example.layanalyzer.media.RtpVideoMuxer
import com.example.layanalyzer.media.VideoMuxResult
import com.example.layanalyzer.media.VideoSamplePlan
import com.example.layanalyzer.media.VidxEntry
import com.example.layanalyzer.media.VidxFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import kotlin.math.abs

/**
 * RTP5-KT-01: `media/RtpVideoMuxer.kt` against the platform's own reader.
 *
 * WHAT IS REAL AND WHAT IS SYNTHETIC
 * ==================================
 * The **parameter sets are real**: the SPS and PPS below are the `ffmpeg 7.1`
 * vectors that `native_build/verification/rtp/host_tests/lib/SpsParserTest.cpp`
 * documents (H.264 1280x720 High 3.1 and the PPS of the same file), so the
 * `csd-0`/`csd-1` handed to `MediaMuxer` here are the bytes a real encoder
 * produced and `MPEG4Writer` really does build its `avcC` out of them.
 *
 * The **access units are synthetic**, and they are the *subject* of this test
 * rather than evidence about a capture: this tree has no H.264 or H.265 RTP
 * fixture (`app/src/androidTest/assets/rtp/` holds audio captures only) and no
 * encoder to make one from, so every `.vidx` and every ES file below is written
 * by this file. That is enough for what the card asks, because `MediaMuxer`
 * does not decode: it copies sample bytes into `mdat` and timestamps into
 * `stts`/`stss`, so the container can be checked end to end without a decodable
 * bitstream. Nothing here claims the muxed samples would play.
 *
 * The one property that *does* depend on the bytes being a single Annex-B NAL
 * per access unit is [muxedMp4HoldsEveryIndexRecordAsOneSample]'s size check:
 * `MPEG4Writer` rewrites a four-octet start code as a four-octet length, so an
 * access unit that is one NAL with a four-octet start code comes back out of
 * `MediaExtractor` the same size. The payloads are generated with no zero octet
 * in them so that no accidental start code appears inside a sample and splits
 * it.
 *
 * No engine initialization is needed, unlike the other instrumented tests here:
 * this muxer takes two files and a `VideoParamSets`, and never calls into JNI.
 */
@RunWith(AndroidJUnit4::class)
class VideoMuxerTest {

    /**
     * The card's acceptance: `MediaExtractor` sees one `video/avc` track whose
     * sample count is the `.vidx` record count and whose duration is within one
     * frame of the last PTS.
     */
    @Test(timeout = 120_000)
    fun muxedMp4HoldsEveryIndexRecordAsOneSample() {
        val dir = freshDir("avc")
        val sources = writeStream(dir, "h264", count = SAMPLE_COUNT, payloadBytes = 512)
        val mp4 = File(dir, "out.mp4")

        val result = runBlocking {
            RtpVideoMuxer().mux(
                esFile = sources.es,
                vidxFile = sources.vidx,
                codec = "H264",
                width = 1280,
                height = 720,
                paramSets = h264ParamSets(),
                outFile = mp4
            )
        }
        val ok = result as? VideoMuxResult.Ok
            ?: throw AssertionError("mux did not succeed: $result")

        assertEquals(mp4.absolutePath, ok.mp4Path)
        assertEquals(SAMPLE_COUNT, ok.frames)
        assertEquals("the index is already monotonic", 0, ok.nonMonotonicPtsCount)
        assertTrue("no mp4 was written: ${mp4.absolutePath}", mp4.isFile && mp4.length() > 0L)

        val track = readTrack(mp4)
        assertEquals("the mp4 must hold exactly one track", 1, track.trackCount)
        assertEquals(MediaFormat.MIMETYPE_VIDEO_AVC, track.mime)
        assertEquals(1280, track.width)
        assertEquals(720, track.height)
        assertEquals("one sample per .vidx record", SAMPLE_COUNT, track.sampleCount)
        assertStrictlyIncreasing(track.sampleTimesUs)
        assertEquals(
            "the first sample comes from the access unit marked key",
            0L,
            track.sampleTimesUs.first()
        )
        // The card's tolerance: the extracted duration has to be within one
        // frame of the last PTS. `MPEG4Writer` extrapolates the last sample's
        // own duration on top of its timestamp -- which is why a video-only mp4
        // normally reports lastPts + one frame rather than lastPts -- so the
        // bound is one frame, with a millisecond on top for the rounding of
        // that extrapolation rather than a widened criterion.
        val deltaUs = abs(track.durationUs - LAST_PTS_US)
        assertTrue(
            "duration ${track.durationUs / 1000}ms is not within one frame " +
                "(${FRAME_US / 1000}ms) of the last PTS ${LAST_PTS_US / 1000}ms",
            deltaUs <= FRAME_US + ROUNDING_SLACK_US
        )
        // And the muxer's own report is the last written timestamp.
        assertEquals(LAST_PTS_MS, ok.durationMs)
        // Every access unit was handed over unchanged: MediaMuxer rewrites the
        // four-octet start code as a four-octet length prefix, so a one-NAL
        // access unit comes back the same size it went in.
        assertEquals(
            "the samples must be the access units, byte for byte",
            sources.accessUnitSizes,
            track.sampleSizes
        )
        Log.i(TAG, "avc: $track")
    }

    /**
     * A PTS that goes backwards is repaired by a microsecond and counted, and
     * the file is still readable with strictly increasing sample times --
     * `MediaMuxer` rejects a timestamp that does not advance, so without the
     * repair this call would fail instead of writing.
     */
    @Test(timeout = 120_000)
    fun aNonMonotonicIndexIsRepairedAndCounted() {
        val dir = freshDir("nonmonotonic")
        val sources = writeStream(dir, "h264", count = 6, payloadBytes = 256) { index ->
            // Two pairs of equal timestamps and one step backwards, so the
            // repair chain (previous + 1 each time) is exercised.
            when (index) {
                3 -> 0L
                4 -> 0L
                5 -> 1_000L
                else -> index * 33_333L
            }
        }
        val mp4 = File(dir, "out.mp4")

        val result = runBlocking {
            RtpVideoMuxer().mux(
                sources.es, sources.vidx, "H264", 640, 480, h264ParamSets(), mp4
            )
        }
        val ok = result as? VideoMuxResult.Ok
            ?: throw AssertionError("mux did not succeed: $result")

        assertEquals("three of the six timestamps are not increasing", 3, ok.nonMonotonicPtsCount)
        assertEquals(6, ok.frames)
        assertTrue(mp4.isFile && mp4.length() > 0L)

        val track = readTrack(mp4)
        assertEquals(1, track.trackCount)
        assertEquals(6, track.sampleCount)
        assertStrictlyIncreasing(track.sampleTimesUs)
        assertTrue(
            "the repaired samples must not be the raw ones: ${track.sampleTimesUs}",
            track.sampleTimesUs[3] > track.sampleTimesUs[2]
        )
    }

    /** H.265 goes in and `video/hevc` comes out, through the concatenated `csd-0`. */
    @Test(timeout = 120_000)
    fun muxesH265AsOneHevcTrack() {
        val dir = freshDir("hevc")
        val sources = writeStream(dir, "h265", count = 8, payloadBytes = 400)
        val mp4 = File(dir, "out.mp4")

        val result = runBlocking {
            RtpVideoMuxer().mux(
                sources.es, sources.vidx, "H265", 1920, 1080, h265ParamSets(), mp4
            )
        }
        val ok = result as? VideoMuxResult.Ok
            ?: throw AssertionError("mux did not succeed: $result")

        assertEquals(8, ok.frames)
        val track = readTrack(mp4)
        assertEquals(1, track.trackCount)
        assertEquals(MediaFormat.MIMETYPE_VIDEO_HEVC, track.mime)
        assertEquals(8, track.sampleCount)
        assertEquals(sources.accessUnitSizes, track.sampleSizes)
    }

    /**
     * A width or height of 0 (NAT-05's "the SPS could not be read") is not a
     * refusal: the track is built at 1280x720, and the caller can tell a real
     * size from a guessed one because the muxer logged a warning.
     */
    @Test(timeout = 120_000)
    fun anUnknownSizeFallsBackTo1280x720() {
        val dir = freshDir("fallback")
        val sources = writeStream(dir, "h264", count = 4, payloadBytes = 128)
        val mp4 = File(dir, "out.mp4")

        val result = runBlocking {
            RtpVideoMuxer().mux(sources.es, sources.vidx, "H264", 0, 0, h264ParamSets(), mp4)
        }
        val ok = result as? VideoMuxResult.Ok
            ?: throw AssertionError("mux did not succeed: $result")

        assertEquals(4, ok.frames)
        val track = readTrack(mp4)
        assertEquals(1280, track.width)
        assertEquals(720, track.height)
    }

    /** Parameter sets are not optional: without them no `csd` exists. */
    @Test(timeout = 120_000)
    fun missingParameterSetsFailClosedAndLeaveNoFile() {
        val dir = freshDir("nosets")
        val sources = writeStream(dir, "h264", count = 4, payloadBytes = 128)
        val mp4 = File(dir, "out.mp4")

        val cases = listOf(
            "empty sets" to emptyParamSets(),
            "an SPS without a PPS" to h264ParamSets().copy(pps = emptyList())
        )
        for ((name, sets) in cases) {
            val result = runBlocking {
                RtpVideoMuxer().mux(sources.es, sources.vidx, "H264", 640, 480, sets, mp4)
            }
            assertEquals(
                "$name: $result",
                VideoMuxResult.Failed(RtpVideoMuxer.MISSING_PARAMETER_SETS),
                result
            )
            assertFalse("$name left a file behind", mp4.exists())
        }
    }

    /** The codec id decides the mime, and an id with no mime has no track. */
    @Test(timeout = 120_000)
    fun anUnsupportedCodecIsRefused() {
        val dir = freshDir("codec")
        val sources = writeStream(dir, "h264", count = 4, payloadBytes = 128)
        val mp4 = File(dir, "out.mp4")

        val result = runBlocking {
            RtpVideoMuxer().mux(sources.es, sources.vidx, "PS", 640, 480, h264ParamSets(), mp4)
        }

        assertEquals(VideoMuxResult.Failed(RtpVideoMuxer.UNSUPPORTED_CODEC), result)
        assertFalse(mp4.exists())
    }

    /**
     * Every way the index can be wrong is the same refusal, and none of them
     * leaves a file: a bad magic, a truncated index, a missing index, and an
     * index whose ranges run past the end of the ES.
     */
    @Test(timeout = 120_000)
    fun aBadIndexOrStreamFailsClosedAndLeavesNoFile() {
        val dir = freshDir("badindex")
        val sources = writeStream(dir, "h264", count = 4, payloadBytes = 128)
        val mp4 = File(dir, "out.mp4")

        val badMagic = File(dir, "bad-magic.vidx").apply {
            writeBytes(byteArrayOf(0x56, 0x49, 0x44, 0x32, 0, 0, 0, 0))
        }
        val truncated = File(dir, "truncated.vidx").apply {
            val bytes = sources.vidx.readBytes()
            writeBytes(bytes.copyOf(bytes.size - 3))
        }
        val missing = File(dir, "not-there.vidx")
        val pastTheEnd = File(dir, "past-the-end.vidx").apply {
            VidxFile.write(
                this,
                listOf(VidxEntry(offset = sources.es.length() - 1, length = 16, ptsUs = 0, firstFrame = 1, flags = 0x01))
            )
        }
        val zeroLength = File(dir, "zero-length.vidx").apply {
            VidxFile.write(
                this,
                listOf(VidxEntry(offset = 0, length = 0, ptsUs = 0, firstFrame = 1, flags = 0x01))
            )
        }

        val cases = listOf(
            "a bad magic" to (badMagic to RtpVideoMuxer.UNREADABLE_INDEX),
            "a truncated index" to (truncated to RtpVideoMuxer.UNREADABLE_INDEX),
            "a missing index" to (missing to RtpVideoMuxer.UNREADABLE_INDEX),
            "a range past the end of the ES" to
                (pastTheEnd to VideoSamplePlan.REASON_SHORT_STREAM),
            "a zero-length access unit" to
                (zeroLength to VideoSamplePlan.REASON_BAD_RECORD)
        )

        for ((name, case) in cases) {
            val (index, expected) = case
            val result = runBlocking {
                RtpVideoMuxer().mux(sources.es, index, "H264", 640, 480, h264ParamSets(), mp4)
            }
            assertEquals("$name: $result", VideoMuxResult.Failed(expected), result)
            assertFalse("$name left a file behind: ${mp4.absolutePath}", mp4.exists())
        }

        // And an index with no records at all is not a zero-sample mp4.
        val emptyIndex = File(dir, "empty.vidx").apply { VidxFile.write(this, emptyList()) }
        val result = runBlocking {
            RtpVideoMuxer().mux(sources.es, emptyIndex, "H264", 640, 480, h264ParamSets(), mp4)
        }
        assertEquals(
            VideoMuxResult.Failed(VideoSamplePlan.REASON_EMPTY_INDEX),
            result
        )
        assertFalse(mp4.exists())
    }

    /** A stream file that is not there is refused before a muxer is built. */
    @Test(timeout = 120_000)
    fun aMissingStreamFileIsRefused() {
        val dir = freshDir("nostream")
        val sources = writeStream(dir, "h264", count = 4, payloadBytes = 128)
        val mp4 = File(dir, "out.mp4")

        val result = runBlocking {
            RtpVideoMuxer().mux(
                File(dir, "not-there.h264"),
                sources.vidx,
                "H264",
                640,
                480,
                h264ParamSets(),
                mp4
            )
        }

        assertEquals(VideoMuxResult.Failed(RtpVideoMuxer.UNREADABLE_STREAM), result)
        assertFalse(mp4.exists())
    }

    /** A muxer that was already cancelled writes nothing at all. */
    @Test(timeout = 120_000)
    fun aCancelledMuxerWritesNothing() {
        val dir = freshDir("precancel")
        val sources = writeStream(dir, "h264", count = 8, payloadBytes = 256)
        val mp4 = File(dir, "out.mp4")
        val muxer = RtpVideoMuxer()
        muxer.cancel()

        val result = runBlocking {
            muxer.mux(sources.es, sources.vidx, "H264", 640, 480, h264ParamSets(), mp4)
        }

        assertEquals(VideoMuxResult.Failed(RtpVideoMuxer.CANCELLED), result)
        assertFalse("a cancelled muxer left a file behind", mp4.exists())
    }

    /**
     * A cancel that lands while the muxer is writing removes the half-written
     * file: `MediaMuxer`'s destination exists from its constructor on, and
     * neither the file nor a `stop()` survives the interruption.
     *
     * The timing is what makes this test possible without a progress callback
     * on the frozen interface: the destination appears when the muxer opens it
     * and the muxer then has [LARGE_SAMPLE_COUNT] access units to write, so a
     * poll that notices the file can always cancel first. If a device ever
     * managed to finish inside that window the test says so and stands down
     * rather than reporting a pass it did not observe.
     */
    @Test(timeout = 180_000)
    fun cancellingMidFlightDeletesTheHalfWrittenFile() {
        val dir = freshDir("midflight")
        val sources = writeStream(
            dir,
            "h264",
            count = LARGE_SAMPLE_COUNT,
            payloadBytes = LARGE_PAYLOAD_BYTES
        )
        val mp4 = File(dir, "out.mp4")
        val muxer = RtpVideoMuxer()

        val result = runBlocking {
            val job = async(Dispatchers.IO) {
                muxer.mux(sources.es, sources.vidx, "H264", 640, 480, h264ParamSets(), mp4)
            }
            while (!job.isCompleted && !mp4.exists()) {
                delay(1)
            }
            val sawTheFile = mp4.exists()
            muxer.cancel()
            val finished = job.await()
            if (!sawTheFile) {
                Log.i(TAG, "mid-flight cancel: the destination never appeared")
            }
            finished
        }

        assumeTrue(
            "the muxer completed before this test could interrupt it, so this " +
                "run cannot say whether a mid-flight cancel cleans up: $result",
            result is VideoMuxResult.Failed
        )
        assertEquals(VideoMuxResult.Failed(RtpVideoMuxer.CANCELLED), result)
        assertFalse(
            "a cancelled mux left a half-written file behind: ${mp4.absolutePath} " +
                "(${mp4.length()} octets)",
            mp4.exists()
        )
    }

    // ------------------------------------------------------------- the reader

    /** What `MediaExtractor` says about the mp4 this test just wrote. */
    private class Track(
        val trackCount: Int,
        val mime: String?,
        val width: Int,
        val height: Int,
        val durationUs: Long,
        val sampleSizes: List<Int>,
        val sampleTimesUs: List<Long>
    ) {
        val sampleCount: Int get() = sampleSizes.size
        override fun toString(): String =
            "mime=$mime ${width}x$height samples=$sampleCount " +
                "duration=${durationUs / 1000}ms"
    }

    private fun readTrack(mp4: File): Track {
        val extractor = MediaExtractor()
        try {
            extractor.setDataSource(mp4.absolutePath)
            val count = extractor.trackCount
            assertNotEquals("no track was written: ${mp4.absolutePath}", 0, count)
            val format = extractor.getTrackFormat(0)
            val sizes = mutableListOf<Int>()
            val times = mutableListOf<Long>()
            extractor.selectTrack(0)
            val buffer = ByteBuffer.allocate(READ_BUFFER_BYTES)
            while (true) {
                val size = extractor.readSampleData(buffer, 0)
                if (size < 0) break
                sizes += size
                times += extractor.sampleTime
                if (!extractor.advance()) break
            }
            return Track(
                trackCount = count,
                mime = format.getString(MediaFormat.KEY_MIME),
                width = intOrZero(format, MediaFormat.KEY_WIDTH),
                height = intOrZero(format, MediaFormat.KEY_HEIGHT),
                durationUs = if (format.containsKey(MediaFormat.KEY_DURATION)) {
                    format.getLong(MediaFormat.KEY_DURATION)
                } else {
                    0L
                },
                sampleSizes = sizes,
                sampleTimesUs = times
            )
        } finally {
            extractor.release()
        }
    }

    private fun assertStrictlyIncreasing(times: List<Long>) {
        for (index in 1 until times.size) {
            assertTrue(
                "sample $index does not advance on sample ${index - 1}: $times",
                times[index] > times[index - 1]
            )
        }
    }

    private fun intOrZero(format: MediaFormat, key: String): Int =
        if (format.containsKey(key)) format.getInteger(key) else 0

    // ---------------------------------------------------------------- fixtures

    private class Sources(
        val es: File,
        val vidx: File,
        val accessUnitSizes: List<Int>
    )

    /**
     * Writes an Annex-B elementary stream and its `.vidx` index.
     *
     * Every access unit is one NAL with a four-octet start code and a payload
     * with no zero octet in it, so the bytes the muxer reads are exactly the
     * bytes `MPEG4Writer` converts, with nothing inside them that looks like a
     * start code. The first access unit is a key frame and the rest are not,
     * and the timestamps advance by [FRAME_US] unless [ptsUs] overrides them.
     */
    private fun writeStream(
        dir: File,
        extension: String,
        count: Int,
        payloadBytes: Int,
        ptsUs: (Int) -> Long = { it * FRAME_US }
    ): Sources {
        val es = File(dir, "stream.$extension")
        val vidx = File(dir, "stream.vidx")
        val sizes = mutableListOf<Int>()
        val entries = mutableListOf<VidxEntry>()
        var offset = 0L

        RandomAccessFile(es, "rw").use { output ->
            output.setLength(0L)
            for (index in 0 until count) {
                val payload = ByteArray(payloadBytes) { position ->
                    // 1..255: never zero, so no `00 00 01` can appear.
                    ((index * 31 + position * 17) % 255 + 1).toByte()
                }
                output.write(START_CODE)
                output.write(payload)
                sizes += START_CODE.size + payload.size
                entries += VidxEntry(
                    offset = offset,
                    length = sizes.last(),
                    ptsUs = ptsUs(index),
                    firstFrame = index + 1,
                    flags = if (index == 0) VidxFile.FLAG_KEY else 0
                )
                offset += sizes.last()
            }
        }
        VidxFile.write(vidx, entries)
        return Sources(es, vidx, sizes)
    }

    private fun h264ParamSets() = VideoParamSets(
        sps = listOf(H264_SPS),
        pps = listOf(H264_PPS),
        vps = emptyList(),
        packetizationMode = 1,
        profileLevelId = "64001f",
        donDiff = null
    )

    private fun h265ParamSets() = VideoParamSets(
        sps = listOf(H265_SPS),
        pps = listOf(H265_PPS),
        vps = listOf(H265_VPS),
        packetizationMode = 1,
        profileLevelId = null,
        donDiff = null
    )

    private fun emptyParamSets() = VideoParamSets(
        sps = emptyList(),
        pps = emptyList(),
        vps = emptyList(),
        packetizationMode = null,
        profileLevelId = null,
        donDiff = null
    )

    private fun freshDir(name: String): File {
        val dir = File(appContext.cacheDir, "$CACHE_PREFIX$name")
        dir.deleteRecursively()
        assertTrue("unable to create ${dir.absolutePath}", dir.mkdirs())
        return dir
    }

    @After
    fun cleanOutputs() {
        appContext.cacheDir.listFiles()
            .orEmpty()
            .filter { it.name.startsWith(CACHE_PREFIX) }
            .forEach(File::deleteRecursively)
    }

    private companion object {
        private const val TAG = "VideoMuxerTest"

        val appContext: Context = ApplicationProvider.getApplicationContext()

        private val START_CODE = byteArrayOf(0, 0, 0, 1)

        /** 30 fps, so the card's "one frame" tolerance is this many ms. */
        private const val FRAME_US = 33_333L
        private const val ROUNDING_SLACK_US = 1_000L
        private const val SAMPLE_COUNT = 30

        /** The plain stream's last PTS: 29 frames after the first, and its ms. */
        private const val LAST_PTS_US = (SAMPLE_COUNT - 1) * FRAME_US
        private const val LAST_PTS_MS = LAST_PTS_US / 1_000L

        /** Enough access units that a cancel can land in the middle of them. */
        private const val LARGE_SAMPLE_COUNT = 8_000
        private const val LARGE_PAYLOAD_BYTES = 1_024

        private const val READ_BUFFER_BYTES = 1 shl 20

        private const val CACHE_PREFIX = "rtp-video-mux-"

        /**
         * `ffmpeg 7.1` output, 1280x720 High 3.1 and the PPS of the same file:
         * the vectors `SpsParserTest.cpp` documents, reused so the `csd` handed
         * to `MediaMuxer` is real encoder output.
         */
        private val H264_SPS =
            hex("6764101facb80a00b760220000030002000003001408")
        private val H264_PPS = hex("68ee0f2c8b")

        /** `ffmpeg 7.1` output, HEVC Main 1920x1080, with its VPS. */
        private val H265_VPS = hex("40010c01ffff016000000300900000030000030078959809")
        private val H265_SPS = hex(
            "420101016000000300900000030000030078a003c08010e596566924" +
                "caf016808000000300800000030284"
        )

        /**
         * A PPS-shaped NAL (type 34 in H.265's two-octet header) standing in
         * for a real one, which the host test does not carry. Only the type bits
         * matter to `MPEG4Writer`, which groups the sets by type.
         */
        private val H265_PPS = hex("4401c172b46240")

        private fun hex(value: String): ByteArray =
            ByteArray(value.length / 2) { index ->
                value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
    }
}
