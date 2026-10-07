package com.example.layanalyzer

import android.content.Context
import android.media.MediaExtractor
import android.media.MediaFormat
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.data.VideoParamSets
import com.example.layanalyzer.media.AacExportResult
import com.example.layanalyzer.media.AacExporter
import com.example.layanalyzer.media.AvMuxResult
import com.example.layanalyzer.media.RtpAudioVideoMuxer
import com.example.layanalyzer.media.VidxEntry
import com.example.layanalyzer.media.VidxFile
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * RTP5-KT-04: `media/RtpAudioVideoMuxer.kt` against the platform's own reader.
 *
 * WHAT IS REAL AND WHAT IS SYNTHETIC
 * ==================================
 * The **audio is real**: the WAV below is 16-bit PCM this file writes, and the
 * `.m4a` is what `AacExporter` (M4-KT-04) makes of it with the device's own AAC
 * encoder, remuxed here byte for byte. That is the route the card words -- the
 * rendered WAV goes *through* `AacExporter`, and the combined muxer only reads
 * the result back -- so the test exercises the real hand-off, including the
 * `csd-0` the encoder's `MediaFormat` carries.
 *
 * The **video is synthetic**, exactly as in `VideoMuxerTest`: this tree holds no
 * H.264/H.265 RTP fixture and no encoder to make one, so the ES and its `.vidx`
 * are written here. `MediaMuxer` does not decode, so a container test does not
 * need a decodable bitstream; the parameter sets are the real `ffmpeg 7.1`
 * vectors `SpsParserTest.cpp` documents, so the `avcC` is built from real bytes.
 *
 * The alignment is asserted against the `.m4a`'s **own** sample times, read back
 * with `MediaExtractor`: the plan's rule is "drop the leading audio samples whose
 * shifted time would be negative", so the expected drop count is derived here the
 * same way the plan derives it, and the first audio sample in the written MP4
 * must sit at `its own time + offset`. Both tolerances are a few milliseconds
 * because `MPEG4Writer` re-quantizes to the track timescale.
 */
@RunWith(AndroidJUnit4::class)
class AudioVideoMuxerTest {

    /**
     * The card's alignment, video first: the audio starts half a second after the
     * video, so its first sample is written at PTS 500 000 and nothing is
     * dropped.
     */
    @Test(timeout = 300_000)
    fun audioAfterVideoKeepsEverySampleAndStartsAtTheOffset() {
        val dir = freshDir("audio-after")
        val sources = writeStream(dir, count = SAMPLE_COUNT, payloadBytes = 512)
        val m4a = encodeAudio(dir)
        val mp4 = File(dir, "out.mp4")
        val offsetUs = 500_000L

        val result = runBlocking {
            RtpAudioVideoMuxer().mux(
                esFile = sources.es,
                vidxFile = sources.vidx,
                codec = "H264",
                width = 1280,
                height = 720,
                paramSets = h264ParamSets(),
                audioFile = m4a,
                outFile = mp4,
                videoStartEpochUs = VIDEO_START_US,
                audioStartEpochUs = VIDEO_START_US + offsetUs
            )
        }
        val ok = result as? AvMuxResult.Ok
            ?: throw AssertionError("the combined mux did not succeed: $result")

        assertEquals(0, ok.droppedAudioSamples)
        assertEquals(offsetUs, ok.offsetUs)
        assertEquals(SAMPLE_COUNT, ok.videoFrames)
        val m4aTimes = readSampleTimes(m4a)
        assertEquals("every audio sample is written", m4aTimes.size, ok.audioSamples)

        val tracks = readTracks(mp4)
        assertEquals("the mp4 must hold exactly two tracks", 2, tracks.size)
        val video = tracks.single { it.mime == MediaFormat.MIMETYPE_VIDEO_AVC }
        val audio = tracks.single { it.mime == AacExporter.MIME_AAC }
        assertEquals(SAMPLE_COUNT, video.sampleCount)
        assertEquals("the samples must be the access units, byte for byte", sources.accessUnitSizes, video.sampleSizes)
        assertEquals("the first access unit is the zero of the timeline", 0L, video.sampleTimesUs.first())
        assertStrictlyIncreasing(video.sampleTimesUs)
        assertEquals("the audio track keeps every sample", m4aTimes.size, audio.sampleCount)
        // The card: the offset is the audio track's first sample PTS.
        assertEquals(
            "the first audio sample must sit at the offset",
            offsetUs.toDouble(),
            audio.sampleTimesUs.first().toDouble(),
            AUDIO_TOLERANCE_US.toDouble()
        )
        assertStrictlyIncreasing(audio.sampleTimesUs)
        Log.i(TAG, "audio-after: video=$video audio=$audio ${ok}")
    }

    /**
     * The case the card does not cover: the audio starts *before* the video, so
     * the raw offset is negative and `MediaMuxer` would refuse it. The leading
     * samples are dropped and counted, and no written sample is negative.
     */
    @Test(timeout = 300_000)
    fun audioBeforeVideoDropsTheLeadingSamplesAndCountsThem() {
        val dir = freshDir("audio-before")
        val sources = writeStream(dir, count = 4, payloadBytes = 256)
        val m4a = encodeAudio(dir)
        val mp4 = File(dir, "out.mp4")
        val offsetUs = -200_000L

        val result = runBlocking {
            RtpAudioVideoMuxer().mux(
                esFile = sources.es,
                vidxFile = sources.vidx,
                codec = "H264",
                width = 640,
                height = 480,
                paramSets = h264ParamSets(),
                audioFile = m4a,
                outFile = mp4,
                videoStartEpochUs = VIDEO_START_US,
                audioStartEpochUs = VIDEO_START_US + offsetUs
            )
        }
        val ok = result as? AvMuxResult.Ok
            ?: throw AssertionError("the combined mux did not succeed: $result")

        val m4aTimes = readSampleTimes(m4a)
        // The plan's rule, derived independently here: a sample is dropped exactly
        // when its shifted time would be negative.
        val expectedDrop = m4aTimes.count { it + offsetUs < 0L }
        assertTrue(
            "this test needs an .m4a long enough to lose some samples: $m4aTimes",
            expectedDrop > 0 && expectedDrop < m4aTimes.size
        )
        assertEquals(expectedDrop, ok.droppedAudioSamples)
        assertEquals(offsetUs, ok.offsetUs)
        assertEquals(m4aTimes.size - expectedDrop, ok.audioSamples)

        val audio = readTracks(mp4).single { it.mime == AacExporter.MIME_AAC }
        assertEquals(m4aTimes.size - expectedDrop, audio.sampleCount)
        assertTrue(
            "no written sample may be negative: ${audio.sampleTimesUs}",
            audio.sampleTimesUs.all { it >= 0L }
        )
        assertEquals(
            "the first kept sample keeps its place on the shared timeline",
            (m4aTimes[expectedDrop] + offsetUs).toDouble(),
            audio.sampleTimesUs.first().toDouble(),
            AUDIO_TOLERANCE_US.toDouble()
        )
        assertStrictlyIncreasing(audio.sampleTimesUs)
    }

    /** A missing `.m4a` is refused before a muxer is built, and leaves no file. */
    @Test(timeout = 300_000)
    fun aMissingAudioFileIsRefused() {
        val dir = freshDir("no-audio")
        val sources = writeStream(dir, count = 4, payloadBytes = 128)
        val mp4 = File(dir, "out.mp4")

        val result = runBlocking {
            RtpAudioVideoMuxer().mux(
                esFile = sources.es,
                vidxFile = sources.vidx,
                codec = "H264",
                width = 640,
                height = 480,
                paramSets = h264ParamSets(),
                audioFile = File(dir, "not-there.m4a"),
                outFile = mp4,
                videoStartEpochUs = VIDEO_START_US,
                audioStartEpochUs = VIDEO_START_US
            )
        }

        assertEquals(AvMuxResult.Failed(RtpAudioVideoMuxer.UNREADABLE_AUDIO), result)
        assertFalse(mp4.exists())
    }

    /** A file that is not an `.m4a` with an AAC track in it is refused the same way. */
    @Test(timeout = 300_000)
    fun aFileWithoutAnAacTrackIsRefused() {
        val dir = freshDir("no-track")
        val sources = writeStream(dir, count = 4, payloadBytes = 128)
        val notAudio = File(dir, "not-audio.m4a").apply { writeBytes(sources.es.readBytes()) }
        val mp4 = File(dir, "out.mp4")

        val result = runBlocking {
            RtpAudioVideoMuxer().mux(
                esFile = sources.es,
                vidxFile = sources.vidx,
                codec = "H264",
                width = 640,
                height = 480,
                paramSets = h264ParamSets(),
                audioFile = notAudio,
                outFile = mp4,
                videoStartEpochUs = VIDEO_START_US,
                audioStartEpochUs = VIDEO_START_US
            )
        }

        assertTrue(
            "an ES renamed .m4a must be refused: $result",
            result is AvMuxResult.Failed
        )
        assertFalse(mp4.exists())
    }

    /** A muxer that was already cancelled writes nothing at all. */
    @Test(timeout = 300_000)
    fun aCancelledMuxerWritesNothing() {
        val dir = freshDir("precancel")
        val sources = writeStream(dir, count = 4, payloadBytes = 128)
        val m4a = encodeAudio(dir)
        val mp4 = File(dir, "out.mp4")
        val muxer = RtpAudioVideoMuxer()
        muxer.cancel()

        val result = runBlocking {
            muxer.mux(
                sources.es,
                sources.vidx,
                "H264",
                640,
                480,
                h264ParamSets(),
                m4a,
                mp4,
                VIDEO_START_US,
                VIDEO_START_US
            )
        }

        assertEquals(AvMuxResult.Failed(RtpAudioVideoMuxer.CANCELLED), result)
        assertFalse("a cancelled muxer left a file behind", mp4.exists())
    }

    // ------------------------------------------------------------- the reader

    /** What `MediaExtractor` says about one track of a file this test wrote. */
    private class Track(
        val mime: String?,
        val sampleSizes: List<Int>,
        val sampleTimesUs: List<Long>
    ) {
        val sampleCount: Int get() = sampleSizes.size
        override fun toString(): String = "mime=$mime samples=$sampleCount"
    }

    private fun readTracks(file: File): List<Track> {
        val extractor = MediaExtractor()
        try {
            extractor.setDataSource(file.absolutePath)
            val count = extractor.trackCount
            assertNotEquals("no track was written: ${file.absolutePath}", 0, count)
            return (0 until count).map { index -> readTrack(extractor, index) }
        } finally {
            extractor.release()
        }
    }

    private fun readTrack(extractor: MediaExtractor, index: Int): Track {
        val format = extractor.getTrackFormat(index)
        extractor.selectTrack(index)
        val sizes = mutableListOf<Int>()
        val times = mutableListOf<Long>()
        val buffer = ByteBuffer.allocate(READ_BUFFER_BYTES)
        while (true) {
            val size = extractor.readSampleData(buffer, 0)
            if (size < 0) break
            sizes += size
            times += extractor.sampleTime
            if (!extractor.advance()) break
        }
        extractor.unselectTrack(index)
        return Track(
            mime = format.getString(MediaFormat.KEY_MIME),
            sampleSizes = sizes,
            sampleTimesUs = times
        )
    }

    /** The AAC track's own sample times, in microseconds. */
    private fun readSampleTimes(m4a: File): List<Long> =
        readTracks(m4a).single { it.mime == AacExporter.MIME_AAC }.sampleTimesUs

    private fun assertStrictlyIncreasing(times: List<Long>) {
        for (index in 1 until times.size) {
            assertTrue(
                "sample $index does not advance on sample ${index - 1}: $times",
                times[index] > times[index - 1]
            )
        }
    }

    // ---------------------------------------------------------------- fixtures

    /**
     * Encodes one second of 16-bit PCM silence into an `.m4a` with M4-KT-04's own
     * exporter -- the card's route, and the only way to get a real AAC track
     * without a capture.
     *
     * A device without an AAC encoder cannot run this test, which is an
     * assumption rather than a failure: `AacExporter` reports it, and the
     * combined muxer has nothing to combine.
     */
    private fun encodeAudio(dir: File): File {
        val wav = File(dir, "audio.wav").apply { writeBytes(pcmWav()) }
        val m4a = File(dir, "audio.m4a")
        val result = runBlocking { AacExporter().export(wav, m4a) }
        assumeTrue("this device has no AAC encoder: $result", result is AacExportResult.Ok)
        assertTrue("the encoder wrote no .m4a", m4a.isFile && m4a.length() > 0L)
        return m4a
    }

    /** A canonical 44-octet RIFF/WAVE header around [PCM_SECONDS] of 16-bit silence. */
    private fun pcmWav(): ByteArray {
        val frames = SAMPLE_RATE * PCM_SECONDS
        val dataBytes = frames * BYTES_PER_SAMPLE
        val out = ByteBuffer.allocate(WAV_HEADER_BYTES + dataBytes)
            .order(ByteOrder.LITTLE_ENDIAN)
        out.put("RIFF".toByteArray(Charsets.US_ASCII))
        out.putInt(WAV_HEADER_BYTES - 8 + dataBytes)
        out.put("WAVE".toByteArray(Charsets.US_ASCII))
        out.put("fmt ".toByteArray(Charsets.US_ASCII))
        out.putInt(16)
        out.putShort(1.toShort())             // PCM
        out.putShort(1.toShort())             // mono
        out.putInt(SAMPLE_RATE)
        out.putInt(SAMPLE_RATE * BYTES_PER_SAMPLE)
        out.putShort(BYTES_PER_SAMPLE.toShort())
        out.putShort(16.toShort())            // bits per sample
        out.put("data".toByteArray(Charsets.US_ASCII))
        out.putInt(dataBytes)
        return out.array()
    }

    private class Sources(
        val es: File,
        val vidx: File,
        val accessUnitSizes: List<Int>
    )

    /**
     * Writes an Annex-B elementary stream and its `.vidx`, as `VideoMuxerTest`
     * does: one NAL per access unit with a four-octet start code and a payload
     * with no zero octet, so nothing inside a sample looks like a start code.
     */
    private fun writeStream(dir: File, count: Int, payloadBytes: Int): Sources {
        val es = File(dir, "stream.h264")
        val vidx = File(dir, "stream.vidx")
        val sizes = mutableListOf<Int>()
        val entries = mutableListOf<VidxEntry>()
        var offset = 0L

        RandomAccessFile(es, "rw").use { output ->
            output.setLength(0L)
            for (index in 0 until count) {
                val payload = ByteArray(payloadBytes) { position ->
                    ((index * 31 + position * 17) % 255 + 1).toByte()
                }
                output.write(START_CODE)
                output.write(payload)
                sizes += START_CODE.size + payload.size
                entries += VidxEntry(
                    offset = offset,
                    length = sizes.last(),
                    ptsUs = index * FRAME_US,
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
        private const val TAG = "AudioVideoMuxerTest"

        val appContext: Context = ApplicationProvider.getApplicationContext()

        private val START_CODE = byteArrayOf(0, 0, 0, 1)

        /** 30 fps, so a video frame is this many microseconds. */
        private const val FRAME_US = 33_333L
        private const val SAMPLE_COUNT = 30

        /** An arbitrary absolute anchor: the two tracks only have to agree on it. */
        private const val VIDEO_START_US = 1_700_000_000_000_000L

        /** 1 s of 44.1 kHz mono: enough for the negative-offset case to lose samples. */
        private const val PCM_SECONDS = 1
        private const val SAMPLE_RATE = 44_100
        private const val BYTES_PER_SAMPLE = 2
        private const val WAV_HEADER_BYTES = 44

        /**
         * `MPEG4Writer` re-quantizes each track to its own timescale, so a
         * sample time read back can differ from the one handed over by a
         * fraction of a millisecond. A few milliseconds is the rounding, not a
         * widened criterion: one AAC frame at 44.1 kHz is 23 ms.
         */
        private const val AUDIO_TOLERANCE_US = 5_000L

        private const val READ_BUFFER_BYTES = 1 shl 20
        private const val CACHE_PREFIX = "rtp-av-mux-"

        /** `ffmpeg 7.1` output, 1280x720 High 3.1 and the PPS of the same file. */
        private val H264_SPS = hex("6764101facb80a00b760220000030002000003001408")
        private val H264_PPS = hex("68ee0f2c8b")

        private fun hex(value: String): ByteArray =
            ByteArray(value.length / 2) { index ->
                value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
    }
}
