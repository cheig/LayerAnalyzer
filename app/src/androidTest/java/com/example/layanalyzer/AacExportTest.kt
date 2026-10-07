// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import android.media.MediaCodecInfo
import android.media.MediaCodecList
import android.media.MediaExtractor
import android.media.MediaFormat
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.data.WavHeader
import com.example.layanalyzer.media.AacExportResult
import com.example.layanalyzer.media.AacExporter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.abs

/**
 * RTP4-KT-04: `media/AacExporter.kt` against a WAV this tree really produced.
 *
 * THE INPUT IS NOT SYNTHETIC
 * ==========================
 * Every acceptance assertion below starts from the WAV that the existing
 * pipeline renders out of the `sip_g711a_bidirectional` fixture -- open the
 * capture, `scanRtpStreams`, `decodeRtpAudio`, take `items[0].wavPath`, exactly
 * as `RtpMediaCodecRenderTest` does. Nothing here hand-builds the WAV the card
 * asks to compress, because a hand-built one would be evidence about a file
 * this app never writes.
 *
 * The one exception is [stereoSourceIsEncodedAsStereo], and it says so in its
 * own comment: the repository's renderer downmixes every stream to mono, so the
 * card's "声道跟随源" cannot be exercised from any fixture. That test's input is
 * a canonical 44-octet-header PCM WAV written in this file and is the *subject*
 * of the test, not evidence about a capture.
 *
 * The duration assertion is the card's: the `MediaExtractor` duration has to be
 * within 100 ms of `WavHeader.parse(wav).frameCount / sampleRate`. AAC-LC
 * frames are 1024 samples, so an encoder pads the final partial frame and the
 * `.m4a` can be up to one frame longer than its source -- 128 ms at 8 kHz. That
 * is a property of the codec, and the assertion is left exactly as the card
 * writes it rather than widened; [exportedM4aOpensAsOneAacTrackWithTheWavDuration]
 * prints the measured difference so a failure is diagnosable.
 */
@RunWith(AndroidJUnit4::class)
class AacExportTest {

    /**
     * The card's acceptance: a real rendered WAV goes in, and the `.m4a` that
     * comes out is a single `audio/mp4a-latm` track whose sample rate, channel
     * count and duration are the WAV's.
     */
    @Test(timeout = 180_000)
    fun exportedM4aOpensAsOneAacTrackWithTheWavDuration() {
        assumeAacEncoderAvailable(SAMPLE_RATE, 1)
        val session = openCapture(TARGET_SAMPLE)
        try {
            val wav = renderWav(session, "ok")
            val header = requireNotNull(WavHeader.parse(wav)) {
                "the rendered WAV is not a readable PCM WAV: ${wav.absolutePath}"
            }
            assertEquals(16, header.bitsPerSample)

            val m4a = File(wav.parentFile, "exported.m4a")
            var lastDone = -1
            var lastTotal = -1
            val result = runBlocking {
                AacExporter().export(wav, m4a) { done, total ->
                    lastDone = done
                    lastTotal = total
                }
            }
            val ok = result as? AacExportResult.Ok
                ?: throw AssertionError("export did not succeed: $result")

            assertEquals(m4a.absolutePath, ok.m4aPath)
            assertEquals(header.sampleRate, ok.sampleRate)
            assertEquals(header.channels, ok.channels)
            assertEquals(
                "durationMs must be the WAV's own duration",
                header.frameCount * 1000L / header.sampleRate,
                ok.durationMs
            )
            // Progress is counted in sample frames and finishes at the total,
            // so the last call is (total, total) -- ``frameCount`` is what the
            // WAV's own header says, not a number this exporter chose.
            assertEquals(header.frameCount.toInt(), lastTotal)
            assertEquals(header.frameCount.toInt(), lastDone)
            assertTrue(
                "no m4a was written: ${m4a.absolutePath}",
                m4a.isFile && m4a.length() > 0L
            )

            assertSingleAacTrack(m4a, header.sampleRate, header.channels)
            assertDurationWithinOneHundredMilliseconds(m4a, wav)
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    /**
     * A cancel takes effect inside the encode loop and leaves nothing behind:
     * the `.m4a` is half-written when the flag is set, and neither `stop()` nor
     * the file itself survives it.
     */
    @Test(timeout = 180_000)
    fun cancelledExportLeavesNoHalfWrittenFile() {
        assumeAacEncoderAvailable(SAMPLE_RATE, 1)
        val session = openCapture(TARGET_SAMPLE)
        try {
            val wav = renderWav(session, "cancel")
            val m4a = File(wav.parentFile, "cancelled.m4a")
            val exporter = AacExporter()
            var calls = 0
            val result = runBlocking {
                exporter.export(wav, m4a) { _, _ ->
                    calls++
                    if (calls >= CANCEL_AFTER_BLOCKS) exporter.cancel()
                }
            }

            assertTrue(
                "the export finished before it could be cancelled: $result",
                calls >= CANCEL_AFTER_BLOCKS
            )
            assertEquals(AacExportResult.Failed(AacExporter.CANCELLED), result)
            assertFalse(
                "a cancelled export left a file behind: ${m4a.absolutePath}",
                m4a.exists()
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    /**
     * Every input the exporter refuses comes back as an error and leaves no
     * `.m4a`, however far the encoder had got. The first two cases are refused
     * before an encoder is even looked up, so they run on a device with no AAC
     * encoder as well.
     */
    @Test(timeout = 180_000)
    fun badInputsFailClosedAndLeaveNoFile() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val wav = renderWav(session, "bad")
            val dir = wav.parentFile
            val cases = listOf(
                Case(
                    name = "a file that does not exist",
                    input = File(dir, "does-not-exist.wav"),
                    expected = AacExporter.UNREADABLE_WAV
                ),
                Case(
                    name = "a file that is not a WAV at all",
                    input = writeGarbage(File(dir, "garbage.wav")),
                    expected = AacExporter.UNREADABLE_WAV
                ),
                Case(
                    name = "a WAV truncated inside its data chunk",
                    input = writeTruncated(File(dir, "truncated.wav"), wav),
                    expected = AacExporter.UNREADABLE_WAV
                ),
                Case(
                    name = "8-bit PCM",
                    input = writeEightBit(File(dir, "eight-bit.wav"), wav),
                    expected = AacExporter.UNSUPPORTED_PCM
                )
            )

            for (case in cases) {
                val m4a = File(dir, "refused.m4a")
                m4a.delete()
                assertFalse(
                    "${case.name} was refused while a stale file was present",
                    m4a.exists()
                )
                val result = runBlocking { AacExporter().export(case.input, m4a) }
                assertEquals("${case.name}: $result", AacExportResult.Failed(case.expected), result)
                assertFalse(
                    "${case.name} left a file behind: ${m4a.absolutePath}",
                    m4a.exists()
                )
            }
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    /**
     * The card's "声道跟随源": a stereo source is encoded as stereo. Nothing in
     * this repository renders stereo -- `renderRtpAudioFromPcm` downmixes every
     * stream to mono -- so the source here is a canonical 44-octet-header PCM
     * WAV written below, and it is the subject of the test rather than evidence
     * about any capture. 44.1 kHz is used because it is the configuration every
     * AAC-LC encoder on every device supports.
     */
    @Test(timeout = 180_000)
    fun stereoSourceIsEncodedAsStereo() {
        assumeAacEncoderAvailable(STEREO_SAMPLE_RATE, 2)
        val dir = freshDir("stereo")
        val wav = writePcmWav(
            file = File(dir, "stereo.wav"),
            sampleRate = STEREO_SAMPLE_RATE,
            channels = 2,
            frames = STEREO_SAMPLE_RATE
        )
        val header = requireNotNull(WavHeader.parse(wav)) {
            "the stereo WAV this test wrote is not readable"
        }
        assertEquals(2, header.channels)

        val m4a = File(dir, "stereo.m4a")
        val result = runBlocking { AacExporter().export(wav, m4a) }
        val ok = result as? AacExportResult.Ok
            ?: throw AssertionError("stereo export did not succeed: $result")

        assertEquals(header.sampleRate, ok.sampleRate)
        assertEquals("the source's two channels must survive the encoder", 2, ok.channels)
        assertTrue("no m4a was written", m4a.isFile && m4a.length() > 0L)
        assertSingleAacTrack(m4a, header.sampleRate, 2)
        assertDurationWithinOneHundredMilliseconds(m4a, wav)
    }

    // ------------------------------------------------------------- assertions

    /** The card's acceptance, first half: one track, AAC-LC, same rate and count. */
    private fun assertSingleAacTrack(m4a: File, sampleRate: Int, channels: Int) {
        val extractor = MediaExtractor()
        try {
            extractor.setDataSource(m4a.absolutePath)
            assertEquals(
                "the m4a must hold exactly one track",
                1,
                extractor.trackCount
            )
            val format = extractor.getTrackFormat(0)
            assertEquals(
                MediaFormat.MIMETYPE_AUDIO_AAC,
                format.getString(MediaFormat.KEY_MIME)
            )
            assertEquals(sampleRate, format.getInteger(MediaFormat.KEY_SAMPLE_RATE))
            assertEquals(channels, format.getInteger(MediaFormat.KEY_CHANNEL_COUNT))

            // The `moov` can describe a track whose `mdat` is unreadable, so
            // the first access unit is read back as well: it is the smallest
            // proof that `stop()` wrote a file and not just a header.
            extractor.selectTrack(0)
            val sample = extractor.readSampleData(ByteBuffer.allocate(READ_BUFFER_BYTES), 0)
            assertTrue("the m4a's first sample could not be read", sample > 0)
        } finally {
            extractor.release()
        }
    }

    /** The card's acceptance, second half: duration within 100 ms of the WAV's. */
    private fun assertDurationWithinOneHundredMilliseconds(m4a: File, wav: File) {
        val header = requireNotNull(WavHeader.parse(wav))
        val wavDurationUs = header.frameCount * MICROS_PER_SECOND / header.sampleRate

        val extractor = MediaExtractor()
        val durationUs = try {
            extractor.setDataSource(m4a.absolutePath)
            val format = extractor.getTrackFormat(0)
            assertTrue(
                "the m4a track carries no duration",
                format.containsKey(MediaFormat.KEY_DURATION)
            )
            format.getLong(MediaFormat.KEY_DURATION)
        } finally {
            extractor.release()
        }

        val deltaMs = abs(durationUs - wavDurationUs) / 1000L
        val detail = "m4a=${durationUs / 1000L}ms wav=${wavDurationUs / 1000L}ms " +
            "delta=${deltaMs}ms frames=${header.frameCount} " +
            "@${header.sampleRate}Hz (one AAC frame is " +
            "${AAC_FRAME_SAMPLES * 1000L / header.sampleRate}ms)"
        Log.i(TAG, "${m4a.name}: $detail")
        assertTrue("the m4a duration is off by $deltaMs ms: $detail", deltaMs < 100L)
    }

    /**
     * Skips -- with the reason spelled out -- on a device with no AAC encoder,
     * which the card requires instead of a failure. A device that has one is
     * never skipped, so this cannot quietly disable the acceptance above.
     */
    private fun assumeAacEncoderAvailable(sampleRate: Int, channels: Int) {
        val format = MediaFormat.createAudioFormat(
            AacExporter.MIME_AAC,
            sampleRate,
            channels
        ).apply {
            setInteger(
                MediaFormat.KEY_AAC_PROFILE,
                MediaCodecInfo.CodecProfileLevel.AACObjectLC
            )
            setInteger(MediaFormat.KEY_BIT_RATE, AacExporter.BIT_RATE)
        }
        val encoder = MediaCodecList(MediaCodecList.REGULAR_CODECS)
            .findEncoderForFormat(format)
        assumeTrue(
            "this device has no AAC-LC encoder for ${sampleRate}Hz/${channels}ch, " +
                "so RTP4-KT-04's acceptance cannot run here",
            encoder != null
        )
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Renders a real WAV out of [TARGET_SAMPLE] with the existing pipeline:
     * `scanRtpStreams` finds the decodable G.711A stream, `decodeRtpAudio`
     * writes the WAV, and the WAV is what the exporter is handed.
     */
    private fun renderWav(session: Long, name: String): File {
        val outDir = freshDir(name)
        val scan = scan(session)
        val streamId = findG711AStream(scan).getString("id")
        val generation = scan.getLong("scanGeneration")

        val result = JSONObject(
            NativeEngine.decodeRtpAudio(
                session,
                JSONObject()
                    .put("scanGeneration", generation)
                    .put("streams", JSONArray().put(streamId))
                    .put("timing", "jitter")
                    .put("jitterMs", 50)
                    .toString(),
                outDir.absolutePath,
                null
            )
        )
        assertEquals(
            "decodeRtpAudio reported an error: ${result.optString("error")}",
            "",
            result.optString("error")
        )
        assertFalse(result.optBoolean("cancelled", true))
        val item = requireNotNull(result.optJSONArray("items")?.optJSONObject(0)) {
            "decodeRtpAudio produced no item for $streamId: $result"
        }
        val wav = File(item.getString("wavPath"))
        assertTrue(
            "decodeRtpAudio wrote no WAV: ${wav.absolutePath}",
            wav.isFile && wav.length() > 0L
        )
        return wav
    }

    private fun scan(session: Long): JSONObject {
        val result = JSONObject(
            NativeEngine.scanRtpStreams(
                session,
                "{\"limitToDisplayFilter\":false}",
                null
            )
        )
        assertEquals(
            "scanRtpStreams reported an error: ${result.optString("error")}",
            "",
            result.optString("error")
        )
        assertFalse(result.optBoolean("cancelled", true))
        return result
    }

    private fun findG711AStream(scan: JSONObject): JSONObject {
        val streams = requireNotNull(scan.optJSONArray("streams"))
        for (index in 0 until streams.length()) {
            val stream = streams.getJSONObject(index)
            if (stream.optLong("ssrc") == TARGET_SSRC &&
                stream.optString("codec") == "g711A" &&
                stream.optString("decodable") == "yes"
            ) {
                return stream
            }
        }
        throw AssertionError(
            "No decodable g711A SSRC=$TARGET_SSRC stream was found: $scan"
        )
    }

    private fun openCapture(sampleName: String): Long {
        val capture = copyAssetFile(
            testContext,
            "rtp/$sampleName.pcap",
            File(appContext.cacheDir, "rtp-aac-export-$sampleName.pcap")
        )
        val session = NativeEngine.openFile(capture.absolutePath, null)
        assertNotEquals(
            "openFile failed: ${NativeEngine.getLastError()}",
            0L,
            session
        )
        return session
    }

    /** Bytes that are not a RIFF/WAVE file at all, so `WavHeader.parse` says no. */
    private fun writeGarbage(file: File): File {
        file.writeBytes(ByteArray(GARBAGE_BYTES) { (it * 31 + 7).toByte() })
        return file
    }

    /** A real rendered WAV with its last octets cut off. */
    private fun writeTruncated(file: File, source: File): File {
        val bytes = source.readBytes()
        file.writeBytes(bytes.copyOf(bytes.size - TRUNCATED_BYTES))
        return file
    }

    /**
     * A real rendered WAV whose `fmt ` chunk declares 8-bit samples. The
     * `blockAlign` is rewritten to match so the file still is a *consistent*
     * 8-bit PCM WAV -- the exporter has to refuse it for the bit depth, not
     * because the header contradicts itself.
     */
    private fun writeEightBit(file: File, source: File): File {
        val bytes = source.readBytes()
        var offset = RIFF_HEADER_BYTES
        while (offset + CHUNK_HEADER_BYTES <= bytes.size) {
            val chunkId = String(bytes, offset, 4, Charsets.US_ASCII)
            val chunkSize = littleEndianUnsignedInt(bytes, offset + 4).toInt()
            if (chunkId == "fmt ") {
                require(chunkSize >= PCM_FMT_BYTES) { "the fmt chunk is too small" }
                val fmt = offset + CHUNK_HEADER_BYTES
                val channels = littleEndianUnsignedShort(bytes, fmt + 2)
                // audioFormat(2) channels(2) sampleRate(4) byteRate(4)
                // blockAlign(2) bitsPerSample(2)
                ByteBuffer.wrap(bytes, fmt + 12, 2)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putShort(channels.toShort())
                ByteBuffer.wrap(bytes, fmt + 14, 2)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putShort(8)
                file.writeBytes(bytes)
                return file
            }
            offset += CHUNK_HEADER_BYTES + chunkSize + (chunkSize and 1)
        }
        throw AssertionError("the rendered WAV has no fmt chunk")
    }

    /** A canonical 44-octet-header 16-bit PCM WAV, as `WavWriter` writes one. */
    private fun writePcmWav(
        file: File,
        sampleRate: Int,
        channels: Int,
        frames: Int
    ): File {
        val dataBytes = frames * channels * BYTES_PER_SAMPLE
        val buffer = ByteBuffer
            .allocate(WAV_HEADER_BYTES + dataBytes)
            .order(ByteOrder.LITTLE_ENDIAN)
        buffer.put("RIFF".toByteArray(Charsets.US_ASCII))
        buffer.putInt(WAV_HEADER_BYTES - 8 + dataBytes)
        buffer.put("WAVE".toByteArray(Charsets.US_ASCII))
        buffer.put("fmt ".toByteArray(Charsets.US_ASCII))
        buffer.putInt(PCM_FMT_BYTES)
        buffer.putShort(1)                                        // PCM
        buffer.putShort(channels.toShort())
        buffer.putInt(sampleRate)
        buffer.putInt(sampleRate * channels * BYTES_PER_SAMPLE)   // byte rate
        buffer.putShort((channels * BYTES_PER_SAMPLE).toShort())  // block align
        buffer.putShort(BITS_PER_SAMPLE.toShort())
        buffer.put("data".toByteArray(Charsets.US_ASCII))
        buffer.putInt(dataBytes)
        // A quiet stereo tone: channel 0 falls, channel 1 rises, so an encoder
        // that merged the channels would still produce a readable file while
        // the track's channel count is what this test asserts on.
        for (frame in 0 until frames) {
            buffer.putShort((frame % 1000).toShort())
            buffer.putShort((1000 - frame % 1000).toShort())
        }
        file.writeBytes(buffer.array())
        return file
    }

    private fun freshDir(name: String): File {
        val dir = File(appContext.cacheDir, "$CACHE_PREFIX$name")
        dir.deleteRecursively()
        assertTrue("unable to create ${dir.absolutePath}", dir.mkdirs())
        return dir
    }

    private fun littleEndianUnsignedInt(bytes: ByteArray, offset: Int): Long =
        (bytes[offset].toLong() and 0xff) or
            ((bytes[offset + 1].toLong() and 0xff) shl 8) or
            ((bytes[offset + 2].toLong() and 0xff) shl 16) or
            ((bytes[offset + 3].toLong() and 0xff) shl 24)

    private fun littleEndianUnsignedShort(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

    @After
    fun cleanOutputs() {
        appContext.cacheDir.listFiles()
            .orEmpty()
            .filter { it.name.startsWith(CACHE_PREFIX) }
            .forEach(File::deleteRecursively)
    }

    private class Case(
        val name: String,
        val input: File,
        val expected: String
    )

    companion object {
        private const val TAG = "AacExportTest"
        private const val TARGET_SAMPLE = "sip_g711a_bidirectional"
        private const val TARGET_SSRC = 2591773570L

        private const val SAMPLE_RATE = 8000
        private const val STEREO_SAMPLE_RATE = 44_100

        /** How many PCM blocks go by before the cancel test pulls the plug. */
        private const val CANCEL_AFTER_BLOCKS = 2

        private const val MICROS_PER_SECOND = 1_000_000L
        private const val AAC_FRAME_SAMPLES = 1024L

        private const val GARBAGE_BYTES = 4096
        private const val TRUNCATED_BYTES = 64
        private const val READ_BUFFER_BYTES = 4096

        private const val CACHE_PREFIX = "rtp-aac-export-"

        private const val RIFF_HEADER_BYTES = 12
        private const val CHUNK_HEADER_BYTES = 8
        private const val PCM_FMT_BYTES = 16
        private const val BITS_PER_SAMPLE = 16
        private const val BYTES_PER_SAMPLE = 2
        private const val WAV_HEADER_BYTES = 44

        private lateinit var appContext: Context
        private lateinit var testContext: Context

        @JvmStatic
        @BeforeClass
        fun initializeEngine() {
            appContext = ApplicationProvider.getApplicationContext()
            testContext = InstrumentationRegistry.getInstrumentation().context
            val application = appContext as LayerAnalyzerApplication

            var engineState = runBlocking {
                withTimeout(30_000) {
                    application.engineState.first {
                        it is EngineState.Ready ||
                            it is EngineState.Failed ||
                            it is EngineState.AwaitingSessionRestore
                    }
                }
            }
            if (engineState is EngineState.AwaitingSessionRestore) {
                application.declineSessionRestore()
                engineState = runBlocking {
                    withTimeout(30_000) {
                        application.engineState.first {
                            it is EngineState.Ready || it is EngineState.Failed
                        }
                    }
                }
            }
            assertTrue(
                (engineState as? EngineState.Failed)?.message
                    ?: "Native engine did not initialize.",
                engineState is EngineState.Ready
            )
            copyAssetFolder(
                appContext,
                "wireshark-data",
                File(appContext.filesDir, "wireshark-data")
            )
        }

        private fun copyAssetFolder(
            context: Context,
            assetPath: String,
            targetDir: File
        ) {
            targetDir.mkdirs()
            val children = context.assets.list(assetPath).orEmpty()
            if (children.isEmpty()) {
                copyAssetFile(context, assetPath, targetDir)
                return
            }
            for (child in children) {
                val childAssetPath = "$assetPath/$child"
                val grandChildren = context.assets.list(childAssetPath).orEmpty()
                if (grandChildren.isEmpty()) {
                    copyAssetFile(
                        context,
                        childAssetPath,
                        File(targetDir, child)
                    )
                } else {
                    copyAssetFolder(
                        context,
                        childAssetPath,
                        File(targetDir, child)
                    )
                }
            }
        }

        private fun copyAssetFile(
            context: Context,
            assetPath: String,
            targetFile: File
        ): File {
            targetFile.parentFile?.mkdirs()
            context.assets.open(assetPath).use { input ->
                targetFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            return targetFile
        }
    }
}
