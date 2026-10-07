// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.data.WavHeader
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * RTP4-NAT-07: contract-level checks for `renderRtpAudioFromPcm` against the
 * capture fixtures that actually exist.
 *
 * WHAT IS NOT TESTED HERE, AND WHY
 * ================================
 * The card's acceptance for this task is the end-to-end MEDIACODEC loop --
 * `extractRtpCodecFrames` -> `MediaCodecAudioDecoder` (RTP4-KT-01) ->
 * `renderRtpAudioFromPcm`, with the WAV duration within 5 % of
 * `frameCount x 20 ms`. **It cannot run in this tree, and no assertion for it is
 * written, `@Ignore`d or weakened here**, for two independent reasons:
 *
 *  1. `media/MediaCodecAudioDecoder.kt` (RTP4-KT-01) does not exist yet, so
 *     nothing in this repository can turn a `.frames` + `.fidx` pair into the
 *     `.pcmchunks` this endpoint consumes. Generating that file by hand would be
 *     fabricating the exact artefact the loop is supposed to produce.
 *  2. There is no AMR-NB, AMR-WB or Opus fixture under
 *     `app/src/androidTest/assets/rtp/` -- the checked-in captures are
 *     `sip_g711a_bidirectional`, `g711u_loss_reorder`, `rtp_no_signal` and
 *     `srtp` (see CONTRIBUTING.md) -- so even the first stage could not produce AMR
 *     frames. Adding such a fixture is RTP4-QA-01's deliverable, and CONTRIBUTING.md
 *     section 4 forbids hand-editing fixtures.
 *
 * What is left is the other half of the contract, which the card does freeze in
 * this tree: the `.pcmchunks` / `.fidx` consistency rules, the fail-closed
 * promise ("a rejected request creates no output file of any kind"), and "the
 * structure is exactly `decodeRtpAudio`'s `items[i]`". The `.fidx` format itself
 * is covered byte-for-byte by the host test
 * `native_build/verification/rtp/host_tests/lib/FidxFileTest.cpp`; the
 * `.pcmchunks` writer belongs to RTP4-KT-01.
 *
 * The PCM fed in below is **synthetic and is the subject of the test**, not
 * evidence about any codec or capture: every block is a per-block ramp whose
 * values make the block order visible, and the stream id is taken from a real
 * scan of the G.711A fixture only because this endpoint resolves streams
 * through the same media snapshot every other RTP endpoint does. Nothing here
 * claims that any real capture decodes to these samples.
 */
@RunWith(AndroidJUnit4::class)
class RtpMediaCodecRenderTest {

    /**
     * The positive path: a well-formed `.fidx` + `.pcmchunks` pair for a stream
     * id that exists in a real fixture's scan renders to a WAV whose PCM is
     * exactly the supplied blocks, and the answer carries the `decodeRtpAudio`
     * item shape.
     */
    @Test(timeout = 120_000)
    fun rendersSyntheticPcmAndCarriesTheDecodeItemKeySet() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            val stream = findG711AStream(scan)
            val streamId = stream.getString("id")
            val generation = scan.getLong("scanGeneration")

            val outDir = freshRequestDir("render-ok")
            val chunks = listOf(
                monoBlock(0, 0),
                monoBlock(1, 1_000),
                monoBlock(2, 2_000),
                monoBlock(3, 3_000),
                monoBlock(4, 4_000)
            )
            // Deliberately written in reverse: the endpoint has to match blocks
            // to `.fidx` entries by `fidxIndex`, not by file order.
            val pcmFile = File(outDir, "$streamId.pcmchunks")
            writeFidx(File(outDir, "$streamId.fidx"), fidxEntries(BLOCK_COUNT))
            writePcmChunks(pcmFile, SAMPLE_RATE, 1, chunks.reversed())

            val result = render(
                session,
                requestJson(generation, streamId, pcmFile),
                outDir
            )
            assertEquals("renderRtpAudioFromPcm: ${result.optString("error")}",
                "", result.optString("error"))
            assertFalse(result.optBoolean("cancelled", true))

            assertEquals(streamId, result.getString("streamId"))
            assertEquals("g711A", result.getString("codec"))
            assertEquals(SAMPLE_RATE, result.getInt("sampleRate"))
            assertEquals(1, result.getInt("channels"))

            val wav = File(result.getString("wavPath"))
            val peaks = File(result.getString("peaksPath"))
            val map = File(result.getString("mapPath"))
            assertEquals(
                File(outDir, "$streamId.wav").absolutePath,
                wav.absolutePath
            )
            assertEquals(
                File(outDir, "$streamId.peaks").absolutePath,
                peaks.absolutePath
            )
            assertEquals(
                File(outDir, "$streamId.map").absolutePath,
                map.absolutePath
            )
            assertTrue("no WAV was written", wav.isFile && wav.length() > 0L)
            assertTrue("no peaks file was written", peaks.isFile && peaks.length() > 0L)
            assertTrue("no map file was written", map.isFile && map.length() > 0L)

            val header = requireNotNull(WavHeader.parse(wav)) {
                "Rendered WAV is not a readable PCM WAV: ${wav.absolutePath}"
            }
            assertEquals(SAMPLE_RATE, header.sampleRate)
            assertEquals(1, header.channels)
            assertEquals(16, header.bitsPerSample)
            assertEquals(
                "the renderer must emit exactly one block per packet at 20 ms per block",
                BLOCK_COUNT.toLong() * SAMPLES_PER_BLOCK,
                header.frameCount
            )
            val durationMs = result.getLong("durationMs")
            assertEquals(
                "durationMs must match the sample count",
                header.frameCount * 1000L / SAMPLE_RATE,
                durationMs
            )

            // The samples are already on an exact 20 ms grid with no jitter, so
            // the renderer has nothing to pad: the WAV is the input, in `fidx`
            // order, with no silence inserted anywhere.
            assertArrayEquals(
                expectedMonoPcm(BLOCK_COUNT),
                readWavDataChunk(wav)
            )
            assertEquals(0, result.getJSONArray("gaps").length())
            assertEquals(0, result.getJSONArray("events").length())

            val stats = result.getJSONObject("stats")
            assertEquals(BLOCK_COUNT.toLong(), stats.getLong("decodedPackets"))
            assertEquals(0L, stats.getLong("droppedLate"))
            assertEquals(0L, stats.getLong("zeroPayloadPackets"))
            // `lost` and `truncatedPackets` are the scan snapshot's, exactly as
            // `decodeRtpAudio` reports them for the same stream.
            assertEquals(stream.getLong("lost"), stats.getLong("lost"))
            assertEquals(
                stream.getLong("truncated"),
                stats.getLong("truncatedPackets")
            )

            // "结构 与 decodeRtpAudio 的 items[i] 完全相同": compared against a
            // real item from the same stream, and separately against the literal
            // key list so the shape stays pinned even if that item changes.
            val reference = requireNotNull(
                decodeNative(session, generation, streamId, freshRequestDir("native"))
                    .optJSONArray("items")?.optJSONObject(0)
            ) { "decodeRtpAudio produced no reference item" }
            assertEquals(
                "the rendered-PCM result must carry the same key set as a " +
                    "decodeRtpAudio item plus the envelope",
                reference.keys().asSequence().toSet() + ENVELOPE_KEYS,
                result.keys().asSequence().toSet()
            )
            assertEquals(EXPECTED_RESULT_KEYS, result.keys().asSequence().toSet())
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    /**
     * A `lost` entry is not a packet: it becomes a `lost` gap on the renderer's
     * clock, and the renderer pads the timestamp step it leaves behind.
     */
    @Test(timeout = 120_000)
    fun lostEntryBecomesALostGapOnTheRendererClock() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            val streamId = findG711AStream(scan).getString("id")
            val generation = scan.getLong("scanGeneration")

            val outDir = freshRequestDir("render-lost")
            val lostIndex = 2
            val entries = fidxEntries(BLOCK_COUNT, lost = setOf(lostIndex))
            val chunks = entries.indices
                .filter { it != lostIndex }
                .map { monoBlock(it, it * 1_000) }
            val pcmFile = File(outDir, "$streamId.pcmchunks")
            writeFidx(File(outDir, "$streamId.fidx"), entries)
            writePcmChunks(pcmFile, SAMPLE_RATE, 1, chunks.reversed())

            val result = render(
                session,
                requestJson(generation, streamId, pcmFile),
                outDir
            )
            assertEquals("renderRtpAudioFromPcm: ${result.optString("error")}",
                "", result.optString("error"))

            val gaps = result.getJSONArray("gaps")
            var lostGap: JSONObject? = null
            for (index in 0 until gaps.length()) {
                if (gaps.getJSONObject(index).getString("reason") == "lost") {
                    lostGap = gaps.getJSONObject(index)
                }
            }
            val gap = requireNotNull(lostGap) {
                "no lost gap was reported: $gaps"
            }
            // The renderer's clock, not the capture clock: `extTs` is staggered
            // by 20 ms per entry and `atMs`/`durMs` follow it.
            assertEquals(40, gap.getInt("atMs"))
            assertEquals(20, gap.getInt("durMs"))
            assertEquals(
                entries[lostIndex].frame.toLong(),
                gap.getLong("frame")
            )
            assertEquals(
                "only the surviving entries are handed to the renderer",
                (BLOCK_COUNT - 1).toLong(),
                result.getJSONObject("stats").getLong("decodedPackets")
            )

            // The renderer replaced the skipped 20 ms slot with silence. It
            // computes that silence in floating point and truncates to a whole
            // sample, so the total is 799 rather than the ideal 800. What this
            // pins is that the hole was padded at all -- 640 would mean it was
            // not -- and that no extra audio was produced.
            val wav = File(result.getString("wavPath"))
            val header = requireNotNull(WavHeader.parse(wav))
            assertEquals(799L, header.frameCount)
            assertEquals(
                799L * 1000L / SAMPLE_RATE,
                result.getLong("durationMs")
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    /** Two-channel chunks are averaged down to the mono the renderer wants. */
    @Test(timeout = 120_000)
    fun stereoChunksAreDownmixedToMono() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            val streamId = findG711AStream(scan).getString("id")
            val generation = scan.getLong("scanGeneration")

            val outDir = freshRequestDir("render-stereo")
            // Left ramps up, right ramps down, so an average that dropped one
            // channel or used the wrong one is visible in the samples.
            val values = ShortArray(SAMPLES_PER_BLOCK * 2) { position ->
                if (position % 2 == 0) (position / 2).toShort()
                else (2_000 - position / 2).toShort()
            }
            val pcmFile = File(outDir, "$streamId.pcmchunks")
            writeFidx(File(outDir, "$streamId.fidx"), fidxEntries(1))
            writePcmChunks(
                pcmFile,
                SAMPLE_RATE,
                2,
                listOf(PcmChunk(fidxIndex = 0, values = values))
            )

            val result = render(
                session,
                requestJson(generation, streamId, pcmFile, channels = 2),
                outDir
            )
            assertEquals("renderRtpAudioFromPcm: ${result.optString("error")}",
                "", result.optString("error"))
            assertEquals(1, result.getInt("channels"))

            val pcm = readWavDataChunk(File(result.getString("wavPath")))
            val buffer = ByteBuffer.wrap(pcm).order(ByteOrder.LITTLE_ENDIAN)
            val samples = ShortArray(pcm.size / 2) { buffer.getShort(it * 2) }
            assertEquals(SAMPLES_PER_BLOCK, samples.size)
            for (index in samples.indices) {
                assertEquals(
                    "sample $index is not the average of the two channels",
                    1_000,
                    samples[index].toInt()
                )
            }
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    /**
     * Every `.pcmchunks` / request inconsistency the card lists must come back
     * as a non-empty `error` and must not leave a `.wav`, `.peaks` or `.map`
     * behind.
     */
    @Test(timeout = 120_000)
    fun inconsistentPcmChunksAndRequestsFailClosed() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            val streamId = findG711AStream(scan).getString("id")
            val generation = scan.getLong("scanGeneration")

            val cases = listOf(                Case(
                    name = "bad magic",
                    pcmFile = { File(it, "$streamId.pcmchunks") },
                    overwrite = { file ->
                        val bytes = file.readBytes()
                        bytes[0] = 'X'.code.toByte()
                        file.writeBytes(bytes)
                    }
                ),
                Case(
                    name = "header sample rate differs from the request",
                    pcmFile = { File(it, "$streamId.pcmchunks") },
                    overwrite = { file ->
                        val bytes = file.readBytes()
                        ByteBuffer.wrap(bytes, 4, 4)
                            .order(ByteOrder.LITTLE_ENDIAN)
                            .putInt(SAMPLE_RATE / 2)
                        file.writeBytes(bytes)
                    }
                ),
                Case(
                    name = "header channel count differs from the request",
                    pcmFile = { File(it, "$streamId.pcmchunks") },
                    overwrite = { file ->
                        val bytes = file.readBytes()
                        ByteBuffer.wrap(bytes, 8, 2)
                            .order(ByteOrder.LITTLE_ENDIAN)
                            .putShort(2)
                        file.writeBytes(bytes)
                    }
                ),
                Case(
                    name = "fidxIndex out of range",
                    pcmFile = { File(it, "$streamId.pcmchunks") },
                    overwrite = { file ->
                        val bytes = file.readBytes()
                        ByteBuffer.wrap(bytes, PCM_HEADER_BYTES, 4)
                            .order(ByteOrder.LITTLE_ENDIAN)
                            .putInt(BLOCK_COUNT + 10)
                        file.writeBytes(bytes)
                    }
                ),
                Case(
                    name = "duplicate fidxIndex",
                    pcmFile = { File(it, "$streamId.pcmchunks") },
                    overwrite = { file ->
                        val bytes = file.readBytes()
                        // Second block header starts right after the first
                        // block's 8 octets plus its 160 samples.
                        val secondBlock =
                            PCM_HEADER_BYTES + 8 + SAMPLES_PER_BLOCK * 2
                        ByteBuffer.wrap(bytes, secondBlock, 4)
                            .order(ByteOrder.LITTLE_ENDIAN)
                            .putInt(0)
                        file.writeBytes(bytes)
                    }
                ),
                Case(
                    name = "block truncated by the end of the file",
                    pcmFile = { File(it, "$streamId.pcmchunks") },
                    overwrite = { file ->
                        val bytes = file.readBytes()
                        file.writeBytes(bytes.copyOf(bytes.size - 100))
                    }
                ),
                Case(
                    name = "missing .pcmchunks",
                    pcmFile = { File(it, "$streamId.pcmchunks") },
                    writePcm = false
                ),
                Case(
                    name = "request sampleRate is zero",
                    pcmFile = { File(it, "$streamId.pcmchunks") },
                    sampleRate = 0
                ),
                Case(
                    name = "request channels outside 1..2",
                    pcmFile = { File(it, "$streamId.pcmchunks") },
                    channels = 3
                )
            )

            for (case in cases) {
                val outDir = freshRequestDir("render-bad")
                val pcmFile = case.pcmFile(outDir)
                writeFidx(File(outDir, "$streamId.fidx"), fidxEntries(BLOCK_COUNT))
                if (case.writePcm) {
                    writePcmChunks(
                        pcmFile,
                        SAMPLE_RATE,
                        1,
                        (0 until BLOCK_COUNT).map { monoBlock(it, it * 1_000) }
                    )
                }
                case.overwrite?.invoke(pcmFile)

                val result = render(
                    session,
                    requestJson(
                        generation,
                        streamId,
                        pcmFile,
                        sampleRate = case.sampleRate,
                        channels = case.channels
                    ),
                    outDir
                )
                assertTrue(
                    "${case.name} did not report an error: $result",
                    result.getString("error").isNotEmpty()
                )
                assertFalse(result.optBoolean("cancelled", true))
                assertNoMediaOutputs(case.name, outDir)
            }
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    /** The two resolution failures the RTP4-NAT-06 helper fixes. */
    @Test(timeout = 120_000)
    fun staleScanAndUnknownStreamAreRejected() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            val streamId = findG711AStream(scan).getString("id")
            val generation = scan.getLong("scanGeneration")

            val staleDir = freshRequestDir("render-stale")
            val stalePcm = File(staleDir, "$streamId.pcmchunks")
            writeFidx(File(staleDir, "$streamId.fidx"), fidxEntries(BLOCK_COUNT))
            writePcmChunks(
                stalePcm,
                SAMPLE_RATE,
                1,
                listOf(monoBlock(0, 0))
            )
            val stale = render(
                session,
                requestJson(generation + 1, streamId, stalePcm),
                staleDir
            )
            assertEquals("staleScan", stale.getString("error"))
            assertFalse(stale.optBoolean("cancelled", true))
            assertNoMediaOutputs("staleScan", staleDir)

            val missingDir = freshRequestDir("render-not-found")
            val missingPcm = File(missingDir, "s9999.pcmchunks")
            writeFidx(File(missingDir, "s9999.fidx"), fidxEntries(BLOCK_COUNT))
            writePcmChunks(missingPcm, SAMPLE_RATE, 1, listOf(monoBlock(0, 0)))
            val notFound = render(
                session,
                requestJson(generation, "s9999", missingPcm),
                missingDir
            )
            assertEquals("notFound", notFound.getString("error"))
            assertNoMediaOutputs("notFound", missingDir)
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    // ---------------------------------------------------------------- helpers

    private fun render(session: Long, request: String, outDir: File): JSONObject {
        val result = JSONObject(
            NativeEngine.renderRtpAudioFromPcm(
                session,
                request,
                outDir.absolutePath
            )
        )
        assertEnvelope(result)
        return result
    }

    private fun decodeNative(
        session: Long,
        generation: Long,
        streamId: String,
        outDir: File
    ): JSONObject {
        val result = JSONObject(
            NativeEngine.decodeRtpAudio(
                session,
                JSONObject()
                    .put("scanGeneration", generation)
                    .put("streams", org.json.JSONArray().put(streamId))
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
        return result
    }

    private fun requestJson(
        generation: Long,
        streamId: String,
        pcmFile: File,
        sampleRate: Int = SAMPLE_RATE,
        channels: Int = 1
    ): String = JSONObject()
        .put("scanGeneration", generation)
        .put("streamId", streamId)
        .put("pcmPath", pcmFile.absolutePath)
        .put("sampleRate", sampleRate)
        .put("channels", channels)
        .put("timing", "jitter")
        .put("jitterMs", 50)
        .toString()

    /** RTP4-NAT-07: every return value carries the envelope, errors included. */
    private fun assertEnvelope(result: JSONObject) {
        assertEquals(
            "schemaVersion must be 1 on every return: $result",
            1,
            result.optInt("schemaVersion", -1)
        )
        assertTrue("result has no 'error' key: $result", result.has("error"))
        assertTrue("error must be a string: $result", result.opt("error") is String)
    }

    private fun assertNoMediaOutputs(name: String, outDir: File) {
        val leftovers = outDir.listFiles().orEmpty().filter {
            it.extension in MEDIA_EXTENSIONS
        }
        assertTrue(
            "$name left rendered output behind: " +
                leftovers.joinToString { it.name },
            leftovers.isEmpty()
        )
    }

    private fun freshRequestDir(name: String): File {
        val dir = requestDir(name)
        dir.deleteRecursively()
        assertTrue("unable to create ${dir.absolutePath}", dir.mkdirs())
        return dir
    }

    private fun requestDir(name: String): File =
        File(appContext.cacheDir, "rtp-media-codec-$name")

    /** Block `index` as one mono 20 ms chunk, every sample offset by `base`. */
    private fun monoBlock(index: Int, base: Int): PcmChunk =
        PcmChunk(
            fidxIndex = index,
            values = ShortArray(SAMPLES_PER_BLOCK) { (base + it).toShort() }
        )

    /** The PCM the renderer must produce from [BLOCK_COUNT] mono blocks. */
    private fun expectedMonoPcm(blocks: Int): ByteArray {
        val buffer = ByteBuffer.allocate(blocks * SAMPLES_PER_BLOCK * 2)
            .order(ByteOrder.LITTLE_ENDIAN)
        for (index in 0 until blocks) {
            for (offset in 0 until SAMPLES_PER_BLOCK) {
                buffer.putShort((index * 1_000 + offset).toShort())
            }
        }
        return buffer.array()
    }

    private fun fidxEntries(
        count: Int,
        lost: Set<Int> = emptySet()
    ): List<FidxSpec> = (0 until count).map { index ->
        FidxSpec(
            frame = FIRST_FRAME + index * FRAME_STEP,
            extTs = FIRST_EXT_TS + index.toLong() * SAMPLES_PER_BLOCK,
            arrivalRel = FIRST_ARRIVAL_REL + index * BLOCK_SECONDS,
            flags = if (index in lost) FIDX_FLAG_LOST else 0
        )
    }

    /**
     * Writes the `.fidx` RTP4-NAT-06 freezes: `"FID1"`, `u32 count`, then
     * `count` 33-octet packed little-endian records (`u64 offset`, `u32 len`,
     * `u32 frame`, `u64 extTs`, `f64 arrivalRel`, `u8 flags`).
     */
    private fun writeFidx(file: File, entries: List<FidxSpec>) {
        val buffer = ByteBuffer
            .allocate(FIDX_HEADER_BYTES + entries.size * FIDX_RECORD_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN)
        buffer.put("FID1".toByteArray(Charsets.US_ASCII))
        buffer.putInt(entries.size)
        for (entry in entries) {
            buffer.putLong(0L)  // offset into `.frames`; unused by this endpoint
            buffer.putInt(entry.length)
            buffer.putInt(entry.frame)
            buffer.putLong(entry.extTs)
            buffer.putDouble(entry.arrivalRel)
            buffer.put(entry.flags.toByte())
        }
        file.writeBytes(buffer.array())
    }

    /** Writes the `.pcmchunks` RTP4-KT-01 will produce. */
    private fun writePcmChunks(
        file: File,
        sampleRate: Int,
        channels: Int,
        chunks: List<PcmChunk>
    ) {
        val payloadBytes = chunks.sumOf { it.values.size * 2 }
        val buffer = ByteBuffer
            .allocate(PCM_HEADER_BYTES + chunks.size * PCM_BLOCK_HEADER_BYTES + payloadBytes)
            .order(ByteOrder.LITTLE_ENDIAN)
        buffer.put("PCM1".toByteArray(Charsets.US_ASCII))
        buffer.putInt(sampleRate)
        buffer.putShort(channels.toShort())
        for (chunk in chunks) {
            buffer.putInt(chunk.fidxIndex)
            buffer.putInt(chunk.values.size / channels)
            for (value in chunk.values) {
                buffer.putShort(value)
            }
        }
        file.writeBytes(buffer.array())
    }

    private fun readWavDataChunk(file: File): ByteArray {
        val bytes = file.readBytes()
        require(bytes.size >= 44) { "WAV is too short: ${file.absolutePath}" }
        require(String(bytes, 0, 4, Charsets.US_ASCII) == "RIFF")
        require(String(bytes, 8, 4, Charsets.US_ASCII) == "WAVE")

        var offset = 12
        while (offset + 8 <= bytes.size) {
            val chunkId = String(bytes, offset, 4, Charsets.US_ASCII)
            val chunkSize = littleEndianUnsignedInt(bytes, offset + 4)
            val dataStart = offset + 8
            val dataEnd = dataStart.toLong() + chunkSize
            require(dataEnd <= bytes.size) {
                "WAV chunk exceeds file size: $chunkId in ${file.absolutePath}"
            }
            if (chunkId == "data") {
                return bytes.copyOfRange(dataStart, dataEnd.toInt())
            }
            offset = dataEnd.toInt() + (chunkSize.toInt() and 1)
        }
        throw AssertionError("WAV has no data chunk: ${file.absolutePath}")
    }

    private fun littleEndianUnsignedInt(bytes: ByteArray, offset: Int): Long =
        (bytes[offset].toLong() and 0xff) or
            ((bytes[offset + 1].toLong() and 0xff) shl 8) or
            ((bytes[offset + 2].toLong() and 0xff) shl 16) or
            ((bytes[offset + 3].toLong() and 0xff) shl 24)

    private fun openCapture(sampleName: String): Long {
        val capture = copyAssetFile(
            testContext,
            "rtp/$sampleName.pcap",
            File(appContext.cacheDir, "rtp-media-codec-$sampleName.pcap")
        )
        val session = NativeEngine.openFile(capture.absolutePath, null)
        assertNotEquals(
            "openFile failed: ${NativeEngine.getLastError()}",
            0L,
            session
        )
        return session
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

    @After
    fun cleanOutputs() {
        appContext.cacheDir.listFiles()
            .orEmpty()
            .filter { it.name.startsWith("rtp-media-codec-") }
            .forEach(File::deleteRecursively)
    }

    private class PcmChunk(val fidxIndex: Int, val values: ShortArray)

    /** One `.pcmchunks` corruption case, plus the request it is called with. */
    private class Case(
        val name: String,
        val pcmFile: (File) -> File,
        val overwrite: ((File) -> Unit)? = null,
        val writePcm: Boolean = true,
        val sampleRate: Int = SAMPLE_RATE,
        val channels: Int = 1
    )

    private class FidxSpec(
        val frame: Int,
        val extTs: Long,
        val arrivalRel: Double,
        val flags: Int = 0,
        val length: Int = 0
    )

    companion object {
        private const val TARGET_SAMPLE = "sip_g711a_bidirectional"
        private const val TARGET_SSRC = 2591773570L

        private const val SAMPLE_RATE = 8000
        private const val SAMPLES_PER_BLOCK = 160
        private const val BLOCK_COUNT = 5
        private const val BLOCK_SECONDS = 0.02
        private const val FIRST_EXT_TS = 1000L
        private const val FIRST_ARRIVAL_REL = 0.5
        private const val FIRST_FRAME = 10
        private const val FRAME_STEP = 2
        private const val FIDX_FLAG_LOST = 0x01

        private const val FIDX_HEADER_BYTES = 8
        private const val FIDX_RECORD_BYTES = 33
        private const val PCM_HEADER_BYTES = 10
        private const val PCM_BLOCK_HEADER_BYTES = 8

        private val MEDIA_EXTENSIONS = setOf("wav", "peaks", "map")
        private val ENVELOPE_KEYS = setOf("schemaVersion", "error", "cancelled")
        private val EXPECTED_RESULT_KEYS = ENVELOPE_KEYS + setOf(
            "streamId",
            "codec",
            "sampleRate",
            "channels",
            "wavPath",
            "peaksPath",
            "mapPath",
            "durationMs",
            "startRel",
            "startAbsEpochMs",
            "gaps",
            "events",
            "stats"
        )

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
