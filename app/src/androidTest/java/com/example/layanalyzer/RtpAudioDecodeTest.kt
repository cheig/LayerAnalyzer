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
import java.security.MessageDigest
import kotlin.math.abs

/**
 * RTP2-QA-01: compares decoded G.711 audio with Wireshark 4.0.10 RTP Player
 * exports and verifies the fail-closed paths for unsupported streams.
 *
 * The checked-in repository intentionally does not synthesize WAV golden
 * files. If the hand-exported files documented in CONTRIBUTING.md (test data) are absent,
 * the hash and duration comparisons are reported as skipped instead of being
 * silently accepted. The UNINTERRUPTED sample-count and unsupported-stream
 * checks remain executable without golden files.
 */
@RunWith(AndroidJUnit4::class)
class RtpAudioDecodeTest {

    @Test(timeout = 120_000)
    fun jitterGoldenPcmHashMatches() {
        assertGoldenPcmHash(RtpTimingMode.JITTER)
    }

    @Test(timeout = 120_000)
    fun rtpTimestampGoldenPcmHashMatches() {
        assertGoldenPcmHash(RtpTimingMode.RTP_TIMESTAMP)
    }

    @Test(timeout = 120_000)
    fun uninterruptedGoldenPcmHashMatches() {
        assertGoldenPcmHash(RtpTimingMode.UNINTERRUPTED)
    }

    @Test(timeout = 120_000)
    fun rtpTimestampDurationMatchesGoldenWithin20Ms() {
        val golden = readGoldenWav(RtpTimingMode.RTP_TIMESTAMP)
        val actual = decodeTarget(RtpTimingMode.RTP_TIMESTAMP)

        assertEquals(
            "RTP_TIMESTAMP sample rate differs from golden",
            golden.header.sampleRate,
            actual.header.sampleRate
        )
        assertEquals(
            "RTP_TIMESTAMP channel count differs from golden",
            golden.header.channels,
            actual.header.channels
        )
        val differenceMs = abs(
            actual.header.frameCount - golden.header.frameCount
        ) * 1000.0 / actual.header.sampleRate
        assertTrue(
            "RTP_TIMESTAMP duration differs by ${"%.3f".format(differenceMs)} ms; " +
                "actual=${actual.header.frameCount} frames, " +
                "golden=${golden.header.frameCount} frames",
            differenceMs <= RTP_TIMESTAMP_DURATION_TOLERANCE_MS
        )
    }

    @Test(timeout = 120_000)
    fun uninterruptedSampleCountEqualsDecodedPacketsTimesSamplesPerPacket() {
        val decoded = decodeTarget(RtpTimingMode.UNINTERRUPTED)
        val decodedPackets = decoded.item!!
            .getJSONObject("stats")
            .getLong("decodedPackets")
        val sourcePackets = requireNotNull(decoded.sourcePackets) {
            "The decoded fixture stream has no scan packet count."
        }
        val expectedSamples = sourcePackets * G711A_SAMPLES_PER_PACKET

        assertEquals(8_000, decoded.header.sampleRate)
        assertEquals(1, decoded.header.channels)
        assertEquals(
            "UNINTERRUPTED must concatenate exactly one decoded packet at a time",
            expectedSamples,
            decoded.header.frameCount
        )
        assertEquals(
            "The target stream contains only decodable G.711A packets",
            sourcePackets,
            decodedPackets
        )
        assertEquals(
            "decodedPackets must describe the rendered G.711A packet count",
            decodedPackets,
            decoded.header.frameCount / G711A_SAMPLES_PER_PACKET
        )
    }

    @Test(timeout = 120_000)
    fun srtpAndNeedsMappingStreamsProduceNoFiles() {
        assertUnsupportedProducesNoFiles(
            sampleName = "srtp",
            expectedReason = "srtp"
        )
        assertUnsupportedProducesNoFiles(
            sampleName = "g711u_loss_reorder",
            expectedReason = "needsMapping",
            needsMappingDerivative = true
        )
    }

    private fun assertGoldenPcmHash(mode: RtpTimingMode) {
        val golden = readGoldenWav(mode)
        val actual = decodeTarget(mode)

        assertEquals(
            "decoded WAV sample rate differs from golden for $mode",
            golden.header.sampleRate,
            actual.header.sampleRate
        )
        assertEquals(
            "decoded WAV channel count differs from golden for $mode",
            golden.header.channels,
            actual.header.channels
        )
        assertEquals(
            "decoded WAV bit depth differs from golden for $mode",
            golden.header.bitsPerSample,
            actual.header.bitsPerSample
        )

        val actualHash = sha256(trimLeadingSilence(actual.pcm))
        val goldenHash = sha256(trimLeadingSilence(golden.pcm))
        assertEquals(
            "PCM SHA-256 differs after removing leading silence for $mode " +
                "(${goldenFile(mode).name})",
            goldenHash,
            actualHash
        )
    }

    private fun decodeTarget(mode: RtpTimingMode): DecodedWav {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            val stream = findStream(scan, TARGET_SSRC)
            val streamId = stream.getString("id")
            val outDir = requestDir("golden-${mode.wireValue}")
            outDir.deleteRecursively()

            val result = decode(session, scan, streamId, mode, outDir)
            assertEquals(
                "decodeRtpAudio reported an error: ${result.optString("error")}",
                "",
                result.optString("error")
            )
            assertFalse(result.optBoolean("cancelled", true))
            assertEquals(0, result.optJSONArray("unsupported")?.length() ?: 0)
            val item = requireNotNull(result.optJSONArray("items")?.optJSONObject(0)) {
                "decodeRtpAudio returned no item: $result"
            }
            assertEquals(streamId, item.getString("streamId"))
            assertEquals(8_000, item.getInt("sampleRate"))
            assertEquals(1, item.getInt("channels"))
            assertEquals(
                "unexpected decoded WAV path",
                File(outDir, "$streamId.wav").absolutePath,
                item.getString("wavPath")
            )
            return readWav(
                File(item.getString("wavPath")),
                item,
                stream.getLong("packets")
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    private fun readGoldenWav(mode: RtpTimingMode): DecodedWav {
        val path = GOLDEN_ASSET_DIR + "/" + goldenFile(mode).name
        assumeTrue(
            "Missing Wireshark 4.0.10 golden WAV '$path'. " +
                "Generate it using CONTRIBUTING.md (test data).",
            assetExists(path)
        )

        val copied = File(
            appContext.cacheDir,
            "rtp-audio-golden-${goldenFile(mode).name}"
        )
        copyAssetFile(testContext, path, copied)
        return readWav(copied, null, null)
    }

    private fun readWav(
        file: File,
        item: JSONObject?,
        sourcePackets: Long?
    ): DecodedWav {
        val header = requireNotNull(WavHeader.parse(file)) {
            "Invalid PCM WAV: ${file.absolutePath}"
        }
        assertEquals(16, header.bitsPerSample)
        val pcm = readWavDataChunk(file)
        assertEquals(
            "WAV header data size does not match the data chunk",
            header.dataBytes,
            pcm.size.toLong()
        )
        assertEquals(
            "WAV frame count does not match the PCM data",
            header.frameCount,
            pcm.size.toLong() / (header.channels * 2)
        )
        return DecodedWav(header, pcm, item, sourcePackets)
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

    private fun trimLeadingSilence(pcm: ByteArray): ByteArray {
        require(pcm.size % 2 == 0) { "PCM byte count must be sample aligned." }
        val samples = ByteBuffer.wrap(pcm).order(ByteOrder.LITTLE_ENDIAN)
        var firstNonZeroSample = 0
        while (firstNonZeroSample < pcm.size / 2 &&
            samples.getShort(firstNonZeroSample * 2).toInt() == 0
        ) {
            firstNonZeroSample++
        }
        return pcm.copyOfRange(firstNonZeroSample * 2, pcm.size)
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }

    private fun assertUnsupportedProducesNoFiles(
        sampleName: String,
        expectedReason: String,
        needsMappingDerivative: Boolean = false
    ) {
        val capture = if (needsMappingDerivative) {
            createNeedsMappingCapture(sampleName)
        } else {
            copyAssetFile(
                testContext,
                "rtp/$sampleName.pcap",
                File(appContext.cacheDir, "rtp-audio-$sampleName.pcap")
            )
        }
        val session = openCapture(capture)
        try {
            val scan = scan(session)
            val stream = findStreamByDecodability(scan, expectedReason)
            val streamId = stream.getString("id")
            val outDir = requestDir("unsupported-$sampleName")
            outDir.deleteRecursively()

            val result = decode(
                session,
                scan,
                streamId,
                RtpTimingMode.JITTER,
                outDir
            )
            assertEquals("", result.optString("error"))
            assertFalse(result.optBoolean("cancelled", true))
            assertEquals(0, result.optJSONArray("items")?.length() ?: 0)
            val unsupported = requireNotNull(
                result.optJSONArray("unsupported")?.optJSONObject(0)
            ) {
                "Expected unsupported $expectedReason stream: $result"
            }
            assertEquals(streamId, unsupported.getString("streamId"))
            assertEquals(expectedReason, unsupported.getString("reason"))
            assertTrue(
                "Unsupported $expectedReason decode created output: " +
                    outDir.listFiles().orEmpty().joinToString(),
                !outDir.exists() || outDir.listFiles().orEmpty().isEmpty()
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    private fun createNeedsMappingCapture(sampleName: String): File {
        val source = copyAssetFile(
            testContext,
            "rtp/$sampleName.pcap",
            File(appContext.cacheDir, "rtp-audio-$sampleName-source.pcap")
        )
        val target = File(
            appContext.cacheDir,
            "rtp-audio-$sampleName-needs-mapping.pcap"
        )
        val bytes = source.readBytes()
        require(bytes.size >= PCAP_GLOBAL_HEADER_BYTES)
        require(
            bytes[0] == 0xd4.toByte() &&
                bytes[1] == 0xc3.toByte() &&
                bytes[2] == 0xb2.toByte() &&
                bytes[3] == 0xa1.toByte()
        ) { "Expected little-endian classic pcap fixture." }
        require(littleEndianUnsignedInt(bytes, 20) == 1L) {
            "Expected Ethernet pcap fixture."
        }

        var mutatedPackets = 0
        var offset = PCAP_GLOBAL_HEADER_BYTES
        while (offset + PCAP_RECORD_HEADER_BYTES <= bytes.size) {
            val capturedLength =
                littleEndianUnsignedInt(bytes, offset + 8).toInt()
            val packetStart = offset + PCAP_RECORD_HEADER_BYTES
            val packetEnd = packetStart + capturedLength
            require(packetEnd <= bytes.size) { "Truncated pcap packet record." }

            val udp = ipv4UdpOffset(bytes, packetStart, packetEnd)
            if (udp != null &&
                networkUnsignedShort(bytes, udp) == G711U_SOURCE_PORT &&
                networkUnsignedShort(bytes, udp + 2) == G711U_DESTINATION_PORT
            ) {
                val rtp = udp + UDP_HEADER_BYTES
                require(rtp + RTP_MIN_HEADER_BYTES <= packetEnd) {
                    "Truncated RTP packet in fixture."
                }
                require((bytes[rtp].toInt() and 0xff).ushr(6) == 2) {
                    "Expected an RTP version 2 packet."
                }
                bytes[rtp + 1] =
                    ((bytes[rtp + 1].toInt() and 0x80) or DYNAMIC_PAYLOAD_TYPE)
                        .toByte()
                // IPv4 permits a zero UDP checksum and the payload change
                // invalidates the original checksum.
                bytes[udp + 6] = 0
                bytes[udp + 7] = 0
                mutatedPackets++
            }
            offset = packetEnd
        }
        require(mutatedPackets > 0) {
            "No G.711U RTP packets were found while deriving needsMapping."
        }
        target.writeBytes(bytes)
        return target
    }

    private fun ipv4UdpOffset(
        bytes: ByteArray,
        packetStart: Int,
        packetEnd: Int
    ): Int? {
        var networkOffset = packetStart
        require(networkOffset + ETHERNET_HEADER_BYTES <= packetEnd) {
            "Truncated Ethernet header."
        }
        var etherType = networkUnsignedShort(bytes, networkOffset + 12)
        networkOffset += ETHERNET_HEADER_BYTES
        while (etherType == VLAN_ETHERTYPE) {
            require(networkOffset + 4 <= packetEnd) { "Truncated VLAN header." }
            etherType = networkUnsignedShort(bytes, networkOffset + 2)
            networkOffset += 4
        }
        if (etherType != IPV4_ETHERTYPE || networkOffset + 20 > packetEnd) {
            return null
        }
        val versionAndHeaderLength = bytes[networkOffset].toInt() and 0xff
        if (versionAndHeaderLength ushr 4 != 4) return null
        val ipHeaderLength = (versionAndHeaderLength and 0x0f) * 4
        if (ipHeaderLength < 20 || networkOffset + ipHeaderLength > packetEnd) {
            return null
        }
        if ((bytes[networkOffset + 9].toInt() and 0xff) != UDP_PROTOCOL) {
            return null
        }
        val udp = networkOffset + ipHeaderLength
        return if (udp + UDP_HEADER_BYTES <= packetEnd) udp else null
    }

    private fun openCapture(sampleName: String): Long {
        val capture = copyAssetFile(
            testContext,
            "rtp/$sampleName.pcap",
            File(appContext.cacheDir, "rtp-audio-$sampleName.pcap")
        )
        return openCapture(capture)
    }

    private fun openCapture(capture: File): Long {
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

    private fun decode(
        session: Long,
        scan: JSONObject,
        streamId: String,
        mode: RtpTimingMode,
        outDir: File
    ): JSONObject {
        val request = JSONObject()
            .put("scanGeneration", scan.getLong("scanGeneration"))
            .put("streams", org.json.JSONArray().put(streamId))
            .put("timing", mode.wireValue)
            .put("jitterMs", 50)
        return JSONObject(
            NativeEngine.decodeRtpAudio(
                session,
                request.toString(),
                outDir.absolutePath,
                null
            )
        )
    }

    private fun findStream(scan: JSONObject, ssrc: Long): JSONObject {
        val streams = requireNotNull(scan.optJSONArray("streams"))
        for (index in 0 until streams.length()) {
            val stream = streams.getJSONObject(index)
            if (stream.optLong("ssrc") == ssrc &&
                stream.optString("codec") == "g711A" &&
                stream.optString("decodable") == "yes"
            ) {
                return stream
            }
        }
        throw AssertionError("No decodable g711A SSRC=$ssrc stream was found: $scan")
    }

    private fun findStreamByDecodability(
        scan: JSONObject,
        decodability: String
    ): JSONObject {
        val streams = requireNotNull(scan.optJSONArray("streams"))
        for (index in 0 until streams.length()) {
            val stream = streams.getJSONObject(index)
            if (stream.optString("decodable") == decodability) {
                return stream
            }
        }
        throw AssertionError(
            "No $decodability stream was found: $scan"
        )
    }

    private fun requestDir(name: String): File =
        File(appContext.cacheDir, "rtp-audio-$name")

    private fun goldenFile(mode: RtpTimingMode): File =
        File("$TARGET_SAMPLE.$TARGET_SSRC.${mode.goldenSuffix}.wav")

    private fun assetExists(path: String): Boolean =
        runCatching {
            testContext.assets.open(path).use { }
        }.isSuccess

    private fun networkUnsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or
            (bytes[offset + 1].toInt() and 0xff)

    private fun littleEndianUnsignedInt(bytes: ByteArray, offset: Int): Long =
        (bytes[offset].toLong() and 0xff) or
            ((bytes[offset + 1].toLong() and 0xff) shl 8) or
            ((bytes[offset + 2].toLong() and 0xff) shl 16) or
            ((bytes[offset + 3].toLong() and 0xff) shl 24)

    private data class DecodedWav(
        val header: WavHeader.Info,
        val pcm: ByteArray,
        val item: JSONObject?,
        val sourcePackets: Long?
    )

    private enum class RtpTimingMode(
        val wireValue: String,
        val goldenSuffix: String
    ) {
        JITTER("jitter", "jitter50"),
        RTP_TIMESTAMP("rtp", "rtpts"),
        UNINTERRUPTED("uninterrupted", "uninterrupted")
    }

    @After
    fun cleanOutputs() {
        appContext.cacheDir.listFiles()
            .orEmpty()
            .filter { it.name.startsWith("rtp-audio-") }
            .forEach(File::deleteRecursively)
    }

    companion object {
        private const val TARGET_SAMPLE = "sip_g711a_bidirectional"
        private const val TARGET_SSRC = 2591773570L
        private const val G711A_SAMPLES_PER_PACKET = 240L
        private const val RTP_TIMESTAMP_DURATION_TOLERANCE_MS = 20.0
        private const val GOLDEN_ASSET_DIR = "rtp/golden"
        private const val PCAP_GLOBAL_HEADER_BYTES = 24
        private const val PCAP_RECORD_HEADER_BYTES = 16
        private const val ETHERNET_HEADER_BYTES = 14
        private const val VLAN_ETHERTYPE = 0x8100
        private const val IPV4_ETHERTYPE = 0x0800
        private const val UDP_PROTOCOL = 17
        private const val UDP_HEADER_BYTES = 8
        private const val RTP_MIN_HEADER_BYTES = 12
        private const val G711U_SOURCE_PORT = 27942
        private const val G711U_DESTINATION_PORT = 6000
        private const val DYNAMIC_PAYLOAD_TYPE = 96

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
