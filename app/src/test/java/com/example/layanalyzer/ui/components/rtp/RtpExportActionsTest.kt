package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.model.RtpCodecSource
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpStream
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RtpExportActionsTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `wav file name uses the frozen format and sanitizes every unsafe character`() {
        val stream = stream(
            src = "2001:db8::1 /",
            srcPort = 50_000,
            dst = "host name",
            dstPort = 60_000,
            ssrcHex = "0x12 34"
        )

        assertEquals(
            "rtp_2001_db8__1___50000-host_name_60000_0x12_34.wav",
            rtpWavExportFileName(stream)
        )
    }

    @Test
    fun `raw extensions map supported codecs case insensitively`() {
        assertEquals("pcma", rtpRawExportExtension("g711A"))
        assertEquals("pcma", rtpRawExportExtension("PCMA"))
        assertEquals("pcmu", rtpRawExportExtension("G711U"))
        assertEquals("l16", rtpRawExportExtension("L16"))
        assertNull(rtpRawExportExtension("opus"))
        assertNull(rtpRawExportExtension(""))
    }

    @Test
    fun `raw file name is unavailable for an unsupported codec`() {
        assertEquals(
            "rtp_10.0.0.1_40000-10.0.0.2_30000_0x1a2b3c4d.pcma",
            rtpRawExportFileName(stream(codec = "g711A"))
        )
        assertNull(rtpRawExportFileName(stream(codec = "opus")))
    }

    @Test
    fun `cache containment accepts descendants and rejects outside paths`() {
        val root = File(temporaryFolder.root, "rtp")
        val cache = RtpMediaCache(root)
        val inside = File(root, "11/22/s0.wav").apply {
            parentFile?.mkdirs()
            writeBytes(byteArrayOf(1))
        }
        val outside = File(temporaryFolder.root, "outside/s0.wav").apply {
            parentFile?.mkdirs()
            writeBytes(byteArrayOf(1))
        }

        assertTrue(cache.contains(inside))
        assertFalse(cache.contains(outside))
        assertFalse(cache.contains(File(root, "../outside/s0.wav")))
    }

    private fun stream(
        src: String = "10.0.0.1",
        srcPort: Int = 40_000,
        dst: String = "10.0.0.2",
        dstPort: Int = 30_000,
        ssrcHex: String = "0x1a2b3c4d",
        codec: String = "g711A"
    ): RtpStream = RtpStream(
        id = "s0",
        src = src,
        srcPort = srcPort,
        dst = dst,
        dstPort = dstPort,
        ssrc = 439_041_101L,
        ssrcHex = ssrcHex,
        pt = 8,
        codec = codec,
        codecSource = RtpCodecSource.STATIC,
        clockRate = 8_000,
        setupFrame = 0L,
        setupMethod = "",
        isSrtp = false,
        packets = 1L,
        expected = 1L,
        lost = 0L,
        lostPct = 0.0,
        seqErrors = 0L,
        outOfOrder = 0L,
        truncated = 0L,
        problem = false,
        minDeltaMs = 0.0,
        meanDeltaMs = 0.0,
        maxDeltaMs = 0.0,
        maxDeltaFrame = 0L,
        minJitterMs = null,
        meanJitterMs = null,
        maxJitterMs = null,
        jitterAvailable = false,
        maxSkewMs = 0.0,
        bytes = 0L,
        firstFrame = 1L,
        lastFrame = 1L,
        startRel = 0.0,
        endRel = 0.0,
        firstAbsEpochUs = 0L,
        ptsSeen = emptyList(),
        decodable = RtpDecodability.YES,
        decodableReason = "",
        primaryPayloadType = 8
    )
}
