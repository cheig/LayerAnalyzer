package com.example.layanalyzer.media

import com.example.layanalyzer.data.VideoParamSets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RTP5-KT-01: the container-level decisions `RtpVideoMuxer` makes, pinned
 * without a device.
 *
 * `MediaMuxer` is Android-only and this machine has no emulator, so the parts
 * of the muxer that can be wrong in a way a *file* would show -- which MIME, how
 * big, and above all which octets go into `csd-0`/`csd-1` -- are pure functions
 * in `VideoMuxFormat` and are asserted here. The octets are the point: the
 * `csd` entries are what `MPEG4Writer` builds the `avcC`/`hvcC` sample
 * description box out of, and a start code in the wrong place or a missing VPS
 * is not something a later test can notice, because `MediaMuxer` muxes whatever
 * it is handed.
 *
 * PROVENANCE OF THE PARAMETER SETS
 * ================================
 * The SPS/PPS/VPS below are real encoder output, not made-up bytes: they are
 * the `ffmpeg 7.1` vectors of `native_build/verification/rtp/host_tests/lib/
 * SpsParserTest.cpp` (H.264 1280x720 High 3.1 and its PPS, H.265 Main 4.0 and
 * its VPS/SPS), which that file documents as produced by encoding two frames of
 * `testsrc` and checked with ffmpeg and h26x-extractor. They are re-used here
 * for the same reason they are used there -- a `csd` built out of invented
 * bytes would prove only that this function copies byte arrays.
 */
class VideoMuxFormatTest {

    @Test
    fun `the MIME strings are the ones MediaExtractor reports`() {
        assertEquals("video/avc", VideoMuxFormat.MIME_H264)
        assertEquals("video/hevc", VideoMuxFormat.MIME_H265)
        assertEquals(VideoMuxFormat.MIME_H264, VideoMuxFormat.mimeFor("H264"))
        assertEquals(VideoMuxFormat.MIME_H265, VideoMuxFormat.mimeFor("H265"))
    }

    @Test
    fun `mimeFor accepts the canonical ids and the HEVC alias`() {
        // The canonical ids of README section 4.3, with the same tolerance
        // `SdpVideoParams.videoKind` has: case and surrounding space do not
        // change the answer, and H265 and HEVC are one codec.
        assertEquals(VideoMuxFormat.MIME_H264, VideoMuxFormat.mimeFor("h264"))
        assertEquals(VideoMuxFormat.MIME_H264, VideoMuxFormat.mimeFor(" H264 "))
        assertEquals(VideoMuxFormat.MIME_H265, VideoMuxFormat.mimeFor("h265"))
        assertEquals(VideoMuxFormat.MIME_H265, VideoMuxFormat.mimeFor("HEVC"))
        assertEquals(VideoMuxFormat.MIME_H265, VideoMuxFormat.mimeFor("hevc"))
    }

    @Test
    fun `mimeFor refuses anything else`() {
        assertNull("a GB28181 PS stream has no inner codec here", VideoMuxFormat.mimeFor("PS"))
        assertNull(VideoMuxFormat.mimeFor("g711A"))
        assertNull(VideoMuxFormat.mimeFor(""))
        assertNull(VideoMuxFormat.mimeFor("H.264"))
    }

    @Test
    fun `the H264 csd is the SPS in csd-0 and the PPS in csd-1, both start-coded`() {
        val csd = requireNotNull(
            VideoMuxFormat.codecSpecificData("H264", sets(sps = H264_SPS, pps = H264_PPS))
        )

        assertArrayEquals(startCoded(H264_SPS), csd.csd0)
        assertArrayEquals(startCoded(H264_PPS), requireNotNull(csd.csd1))
        // And the start code itself, spelled out: four octets, not three.
        assertArrayEquals(byteArrayOf(0, 0, 0, 1), csd.csd0.copyOfRange(0, 4))
        assertEquals(4 + H264_SPS.size, csd.csd0.size)
        assertEquals(4 + H264_PPS.size, csd.csd1!!.size)
    }

    @Test
    fun `the H265 csd is the VPS, the SPS and the PPS concatenated in csd-0`() {
        val csd = requireNotNull(
            VideoMuxFormat.codecSpecificData(
                "H265",
                sets(sps = H265_SPS, pps = H265_PPS, vps = H265_VPS)
            )
        )

        assertArrayEquals(
            startCoded(H265_VPS) + startCoded(H265_SPS) + startCoded(H265_PPS),
            csd.csd0
        )
        // Each set keeps its own start code, in this order and no other.
        assertArrayEquals(byteArrayOf(0, 0, 0, 1), csd.csd0.copyOfRange(0, 4))
        assertArrayEquals(byteArrayOf(0, 0, 0, 1), csd.csd0.copyOfRange(4 + H265_VPS.size, 8 + H265_VPS.size))
        assertArrayEquals(
            byteArrayOf(0, 0, 0, 1),
            csd.csd0.copyOfRange(8 + H265_VPS.size + H265_SPS.size, 12 + H265_VPS.size + H265_SPS.size)
        )
        assertNull("H265 has no second csd entry", csd.csd1)
    }

    @Test
    fun `an H265 stream without a VPS still gets its SPS and PPS`() {
        // The VPS is one more array entry in hvcC and encoders do omit it from
        // SDP, so it is optional where the SPS and the PPS are not.
        val csd = requireNotNull(
            VideoMuxFormat.codecSpecificData("HEVC", sets(sps = H265_SPS, pps = H265_PPS))
        )

        assertArrayEquals(startCoded(H265_SPS) + startCoded(H265_PPS), csd.csd0)
        assertNull(csd.csd1)
    }

    @Test
    fun `the first SPS and the first PPS are the ones that survive`() {
        // `avcC` holds exactly one of each, and SDP's convention (which KT-00
        // follows) is that the first entry is the one to keep.
        val csd = requireNotNull(
            VideoMuxFormat.codecSpecificData(
                "H264",
                setsOf(sps = listOf(H264_SPS, OTHER_SPS), pps = listOf(H264_PPS, OTHER_SPS))
            )
        )

        assertArrayEquals(startCoded(H264_SPS), csd.csd0)
        assertArrayEquals(startCoded(H264_PPS), requireNotNull(csd.csd1))
    }

    @Test
    fun `missing parameter sets are refused for both codecs`() {
        assertNull(
            "H264 without a PPS has no avcC",
            VideoMuxFormat.codecSpecificData("H264", sets(sps = H264_SPS))
        )
        assertNull(
            "H264 without an SPS has no avcC",
            VideoMuxFormat.codecSpecificData("H264", sets(pps = H264_PPS))
        )
        assertNull(
            "H265 without a PPS has no hvcC",
            VideoMuxFormat.codecSpecificData("H265", sets(sps = H265_SPS, vps = H265_VPS))
        )
        assertNull(
            "H265 without an SPS has no hvcC",
            VideoMuxFormat.codecSpecificData("H265", sets(pps = H265_PPS))
        )
        assertNull(
            "empty sets are the card's 缺少参数集 case",
            VideoMuxFormat.codecSpecificData("H264", sets())
        )
        assertNull(VideoMuxFormat.codecSpecificData("H265", sets()))
        assertNull("and so is an unsupported codec", VideoMuxFormat.codecSpecificData("PS", sets()))
    }

    @Test
    fun `an empty parameter set is not a parameter set`() {
        // `SdpVideoParams` never produces a zero-length entry, but the type
        // allows it and a zero-octet SPS would be a start code followed by
        // nothing at all.
        assertNull(VideoMuxFormat.codecSpecificData("H264", sets(sps = ByteArray(0), pps = H264_PPS)))    }

    @Test
    fun `a zero or negative width or height falls back to 1280x720 and says so`() {
        val unknown = VideoMuxFormat.dimensions(0, 0)
        assertEquals(1280, unknown.width)
        assertEquals(720, unknown.height)
        assertTrue("a fallback must be visible to the caller", unknown.usedFallback)

        // NAT-05 leaves *both* at 0 when it cannot read the SPS; one of the
        // pair alone is the same request, since a size is only meaningful as a
        // pair.
        assertTrue(VideoMuxFormat.dimensions(1280, 0).usedFallback)
        assertTrue(VideoMuxFormat.dimensions(0, 720).usedFallback)
        assertTrue(VideoMuxFormat.dimensions(-640, -480).usedFallback)
        assertEquals(1280, VideoMuxFormat.dimensions(0, 0).width)
        assertEquals(720, VideoMuxFormat.dimensions(-1, -1).height)
    }

    @Test
    fun `a real size is used unchanged and is not marked as a fallback`() {
        val size = VideoMuxFormat.dimensions(1920, 1080)
        assertEquals(1920, size.width)
        assertEquals(1080, size.height)
        assertFalse(size.usedFallback)

        val portrait = VideoMuxFormat.dimensions(720, 1280)
        assertEquals(720, portrait.width)
        assertEquals(1280, portrait.height)
        assertFalse(portrait.usedFallback)
    }

    @Test
    fun `the start code is four octets and is prepended, never appended`() {
        assertArrayEquals(byteArrayOf(0, 0, 0, 1), VideoMuxFormat.START_CODE)
        assertEquals(4, VideoMuxFormat.START_CODE_BYTES)
        assertArrayEquals(
            byteArrayOf(0, 0, 0, 1, 0x67, 0x42),
            VideoMuxFormat.withStartCode(byteArrayOf(0x67, 0x42))
        )
        assertArrayEquals(
            "a set that is already start-coded would get a second start code",
            byteArrayOf(0, 0, 0, 1, 0, 0, 0, 1, 0x67),
            VideoMuxFormat.withStartCode(startCoded(byteArrayOf(0x67)))
        )
    }

    // ---------------------------------------------------------------- fixtures

    /** The usual case: at most one set of each kind, as KT-00 produces them. */
    private fun sets(
        sps: ByteArray? = null,
        pps: ByteArray? = null,
        vps: ByteArray? = null
    ) = setsOf(listOfNotNull(sps), listOfNotNull(pps), listOfNotNull(vps))

    private fun setsOf(
        sps: List<ByteArray> = emptyList(),
        pps: List<ByteArray> = emptyList(),
        vps: List<ByteArray> = emptyList()
    ) = VideoParamSets(
        sps = sps,
        pps = pps,
        vps = vps,
        packetizationMode = null,
        profileLevelId = null,
        donDiff = null
    )

    private fun startCoded(nal: ByteArray): ByteArray = VideoMuxFormat.withStartCode(nal)

    private companion object {
        /** `ffmpeg 7.1` output, 1280x720, High, Level 3.1 (SpsParserTest.cpp). */
        val H264_SPS = hex("6764101facb80a00b760220000030002000003001408")

        /** The PPS of the same file. */
        val H264_PPS = hex("68ee0f2c8b")

        /** `ffmpeg 7.1` output, HEVC Main, 1920x1080 (SpsParserTest.cpp). */
        val H265_VPS = hex("40010c01ffff016000000300900000030000030078959809")
        val H265_SPS = hex("420101016000000300900000030000030078a003c08010e596566924caf016808000000300800000030284")

        /**
         * A PPS-shaped NAL (type 34 in the two-octet H.265 header) standing in
         * for a real one, which the host test does not carry. Only the type bits
         * matter to the code under test, which copies bytes.
         */
        val H265_PPS = hex("4401c172b46240")

        /** A second SPS, to prove the first one wins. */
        val OTHER_SPS = hex("67641028acb80f0044fcb80880000003008000000502")

        private fun hex(value: String): ByteArray =
            ByteArray(value.length / 2) { index ->
                value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
    }
}
