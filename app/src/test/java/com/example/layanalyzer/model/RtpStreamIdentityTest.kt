package com.example.layanalyzer.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RtpStreamIdentityTest {
    @Test
    fun extractsAndMatchesIpv4RtpIdentity() {
        val identity = RtpStreamIdentity.fromProtocolTree(
            ProtocolNode(
                label = "Frame",
                children = listOf(
                    ProtocolNode(label = "IPv4", children = listOf(
                        ProtocolNode(label = "Source", filter = "ip.src", filterValue = "192.0.2.10"),
                        ProtocolNode(label = "Destination", filter = "ip.dst", filterValue = "198.51.100.20")
                    )),
                    ProtocolNode(label = "UDP", children = listOf(
                        ProtocolNode(label = "Source Port", filter = "udp.srcport", filterValue = "40000"),
                        ProtocolNode(label = "Destination Port", filter = "udp.dstport", filterValue = "50000")
                    )),
                    ProtocolNode(label = "RTP", filter = "rtp", children = listOf(
                            ProtocolNode(label = "SSRC", filter = "rtp.ssrc", filterValue = "0x1a2b3c4d")
                        ))
                )
            )
        )

        assertEquals(RtpStreamIdentity("192.0.2.10", 40000, "198.51.100.20", 50000, 0x1a2b3c4dL), identity)
        assertTrue(identity!!.matches(stream(identity)))
    }

    @Test
    fun rejectsProtocolTreeWithoutCompleteRtpIdentity() {
        assertNull(RtpStreamIdentity.fromProtocolTree(ProtocolNode(label = "Frame")))
    }

    private fun stream(identity: RtpStreamIdentity) = RtpStream(
        id = "s0", src = identity.src, srcPort = identity.srcPort,
        dst = identity.dst, dstPort = identity.dstPort, ssrc = identity.ssrc,
        ssrcHex = "0x1a2b3c4d", pt = 96, codec = "", codecSource = RtpCodecSource.UNKNOWN,
        clockRate = 0, setupFrame = 1L, setupMethod = "", isSrtp = false,
        packets = 1L, expected = 1L, lost = 0L, lostPct = 0.0,
        seqErrors = 0L, outOfOrder = 0L, truncated = 0L, problem = false,
        minDeltaMs = 0.0, meanDeltaMs = 0.0, maxDeltaMs = 0.0, maxDeltaFrame = 0L,
        minJitterMs = null, meanJitterMs = null, maxJitterMs = null, jitterAvailable = false,
        maxSkewMs = 0.0, bytes = 0L, firstFrame = 1L, lastFrame = 1L,
        startRel = 0.0, endRel = 0.0, firstAbsEpochUs = 0L, ptsSeen = listOf(96),
        decodable = RtpDecodability.NEEDS_MAPPING, decodableReason = "", primaryPayloadType = 96
    )
}
