package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.model.RtpUnsupportedReason
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RtpPlayerFormattingTest {
    @Test
    fun `player time uses mm ss tenths`() {
        assertEquals("00:00.0", formatRtpPlayerTime(-1L))
        assertEquals("00:00.0", formatRtpPlayerTime(99L))
        assertEquals("00:01.2", formatRtpPlayerTime(1_299L))
        assertEquals("61:01.0", formatRtpPlayerTime(3_661_000L))
    }

    @Test
    fun `unsupported reasons map case-insensitively`() {
        assertEquals(RtpUnsupportedReason.SRTP, RtpUnsupportedReason.fromWire("srtp"))
        assertEquals(
            RtpUnsupportedReason.NEEDS_MAPPING,
            RtpUnsupportedReason.fromWire(" NEEDSMAPPING ")
        )
        assertEquals(
            RtpUnsupportedReason.STALE_SCAN,
            RtpUnsupportedReason.fromWire("staleScan")
        )
        assertNull(RtpUnsupportedReason.fromWire("futureReason"))
    }
}
