// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class LiveCaptureStoreTest {
    @Test
    fun reportsDroppedPacketsAndWriteErrors() {
        LiveCaptureStore.start("capture.pcap")
        LiveCaptureStore.recordOffered()
        LiveCaptureStore.recordDropped()
        LiveCaptureStore.recordIoError("disk full")
        LiveCaptureStore.stop()

        val state = LiveCaptureStore.state.value
        assertEquals(1L, state.offeredPacketCount)
        assertEquals(1L, state.droppedPacketCount)
        assertEquals(1L, state.ioErrorCount)
        assertEquals("disk full", state.lastIoError)
        assertFalse(state.captureIsComplete)
    }

    @Test
    fun serviceFailureIsIncompleteEvenWhenNoPacketWasDropped() {
        LiveCaptureStore.start("capture-failure.pcap")
        LiveCaptureStore.recordOffered()
        LiveCaptureStore.recordPacket(0L, byteArrayOf(1), 1)
        LiveCaptureStore.fail("network changed")

        val state = LiveCaptureStore.state.value
        assertFalse(state.captureIsComplete)
        assertEquals("network changed", state.error)
    }

    @Test
    fun parsesIpv4AndClampsLength() {
        val packet = ByteArray(20)
        packet[0] = 0x45
        packet[9] = 6
        packet[12] = 192.toByte()
        packet[13] = 168.toByte()
        packet[14] = 1
        packet[15] = 2
        packet[16] = 8
        packet[17] = 8
        packet[18] = 4
        packet[19] = 4

        val preview = LiveCaptureStore.parsePreview(7, 123, packet, 999)
        assertEquals(20, preview.length)
        assertEquals(4, preview.ipVersion)
        assertEquals("TCP", preview.protocol)
        assertEquals("192.168.1.2", preview.source)
        assertEquals("8.8.4.4", preview.destination)
    }

    @Test
    fun parsesIpv6AndReportsTruncation() {
        val packet = ByteArray(40)
        packet[0] = 0x60
        packet[6] = 17
        packet[8] = 0x20
        packet[9] = 0x01
        packet[23] = 1
        packet[24] = 0x20
        packet[25] = 0x01
        packet[39] = 2

        val preview = LiveCaptureStore.parsePreview(1, 0, packet, packet.size)
        assertEquals(6, preview.ipVersion)
        assertEquals("UDP", preview.protocol)
        assertEquals("2001:0:0:0:0:0:0:1", preview.source)
        assertEquals("2001:0:0:0:0:0:0:2", preview.destination)

        val truncated = LiveCaptureStore.parsePreview(2, 0, byteArrayOf(0x45), 1)
        assertEquals("truncated", truncated.source)
        assertEquals("IPv4", truncated.protocol)
    }
}
